"""Memory review API and RBAC tests (ISSUE-081)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.api.v1.deps import get_memory_governance
from app.core.errors import MemoryReviewConflictError, MemoryReviewNotFoundError
from app.main import app
from app.models.memory import MemoryReview

_DEV_TOKENS = json.dumps(
    {
        "analyst-token": {"subject": "analyst-1", "roles": ["analyst"]},
        "approver-token": {"subject": "approver-1", "roles": ["approver"]},
    }
)


class _Governance:
    def __init__(self) -> None:
        self.filters: list[str | None] = []
        self.promotions: list[tuple[str, str]] = []
        self.demotions: list[tuple[str, str, str]] = []

    async def list_pending(self, kb_name: str | None = None) -> list[MemoryReview]:
        self.filters.append(kb_name)
        return [
            MemoryReview(
                review_id="rev-acde1234",
                kb_name="fp_case_kb",
                candidate_type="fp_rule",
                payload={"alert_signature": "Backup Service Login"},
                status="pending",
                confidence=0.9,
                created_at=datetime(2026, 7, 29, tzinfo=UTC),
            )
        ]

    async def promote(self, review_id: str, operator: str) -> None:
        if review_id == "rev-missing":
            raise MemoryReviewNotFoundError(
                "memory review not found",
                details={"review_id": review_id},
            )
        if review_id == "rev-demoted":
            raise MemoryReviewConflictError(
                "memory review is already demoted",
                details={"review_id": review_id, "status": "demoted"},
            )
        self.promotions.append((review_id, operator))

    async def demote(self, review_id: str, operator: str, reason: str) -> None:
        self.demotions.append((review_id, operator, reason))


@pytest.fixture(autouse=True)
def _dev_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEV_AUTH_TOKENS", _DEV_TOKENS)


@pytest.fixture
def governance() -> _Governance:
    return _Governance()


@pytest.fixture
def client(governance: _Governance) -> TestClient:
    app.dependency_overrides[get_memory_governance] = lambda: governance
    yield TestClient(app)
    app.dependency_overrides.clear()


def _hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_list_pending_reviews_supports_kb_filter(
    client: TestClient,
    governance: _Governance,
) -> None:
    response = client.get(
        "/api/v1/knowledge/reviews?kb_name=fp_case_kb",
        headers=_hdr("analyst-token"),
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["review_id"] == "rev-acde1234"
    assert governance.filters == ["fp_case_kb"]


def test_approver_can_promote_and_operator_comes_from_principal(
    client: TestClient,
    governance: _Governance,
) -> None:
    response = client.post(
        "/api/v1/knowledge/reviews/rev-acde1234/promote",
        headers=_hdr("approver-token"),
    )

    assert response.status_code == 200
    assert response.json()["status"] == "promoted"
    assert governance.promotions == [("rev-acde1234", "approver-1")]


def test_approver_can_reject_with_reason(
    client: TestClient,
    governance: _Governance,
) -> None:
    response = client.post(
        "/api/v1/knowledge/reviews/rev-acde1234/reject",
        headers=_hdr("approver-token"),
        json={"reason": "Insufficient corroborating evidence"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "demoted"
    assert governance.demotions == [
        ("rev-acde1234", "approver-1", "Insufficient corroborating evidence")
    ]


def test_promote_unknown_review_returns_404(client: TestClient) -> None:
    response = client.post(
        "/api/v1/knowledge/reviews/rev-missing/promote",
        headers=_hdr("approver-token"),
    )

    assert response.status_code == 404
    assert response.json()["error_code"] == "memory_review_not_found"
    assert response.json()["details"]["review_id"] == "rev-missing"


def test_promote_already_demoted_review_returns_409(client: TestClient) -> None:
    response = client.post(
        "/api/v1/knowledge/reviews/rev-demoted/promote",
        headers=_hdr("approver-token"),
    )

    assert response.status_code == 409
    assert response.json()["error_code"] == "memory_review_conflict"
    assert response.json()["details"]["status"] == "demoted"


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/v1/knowledge/reviews/rev-acde1234/promote", None),
        (
            "/api/v1/knowledge/reviews/rev-acde1234/reject",
            {"reason": "Not approved"},
        ),
    ],
)
def test_analyst_cannot_decide_reviews(
    client: TestClient,
    path: str,
    body: dict[str, Any] | None,
) -> None:
    response = client.post(path, headers=_hdr("analyst-token"), json=body)

    assert response.status_code == 403
    assert response.json()["error_code"] == "forbidden"


def test_reject_request_cannot_override_operator(client: TestClient) -> None:
    response = client.post(
        "/api/v1/knowledge/reviews/rev-acde1234/reject",
        headers=_hdr("approver-token"),
        json={"reason": "Not approved", "operator": "attacker"},
    )

    assert response.status_code == 422
    assert response.json()["error_code"] == "validation_error"


def test_reject_requires_non_whitespace_reason(client: TestClient) -> None:
    response = client.post(
        "/api/v1/knowledge/reviews/rev-acde1234/reject",
        headers=_hdr("approver-token"),
        json={"reason": "   "},
    )

    assert response.status_code == 422
    assert response.json()["error_code"] == "validation_error"
