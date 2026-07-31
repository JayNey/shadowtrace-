"""Evidence collection API tests (ISSUE-101)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.api.v1.deps import _get_context_store, get_event_service
from app.core.auth import Principal, get_principal
from app.main import app
from app.models.agent_io import CollectionStatus
from app.models.context import EventContext
from app.models.enums import EvidenceSource


class _EventService:
    def __init__(self, *, exists: bool = True) -> None:
        self._exists = exists

    async def get_event(self, event_id: str) -> object | None:
        return object() if self._exists else None


class _ContextStore:
    def __init__(
        self,
        evidence_output: dict[str, Any] | None,
        *,
        context_exists: bool = True,
    ) -> None:
        self._evidence_output = evidence_output
        self._context_exists = context_exists

    async def get_full_context(self, event_id: str) -> EventContext:
        if not self._context_exists:
            raise KeyError(f"security_event not found: {event_id}")
        return EventContext(evidence_output=self._evidence_output)


@pytest.fixture(autouse=True)
def _clear_overrides() -> Iterator[None]:
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def _client(
    evidence_output: dict[str, Any] | None,
    *,
    event_exists: bool = True,
    context_exists: bool = True,
) -> TestClient:
    async def _principal() -> Principal:
        return Principal(subject="analyst-1", roles=["analyst"])

    async def _event_service() -> _EventService:
        return _EventService(exists=event_exists)

    def _context_store() -> _ContextStore:
        return _ContextStore(evidence_output, context_exists=context_exists)

    app.dependency_overrides[get_principal] = _principal
    app.dependency_overrides[get_event_service] = _event_service
    app.dependency_overrides[_get_context_store] = _context_store
    return TestClient(app)


def _evidence_output() -> dict[str, Any]:
    return {
        "evidence_list": [],
        "conflicts": [],
        "gaps": [
            {
                "event_id": "evt-api-101",
                "missing_source": EvidenceSource.ENDPOINT.value,
                "reason": "source_skipped",
                "detail": {
                    "tool_name": "query_edr_process",
                    "description": "required entity missing or invalid for query_edr_process",
                },
            }
        ],
        "success_sources": [],
        "failed_sources": [EvidenceSource.ENDPOINT.value],
        "overall_confidence": 0.0,
        "collection_status": CollectionStatus.FAILED.value,
    }


def test_get_event_evidence_returns_gaps_and_collection_status() -> None:
    response = _client(_evidence_output()).get("/api/v1/events/evt-api-101/evidence")

    assert response.status_code == 200
    payload = response.json()
    assert payload["event_id"] == "evt-api-101"
    assert payload["collection_status"] == CollectionStatus.FAILED.value
    assert payload["gaps"][0]["reason"] == "source_skipped"
    assert payload["gaps"][0]["missing_source"] == EvidenceSource.ENDPOINT.value
    assert payload["query_summary"] == []


def test_get_event_evidence_not_ready_when_missing_output() -> None:
    response = _client(None).get("/api/v1/events/evt-api-101/evidence")

    assert response.status_code == 404
    assert response.json()["error_code"] == "evidence_not_ready"


def test_get_event_evidence_event_not_found_first() -> None:
    response = _client(_evidence_output(), event_exists=False).get(
        "/api/v1/events/missing/evidence"
    )

    assert response.status_code == 404
    assert response.json()["error_code"] == "event_not_found"
