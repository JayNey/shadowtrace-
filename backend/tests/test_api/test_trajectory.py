"""Contract tests for GET /events/{event_id}/trajectory (ISSUE-341 / #984).

Infrastructure failures must surface as HTTP 503 ``dependency_unavailable``;
genuinely empty decision traces keep HTTP 200 with ``insufficient_trace=True``.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from app.api.v1.deps import get_event_service, reset_deps
from app.main import app
from app.models.trajectory import TrajectoryReport
from app.services.trajectory_analyzer import TrajectoryAnalyzer

_DEV_TOKENS = json.dumps(
    {
        "analyst-token": {"subject": "analyst-1", "roles": ["analyst"]},
    }
)


@pytest.fixture(autouse=True)
def _dev_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.config import get_settings

    monkeypatch.setenv("DEV_AUTH_TOKENS", _DEV_TOKENS)
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _reset_services() -> None:
    reset_deps()
    app.dependency_overrides.clear()


@pytest.fixture
def client() -> TestClient:
    event = MagicMock()
    event.event_id = "evt-traj-contract"

    event_service = MagicMock()
    event_service.get_event = AsyncMock(return_value=event)
    app.dependency_overrides[get_event_service] = lambda: event_service
    return TestClient(app)


def _hdr() -> dict[str, str]:
    return {"Authorization": "Bearer analyst-token"}


def test_trajectory_session_factory_missing_returns_503(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.api.v1.trajectory as trajectory_mod

    monkeypatch.setattr(trajectory_mod, "_try_get_session_factory", lambda: None)

    resp = client.get("/api/v1/events/evt-traj-contract/trajectory", headers=_hdr())

    assert resp.status_code == 503
    body = resp.json()
    assert body["error_code"] == "dependency_unavailable"
    assert "insufficient_trace" not in body


def test_trajectory_sqlalchemy_error_returns_503(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.api.v1.trajectory as trajectory_mod

    monkeypatch.setattr(trajectory_mod, "_try_get_session_factory", lambda: MagicMock())
    monkeypatch.setattr(
        TrajectoryAnalyzer,
        "analyze",
        AsyncMock(side_effect=OperationalError("SELECT 1", {}, Exception("db down"))),
    )

    resp = client.get("/api/v1/events/evt-traj-contract/trajectory", headers=_hdr())

    assert resp.status_code == 503
    body = resp.json()
    assert body["error_code"] == "dependency_unavailable"
    assert "insufficient_trace" not in body


def test_trajectory_empty_trace_returns_200_with_insufficient_trace_flag(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.api.v1.trajectory as trajectory_mod

    monkeypatch.setattr(trajectory_mod, "_try_get_session_factory", lambda: MagicMock())
    monkeypatch.setattr(
        TrajectoryAnalyzer,
        "analyze",
        AsyncMock(
            return_value=TrajectoryReport(
                event_id="evt-traj-contract",
                insufficient_trace=True,
            )
        ),
    )

    resp = client.get("/api/v1/events/evt-traj-contract/trajectory", headers=_hdr())

    assert resp.status_code == 200
    body = resp.json()
    assert body["event_id"] == "evt-traj-contract"
    assert body["insufficient_trace"] is True
