"""Celery-mode API tests (ISSUE-056)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.main import app
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    InvestigationIntentStatus,
    Severity,
    SourceObjectKind,
)
from app.models.security_event import SecurityEvent
from app.models.source import SourceReference
from app.tasks.investigation_tasks import register_task_metadata
from tests.support.fake_redis import InMemoryFakeRedis, patch_redis_client

_DEV_TOKENS = json.dumps(
    {
        "analyst-token": {"subject": "analyst-1", "roles": ["analyst"]},
    }
)


@pytest.fixture(autouse=True)
def _celery_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("DEV_AUTH_TOKENS", _DEV_TOKENS)
    monkeypatch.setenv("TASK_MODE", "celery")
    monkeypatch.setenv("LLM_MODE", "mock")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def fake_redis_store(monkeypatch: pytest.MonkeyPatch) -> InMemoryFakeRedis:
    fake = patch_redis_client(monkeypatch)
    celery_app.conf.result_backend = "cache+memory://"
    celery_app.conf.broker_url = "memory://"
    return fake


def _hdr() -> dict[str, str]:
    return {"Authorization": "Bearer analyst-token"}


def _durable_intent_double(
    event_id: str,
    *,
    on_schedule_dispatch: Any | None = None,
) -> object:
    class _IntentService:
        def __init__(self) -> None:
            self.schedule_calls = 0

        async def create_or_replay_http_intent(
            self,
            _event_id: str,
            **_kwargs: object,
        ) -> SimpleNamespace:
            return SimpleNamespace(
                intent_id=f"iin-{event_id}",
                event_id=event_id,
                task_id=f"task-{event_id}",
                revision=1,
                status=InvestigationIntentStatus.PENDING,
                created=True,
            )

        def schedule_dispatch(
            self,
            *,
            event_id: str | None = None,
            intent_id: str | None = None,
            trigger: str = "unspecified",
        ) -> None:
            """Mirror production: trigger dispatch best-effort and never raise."""
            del event_id, intent_id, trigger
            self.schedule_calls += 1
            if on_schedule_dispatch is None:
                return
            try:
                on_schedule_dispatch()
            except Exception:
                return

    return _IntentService()


@pytest.mark.asyncio
async def test_get_task_returns_celery_state_without_resolve_mock(
    fake_redis_store: InMemoryFakeRedis,
) -> None:
    """Regression: GET /tasks must not call asyncio.run inside async handler."""
    task_id = "task-api-state-001"
    await register_task_metadata(task_id, "evt-celery-api")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        resp = await client.get(f"/api/v1/tasks/{task_id}", headers=_hdr())

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["task_id"] == task_id
    assert body["event_id"] == "evt-celery-api"
    assert isinstance(body["state"], str)


@pytest.mark.asyncio
async def test_get_task_maps_retry_to_unknown(
    fake_redis_store: InMemoryFakeRedis,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task_id = "task-api-retry-unknown"
    await register_task_metadata(task_id, "evt-retry-unknown")

    class _FakeResult:
        state = "RETRY"
        info = None
        args = ("evt-retry-unknown",)

    with patch("celery.result.AsyncResult", return_value=_FakeResult()):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            resp = await client.get(f"/api/v1/tasks/{task_id}", headers=_hdr())

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["state"] == "UNKNOWN"
    assert body["event_id"] == "evt-retry-unknown"


@pytest.mark.asyncio
async def test_get_task_maps_revoked_to_unknown(
    fake_redis_store: InMemoryFakeRedis,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task_id = "task-api-revoked-unknown"
    await register_task_metadata(task_id, "evt-revoked-unknown")

    class _FakeResult:
        state = "REVOKED"
        info = None
        args = ("evt-revoked-unknown",)

    with patch("celery.result.AsyncResult", return_value=_FakeResult()):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            resp = await client.get(f"/api/v1/tasks/{task_id}", headers=_hdr())

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["state"] == "UNKNOWN"
    assert body["event_id"] == "evt-revoked-unknown"


@pytest.mark.asyncio
async def test_get_task_unknown_id_returns_404(fake_redis_store: InMemoryFakeRedis) -> None:
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        resp = await client.get("/api/v1/tasks/task-does-not-exist", headers=_hdr())

    assert resp.status_code == 404, resp.text
    assert resp.json()["error_code"] == "not_found"


@pytest.mark.asyncio
async def test_investigate_celery_mode_returns_task_id(
    fake_redis_store: InMemoryFakeRedis,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id = "evt-celery-dispatch"

    async def _fake_get_event(_event_id: str) -> SecurityEvent:
        return SecurityEvent(
            event_id=event_id,
            event_type=EventType.OTHER,
            title="celery",
            status=EventStatus.NEW,
            severity=Severity.LOW,
            creation_source_ref=SourceReference(
                source_kind=SourceObjectKind.INCIDENT,
                source_product="manual",
                source_tenant_id="tenant-test",
                connector_id="conn-test",
                source_object_id="manual-1",
                ingested_at=datetime.now(UTC),
            ),
            disposition_policy=DispositionPolicy.NOT_REQUIRED,
        )

    class _EventService:
        async def get_event(self, eid: str) -> SecurityEvent | None:
            return await _fake_get_event(eid)

    from app.api.v1.deps import get_event_service, get_investigation_intent_service

    app.dependency_overrides[get_event_service] = lambda: _EventService()
    app.dependency_overrides[get_investigation_intent_service] = lambda: _durable_intent_double(
        event_id
    )

    def _fake_apply_async(*_args: Any, **kwargs: Any) -> MagicMock:
        return MagicMock(id=kwargs["task_id"])

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        _fake_apply_async,
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        resp = await client.post(f"/api/v1/events/{event_id}/investigate", headers=_hdr())

    app.dependency_overrides.clear()
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["task_id"] != event_id
    assert body["event_id"] == event_id


@pytest.mark.asyncio
async def test_investigate_celery_broker_unavailable_keeps_accepted_intent(
    fake_redis_store: InMemoryFakeRedis,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from kombu.exceptions import OperationalError

    event_id = "evt-broker-down"
    del fake_redis_store  # fixture patches redis; unused body

    async def _fake_get_event(_event_id: str) -> SecurityEvent:
        return SecurityEvent(
            event_id=event_id,
            event_type=EventType.OTHER,
            title="celery",
            status=EventStatus.NEW,
            severity=Severity.LOW,
            creation_source_ref=SourceReference(
                source_kind=SourceObjectKind.INCIDENT,
                source_product="manual",
                source_tenant_id="tenant-test",
                connector_id="conn-test",
                source_object_id="manual-1",
                ingested_at=datetime.now(UTC),
            ),
            disposition_policy=DispositionPolicy.NOT_REQUIRED,
        )

    class _EventService:
        async def get_event(self, eid: str) -> SecurityEvent | None:
            return await _fake_get_event(eid)

    from app.api.v1.deps import get_event_service, get_investigation_intent_service

    def _boom() -> None:
        raise OperationalError("broker down")

    intent_double = _durable_intent_double(event_id, on_schedule_dispatch=_boom)
    app.dependency_overrides[get_event_service] = lambda: _EventService()
    app.dependency_overrides[get_investigation_intent_service] = lambda: intent_double

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        resp = await client.post(f"/api/v1/events/{event_id}/investigate", headers=_hdr())

    app.dependency_overrides.clear()
    assert resp.status_code == 202, resp.text
    assert resp.json()["intent_id"] == f"iin-{event_id}"
    assert intent_double.schedule_calls == 1


@pytest.mark.asyncio
async def test_investigate_celery_zero_workers_still_returns_202(
    fake_redis_store: InMemoryFakeRedis,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dispatch must not inspect worker liveness before publish (#622)."""
    event_id = "evt-zero-workers"

    async def _fake_get_event(_event_id: str) -> SecurityEvent:
        return SecurityEvent(
            event_id=event_id,
            event_type=EventType.OTHER,
            title="celery",
            status=EventStatus.NEW,
            severity=Severity.LOW,
            creation_source_ref=SourceReference(
                source_kind=SourceObjectKind.INCIDENT,
                source_product="manual",
                source_tenant_id="tenant-test",
                connector_id="conn-test",
                source_object_id="manual-1",
                ingested_at=datetime.now(UTC),
            ),
            disposition_policy=DispositionPolicy.NOT_REQUIRED,
        )

    class _EventService:
        async def get_event(self, eid: str) -> SecurityEvent | None:
            return await _fake_get_event(eid)

    from app.api.v1.deps import get_event_service, get_investigation_intent_service

    app.dependency_overrides[get_event_service] = lambda: _EventService()
    app.dependency_overrides[get_investigation_intent_service] = lambda: _durable_intent_double(
        event_id
    )

    def _fake_apply_async(*_args: Any, **kwargs: Any) -> MagicMock:
        return MagicMock(id=kwargs["task_id"])

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        _fake_apply_async,
    )

    with patch("app.core.celery_health.probe_celery_workers") as probe_mock:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            resp = await client.post(f"/api/v1/events/{event_id}/investigate", headers=_hdr())

    app.dependency_overrides.clear()
    probe_mock.assert_not_called()
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["event_id"] == event_id
    assert body["task_id"] != event_id
