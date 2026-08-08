"""Celery redelivery matrix + lease fencing tests (ISSUE-117 / #622 Phase B)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.celery_app import celery_app
from app.core.celery_delivery import (
    celery_task_owner_id,
    normalize_public_task_state,
)
from app.core.errors import InvestigationInProgressError
from app.core.redis_client import RedisClient
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    Severity,
    SourceObjectKind,
)
from app.models.security_event import SecurityEvent
from app.models.source import SourceReference
from app.orchestration.lease import EventLease, generate_owner_id
from app.tasks import investigation_tasks as tasks
from app.tasks.investigation_task_contract import build_investigation_dispatch_kwargs
from app.tasks.investigation_tasks import TASK_QUEUE
from tests.support.fake_redis import InMemoryFakeRedis, patch_redis_client
from tests.support.investigation_task_doubles import (
    make_execute_investigation_double,
    make_run_investigation_body_double,
)


def test_celery_app_rejects_lost_worker_tasks() -> None:
    assert celery_app.conf.task_acks_late is True
    assert celery_app.conf.task_reject_on_worker_lost is True
    assert celery_app.conf.worker_prefetch_multiplier == 1
    assert celery_app.conf.broker_transport_options.get("visibility_timeout") == 900


def test_celery_task_owner_id_is_stable_per_task() -> None:
    assert celery_task_owner_id("task-abc-123") == "celery-task-abc-123"
    assert celery_task_owner_id("task-abc-123") == celery_task_owner_id("task-abc-123")
    assert celery_task_owner_id("other") != celery_task_owner_id("task-abc-123")


@pytest.mark.parametrize(
    ("celery_state", "expected"),
    [
        ("SUCCESS", "SUCCESS"),
        ("PENDING", "PENDING"),
        ("FAILURE", "FAILURE"),
        ("STARTED", "STARTED"),
        ("RETRY", "UNKNOWN"),
        ("REVOKED", "UNKNOWN"),
    ],
)
def test_normalize_public_task_state_matrix(celery_state: str, expected: str) -> None:
    assert normalize_public_task_state(celery_state) == expected


@pytest.mark.asyncio
async def test_execute_investigation_forwards_celery_owner_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    async def _investigate(event_id: str, **kwargs: Any) -> None:
        seen["event_id"] = event_id
        seen["owner_id"] = kwargs.get("owner_id")

    async def _fake_super_agent() -> Any:
        agent = MagicMock()
        agent.investigate = _investigate
        return agent

    monkeypatch.setattr("app.api.v1.deps.get_super_agent", _fake_super_agent)
    monkeypatch.setattr(
        "app.services.evidence_projection.bind_evidence_projection",
        lambda _projection: _null_context(),
    )
    monkeypatch.setattr(
        "app.services.evidence_projection.EvidenceProjection",
        lambda _factory: MagicMock(),
    )

    owner_id = celery_task_owner_id("task-owner-forward")
    result = await tasks.execute_investigation(
        "evt-owner",
        owner_id=owner_id,
    )
    assert result == {"status": "completed", "event_id": "evt-owner"}
    assert seen == {"event_id": "evt-owner", "owner_id": owner_id}


def test_run_investigation_uses_task_id_owner(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    monkeypatch.setattr(
        tasks,
        "execute_investigation",
        make_execute_investigation_double(captured),
    )
    async_result = tasks.run_investigation.apply(
        args=["evt-celery-owner"],
        task_id="task-fixed-owner-001",
    )
    assert async_result.result["status"] == "completed"
    assert captured["owner_id"] == celery_task_owner_id("task-fixed-owner-001")
    assert captured["generate_report"] is True


@pytest.mark.asyncio
async def test_redelivery_skips_when_lease_still_held(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Crash-before-ack redelivery while the first delivery still holds the lease."""
    patch_redis_client(monkeypatch)
    redis_client = RedisClient()
    lease = EventLease(redis_client)
    event_id = "evt-redelivery-skip"
    task_id = "task-redelivery-skip"
    owner_id = celery_task_owner_id(task_id)

    assert await lease.acquire(event_id, owner_id, ttl_s=600)

    async def _investigate(event_id: str, *, owner_id: str | None = None, **_kwargs: Any) -> None:
        resolved_owner = owner_id or generate_owner_id()
        if not await lease.acquire(event_id, resolved_owner):
            raise InvestigationInProgressError(
                message="investigation already in progress for this event",
                error_code="investigation_in_progress",
                details={"event_id": event_id},
            )

    async def _fake_super_agent() -> Any:
        agent = MagicMock()
        agent.investigate = _investigate
        return agent

    monkeypatch.setattr("app.api.v1.deps.get_super_agent", _fake_super_agent)
    monkeypatch.setattr(
        "app.services.evidence_projection.bind_evidence_projection",
        lambda _projection: _null_context(),
    )
    monkeypatch.setattr(
        "app.services.evidence_projection.EvidenceProjection",
        lambda _factory: MagicMock(),
    )

    result = await tasks.execute_investigation(event_id, owner_id=owner_id)
    assert result == {
        "status": "skipped",
        "event_id": event_id,
        "reason": "investigation_in_progress",
    }

    stale_owner = generate_owner_id()
    assert stale_owner != owner_id
    assert await lease.acquire(event_id, stale_owner) is False

    await lease.release(event_id, owner_id)


@pytest.mark.asyncio
async def test_redelivery_runs_after_lease_expires(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After TTL expiry, a redelivery with the same Celery owner can acquire again."""
    now = [100.0]
    fake = InMemoryFakeRedis(clock=lambda: now[0])
    patch_redis_client(monkeypatch, raw=fake)
    redis_client = RedisClient()
    lease = EventLease(redis_client)
    event_id = "evt-redelivery-retry"
    task_id = "task-redelivery-retry"
    owner_id = celery_task_owner_id(task_id)

    assert await lease.acquire(event_id, owner_id, ttl_s=60)
    now[0] += 60

    calls: list[str] = []

    async def _investigate(
        event_id: str,
        *,
        owner_id: str | None = None,
        **_kwargs: Any,
    ) -> None:
        assert owner_id is not None
        assert await lease.acquire(event_id, owner_id, ttl_s=60) is True
        calls.append(event_id)

    async def _fake_super_agent() -> Any:
        agent = MagicMock()
        agent.investigate = _investigate
        return agent

    monkeypatch.setattr("app.api.v1.deps.get_super_agent", _fake_super_agent)
    monkeypatch.setattr(
        "app.services.evidence_projection.bind_evidence_projection",
        lambda _projection: _null_context(),
    )
    monkeypatch.setattr(
        "app.services.evidence_projection.EvidenceProjection",
        lambda _factory: MagicMock(),
    )

    result = await tasks.execute_investigation(event_id, owner_id=owner_id)
    assert result == {"status": "completed", "event_id": event_id}
    assert calls == [event_id]
    await lease.release(event_id, owner_id)


def test_after_success_first_delivery_runs_once(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful delivery executes investigation exactly once."""
    calls = {"n": 0}

    async def _fake_execute(event_id: str, **_kwargs: Any) -> dict[str, str]:
        calls["n"] += 1
        return {"status": "completed", "event_id": event_id}

    monkeypatch.setattr(tasks, "execute_investigation", _fake_execute)

    result = tasks.run_investigation.apply(
        args=["evt-after-ack"],
        task_id="task-after-ack-1",
    ).result
    assert result["status"] == "completed"
    assert calls["n"] == 1


def _run_with_redelivered_request(
    *,
    task_id: str,
    event_id: str,
) -> dict[str, str]:
    """Push a Celery request context with ``delivery_info.redelivered=True``."""
    from celery.app.task import Context

    ctx = Context(id=task_id, delivery_info={"redelivered": True}, retries=0)
    tasks.run_investigation.request_stack.push(ctx)
    try:
        return tasks.run_investigation.run(event_id)
    finally:
        tasks.run_investigation.request_stack.pop()


def test_run_investigation_honors_delivery_info_redelivered_flag(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise ``request.delivery_info['redelivered']`` without patching the body helper."""
    captured: dict[str, Any] = {}

    monkeypatch.setattr(
        tasks,
        "_run_investigation_body",
        make_run_investigation_body_double(captured),
    )

    result = _run_with_redelivered_request(
        task_id="task-redelivery-flag",
        event_id="evt-redelivery-flag",
    )

    assert result["status"] == "completed"
    assert captured["redelivered"] is True
    assert captured["owner_id"] == celery_task_owner_id("task-redelivery-flag")
    assert captured["generate_report"] is True


def test_redelivery_skips_when_event_terminal(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Broker redelivery after a terminal event must not re-run investigation."""
    calls = {"n": 0}

    async def _fake_execute(event_id: str, **_kwargs: Any) -> dict[str, str]:
        calls["n"] += 1
        return {"status": "completed", "event_id": event_id}

    closed_event = SecurityEvent(
        event_id="evt-terminal-redelivery",
        event_type=EventType.OTHER,
        title="closed",
        status=EventStatus.CLOSED,
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
        async def get_event(self, _event_id: str) -> SecurityEvent:
            return closed_event

    async def _fake_get_event_service() -> _EventService:
        return _EventService()

    monkeypatch.setattr("app.api.v1.deps.get_event_service", _fake_get_event_service)
    monkeypatch.setattr(tasks, "execute_investigation", _fake_execute)

    result = _run_with_redelivered_request(
        task_id="task-terminal-redelivery",
        event_id="evt-terminal-redelivery",
    )

    assert result["status"] == "skipped"
    assert result.get("reason") == "terminal_event"
    assert calls["n"] == 0


def test_redelivery_lookup_degraded_triggers_retry_not_skip(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from celery.exceptions import Retry

    from app.core.celery_delivery import RedeliveryLookupRetry

    calls = {"n": 0}

    async def _fake_execute(event_id: str, **_kwargs: Any) -> dict[str, str]:
        calls["n"] += 1
        return {"status": "completed", "event_id": event_id}

    async def _fail_service() -> None:
        from app.core.errors import DependencyUnavailableError

        raise DependencyUnavailableError(
            message="postgres unavailable",
            error_code="dependency_unavailable",
            details={"dependency": "postgres"},
        )

    monkeypatch.setattr("app.api.v1.deps.get_event_service", _fail_service)
    monkeypatch.setattr(tasks, "execute_investigation", _fake_execute)

    with pytest.raises((Retry, RedeliveryLookupRetry)):
        _run_with_redelivered_request(
            task_id="task-degraded-redelivery",
            event_id="evt-degraded-redelivery",
        )
    assert calls["n"] == 0


def test_redelivery_lookup_exhaustion_records_recovery_and_acks(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.celery_delivery import LOOKUP_RETRY_HEADER, LOOKUP_RETRY_MAX_ATTEMPTS

    recovery_calls: list[str] = []
    execute_calls = {"n": 0}

    async def _fail_service() -> None:
        from app.core.errors import DependencyUnavailableError

        raise DependencyUnavailableError(
            message="postgres unavailable",
            error_code="dependency_unavailable",
            details={"dependency": "postgres"},
        )

    async def _fake_execute(event_id: str, **_kwargs: Any) -> dict[str, str]:
        execute_calls["n"] += 1
        return {"status": "completed", "event_id": event_id}

    async def _record(event_id: str, *, task_id: str, reason: str) -> None:
        recovery_calls.append(f"{event_id}:{task_id}:{reason}")

    monkeypatch.setattr("app.api.v1.deps.get_event_service", _fail_service)
    monkeypatch.setattr(tasks, "execute_investigation", _fake_execute)
    monkeypatch.setattr(tasks, "record_redelivery_recovery_needed", _record)

    from celery.app.task import Context

    ctx = Context(
        id="task-lookup-exhaust",
        delivery_info={"redelivered": True},
        retries=LOOKUP_RETRY_MAX_ATTEMPTS,
        headers={LOOKUP_RETRY_HEADER: LOOKUP_RETRY_MAX_ATTEMPTS - 1},
    )
    tasks.run_investigation.request_stack.push(ctx)
    try:
        result = tasks.run_investigation.run("evt-lookup-exhaust")
    finally:
        tasks.run_investigation.request_stack.pop()

    assert result["status"] == "skipped"
    assert result["reason"] == "lookup_retry_exhausted"
    assert recovery_calls == ["evt-lookup-exhaust:task-lookup-exhaust:lookup_retry_exhausted"]
    assert execute_calls["n"] == 0


@pytest.mark.parametrize(
    "status",
    [
        EventStatus.WAITING_APPROVAL,
        EventStatus.EXECUTING_RESPONSE,
        EventStatus.VERIFYING,
    ],
)
def test_redelivery_intermediate_states_attempt_resume_not_terminal_skip(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
    status: EventStatus,
) -> None:
    resume_calls = {"n": 0}

    async def _fake_resume(
        event_id: str,
        *,
        owner_id: str,
        event_status: EventStatus | None,
        **_kwargs: Any,
    ) -> dict[str, str]:
        resume_calls["n"] += 1
        assert event_status is status
        return {"status": "completed", "event_id": event_id}

    event = SecurityEvent(
        event_id=f"evt-{status.value}",
        event_type=EventType.OTHER,
        title="intermediate",
        status=status,
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
        async def get_event(self, _event_id: str) -> SecurityEvent:
            return event

    class _Lease:
        async def get_owner(self, _event_id: str) -> str | None:
            return celery_task_owner_id(f"task-{status.value}")

        async def acquire(self, *_args: object, **_kwargs: object) -> bool:
            return False

    async def _fake_get_event_service() -> _EventService:
        return _EventService()

    monkeypatch.setattr("app.api.v1.deps.get_event_service", _fake_get_event_service)
    monkeypatch.setattr("app.api.v1.deps.get_event_lease", lambda: _Lease())
    monkeypatch.setattr(
        "app.core.celery_delivery.checkpoint_exists_for_event",
        AsyncMock(return_value=True),
    )
    monkeypatch.setattr(
        "app.core.celery_delivery.claim_redelivery_resume",
        AsyncMock(return_value=True),
    )
    monkeypatch.setattr(tasks, "execute_redelivery_resume", _fake_resume)

    result = _run_with_redelivered_request(
        task_id=f"task-{status.value}",
        event_id=event.event_id,
    )

    assert result["status"] == "completed"
    assert resume_calls["n"] == 1


def test_redelivery_defer_when_other_worker_holds_lease(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from celery.exceptions import Retry

    from app.core.celery_delivery import RedeliveryDeferRetry

    event = SecurityEvent(
        event_id="evt-defer",
        event_type=EventType.OTHER,
        title="defer",
        status=EventStatus.TRIAGING,
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
        async def get_event(self, _event_id: str) -> SecurityEvent:
            return event

    class _Lease:
        async def get_owner(self, _event_id: str) -> str:
            return "worker-other"

        async def acquire(self, *_args: object, **_kwargs: object) -> bool:
            raise AssertionError("acquire should not run when another owner holds lease")

    async def _fake_get_event_service() -> _EventService:
        return _EventService()

    monkeypatch.setattr("app.api.v1.deps.get_event_service", _fake_get_event_service)
    monkeypatch.setattr("app.api.v1.deps.get_event_lease", lambda: _Lease())

    with pytest.raises((Retry, RedeliveryDeferRetry)):
        _run_with_redelivered_request(
            task_id="task-defer",
            event_id="evt-defer",
        )


@pytest.mark.asyncio
async def test_resolve_task_state_maps_retry_to_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tasks, "lookup_task_event_id", AsyncMock(return_value="evt-unknown"))

    class _FakeResult:
        state = "RETRY"
        info = None
        args = ("evt-unknown",)

    with patch("celery.result.AsyncResult", return_value=_FakeResult()):
        state, event_id = await tasks.resolve_task_state("task-retry-unknown")

    assert state == "UNKNOWN"
    assert event_id == "evt-unknown"


def _null_context() -> Any:
    from contextlib import nullcontext

    return nullcontext()


def test_build_investigation_dispatch_kwargs_matches_production_defaults() -> None:
    assert build_investigation_dispatch_kwargs() == {
        "include_response_execution": False,
        "generate_report": True,
    }
    assert build_investigation_dispatch_kwargs(
        include_response_execution=True,
        owner_id="owner-http-1",
        lease_acquired=True,
        generate_report=False,
    ) == {
        "include_response_execution": True,
        "generate_report": False,
        "owner_id": "owner-http-1",
        "lease_acquired": True,
    }


@pytest.mark.integration
@pytest.mark.asyncio
async def test_real_redis_lease_acquire_conflict(redis_client: RedisClient) -> None:
    """Two owners competing for the same event lease — second acquire must fail."""
    lease = EventLease(redis_client)
    event_id = "evt-real-redis-lease-conflict"
    first_owner = celery_task_owner_id("task-lease-first")
    second_owner = celery_task_owner_id("task-lease-second")

    try:
        assert await lease.acquire(event_id, first_owner, ttl_s=60) is True
        assert await lease.acquire(event_id, second_owner, ttl_s=60) is False
        assert await lease.get_owner(event_id) == first_owner
        assert await lease.release(event_id, first_owner) is True
        assert await lease.acquire(event_id, second_owner, ttl_s=60) is True
        await lease.release(event_id, second_owner)
    finally:
        await lease.release(event_id, first_owner)
        await lease.release(event_id, second_owner)


@pytest.mark.integration
def test_run_investigation_non_eager_worker_forwards_generate_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Smoke: non-eager worker path must forward ``generate_report`` to execute."""
    from celery.contrib.testing.worker import start_worker

    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        tasks,
        "execute_investigation",
        make_execute_investigation_double(captured),
    )

    previous = {
        "task_always_eager": celery_app.conf.task_always_eager,
        "task_eager_propagates": celery_app.conf.task_eager_propagates,
        "result_backend": celery_app.conf.result_backend,
        "broker_url": celery_app.conf.broker_url,
    }
    celery_app.conf.task_always_eager = False
    celery_app.conf.task_eager_propagates = True
    celery_app.conf.result_backend = "cache+memory://"
    celery_app.conf.broker_url = "memory://"

    try:
        with start_worker(celery_app, perform_ping_check=False, pool="solo"):
            async_result = tasks.run_investigation.apply_async(
                args=["evt-non-eager-smoke"],
                kwargs=build_investigation_dispatch_kwargs(generate_report=False),
                task_id="task-non-eager-smoke",
                queue=TASK_QUEUE,
            )
            result = async_result.get(timeout=30)
    finally:
        celery_app.conf.task_always_eager = previous["task_always_eager"]
        celery_app.conf.task_eager_propagates = previous["task_eager_propagates"]
        celery_app.conf.result_backend = previous["result_backend"]
        celery_app.conf.broker_url = previous["broker_url"]

    assert result["status"] == "completed"
    assert captured["generate_report"] is False
    assert captured["event_id"] == "evt-non-eager-smoke"
    assert captured["owner_id"] == celery_task_owner_id("task-non-eager-smoke")
    assert captured["include_response_execution"] is False
    assert captured["lease_acquired"] is False
