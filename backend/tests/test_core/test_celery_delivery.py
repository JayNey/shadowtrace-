"""Unit tests for Celery delivery helpers (ISSUE-117 / ISSUE-275)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from app.core.celery_delivery import (
    REDELIVERY_ACK_TERMINAL_STATUSES,
    RedeliveryDecision,
    RedeliveryHandoffAction,
    RedeliveryLookupRetry,
    celery_task_owner_id,
    evaluate_redelivered_investigation_decision,
    evaluate_redelivered_investigation_skip,
    evaluate_redelivery_handoff,
    lookup_retry_countdown,
    normalize_public_task_state,
    should_skip_redelivered_investigation,
)
from app.core.errors import DependencyUnavailableError
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    Severity,
    SourceObjectKind,
)
from app.models.security_event import SecurityEvent
from app.models.source import SourceReference


def _sample_event(*, event_id: str, status: EventStatus) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        event_type=EventType.OTHER,
        title="redelivery-test",
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


def test_celery_task_owner_id_requires_non_empty_task_id() -> None:
    with pytest.raises(ValueError, match="task_id is required"):
        celery_task_owner_id("")


def test_normalize_public_task_state_defaults_pending() -> None:
    assert normalize_public_task_state("") == "PENDING"
    assert normalize_public_task_state("pending") == "PENDING"


def test_lookup_retry_countdown_is_bounded() -> None:
    assert 2.0 <= lookup_retry_countdown(1) <= 62.6
    assert lookup_retry_countdown(10) <= 78.0


@pytest.mark.parametrize(
    "status",
    sorted(REDELIVERY_ACK_TERMINAL_STATUSES, key=lambda item: item.value),
)
@pytest.mark.asyncio
async def test_ack_terminal_decision_for_terminal_states(
    monkeypatch: pytest.MonkeyPatch,
    status: EventStatus,
) -> None:
    event = _sample_event(event_id=f"evt-{status.value}", status=status)

    class _EventService:
        async def get_event(self, _event_id: str) -> SecurityEvent:
            return event

    monkeypatch.setattr(
        "app.api.v1.deps.get_event_service",
        AsyncMock(return_value=_EventService()),
    )
    decision, resolved = await evaluate_redelivered_investigation_decision(event.event_id)
    assert decision is RedeliveryDecision.ACK_TERMINAL
    assert resolved is status
    assert await should_skip_redelivered_investigation(event.event_id) is True
    skip, reason = await evaluate_redelivered_investigation_skip(event.event_id)
    assert skip is True
    assert reason == "terminal_event"


@pytest.mark.asyncio
async def test_resume_or_defer_decision_for_new_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = _sample_event(event_id="evt-new", status=EventStatus.NEW)

    class _EventService:
        async def get_event(self, _event_id: str) -> SecurityEvent:
            return event

    monkeypatch.setattr(
        "app.api.v1.deps.get_event_service",
        AsyncMock(return_value=_EventService()),
    )
    decision, resolved = await evaluate_redelivered_investigation_decision("evt-new")
    assert decision is RedeliveryDecision.RESUME_OR_DEFER
    assert resolved is EventStatus.NEW
    assert await should_skip_redelivered_investigation("evt-new") is False
    skip, reason = await evaluate_redelivered_investigation_skip("evt-new")
    assert skip is False
    assert reason is None


@pytest.mark.asyncio
async def test_intermediate_status_is_not_terminal_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = _sample_event(event_id="evt-exec", status=EventStatus.EXECUTING_RESPONSE)

    class _EventService:
        async def get_event(self, _event_id: str) -> SecurityEvent:
            return event

    monkeypatch.setattr(
        "app.api.v1.deps.get_event_service",
        AsyncMock(return_value=_EventService()),
    )
    decision, resolved = await evaluate_redelivered_investigation_decision("evt-exec")
    assert decision is RedeliveryDecision.RESUME_OR_DEFER
    assert resolved is EventStatus.EXECUTING_RESPONSE


@pytest.mark.asyncio
async def test_lookup_degraded_raises_retry_not_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fail_service() -> None:
        raise DependencyUnavailableError(
            message="postgres unavailable",
            error_code="dependency_unavailable",
            details={"dependency": "postgres"},
        )

    monkeypatch.setattr("app.api.v1.deps.get_event_service", _fail_service)
    with pytest.raises(RedeliveryLookupRetry):
        await evaluate_redelivered_investigation_decision("evt-degraded")
    with pytest.raises(RedeliveryLookupRetry):
        await should_skip_redelivered_investigation("evt-degraded")


@pytest.mark.asyncio
async def test_handoff_resume_when_delivery_owns_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner_id = celery_task_owner_id("task-handoff")

    class _Lease:
        async def get_owner(self, _event_id: str) -> str:
            return owner_id

        async def acquire(self, *_args: object, **_kwargs: object) -> bool:
            raise AssertionError("acquire should not run when owner matches")

    monkeypatch.setattr("app.api.v1.deps.get_event_lease", lambda: _Lease())
    verdict = await evaluate_redelivery_handoff(
        "evt-handoff",
        task_id="task-handoff",
        owner_id=owner_id,
        event_status=EventStatus.TRIAGING,
    )
    assert verdict.action is RedeliveryHandoffAction.RESUME
    assert verdict.reason == "lease_owned_by_delivery"


@pytest.mark.asyncio
async def test_handoff_defer_when_other_owner_holds_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Lease:
        async def get_owner(self, _event_id: str) -> str:
            return "worker-other"

        async def acquire(self, *_args: object, **_kwargs: object) -> bool:
            raise AssertionError("acquire should not run when another owner holds lease")

    monkeypatch.setattr("app.api.v1.deps.get_event_lease", lambda: _Lease())
    verdict = await evaluate_redelivery_handoff(
        "evt-contention",
        task_id="task-contention",
        owner_id=celery_task_owner_id("task-contention"),
        event_status=EventStatus.VERIFYING,
    )
    assert verdict.action is RedeliveryHandoffAction.RETRY_DEFER
    assert verdict.reason == "lease_held_by_other"


@pytest.mark.asyncio
async def test_record_redelivery_recovery_needed_writes_flag_and_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flag_calls: list[tuple[str, str, object]] = []
    audit_rows: list[object] = []

    class _Flags:
        async def set_flag(
            self,
            event_id: str,
            flag_name: str,
            value: object,
            *,
            writer: str,
        ) -> list[str]:
            flag_calls.append((event_id, flag_name, value))
            return [f"{flag_name}={value}"]

    class _Session:
        async def __aenter__(self) -> _Session:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def scalar(self, _stmt: object) -> str:
            return EventStatus.TRIAGING.value

        def add(self, row: object) -> None:
            audit_rows.append(row)

        def begin(self) -> _Session:
            return self

    class _SessionFactory:
        def __call__(self) -> _Session:
            return _Session()

    monkeypatch.setattr("app.api.v1.deps._get_degraded_flags", lambda: _Flags())
    monkeypatch.setattr("app.api.v1.deps._get_session_factory", lambda: _SessionFactory())

    from app.core.celery_delivery import (
        REDELIVERY_RECOVERY_FLAG,
        record_redelivery_recovery_needed,
    )

    await record_redelivery_recovery_needed(
        "evt-recovery",
        task_id="task-recovery",
        reason="lookup_retry_exhausted",
    )
    assert flag_calls == [
        ("evt-recovery", REDELIVERY_RECOVERY_FLAG, "lookup_retry_exhausted|task_id=task-recovery")
    ]
    assert len(audit_rows) == 1
