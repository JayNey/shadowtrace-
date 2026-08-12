"""Soft time limit atomic outcome tests (ISSUE-314)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.metrics import (
    reset_soft_time_limit_metrics_for_tests,
    soft_time_limit_outcome_health_snapshot,
)
from app.db import models as orm
from app.models.enums import EventStatus, InvestigationIntentStatus, Severity
from app.services.soft_time_limit_outcome import (
    SoftTimeLimitDecision,
    SoftTimeLimitProbe,
    apply_soft_time_limit_outcome,
    decide_soft_time_limit_outcome,
)


@pytest.fixture(autouse=True)
def _reset_soft_limit_metrics() -> None:
    reset_soft_time_limit_metrics_for_tests()


async def _seed_event_and_intent(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_status: EventStatus = EventStatus.ANALYZING,
    intent_status: InvestigationIntentStatus = InvestigationIntentStatus.STARTED,
    attempt: int = 0,
    broker_task_id: str | None = None,
    omit_durable_broker: bool = False,
    orchestration_mode: str = "graph",
) -> tuple[str, str, str]:
    event_id = f"evt-soft-{uuid4().hex[:8]}"
    intent_id = f"iin-soft-{uuid4().hex[:8]}"
    resolved_broker = (
        None
        if omit_durable_broker
        else (broker_task_id or f"task-soft-{uuid4().hex[:10]}")
    )
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="soft limit",
                    description="",
                    status=event_status.value,
                    severity=Severity.MEDIUM.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                    row_version=1,
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="http_investigate",
                    intent_version="issue276_v1",
                    status=intent_status.value,
                    revision=1,
                    attempt=attempt,
                    broker_task_id=resolved_broker,
                    include_response_execution=False,
                    generate_report=True,
                    orchestration_mode=orchestration_mode,
                )
            )
    return event_id, intent_id, resolved_broker or ""


def test_decide_terminal_when_side_effect_phase() -> None:
    probe = SoftTimeLimitProbe(
        has_checkpoint=True,
        checkpoint_recoverable=True,
        last_checkpoint_node="verify_node",
        side_effect_signals=(),
        unknown_outbox_count=0,
    )
    decision = decide_soft_time_limit_outcome(
        event_status=EventStatus.VERIFYING.value,
        probe=probe,
        intent_attempt=0,
        max_attempts=5,
        has_intent=True,
    )
    assert decision is SoftTimeLimitDecision.RECONCILE_REQUIRED


def test_decide_recovered_for_pure_investigation_with_checkpoint() -> None:
    probe = SoftTimeLimitProbe(
        has_checkpoint=True,
        checkpoint_recoverable=True,
        last_checkpoint_node="risk_agent",
        side_effect_signals=(),
        unknown_outbox_count=0,
    )
    decision = decide_soft_time_limit_outcome(
        event_status=EventStatus.ANALYZING.value,
        probe=probe,
        intent_attempt=1,
        max_attempts=5,
        has_intent=True,
    )
    assert decision is SoftTimeLimitDecision.RECOVERED


def test_decide_reporting_is_terminal_not_recovered() -> None:
    """REPORTING must not RECOVERED — dispatch resume set excludes it."""
    probe = SoftTimeLimitProbe(
        has_checkpoint=True,
        checkpoint_recoverable=True,
        last_checkpoint_node="report",
        side_effect_signals=(),
        unknown_outbox_count=0,
    )
    decision = decide_soft_time_limit_outcome(
        event_status=EventStatus.REPORTING.value,
        probe=probe,
        intent_attempt=0,
        max_attempts=5,
        has_intent=True,
    )
    assert decision is SoftTimeLimitDecision.TERMINAL


def test_decide_new_is_terminal_not_recovered() -> None:
    """NEW is not dispatch-resumable; soft-limit must TERMINAL, not cold-start RECOVERED."""
    probe = SoftTimeLimitProbe(
        has_checkpoint=True,
        checkpoint_recoverable=True,
        last_checkpoint_node="triage",
        side_effect_signals=(),
        unknown_outbox_count=0,
    )
    decision = decide_soft_time_limit_outcome(
        event_status=EventStatus.NEW.value,
        probe=probe,
        intent_attempt=0,
        max_attempts=5,
        has_intent=True,
    )
    assert decision is SoftTimeLimitDecision.TERMINAL


def test_pure_investigation_statuses_are_dispatch_resumable() -> None:
    """RECOVERED set must stay aligned with intent/celery resume sets (ISSUE-314)."""
    from app.core.celery_delivery import REDELIVERY_RESUME_STATUSES
    from app.services.investigation_intent_service import _EVENT_INVESTIGATION_RESUMABLE
    from app.services.soft_time_limit_outcome import _PURE_INVESTIGATION_STATUSES

    redelivery = {status.value for status in REDELIVERY_RESUME_STATUSES}
    for status in _PURE_INVESTIGATION_STATUSES:
        assert status in redelivery, status
        assert status in _EVENT_INVESTIGATION_RESUMABLE, status


def test_decide_closed_is_ignored() -> None:
    probe = SoftTimeLimitProbe(
        has_checkpoint=False,
        checkpoint_recoverable=False,
        last_checkpoint_node=None,
        side_effect_signals=(),
        unknown_outbox_count=0,
    )
    decision = decide_soft_time_limit_outcome(
        event_status=EventStatus.CLOSED.value,
        probe=probe,
        intent_attempt=0,
        max_attempts=5,
        has_intent=True,
    )
    assert decision is SoftTimeLimitDecision.IGNORED


def test_decide_contained_is_terminal_not_reconcile() -> None:
    """CONTAINED still has outbound edges; soft-limit must TERMINAL (FAILED+DEAD)."""
    probe = SoftTimeLimitProbe(
        has_checkpoint=False,
        checkpoint_recoverable=False,
        last_checkpoint_node=None,
        side_effect_signals=(),
        unknown_outbox_count=0,
    )
    decision = decide_soft_time_limit_outcome(
        event_status=EventStatus.CONTAINED.value,
        probe=probe,
        intent_attempt=0,
        max_attempts=5,
        has_intent=True,
    )
    assert decision is SoftTimeLimitDecision.TERMINAL


def test_decide_contained_with_unknown_outbox_is_reconcile() -> None:
    """UNKNOWN writeback ambiguity must win over CONTAINED → TERMINAL."""
    probe = SoftTimeLimitProbe(
        has_checkpoint=False,
        checkpoint_recoverable=False,
        last_checkpoint_node=None,
        side_effect_signals=("unknown_outbox_count:1",),
        unknown_outbox_count=1,
    )
    decision = decide_soft_time_limit_outcome(
        event_status=EventStatus.CONTAINED.value,
        probe=probe,
        intent_attempt=0,
        max_attempts=5,
        has_intent=True,
    )
    assert decision is SoftTimeLimitDecision.RECONCILE_REQUIRED


def test_decide_terminal_when_attempts_exhausted() -> None:
    probe = SoftTimeLimitProbe(
        has_checkpoint=True,
        checkpoint_recoverable=True,
        last_checkpoint_node="triage_agent",
        side_effect_signals=(),
        unknown_outbox_count=0,
    )
    decision = decide_soft_time_limit_outcome(
        event_status=EventStatus.TRIAGING.value,
        probe=probe,
        intent_attempt=4,
        max_attempts=5,
        has_intent=True,
    )
    assert decision is SoftTimeLimitDecision.TERMINAL


@pytest.mark.asyncio
async def test_apply_terminal_marks_event_failed_and_intent_dead(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, intent_id, broker_task_id = await _seed_event_and_intent(session_factory)
    monkeypatch.setattr(
        "app.services.soft_time_limit_outcome.probe_soft_time_limit_context",
        AsyncMock(
            return_value=SoftTimeLimitProbe(
                has_checkpoint=False,
                checkpoint_recoverable=False,
                last_checkpoint_node=None,
                side_effect_signals=(),
                unknown_outbox_count=0,
            )
        ),
    )
    invalidated: list[str] = []

    async def _invalidate(eid: str) -> None:
        invalidated.append(eid)

    monkeypatch.setattr(
        "app.orchestration.checkpointer.invalidate_event_checkpoint",
        _invalidate,
    )

    result = await apply_soft_time_limit_outcome(
        event_id,
        session_factory=session_factory,
        intent_id=intent_id,
        broker_task_id=broker_task_id,
        settings=Settings(auto_investigate_max_attempts=5),
    )
    assert result.decision is SoftTimeLimitDecision.TERMINAL
    assert invalidated == [event_id]
    assert soft_time_limit_outcome_health_snapshot()["soft_limit_terminal"] == 1

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        intent = await session.get(orm.InvestigationIntent, intent_id)
        assert event is not None
        assert intent is not None
        assert event.status == EventStatus.FAILED.value
        assert intent.status == InvestigationIntentStatus.DEAD.value
        assert intent.last_error == "soft_time_limit_exceeded"


@pytest.mark.asyncio
async def test_apply_recovered_marks_intent_retry_without_event_failed(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, intent_id, broker_task_id = await _seed_event_and_intent(
        session_factory,
        event_status=EventStatus.ANALYZING,
    )
    monkeypatch.setattr(
        "app.services.soft_time_limit_outcome.probe_soft_time_limit_context",
        AsyncMock(
            return_value=SoftTimeLimitProbe(
                has_checkpoint=True,
                checkpoint_recoverable=True,
                last_checkpoint_node="evidence_agent",
                side_effect_signals=(),
                unknown_outbox_count=0,
            )
        ),
    )
    invalidated: list[str] = []

    async def _invalidate(eid: str) -> None:
        invalidated.append(eid)

    monkeypatch.setattr(
        "app.orchestration.checkpointer.invalidate_event_checkpoint",
        _invalidate,
    )
    intent_service = MagicMock()
    intent_service.schedule_dispatch = MagicMock()

    result = await apply_soft_time_limit_outcome(
        event_id,
        session_factory=session_factory,
        intent_id=intent_id,
        broker_task_id=broker_task_id,
        settings=Settings(auto_investigate_max_attempts=5),
        intent_service=intent_service,
    )
    assert result.decision is SoftTimeLimitDecision.RECOVERED
    assert invalidated == []
    assert soft_time_limit_outcome_health_snapshot()["soft_limit_recovered"] == 1
    intent_service.schedule_dispatch.assert_called_once()

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        intent = await session.get(orm.InvestigationIntent, intent_id)
        assert event is not None
        assert intent is not None
        assert event.status == EventStatus.ANALYZING.value
        assert intent.status == InvestigationIntentStatus.RETRY.value
        assert intent.attempt == 1


@pytest.mark.asyncio
async def test_apply_soft_limit_stale_broker_is_full_noop(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    new_owner = f"task-NEW-{uuid4().hex[:10]}"
    event_id, intent_id, broker_task_id = await _seed_event_and_intent(
        session_factory,
        event_status=EventStatus.ANALYZING,
        broker_task_id=new_owner,
    )
    assert broker_task_id == new_owner
    monkeypatch.setattr(
        "app.services.soft_time_limit_outcome.probe_soft_time_limit_context",
        AsyncMock(
            return_value=SoftTimeLimitProbe(
                has_checkpoint=False,
                checkpoint_recoverable=False,
                last_checkpoint_node=None,
                side_effect_signals=(),
                unknown_outbox_count=0,
            )
        ),
    )
    invalidated: list[str] = []

    async def _invalidate(eid: str) -> None:
        invalidated.append(eid)

    monkeypatch.setattr(
        "app.orchestration.checkpointer.invalidate_event_checkpoint",
        _invalidate,
    )
    intent_service = MagicMock()
    intent_service.schedule_dispatch = MagicMock()

    result = await apply_soft_time_limit_outcome(
        event_id,
        session_factory=session_factory,
        intent_id=intent_id,
        broker_task_id=f"task-OLD-{uuid4().hex[:10]}",
        settings=Settings(auto_investigate_max_attempts=5),
        intent_service=intent_service,
    )
    assert result.decision is SoftTimeLimitDecision.IGNORED
    assert result.reason == "soft_time_limit_exceeded:stale_broker"
    assert invalidated == []
    intent_service.schedule_dispatch.assert_not_called()
    assert soft_time_limit_outcome_health_snapshot()["soft_limit_ignored"] == 1

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        intent = await session.get(orm.InvestigationIntent, intent_id)
        assert event is not None
        assert intent is not None
        assert event.status == EventStatus.ANALYZING.value
        assert intent.status == InvestigationIntentStatus.STARTED.value
        assert intent.broker_task_id == new_owner


@pytest.mark.asyncio
async def test_apply_soft_limit_reconcile_does_not_schedule_dispatch(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, intent_id, broker_task_id = await _seed_event_and_intent(
        session_factory,
        event_status=EventStatus.VERIFYING,
    )
    monkeypatch.setattr(
        "app.services.soft_time_limit_outcome.probe_soft_time_limit_context",
        AsyncMock(
            return_value=SoftTimeLimitProbe(
                has_checkpoint=True,
                checkpoint_recoverable=True,
                last_checkpoint_node="verify_node",
                side_effect_signals=(),
                unknown_outbox_count=0,
            )
        ),
    )
    intent_service = MagicMock()
    intent_service.schedule_dispatch = MagicMock()
    degraded_flags = AsyncMock()

    result = await apply_soft_time_limit_outcome(
        event_id,
        session_factory=session_factory,
        intent_id=intent_id,
        broker_task_id=broker_task_id,
        settings=Settings(auto_investigate_max_attempts=5),
        intent_service=intent_service,
        degraded_flags=degraded_flags,
    )
    assert result.decision is SoftTimeLimitDecision.RECONCILE_REQUIRED
    intent_service.schedule_dispatch.assert_not_called()
    degraded_flags.set_flag.assert_awaited()
    assert soft_time_limit_outcome_health_snapshot()["soft_limit_reconcile_required"] == 1

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        intent = await session.get(orm.InvestigationIntent, intent_id)
        assert event is not None
        assert intent is not None
        assert event.status == EventStatus.FAILED.value
        assert intent.status == InvestigationIntentStatus.DEAD.value


@pytest.mark.asyncio
async def test_apply_reporting_marks_failed_dead_not_recovered(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, intent_id, broker_task_id = await _seed_event_and_intent(
        session_factory,
        event_status=EventStatus.REPORTING,
    )
    monkeypatch.setattr(
        "app.services.soft_time_limit_outcome.probe_soft_time_limit_context",
        AsyncMock(
            return_value=SoftTimeLimitProbe(
                has_checkpoint=True,
                checkpoint_recoverable=True,
                last_checkpoint_node="report",
                side_effect_signals=(),
                unknown_outbox_count=0,
            )
        ),
    )
    intent_service = MagicMock()
    intent_service.schedule_dispatch = MagicMock()

    result = await apply_soft_time_limit_outcome(
        event_id,
        session_factory=session_factory,
        intent_id=intent_id,
        broker_task_id=broker_task_id,
        settings=Settings(auto_investigate_max_attempts=5),
        intent_service=intent_service,
    )
    assert result.decision is SoftTimeLimitDecision.TERMINAL
    intent_service.schedule_dispatch.assert_not_called()

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        intent = await session.get(orm.InvestigationIntent, intent_id)
        assert event is not None
        assert intent is not None
        assert event.status == EventStatus.FAILED.value
        assert intent.status == InvestigationIntentStatus.DEAD.value


@pytest.mark.asyncio
async def test_apply_stale_broker_ignored_when_intent_retry(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    new_owner = f"task-NEW-{uuid4().hex[:10]}"
    event_id, intent_id, _ = await _seed_event_and_intent(
        session_factory,
        event_status=EventStatus.ANALYZING,
        intent_status=InvestigationIntentStatus.RETRY,
        attempt=1,
        broker_task_id=new_owner,
    )
    monkeypatch.setattr(
        "app.services.soft_time_limit_outcome.probe_soft_time_limit_context",
        AsyncMock(
            return_value=SoftTimeLimitProbe(
                has_checkpoint=False,
                checkpoint_recoverable=False,
                last_checkpoint_node=None,
                side_effect_signals=(),
                unknown_outbox_count=0,
            )
        ),
    )
    intent_service = MagicMock()
    intent_service.schedule_dispatch = MagicMock()

    result = await apply_soft_time_limit_outcome(
        event_id,
        session_factory=session_factory,
        intent_id=intent_id,
        broker_task_id=f"task-OLD-{uuid4().hex[:10]}",
        settings=Settings(auto_investigate_max_attempts=5),
        intent_service=intent_service,
    )
    assert result.decision is SoftTimeLimitDecision.IGNORED
    assert result.reason == "soft_time_limit_exceeded:stale_broker"
    intent_service.schedule_dispatch.assert_not_called()

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        intent = await session.get(orm.InvestigationIntent, intent_id)
        assert event is not None
        assert intent is not None
        assert event.status == EventStatus.ANALYZING.value
        assert intent.status == InvestigationIntentStatus.RETRY.value
        assert intent.broker_task_id == new_owner


@pytest.mark.asyncio
async def test_apply_closed_event_heals_intent_without_failed_rewrite(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, intent_id, broker_task_id = await _seed_event_and_intent(
        session_factory,
        event_status=EventStatus.CLOSED,
        intent_status=InvestigationIntentStatus.STARTED,
    )
    monkeypatch.setattr(
        "app.services.soft_time_limit_outcome.probe_soft_time_limit_context",
        AsyncMock(
            return_value=SoftTimeLimitProbe(
                has_checkpoint=False,
                checkpoint_recoverable=False,
                last_checkpoint_node=None,
                side_effect_signals=(),
                unknown_outbox_count=0,
            )
        ),
    )
    intent_service = MagicMock()
    intent_service.schedule_dispatch = MagicMock()

    result = await apply_soft_time_limit_outcome(
        event_id,
        session_factory=session_factory,
        intent_id=intent_id,
        broker_task_id=broker_task_id,
        settings=Settings(auto_investigate_max_attempts=5),
        intent_service=intent_service,
    )
    assert result.decision is SoftTimeLimitDecision.IGNORED
    assert result.reason == "soft_time_limit_exceeded:already_terminal"
    intent_service.schedule_dispatch.assert_not_called()

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        intent = await session.get(orm.InvestigationIntent, intent_id)
        assert event is not None
        assert intent is not None
        assert event.status == EventStatus.CLOSED.value
        assert intent.status == InvestigationIntentStatus.DEAD.value


@pytest.mark.asyncio
async def test_apply_soft_limit_attempts_exhausted_dead_and_failed(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, intent_id, broker_task_id = await _seed_event_and_intent(
        session_factory,
        event_status=EventStatus.ANALYZING,
        attempt=4,
    )
    monkeypatch.setattr(
        "app.services.soft_time_limit_outcome.probe_soft_time_limit_context",
        AsyncMock(
            return_value=SoftTimeLimitProbe(
                has_checkpoint=True,
                checkpoint_recoverable=True,
                last_checkpoint_node="risk_agent",
                side_effect_signals=(),
                unknown_outbox_count=0,
            )
        ),
    )
    intent_service = MagicMock()
    intent_service.schedule_dispatch = MagicMock()

    result = await apply_soft_time_limit_outcome(
        event_id,
        session_factory=session_factory,
        intent_id=intent_id,
        broker_task_id=broker_task_id,
        settings=Settings(auto_investigate_max_attempts=5),
        intent_service=intent_service,
    )
    assert result.decision is SoftTimeLimitDecision.TERMINAL
    intent_service.schedule_dispatch.assert_not_called()

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        intent = await session.get(orm.InvestigationIntent, intent_id)
        assert event is not None
        assert intent is not None
        assert event.status == EventStatus.FAILED.value
        assert intent.status == InvestigationIntentStatus.DEAD.value


@pytest.mark.asyncio
async def test_apply_soft_limit_contained_marks_failed_and_dead_atomically(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, intent_id, broker_task_id = await _seed_event_and_intent(
        session_factory,
        event_status=EventStatus.CONTAINED,
        intent_status=InvestigationIntentStatus.STARTED,
    )
    monkeypatch.setattr(
        "app.services.soft_time_limit_outcome.probe_soft_time_limit_context",
        AsyncMock(
            return_value=SoftTimeLimitProbe(
                has_checkpoint=False,
                checkpoint_recoverable=False,
                last_checkpoint_node=None,
                side_effect_signals=(),
                unknown_outbox_count=0,
            )
        ),
    )
    intent_service = MagicMock()
    intent_service.schedule_dispatch = MagicMock()
    degraded_flags = AsyncMock()

    result = await apply_soft_time_limit_outcome(
        event_id,
        session_factory=session_factory,
        intent_id=intent_id,
        broker_task_id=broker_task_id,
        settings=Settings(auto_investigate_max_attempts=5),
        intent_service=intent_service,
        degraded_flags=degraded_flags,
    )
    assert result.decision is SoftTimeLimitDecision.TERMINAL
    intent_service.schedule_dispatch.assert_not_called()
    degraded_flags.set_flag.assert_not_awaited()

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        intent = await session.get(orm.InvestigationIntent, intent_id)
        assert event is not None
        assert intent is not None
        assert event.status == EventStatus.FAILED.value
        assert intent.status == InvestigationIntentStatus.DEAD.value


@pytest.mark.asyncio
async def test_apply_soft_limit_missing_broker_is_fail_closed_noop(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, intent_id, _ = await _seed_event_and_intent(
        session_factory,
        event_status=EventStatus.ANALYZING,
    )
    monkeypatch.setattr(
        "app.services.soft_time_limit_outcome.probe_soft_time_limit_context",
        AsyncMock(
            return_value=SoftTimeLimitProbe(
                has_checkpoint=False,
                checkpoint_recoverable=False,
                last_checkpoint_node=None,
                side_effect_signals=(),
                unknown_outbox_count=0,
            )
        ),
    )
    intent_service = MagicMock()
    intent_service.schedule_dispatch = MagicMock()
    invalidated: list[str] = []

    async def _invalidate(eid: str) -> None:
        invalidated.append(eid)

    monkeypatch.setattr(
        "app.orchestration.checkpointer.invalidate_event_checkpoint",
        _invalidate,
    )

    result = await apply_soft_time_limit_outcome(
        event_id,
        session_factory=session_factory,
        intent_id=intent_id,
        broker_task_id=None,
        settings=Settings(auto_investigate_max_attempts=5),
        intent_service=intent_service,
    )
    assert result.decision is SoftTimeLimitDecision.IGNORED
    assert result.reason == "soft_time_limit_exceeded:missing_broker"
    assert invalidated == []
    intent_service.schedule_dispatch.assert_not_called()

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        intent = await session.get(orm.InvestigationIntent, intent_id)
        assert event is not None
        assert intent is not None
        assert event.status == EventStatus.ANALYZING.value
        assert intent.status == InvestigationIntentStatus.STARTED.value


@pytest.mark.asyncio
async def test_apply_analysis_only_soft_limit_never_recovers(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, intent_id, broker_task_id = await _seed_event_and_intent(
        session_factory,
        event_status=EventStatus.ANALYZING,
        orchestration_mode="analysis_only",
    )
    monkeypatch.setattr(
        "app.services.soft_time_limit_outcome.probe_soft_time_limit_context",
        AsyncMock(
            return_value=SoftTimeLimitProbe(
                has_checkpoint=True,
                checkpoint_recoverable=True,
                last_checkpoint_node="triage",
                side_effect_signals=(),
                unknown_outbox_count=0,
            )
        ),
    )
    intent_service = MagicMock()
    intent_service.schedule_dispatch = MagicMock()

    result = await apply_soft_time_limit_outcome(
        event_id,
        session_factory=session_factory,
        intent_id=intent_id,
        broker_task_id=broker_task_id,
        settings=Settings(auto_investigate_max_attempts=5),
        intent_service=intent_service,
    )
    assert result.decision is SoftTimeLimitDecision.TERMINAL
    intent_service.schedule_dispatch.assert_not_called()

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        intent = await session.get(orm.InvestigationIntent, intent_id)
        assert event is not None
        assert intent is not None
        assert event.status == EventStatus.FAILED.value
        assert intent.status == InvestigationIntentStatus.DEAD.value


@pytest.mark.asyncio
async def test_apply_soft_limit_missing_durable_broker_is_fail_closed_noop(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, intent_id, _ = await _seed_event_and_intent(
        session_factory,
        event_status=EventStatus.ANALYZING,
        omit_durable_broker=True,
    )
    monkeypatch.setattr(
        "app.services.soft_time_limit_outcome.probe_soft_time_limit_context",
        AsyncMock(
            return_value=SoftTimeLimitProbe(
                has_checkpoint=False,
                checkpoint_recoverable=False,
                last_checkpoint_node=None,
                side_effect_signals=(),
                unknown_outbox_count=0,
            )
        ),
    )
    intent_service = MagicMock()
    intent_service.schedule_dispatch = MagicMock()

    result = await apply_soft_time_limit_outcome(
        event_id,
        session_factory=session_factory,
        intent_id=intent_id,
        broker_task_id="task-caller-has-id",
        settings=Settings(auto_investigate_max_attempts=5),
        intent_service=intent_service,
    )
    assert result.decision is SoftTimeLimitDecision.IGNORED
    assert result.reason == "soft_time_limit_exceeded:missing_broker"
    intent_service.schedule_dispatch.assert_not_called()

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        intent = await session.get(orm.InvestigationIntent, intent_id)
        assert event is not None
        assert intent is not None
        assert event.status == EventStatus.ANALYZING.value
        assert intent.status == InvestigationIntentStatus.STARTED.value


@pytest.mark.asyncio
async def test_apply_soft_limit_orphan_terminal_intent_stale_broker_converges(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DEAD intent + non-terminal event + stale broker → FAILED (orphan heal)."""
    durable_id = f"task-owner-b-{uuid4().hex[:10]}"
    event_id, intent_id, durable = await _seed_event_and_intent(
        session_factory,
        event_status=EventStatus.CONTAINED,
        intent_status=InvestigationIntentStatus.DEAD,
        broker_task_id=durable_id,
    )
    monkeypatch.setattr(
        "app.services.soft_time_limit_outcome.probe_soft_time_limit_context",
        AsyncMock(
            return_value=SoftTimeLimitProbe(
                has_checkpoint=False,
                checkpoint_recoverable=False,
                last_checkpoint_node=None,
                side_effect_signals=(),
                unknown_outbox_count=0,
            )
        ),
    )
    intent_service = MagicMock()
    intent_service.schedule_dispatch = MagicMock()
    invalidated: list[str] = []

    async def _invalidate(eid: str) -> None:
        invalidated.append(eid)

    monkeypatch.setattr(
        "app.orchestration.checkpointer.invalidate_event_checkpoint",
        _invalidate,
    )

    result = await apply_soft_time_limit_outcome(
        event_id,
        session_factory=session_factory,
        intent_id=intent_id,
        broker_task_id=f"task-owner-a-{uuid4().hex[:10]}",
        settings=Settings(auto_investigate_max_attempts=5),
        intent_service=intent_service,
    )
    assert result.decision is SoftTimeLimitDecision.TERMINAL
    assert result.reason == "soft_time_limit_exceeded:orphan_terminal_intent"
    intent_service.schedule_dispatch.assert_not_called()
    assert invalidated == [event_id]

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        intent = await session.get(orm.InvestigationIntent, intent_id)
        assert event is not None
        assert intent is not None
        assert event.status == EventStatus.FAILED.value
        assert intent.status == InvestigationIntentStatus.DEAD.value
        assert intent.broker_task_id == durable


@pytest.mark.asyncio
async def test_apply_soft_limit_orphan_missing_durable_broker_converges(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DEAD intent without durable broker + non-terminal event → FAILED orphan heal."""
    event_id, intent_id, _ = await _seed_event_and_intent(
        session_factory,
        event_status=EventStatus.ANALYZING,
        intent_status=InvestigationIntentStatus.DEAD,
        omit_durable_broker=True,
    )
    monkeypatch.setattr(
        "app.services.soft_time_limit_outcome.probe_soft_time_limit_context",
        AsyncMock(
            return_value=SoftTimeLimitProbe(
                has_checkpoint=False,
                checkpoint_recoverable=False,
                last_checkpoint_node=None,
                side_effect_signals=(),
                unknown_outbox_count=0,
            )
        ),
    )
    intent_service = MagicMock()
    intent_service.schedule_dispatch = MagicMock()

    result = await apply_soft_time_limit_outcome(
        event_id,
        session_factory=session_factory,
        intent_id=intent_id,
        broker_task_id="task-caller-has-id",
        settings=Settings(auto_investigate_max_attempts=5),
        intent_service=intent_service,
    )
    assert result.decision is SoftTimeLimitDecision.TERMINAL
    assert result.reason == "soft_time_limit_exceeded:orphan_terminal_intent"
    intent_service.schedule_dispatch.assert_not_called()

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        intent = await session.get(orm.InvestigationIntent, intent_id)
        assert event is not None
        assert intent is not None
        assert event.status == EventStatus.FAILED.value
        assert intent.status == InvestigationIntentStatus.DEAD.value


@pytest.mark.asyncio
async def test_apply_soft_limit_orphan_with_active_sibling_is_noop(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Orphan fence stays no-op when a live sibling intent still owns the event."""
    durable_id = f"task-owner-b-{uuid4().hex[:10]}"
    event_id, intent_id, durable = await _seed_event_and_intent(
        session_factory,
        event_status=EventStatus.CONTAINED,
        intent_status=InvestigationIntentStatus.DEAD,
        broker_task_id=durable_id,
    )
    sibling_id = f"iin-soft-sib-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.InvestigationIntent(
                    intent_id=sibling_id,
                    event_id=event_id,
                    # Distinct kind/version to satisfy uq_investigation_intent_event_kind_version.
                    intent_kind="http_investigate",
                    intent_version="issue314_sibling_v1",
                    status=InvestigationIntentStatus.STARTED.value,
                    revision=1,
                    attempt=0,
                    broker_task_id=f"task-sibling-{uuid4().hex[:10]}",
                    include_response_execution=False,
                    generate_report=True,
                    orchestration_mode="graph",
                )
            )

    monkeypatch.setattr(
        "app.services.soft_time_limit_outcome.probe_soft_time_limit_context",
        AsyncMock(
            return_value=SoftTimeLimitProbe(
                has_checkpoint=False,
                checkpoint_recoverable=False,
                last_checkpoint_node=None,
                side_effect_signals=(),
                unknown_outbox_count=0,
            )
        ),
    )
    intent_service = MagicMock()
    intent_service.schedule_dispatch = MagicMock()

    result = await apply_soft_time_limit_outcome(
        event_id,
        session_factory=session_factory,
        intent_id=intent_id,
        broker_task_id=f"task-owner-a-{uuid4().hex[:10]}",
        settings=Settings(auto_investigate_max_attempts=5),
        intent_service=intent_service,
    )
    assert result.decision is SoftTimeLimitDecision.IGNORED
    assert result.reason == "soft_time_limit_exceeded:stale_broker"
    intent_service.schedule_dispatch.assert_not_called()

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        intent = await session.get(orm.InvestigationIntent, intent_id)
        sibling = await session.get(orm.InvestigationIntent, sibling_id)
        assert event is not None
        assert intent is not None
        assert sibling is not None
        assert event.status == EventStatus.CONTAINED.value
        assert intent.status == InvestigationIntentStatus.DEAD.value
        assert intent.broker_task_id == durable
        assert sibling.status == InvestigationIntentStatus.STARTED.value


@pytest.mark.asyncio
async def test_apply_soft_limit_orphan_with_pending_sibling_is_noop(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PENDING successor intent blocks orphan FAILED heal (ISSUE-314)."""
    durable_id = f"task-owner-b-{uuid4().hex[:10]}"
    event_id, intent_id, durable = await _seed_event_and_intent(
        session_factory,
        event_status=EventStatus.CONTAINED,
        intent_status=InvestigationIntentStatus.DEAD,
        broker_task_id=durable_id,
    )
    sibling_id = f"iin-soft-pend-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.InvestigationIntent(
                    intent_id=sibling_id,
                    event_id=event_id,
                    intent_kind="http_investigate",
                    intent_version="issue314_pending_sibling_v1",
                    status=InvestigationIntentStatus.PENDING.value,
                    revision=1,
                    attempt=0,
                    broker_task_id=f"task-pending-{uuid4().hex[:10]}",
                    include_response_execution=False,
                    generate_report=True,
                    orchestration_mode="graph",
                )
            )

    monkeypatch.setattr(
        "app.services.soft_time_limit_outcome.probe_soft_time_limit_context",
        AsyncMock(
            return_value=SoftTimeLimitProbe(
                has_checkpoint=False,
                checkpoint_recoverable=False,
                last_checkpoint_node=None,
                side_effect_signals=(),
                unknown_outbox_count=0,
            )
        ),
    )
    intent_service = MagicMock()
    intent_service.schedule_dispatch = MagicMock()

    result = await apply_soft_time_limit_outcome(
        event_id,
        session_factory=session_factory,
        intent_id=intent_id,
        broker_task_id=f"task-owner-a-{uuid4().hex[:10]}",
        settings=Settings(auto_investigate_max_attempts=5),
        intent_service=intent_service,
    )
    assert result.decision is SoftTimeLimitDecision.IGNORED
    assert result.reason == "soft_time_limit_exceeded:stale_broker"
    intent_service.schedule_dispatch.assert_not_called()

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        intent = await session.get(orm.InvestigationIntent, intent_id)
        sibling = await session.get(orm.InvestigationIntent, sibling_id)
        assert event is not None
        assert intent is not None
        assert sibling is not None
        assert event.status == EventStatus.CONTAINED.value
        assert intent.status == InvestigationIntentStatus.DEAD.value
        assert intent.broker_task_id == durable
        assert sibling.status == InvestigationIntentStatus.PENDING.value


@pytest.mark.asyncio
async def test_apply_soft_limit_orphan_with_unknown_outbox_is_reconcile(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Orphan heal must not skip UNKNOWN writeback reconcile (ISSUE-314)."""
    durable_id = f"task-owner-b-{uuid4().hex[:10]}"
    event_id, intent_id, durable = await _seed_event_and_intent(
        session_factory,
        event_status=EventStatus.CONTAINED,
        intent_status=InvestigationIntentStatus.DEAD,
        broker_task_id=durable_id,
    )
    monkeypatch.setattr(
        "app.services.soft_time_limit_outcome.probe_soft_time_limit_context",
        AsyncMock(
            return_value=SoftTimeLimitProbe(
                has_checkpoint=False,
                checkpoint_recoverable=False,
                last_checkpoint_node=None,
                # Survive TOCTOU outbox refresh (no durable UNKNOWN rows in this unit test).
                side_effect_signals=("unknown_submit",),
                unknown_outbox_count=0,
            )
        ),
    )
    intent_service = MagicMock()
    intent_service.schedule_dispatch = MagicMock()
    degraded_flags = AsyncMock()

    result = await apply_soft_time_limit_outcome(
        event_id,
        session_factory=session_factory,
        intent_id=intent_id,
        broker_task_id=f"task-owner-a-{uuid4().hex[:10]}",
        settings=Settings(auto_investigate_max_attempts=5),
        intent_service=intent_service,
        degraded_flags=degraded_flags,
    )
    assert result.decision is SoftTimeLimitDecision.RECONCILE_REQUIRED
    assert result.reason == "soft_time_limit_exceeded:reconcile_required"
    intent_service.schedule_dispatch.assert_not_called()
    degraded_flags.set_flag.assert_awaited()

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        intent = await session.get(orm.InvestigationIntent, intent_id)
        assert event is not None
        assert intent is not None
        assert event.status == EventStatus.FAILED.value
        assert intent.status == InvestigationIntentStatus.DEAD.value
        assert intent.broker_task_id == durable
