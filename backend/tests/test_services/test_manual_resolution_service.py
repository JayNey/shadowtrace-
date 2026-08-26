"""ISSUE-277 durable manual-resolution resume intent tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import IdempotencyKeyReuseError, ValidationError
from app.db import models as orm
from app.models.enums import (
    ActionCategory,
    ActionLevel,
    ActionStatus,
    EventStatus,
    ExecutionOwner,
    ExecutionSubstate,
    GraphResumeIntentStatus,
    Severity,
)
from app.services.action_execution_service import ActionExecutionService
from app.services.context_service import unwrap_journal_value
from app.services.manual_resolution_service import (
    RESOLUTION_SOURCE_ACTION_UNKNOWN,
    SUBJECT_KIND_ACTION,
    ManualResolutionService,
)


async def _seed_event(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    status: EventStatus = EventStatus.VERIFYING,
) -> str:
    event_id = f"evt-277-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Manual resolution",
                    description="",
                    status=status.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
    return event_id


async def _seed_unknown_action(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> str:
    from app.models.enums import ActionExecutionPhase, WritebackReadiness

    action_id = f"act-277-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{action_id}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="isolate host",
                    tool_name="isolate_host",
                    action_level=ActionLevel.L2.value,
                    execution_owner=ExecutionOwner.DIRECT_TOOL.value,
                    execution_phase=ActionExecutionPhase.IMMEDIATE.value,
                    status=ActionStatus.UNKNOWN.value,
                    target_type="host",
                    target="host-1",
                    parameters={"host_id": "host-1"},
                    writeback_required=False,
                    writeback_applicable=False,
                    writeback_readiness=WritebackReadiness.NOT_REQUIRED.value,
                )
            )
    return action_id


@pytest.mark.asyncio
async def test_enter_manual_hold_persists_generation_and_substate(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    service = ManualResolutionService(session_factory)
    snap = await service.enter_manual_hold(
        event_id,
        reason="verify_need_manual_resolution",
        pending_ids=["wbk-1", "act-1"],
        checkpoint_id=event_id,
        event_status=EventStatus.VERIFYING,
    )
    assert snap.generation == 1
    async with session_factory() as session:
        substate = await session.scalar(
            select(orm.EventContextJournal.value)
            .where(
                orm.EventContextJournal.event_id == event_id,
                orm.EventContextJournal.field_name == "execution_substate",
            )
            .order_by(orm.EventContextJournal.version.desc())
            .limit(1)
        )
        hold = await session.scalar(
            select(orm.EventContextJournal.value)
            .where(
                orm.EventContextJournal.event_id == event_id,
                orm.EventContextJournal.field_name == "manual_hold",
            )
            .order_by(orm.EventContextJournal.version.desc())
            .limit(1)
        )

    assert unwrap_journal_value(substate) == ExecutionSubstate.MANUAL_RESOLUTION.value
    hold_val = unwrap_journal_value(hold)
    assert hold_val["generation"] == 1
    assert hold_val["pending_ids"] == ["wbk-1", "act-1"]


@pytest.mark.asyncio
async def test_resume_intent_operation_id_replay_and_conflict(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    service = ManualResolutionService(session_factory)
    await service.enter_manual_hold(
        event_id,
        reason="verify_need_manual_resolution",
        pending_ids=["wbk-1"],
        checkpoint_id=event_id,
        event_status=EventStatus.VERIFYING,
    )
    first = await service.create_or_replay_resume_intent(
        event_id,
        resolution_source=RESOLUTION_SOURCE_ACTION_UNKNOWN,
        subject_kind=SUBJECT_KIND_ACTION,
        subject_id="act-1",
        resolution="mark_success",
        principal="analyst-1",
        operation_id=f"op-{event_id}",
    )
    replay = await service.create_or_replay_resume_intent(
        event_id,
        resolution_source=RESOLUTION_SOURCE_ACTION_UNKNOWN,
        subject_kind=SUBJECT_KIND_ACTION,
        subject_id="act-1",
        resolution="mark_success",
        principal="analyst-1",
        operation_id=f"op-{event_id}",
    )
    assert replay.intent_id == first.intent_id
    with pytest.raises(IdempotencyKeyReuseError):
        await service.create_or_replay_resume_intent(
            event_id,
            resolution_source=RESOLUTION_SOURCE_ACTION_UNKNOWN,
            subject_kind=SUBJECT_KIND_ACTION,
            subject_id="act-2",
            resolution="mark_failed",
            principal="analyst-1",
            operation_id=f"op-{event_id}",
        )


@pytest.mark.asyncio
async def test_claim_and_run_fences_stale_generation(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    resumed: list[str] = []

    async def _runner(eid: str) -> None:
        resumed.append(eid)

    service = ManualResolutionService(session_factory, resume_runner=_runner)
    await service.enter_manual_hold(
        event_id,
        reason="verify_need_manual_resolution",
        pending_ids=[],
        checkpoint_id=event_id,
        event_status=EventStatus.VERIFYING,
    )
    intent = await service.create_or_replay_resume_intent(
        event_id,
        resolution_source=RESOLUTION_SOURCE_ACTION_UNKNOWN,
        subject_kind=SUBJECT_KIND_ACTION,
        subject_id="act-stale",
        resolution="mark_success",
        principal="analyst-1",
    )
    # Bump generation so the pending intent becomes stale.
    await service.enter_manual_hold(
        event_id,
        reason="still_blocked",
        pending_ids=["wbk-2"],
        checkpoint_id=event_id,
        event_status=EventStatus.VERIFYING,
    )
    claimed = await service._claim_batch(limit=100)
    assert intent.intent_id in claimed
    ok = await service._run_claimed_intent(intent.intent_id)
    assert ok is False
    assert event_id not in resumed
    async with session_factory() as session:
        row = await session.get(orm.GraphResumeIntent, intent.intent_id)
        assert row is not None
        assert row.status == GraphResumeIntentStatus.SKIPPED.value
        assert row.skip_reason == "stale_hold_generation"


@pytest.mark.asyncio
async def test_claim_and_run_clears_hold_and_invokes_runner(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    resumed: list[str] = []

    async def _runner(eid: str) -> None:
        resumed.append(eid)

    service = ManualResolutionService(session_factory, resume_runner=_runner)
    await service.enter_manual_hold(
        event_id,
        reason="verify_need_manual_resolution",
        pending_ids=["wbk-1"],
        checkpoint_id=event_id,
        event_status=EventStatus.VERIFYING,
    )
    intent = await service.create_or_replay_resume_intent(
        event_id,
        resolution_source=RESOLUTION_SOURCE_ACTION_UNKNOWN,
        subject_kind=SUBJECT_KIND_ACTION,
        subject_id="act-ok",
        resolution="mark_success",
        principal="analyst-1",
    )
    claimed = await service._claim_batch(limit=100)
    assert intent.intent_id in claimed
    ok = await service._run_claimed_intent(intent.intent_id)
    assert ok is True
    assert resumed == [event_id]
    async with session_factory() as session:
        row = await session.get(orm.GraphResumeIntent, intent.intent_id)
        assert row is not None
        assert row.status == GraphResumeIntentStatus.TERMINAL.value
        substate = await session.scalar(
            select(orm.EventContextJournal.value)
            .where(
                orm.EventContextJournal.event_id == event_id,
                orm.EventContextJournal.field_name == "execution_substate",
            )
            .order_by(orm.EventContextJournal.version.desc())
            .limit(1)
        )
        assert unwrap_journal_value(substate) == ExecutionSubstate.NONE.value


@pytest.mark.asyncio
async def test_create_resume_intent_requires_manual_hold(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    service = ManualResolutionService(session_factory)
    with pytest.raises(ValidationError, match="MANUAL_RESOLUTION"):
        await service.create_or_replay_resume_intent(
            event_id,
            resolution_source=RESOLUTION_SOURCE_ACTION_UNKNOWN,
            subject_kind=SUBJECT_KIND_ACTION,
            subject_id="act-1",
            resolution="mark_success",
            principal="analyst-1",
        )


@pytest.mark.asyncio
async def test_concurrent_resolutions_share_one_active_intent(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    service = ManualResolutionService(session_factory)
    await service.enter_manual_hold(
        event_id,
        reason="verify_need_manual_resolution",
        pending_ids=["act-a", "act-b"],
        checkpoint_id=event_id,
        event_status=EventStatus.VERIFYING,
    )

    async def _create(subject_id: str):
        return await service.create_or_replay_resume_intent(
            event_id,
            resolution_source=RESOLUTION_SOURCE_ACTION_UNKNOWN,
            subject_kind=SUBJECT_KIND_ACTION,
            subject_id=subject_id,
            resolution="mark_success",
            principal="analyst-1",
        )

    first, second = await asyncio.gather(_create("act-a"), _create("act-b"))
    assert first.intent_id == second.intent_id
    async with session_factory() as session:
        active = (
            await session.scalars(
                select(orm.GraphResumeIntent).where(
                    orm.GraphResumeIntent.event_id == event_id,
                    orm.GraphResumeIntent.status.in_(
                        [
                            GraphResumeIntentStatus.PENDING.value,
                            GraphResumeIntentStatus.CLAIMED.value,
                            GraphResumeIntentStatus.STARTED.value,
                            GraphResumeIntentStatus.RETRY.value,
                        ]
                    ),
                )
            )
        ).all()
        assert len(active) == 1


@pytest.mark.asyncio
async def test_pending_intent_survives_dispatch_crash_and_recovers(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    resumed: list[str] = []

    async def _boom(_eid: str) -> None:
        raise RuntimeError("worker killed after claim")

    async def _ok(eid: str) -> None:
        resumed.append(eid)

    service = ManualResolutionService(
        session_factory,
        resume_runner=_boom,
        max_attempts=5,
    )
    await service.enter_manual_hold(
        event_id,
        reason="verify_need_manual_resolution",
        pending_ids=[],
        checkpoint_id=event_id,
        event_status=EventStatus.VERIFYING,
    )
    intent = await service.create_or_replay_resume_intent(
        event_id,
        resolution_source=RESOLUTION_SOURCE_ACTION_UNKNOWN,
        subject_kind=SUBJECT_KIND_ACTION,
        subject_id="act-crash",
        resolution="mark_success",
        principal="analyst-1",
    )
    claimed = await service._claim_batch(limit=100)
    assert intent.intent_id in claimed
    assert await service._run_claimed_intent(intent.intent_id) is False
    async with session_factory() as session:
        row = await session.get(orm.GraphResumeIntent, intent.intent_id)
        assert row is not None
        assert row.status == GraphResumeIntentStatus.RETRY.value
        substate = await session.scalar(
            select(orm.EventContextJournal.value)
            .where(
                orm.EventContextJournal.event_id == event_id,
                orm.EventContextJournal.field_name == "execution_substate",
            )
            .order_by(orm.EventContextJournal.version.desc())
            .limit(1)
        )
        assert unwrap_journal_value(substate) == ExecutionSubstate.MANUAL_RESOLUTION.value

    service.bind_resume_runner(_ok)
    claimed2 = await service._claim_batch(limit=100)
    assert intent.intent_id in claimed2
    assert await service._run_claimed_intent(intent.intent_id) is True
    assert resumed == [event_id]
    async with session_factory() as session:
        row = await session.get(orm.GraphResumeIntent, intent.intent_id)
        assert row is not None
        assert row.status == GraphResumeIntentStatus.TERMINAL.value
        substate = await session.scalar(
            select(orm.EventContextJournal.value)
            .where(
                orm.EventContextJournal.event_id == event_id,
                orm.EventContextJournal.field_name == "execution_substate",
            )
            .order_by(orm.EventContextJournal.version.desc())
            .limit(1)
        )
        assert unwrap_journal_value(substate) == ExecutionSubstate.NONE.value


@pytest.mark.asyncio
async def test_resolve_unknown_creates_intent_in_same_transaction(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    action_id = await _seed_unknown_action(session_factory, event_id)

    async def _noop_runner(_eid: str) -> None:
        return None

    manual = ManualResolutionService(session_factory, resume_runner=_noop_runner)
    await manual.enter_manual_hold(
        event_id,
        reason="verify_need_manual_resolution",
        pending_ids=[action_id],
        checkpoint_id=event_id,
        event_status=EventStatus.VERIFYING,
    )

    class _NoopSync:
        pass

    class _NoopExecutor:
        job_store = None

    class _NoopMachine:
        pass

    class _NoopStore:
        pass

    execution = ActionExecutionService(
        session_factory,
        disposition_sync=_NoopSync(),  # type: ignore[arg-type]
        tool_executor=_NoopExecutor(),  # type: ignore[arg-type]
        state_machine=_NoopMachine(),  # type: ignore[arg-type]
        context_store=_NoopStore(),  # type: ignore[arg-type]
        manual_resolution=manual,
    )
    resolved = await execution.resolve_unknown(
        action_id,
        "mark_success",
        principal="analyst-1",
        comment="confirmed by readback",
        operation_id=f"op-{action_id}",
    )
    assert resolved.status is ActionStatus.SUCCESS
    async with session_factory() as session:
        intent = await session.scalar(
            select(orm.GraphResumeIntent).where(
                orm.GraphResumeIntent.event_id == event_id,
                orm.GraphResumeIntent.subject_id == action_id,
            )
        )
        assert intent is not None
        assert intent.operation_id == f"op-{action_id}"
        assert intent.hold_generation == 1
        # schedule_dispatch may race; pin PENDING before any claim in dedicated tests.
        assert intent.status in {
            GraphResumeIntentStatus.PENDING.value,
            GraphResumeIntentStatus.CLAIMED.value,
            GraphResumeIntentStatus.STARTED.value,
            GraphResumeIntentStatus.TERMINAL.value,
            GraphResumeIntentStatus.RETRY.value,
        }


@pytest.mark.asyncio
async def test_pending_intent_survives_pre_claim_kill_then_reconcile_dispatch(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Commit-then-kill: PENDING survives without in-process schedule_dispatch."""
    from app.core.config import get_settings

    monkeypatch.setenv("TASK_MODE", "celery")
    get_settings.cache_clear()
    delay_calls: list[str] = []

    class _DelayTask:
        def delay(self) -> None:
            delay_calls.append("delay")

    monkeypatch.setattr(
        "app.tasks.graph_resume_intent_tasks.dispatch_pending_graph_resume_intents",
        _DelayTask(),
    )

    event_id = await _seed_event(session_factory)
    resumed: list[str] = []

    async def _ok(eid: str) -> None:
        resumed.append(eid)

    service = ManualResolutionService(session_factory, resume_runner=_ok)
    await service.enter_manual_hold(
        event_id,
        reason="verify_need_manual_resolution",
        pending_ids=[],
        checkpoint_id=event_id,
        event_status=EventStatus.VERIFYING,
    )
    intent = await service.create_or_replay_resume_intent(
        event_id,
        resolution_source=RESOLUTION_SOURCE_ACTION_UNKNOWN,
        subject_kind=SUBJECT_KIND_ACTION,
        subject_id="act-preclaim",
        resolution="mark_success",
        principal="analyst-1",
    )
    # Simulate process kill: only Celery delay was attempted; no claim yet.
    service.schedule_dispatch()
    assert delay_calls == ["delay"]
    async with session_factory() as session:
        row = await session.get(orm.GraphResumeIntent, intent.intent_id)
        assert row is not None
        assert row.status == GraphResumeIntentStatus.PENDING.value

    # Reclaim path used by beat reconcile/dispatch (no in-process create_task).
    assert await service.claim_and_run_batch(limit=20) >= 1
    assert resumed == [event_id]
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_concurrent_claim_runs_resume_runner_once(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    calls: list[str] = []

    async def _runner(eid: str) -> None:
        calls.append(eid)
        await asyncio.sleep(0.05)

    service = ManualResolutionService(session_factory, resume_runner=_runner)
    await service.enter_manual_hold(
        event_id,
        reason="verify_need_manual_resolution",
        pending_ids=["a", "b"],
        checkpoint_id=event_id,
        event_status=EventStatus.VERIFYING,
    )
    await service.create_or_replay_resume_intent(
        event_id,
        resolution_source=RESOLUTION_SOURCE_ACTION_UNKNOWN,
        subject_kind=SUBJECT_KIND_ACTION,
        subject_id="act-a",
        resolution="mark_success",
        principal="analyst-1",
    )
    results = await asyncio.gather(
        service.claim_and_run_batch(limit=20),
        service.claim_and_run_batch(limit=20),
    )
    assert sum(results) == 1
    assert calls == [event_id]


async def _seed_writeback_outbox(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    *,
    writeback_status: str,
) -> tuple[str, str]:
    from app.models.enums import ActionExecutionPhase, WritebackReadiness

    writeback_id = f"wbk-277-{uuid4().hex[:8]}"
    action_id = f"act-wb-{uuid4().hex[:8]}"
    source_record_id = f"src-{uuid4().hex[:8]}"
    connector_id = f"conn-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SourceConnector(
                    connector_id=connector_id,
                    source_product="mock_xdr",
                    display_name="ISSUE-277 connector",
                )
            )
            await session.flush()
            session.add(
                orm.SourceObject(
                    source_record_id=source_record_id,
                    source_product="mock_xdr",
                    source_tenant_id="t1",
                    connector_id=connector_id,
                    source_kind="incident",
                    source_object_id=f"INC-{uuid4().hex[:8]}",
                    normalized={},
                    raw_payload={},
                )
            )
            await session.flush()
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{action_id}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="block ip",
                    tool_name="block_ip",
                    action_level=ActionLevel.L2.value,
                    execution_owner=ExecutionOwner.XDR_MANAGED.value,
                    execution_phase=ActionExecutionPhase.IMMEDIATE.value,
                    status=ActionStatus.UNKNOWN.value,
                    writeback_required=True,
                    writeback_applicable=True,
                    writeback_readiness=WritebackReadiness.READY.value,
                    writeback_status=writeback_status,
                )
            )
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-{uuid4().hex[:8]}",
                    writeback_id=writeback_id,
                    disposition_id=f"disp-{uuid4().hex[:8]}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="h" * 64,
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{uuid4().hex[:8]}",
                    command_payload={},
                    command_payload_sha256="a" * 64,
                    delivery_status="delivered",
                    latest_writeback_status=writeback_status,
                )
            )
    return writeback_id, action_id


@pytest.mark.asyncio
async def test_resolve_writeback_on_manual_hold_creates_intent_not_direct_resume(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    from app.models.enums import WritebackStatus
    from app.services.disposition_sync_service import DispositionSyncService
    from app.services.manual_resolution_service import (
        RESOLUTION_SOURCE_WRITEBACK_MANUAL,
    )

    event_id = await _seed_event(session_factory)
    writeback_id, _action_id = await _seed_writeback_outbox(
        session_factory,
        event_id,
        writeback_status=WritebackStatus.UNKNOWN.value,
    )

    resume_calls: list[str] = []

    async def _direct_resume(eid: str) -> None:
        resume_calls.append(eid)

    async def _noop_runner(_eid: str) -> None:
        return None

    manual = ManualResolutionService(session_factory, resume_runner=_noop_runner)
    await manual.enter_manual_hold(
        event_id,
        reason="verify_need_manual_resolution",
        pending_ids=[writeback_id],
        checkpoint_id=event_id,
        event_status=EventStatus.VERIFYING,
    )

    class _Store:
        async def set(self, *_a: object, **_k: object) -> None:
            return None

        async def _merge_writeback_summary(self, *_a: object, **_k: object) -> None:
            return None

    sync = DispositionSyncService(
        session_factory,
        context_store=_Store(),  # type: ignore[arg-type]
        adapter_registry={},
        resume_investigation=_direct_resume,
        manual_resolution=manual,
    )

    async def _noop_summary(_eid: str) -> None:
        return None

    sync._sync_writeback_summary = _noop_summary  # type: ignore[method-assign]
    status = await sync.resolve_writeback(
        writeback_id,
        "mark_failed",
        principal="admin-1",
        comment="confirmed failed",
        operation_id=f"op-{writeback_id}",
    )
    assert status is WritebackStatus.FAILED
    assert resume_calls == []
    async with session_factory() as session:
        intent = await session.scalar(
            select(orm.GraphResumeIntent).where(
                orm.GraphResumeIntent.event_id == event_id,
                orm.GraphResumeIntent.resolution_source == RESOLUTION_SOURCE_WRITEBACK_MANUAL,
            )
        )
        assert intent is not None
        assert intent.subject_id == writeback_id


@pytest.mark.asyncio
async def test_resolve_writeback_replay_after_commit_schedules_pending_intent(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import get_settings
    from app.models.enums import WritebackStatus
    from app.services.disposition_sync_service import DispositionSyncService

    monkeypatch.setenv("TASK_MODE", "background")
    get_settings.cache_clear()

    event_id = await _seed_event(session_factory)
    writeback_id, _action_id = await _seed_writeback_outbox(
        session_factory,
        event_id,
        writeback_status=WritebackStatus.UNKNOWN.value,
    )

    schedule_calls: list[str] = []

    async def _noop_runner(_eid: str) -> None:
        return None

    manual = ManualResolutionService(session_factory, resume_runner=_noop_runner)

    def _track_schedule(
        *,
        event_id: str | None = None,
        intent_id: str | None = None,
        trigger: str = "unspecified",
    ) -> None:
        del event_id, intent_id, trigger
        schedule_calls.append("schedule")
        # Do not run in-process claim — simulate kill before dispatch.

    manual.schedule_dispatch = _track_schedule  # type: ignore[method-assign]
    await manual.enter_manual_hold(
        event_id,
        reason="verify_need_manual_resolution",
        pending_ids=[writeback_id],
        checkpoint_id=event_id,
        event_status=EventStatus.VERIFYING,
    )

    class _Store:
        async def set(self, *_a: object, **_k: object) -> None:
            return None

        async def _merge_writeback_summary(self, *_a: object, **_k: object) -> None:
            return None

    sync = DispositionSyncService(
        session_factory,
        context_store=_Store(),  # type: ignore[arg-type]
        adapter_registry={},
        resume_investigation=None,
        manual_resolution=manual,
    )

    async def _noop_summary(_eid: str) -> None:
        return None

    sync._sync_writeback_summary = _noop_summary  # type: ignore[method-assign]
    op_id = f"op-replay-{writeback_id}"
    await sync.resolve_writeback(
        writeback_id,
        "mark_failed",
        principal="admin-1",
        comment="first",
        operation_id=op_id,
    )
    assert schedule_calls == ["schedule"]
    tracked: list[str] = []

    def _track2(
        *,
        event_id: str | None = None,
        intent_id: str | None = None,
        trigger: str = "unspecified",
    ) -> None:
        del event_id, intent_id, trigger
        tracked.append("replay")

    manual.schedule_dispatch = _track2  # type: ignore[method-assign]
    again = await sync.resolve_writeback(
        writeback_id,
        "mark_failed",
        principal="admin-1",
        comment="replay",
        operation_id=op_id,
    )
    assert again is WritebackStatus.FAILED
    assert tracked == ["replay"]
    get_settings.cache_clear()


def test_beat_schedule_includes_graph_resume_intent_tasks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import get_settings

    monkeypatch.setenv("TASK_MODE", "celery")
    get_settings.cache_clear()
    from app.core.celery_app import _build_beat_schedule

    schedule = _build_beat_schedule()
    assert "shadowtrace-dispatch-graph-resume-intents" in schedule
    assert "shadowtrace-reconcile-graph-resume-intents" in schedule
    get_settings.cache_clear()


def test_graph_resume_schedule_skipped_no_loop_is_observable(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """ISSUE-324: no running loop must not silently skip graph resume dispatch."""
    import logging
    from unittest.mock import AsyncMock

    from app.core.config import get_settings
    from app.core.metrics import (
        dispatch_schedule_health_snapshot,
        reset_dispatch_schedule_metrics_for_tests,
    )

    reset_dispatch_schedule_metrics_for_tests()
    monkeypatch.setenv("TASK_MODE", "celery")
    get_settings.cache_clear()

    class _BoomDelay:
        def delay(self) -> None:
            raise ConnectionError("amqp://user:secret@broker:5672/vhost is down")

    monkeypatch.setattr(
        "app.tasks.graph_resume_intent_tasks.dispatch_pending_graph_resume_intents",
        _BoomDelay(),
    )

    degraded = MagicMock()
    degraded.set_flag = AsyncMock(return_value=["graph_resume_dispatch_unavailable=test_no_loop"])
    session_factory = MagicMock()
    service = ManualResolutionService(session_factory, degraded_flags=degraded)

    resume_logger = logging.getLogger("app.services.manual_resolution_service")
    resume_logger.disabled = False
    resume_logger.propagate = True
    with caplog.at_level(logging.WARNING, logger="app.services.manual_resolution_service"):
        service.schedule_dispatch(
            event_id="evt-no-loop",
            intent_id="gri-no-loop",
            trigger="test_no_loop",
        )

    snapshot = dispatch_schedule_health_snapshot()
    assert snapshot.get("graph_resume:resume_enqueue_failed") == 1
    assert snapshot.get("graph_resume:resume_schedule_skipped_no_loop") == 1
    degraded.set_flag.assert_awaited_once_with(
        "evt-no-loop",
        "graph_resume_dispatch_unavailable",
        "test_no_loop",
        writer="ManualResolutionService",
    )
    assert "secret" not in caplog.text
    assert "amqp://" not in caplog.text
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_graph_resume_in_process_dispatch_failure_sets_degraded_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-324: Celery fail + in-process fail must set graph_resume_dispatch_unavailable."""
    import asyncio
    from unittest.mock import AsyncMock

    from app.core.config import get_settings
    from app.core.metrics import (
        dispatch_schedule_health_snapshot,
        reset_dispatch_schedule_metrics_for_tests,
    )

    reset_dispatch_schedule_metrics_for_tests()
    monkeypatch.setenv("TASK_MODE", "celery")
    get_settings.cache_clear()

    class _BoomDelay:
        def delay(self) -> None:
            raise ConnectionError("broker down")

    monkeypatch.setattr(
        "app.tasks.graph_resume_intent_tasks.dispatch_pending_graph_resume_intents",
        _BoomDelay(),
    )

    degraded = MagicMock()
    degraded.set_flag = AsyncMock(return_value=["graph_resume_dispatch_unavailable=test_ip_fail"])
    service = ManualResolutionService(MagicMock(), degraded_flags=degraded)

    async def _boom_intent(_intent_id: str) -> bool:
        raise RuntimeError("in-process dispatch failed")

    monkeypatch.setattr(service, "claim_and_run_intent", _boom_intent)

    created: list[asyncio.Task[object]] = []
    loop = asyncio.get_running_loop()
    orig_create = loop.create_task

    def _capture(coro: object, *args: object, **kwargs: object) -> asyncio.Task[object]:
        task = orig_create(coro, *args, **kwargs)  # type: ignore[arg-type]
        created.append(task)
        return task

    monkeypatch.setattr(loop, "create_task", _capture)
    service.schedule_dispatch(
        event_id="evt-ip-fail",
        intent_id="gri-ip-fail",
        trigger="test_ip_fail",
    )
    assert created
    await created[0]

    snapshot = dispatch_schedule_health_snapshot()
    assert snapshot.get("graph_resume:resume_enqueue_failed") == 1
    assert snapshot.get("graph_resume:resume_scheduled", 0) == 0
    degraded.set_flag.assert_awaited_once_with(
        "evt-ip-fail",
        "graph_resume_dispatch_unavailable",
        "test_ip_fail",
        writer="ManualResolutionService",
    )
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_graph_resume_schedule_celery_success_records_metric(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import get_settings
    from app.core.metrics import (
        dispatch_schedule_health_snapshot,
        reset_dispatch_schedule_metrics_for_tests,
    )

    reset_dispatch_schedule_metrics_for_tests()
    monkeypatch.setenv("TASK_MODE", "celery")
    get_settings.cache_clear()
    delay_calls: list[str] = []

    class _DelayTask:
        def delay(self) -> None:
            delay_calls.append("delay")

    monkeypatch.setattr(
        "app.tasks.graph_resume_intent_tasks.dispatch_pending_graph_resume_intents",
        _DelayTask(),
    )

    service = ManualResolutionService(MagicMock())
    service.schedule_dispatch(event_id="evt-celery", trigger="test_celery")
    assert delay_calls == ["delay"]
    snapshot = dispatch_schedule_health_snapshot()
    assert snapshot.get("graph_resume:resume_scheduled") == 1
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_graph_resume_in_process_fallback_binds_target_intent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-324: Celery fail + in-process must run the passed intent, not global backlog."""
    from app.core.config import get_settings
    from app.core.metrics import (
        dispatch_schedule_health_snapshot,
        reset_dispatch_schedule_metrics_for_tests,
    )

    reset_dispatch_schedule_metrics_for_tests()
    monkeypatch.setenv("TASK_MODE", "celery")
    get_settings.cache_clear()

    class _BoomDelay:
        def delay(self) -> None:
            raise ConnectionError("broker down")

    monkeypatch.setattr(
        "app.tasks.graph_resume_intent_tasks.dispatch_pending_graph_resume_intents",
        _BoomDelay(),
    )

    service = ManualResolutionService(MagicMock())
    called: list[str] = []

    async def _run_intent(intent_id: str) -> bool:
        called.append(intent_id)
        return True

    async def _run_batch(*, limit: int = 20) -> int:
        called.append(f"batch:{limit}")
        return 1

    monkeypatch.setattr(service, "claim_and_run_intent", _run_intent)
    monkeypatch.setattr(service, "claim_and_run_batch", _run_batch)

    created: list[asyncio.Task[object]] = []
    loop = asyncio.get_running_loop()
    orig_create = loop.create_task

    def _capture(coro: object, *args: object, **kwargs: object) -> asyncio.Task[object]:
        task = orig_create(coro, *args, **kwargs)  # type: ignore[arg-type]
        created.append(task)
        return task

    monkeypatch.setattr(loop, "create_task", _capture)
    service.schedule_dispatch(
        event_id="evt-bind",
        intent_id="gri-target",
        trigger="test_bind",
    )
    assert created
    await created[0]
    assert called == ["gri-target"]
    snapshot = dispatch_schedule_health_snapshot()
    assert snapshot.get("graph_resume:resume_enqueue_failed") == 1
    assert snapshot.get("graph_resume:resume_scheduled") == 1
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_graph_resume_in_process_ran_zero_does_not_count_resume_scheduled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import get_settings
    from app.core.metrics import (
        dispatch_schedule_health_snapshot,
        reset_dispatch_schedule_metrics_for_tests,
    )

    reset_dispatch_schedule_metrics_for_tests()
    monkeypatch.setenv("TASK_MODE", "celery")
    get_settings.cache_clear()

    class _BoomDelay:
        def delay(self) -> None:
            raise ConnectionError("broker down")

    monkeypatch.setattr(
        "app.tasks.graph_resume_intent_tasks.dispatch_pending_graph_resume_intents",
        _BoomDelay(),
    )

    service = ManualResolutionService(MagicMock())

    async def _empty_intent(_intent_id: str) -> bool:
        return False

    monkeypatch.setattr(service, "claim_and_run_intent", _empty_intent)

    created: list[asyncio.Task[object]] = []
    loop = asyncio.get_running_loop()
    orig_create = loop.create_task

    def _capture(coro: object, *args: object, **kwargs: object) -> asyncio.Task[object]:
        task = orig_create(coro, *args, **kwargs)  # type: ignore[arg-type]
        created.append(task)
        return task

    monkeypatch.setattr(loop, "create_task", _capture)
    service.schedule_dispatch(
        event_id="evt-empty",
        intent_id="gri-empty",
        trigger="test_empty",
    )
    assert created
    await created[0]
    snapshot = dispatch_schedule_health_snapshot()
    assert snapshot.get("graph_resume:resume_enqueue_failed") == 1
    assert snapshot.get("graph_resume:resume_scheduled", 0) == 0
    assert snapshot.get("graph_resume:resume_in_process_empty") == 1
    get_settings.cache_clear()


def test_graph_resume_schedule_dispatch_flags_all_reconcile_event_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-324: reconcile_stale enqueue failure must flag every recovered event."""
    from unittest.mock import AsyncMock

    from app.core.config import get_settings
    from app.core.metrics import (
        dispatch_schedule_health_snapshot,
        reset_dispatch_schedule_metrics_for_tests,
    )

    reset_dispatch_schedule_metrics_for_tests()
    monkeypatch.setenv("TASK_MODE", "celery")
    get_settings.cache_clear()

    class _BoomDelay:
        def delay(self) -> None:
            raise ConnectionError("broker down")

    monkeypatch.setattr(
        "app.tasks.graph_resume_intent_tasks.dispatch_pending_graph_resume_intents",
        _BoomDelay(),
    )

    degraded = MagicMock()
    degraded.set_flag = AsyncMock(
        return_value=["graph_resume_dispatch_unavailable=reconcile_stale"]
    )
    service = ManualResolutionService(MagicMock(), degraded_flags=degraded)
    service.schedule_dispatch(
        event_ids=["evt-a", "evt-b"],
        trigger="reconcile_stale",
    )
    snapshot = dispatch_schedule_health_snapshot()
    assert snapshot.get("graph_resume:resume_enqueue_failed") == 1
    assert snapshot.get("graph_resume:resume_schedule_skipped_no_loop") == 1
    assert degraded.set_flag.await_count == 2
    degraded.set_flag.assert_any_await(
        "evt-a",
        "graph_resume_dispatch_unavailable",
        "reconcile_stale",
        writer="ManualResolutionService",
    )
    degraded.set_flag.assert_any_await(
        "evt-b",
        "graph_resume_dispatch_unavailable",
        "reconcile_stale",
        writer="ManualResolutionService",
    )
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_graph_resume_in_process_single_flight_does_not_drop_second_intent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-324: coalesced in-process dispatch must still run the second intent."""
    from app.core.config import get_settings
    from app.core.metrics import (
        dispatch_schedule_health_snapshot,
        reset_dispatch_schedule_metrics_for_tests,
    )

    reset_dispatch_schedule_metrics_for_tests()
    monkeypatch.setenv("TASK_MODE", "celery")
    get_settings.cache_clear()

    class _BoomDelay:
        def delay(self) -> None:
            raise ConnectionError("broker down")

    monkeypatch.setattr(
        "app.tasks.graph_resume_intent_tasks.dispatch_pending_graph_resume_intents",
        _BoomDelay(),
    )

    service = ManualResolutionService(MagicMock())
    called: list[str] = []
    started = asyncio.Event()
    release = asyncio.Event()

    async def _run_intent(intent_id: str) -> bool:
        called.append(intent_id)
        if intent_id == "gri-a":
            started.set()
            await release.wait()
        return True

    monkeypatch.setattr(service, "claim_and_run_intent", _run_intent)

    service.schedule_dispatch(
        event_id="evt-a",
        intent_id="gri-a",
        trigger="first",
    )
    await started.wait()
    service.schedule_dispatch(
        event_id="evt-b",
        intent_id="gri-b",
        trigger="second",
    )
    release.set()
    for _ in range(50):
        if called == ["gri-a", "gri-b"]:
            break
        await asyncio.sleep(0)
    assert called == ["gri-a", "gri-b"]
    snapshot = dispatch_schedule_health_snapshot()
    assert snapshot.get("graph_resume:resume_enqueue_failed") == 2
    assert snapshot.get("graph_resume:resume_schedule_coalesced") == 1
    assert snapshot.get("graph_resume:resume_scheduled") == 2
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_reconcile_stale_passes_changed_event_ids_to_schedule_dispatch(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-324: reconcile_stale must forward recovered event ids."""
    from app.core.config import get_settings

    monkeypatch.setenv("TASK_MODE", "celery")
    get_settings.cache_clear()

    class _DelayTask:
        def delay(self) -> None:
            return None

    monkeypatch.setattr(
        "app.tasks.graph_resume_intent_tasks.dispatch_pending_graph_resume_intents",
        _DelayTask(),
    )

    event_id = await _seed_event(session_factory)

    async def _ok(_eid: str) -> None:
        return None

    service = ManualResolutionService(session_factory, resume_runner=_ok)
    await service.enter_manual_hold(
        event_id,
        reason="verify_need_manual_resolution",
        pending_ids=[],
        checkpoint_id=event_id,
        event_status=EventStatus.VERIFYING,
    )
    intent = await service.create_or_replay_resume_intent(
        event_id,
        resolution_source=RESOLUTION_SOURCE_ACTION_UNKNOWN,
        subject_kind=SUBJECT_KIND_ACTION,
        subject_id="act-stale",
        resolution="mark_success",
        principal="analyst-1",
    )
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.GraphResumeIntent, intent.intent_id)
            assert row is not None
            row.status = GraphResumeIntentStatus.CLAIMED.value
            row.claim_owner = "dispatcher"
            row.claim_expires_at = datetime.now(UTC) - timedelta(seconds=1)

    captured: dict[str, object] = {}

    def _capture_dispatch(**kwargs: object) -> None:
        captured.update(kwargs)

    service.schedule_dispatch = _capture_dispatch  # type: ignore[method-assign]
    changed = await service.reconcile_stale()
    assert changed >= 1
    assert captured.get("trigger") == "reconcile_stale"
    event_ids = captured.get("event_ids")
    assert isinstance(event_ids, list)
    assert event_id in event_ids
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_nested_wakeup_deferred_does_not_burn_dead_budget(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    from app.orchestration.graph_resume_observability import GraphResumeDeferredError

    event_id = await _seed_event(session_factory, status=EventStatus.WAITING_APPROVAL)

    async def _deferred(_eid: str) -> None:
        raise GraphResumeDeferredError(
            "cannot resume while event is still WAITING_APPROVAL",
            event_id=_eid,
            error_type="waiting_approval",
        )

    service = ManualResolutionService(
        session_factory,
        resume_runner=_deferred,
        max_attempts=1,
    )
    service.schedule_dispatch = lambda **_kwargs: None  # type: ignore[method-assign]
    intent = await service.enqueue_nested_wakeup(event_id, reason="waiting_approval")
    assert intent is not None

    claimed = await service._claim_batch(limit=100)
    assert intent.intent_id in claimed
    assert await service._run_claimed_intent(intent.intent_id) is False
    async with session_factory() as session:
        row = await session.get(orm.GraphResumeIntent, intent.intent_id)
        assert row is not None
        assert row.status == GraphResumeIntentStatus.RETRY.value
        assert int(row.attempt or 0) == 0

    claimed_again = await service._claim_batch(limit=100)
    assert intent.intent_id in claimed_again
    assert await service._run_claimed_intent(intent.intent_id) is False
    async with session_factory() as session:
        row = await session.get(orm.GraphResumeIntent, intent.intent_id)
        assert row is not None
        assert row.status == GraphResumeIntentStatus.RETRY.value
        assert int(row.attempt or 0) == 0
