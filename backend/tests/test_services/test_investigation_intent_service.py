"""Investigation intent durable ledger tests (ISSUE-108 / #612)."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.errors import IdempotencyKeyReuseError, InvestigationInProgressError
from app.db import models as orm
from app.models.enums import EventStatus, InvestigationIntentStatus, Severity, SourceObjectKind
from app.models.investigation_intent import (
    PRIMARY_LINK_ROLE,
    PROVISIONAL_LINK_ROLE,
    IntentDeliveryAdmission,
    InvestigationIntentTransitionError,
    validate_intent_transition,
)
from app.services.auto_investigate_policy import AutoInvestigatePolicyService
from app.services.auto_response_policy import AutoResponsePolicyService
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService
from app.services.investigation_intent_service import (
    InvestigationIntentService,
    deterministic_investigation_task_id,
    http_investigation_payload_sha256,
)


@pytest.fixture(autouse=True)
def _suppress_background_intent_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    if request.node.name == "test_reconcile_stale_schedules_dispatch":
        return
    monkeypatch.setattr(
        "app.tasks.investigation_intent_tasks.dispatch_pending_investigation_intents.delay",
        lambda: None,
    )


async def _seed_http_intake_event(
    session_factory: async_sessionmaker[AsyncSession],
) -> str:
    event_id = f"evt-http-intake-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="HTTP durable intake",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                    row_version=3,
                )
            )
            await session.flush()
            loaded = await session.get(orm.SecurityEvent, event_id)
            assert loaded is not None, f"failed to seed event {event_id}"
    return event_id


def test_intent_transition_validation() -> None:
    validate_intent_transition(
        InvestigationIntentStatus.PENDING,
        InvestigationIntentStatus.CLAIMED,
    )
    validate_intent_transition(
        InvestigationIntentStatus.CLAIMED,
        InvestigationIntentStatus.SKIPPED,
    )
    validate_intent_transition(
        InvestigationIntentStatus.ENQUEUED,
        InvestigationIntentStatus.DEAD,
    )
    validate_intent_transition(
        InvestigationIntentStatus.PENDING,
        InvestigationIntentStatus.SKIPPED,
    )
    validate_intent_transition(
        InvestigationIntentStatus.RETRY,
        InvestigationIntentStatus.SKIPPED,
    )
    validate_intent_transition(
        InvestigationIntentStatus.DEAD,
        InvestigationIntentStatus.RETRY,
    )
    validate_intent_transition(
        InvestigationIntentStatus.SKIPPED,
        InvestigationIntentStatus.RETRY,
    )
    with pytest.raises(InvestigationIntentTransitionError):
        validate_intent_transition(
            InvestigationIntentStatus.PENDING,
            InvestigationIntentStatus.TERMINAL,
        )


def test_deterministic_task_id_stable() -> None:
    first = deterministic_investigation_task_id("iin-abc", 2)
    second = deterministic_investigation_task_id("iin-abc", 2)
    third = deterministic_investigation_task_id("iin-abc", 3)
    assert first == second
    assert first != third


@pytest.mark.asyncio
async def test_http_intent_commit_replay_and_payload_conflict(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_http_intake_event(session_factory)
    settings = Settings(TASK_MODE="celery")
    service = InvestigationIntentService(session_factory, settings=settings)
    payload_hash = http_investigation_payload_sha256(
        event_id=event_id,
        force_replan=False,
        include_response_execution=False,
        generate_report=True,
        orchestration_mode="graph",
    )

    first = await service.create_or_replay_http_intent(
        event_id,
        requested_by="analyst-1",
        request_idempotency_key=f"req-http-1:{event_id}",
        request_payload_sha256=payload_hash,
        orchestration_mode="graph",
        include_response_execution=False,
        generate_report=True,
    )
    replay = await service.create_or_replay_http_intent(
        event_id,
        requested_by="analyst-1",
        request_idempotency_key=f"req-http-1:{event_id}",
        request_payload_sha256=payload_hash,
        orchestration_mode="graph",
        include_response_execution=False,
        generate_report=True,
    )

    assert first.created is True
    assert replay.created is False
    assert replay.intent_id == first.intent_id
    assert replay.task_id == first.task_id
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, first.intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.PENDING.value
        assert row.request_payload_sha256 == payload_hash
        assert row.requested_by == "analyst-1"

    changed_hash = http_investigation_payload_sha256(
        event_id=event_id,
        force_replan=False,
        include_response_execution=False,
        generate_report=False,
        orchestration_mode="graph",
    )
    with pytest.raises(IdempotencyKeyReuseError):
        await service.create_or_replay_http_intent(
            event_id,
            requested_by="analyst-1",
            request_idempotency_key=f"req-http-1:{event_id}",
            request_payload_sha256=changed_hash,
            orchestration_mode="graph",
            include_response_execution=False,
            generate_report=False,
        )


@pytest.mark.asyncio
async def test_http_intent_different_key_for_same_event_is_rejected(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_http_intake_event(session_factory)
    service = InvestigationIntentService(
        session_factory,
        settings=Settings(TASK_MODE="celery"),
    )
    payload_hash = http_investigation_payload_sha256(
        event_id=event_id,
        force_replan=False,
        include_response_execution=False,
        generate_report=True,
        orchestration_mode="graph",
    )
    await service.create_or_replay_http_intent(
        event_id,
        requested_by="analyst-1",
        request_idempotency_key=f"req-http-first:{event_id}",
        request_payload_sha256=payload_hash,
        orchestration_mode="graph",
        include_response_execution=False,
        generate_report=True,
    )

    with pytest.raises(InvestigationInProgressError):
        await service.create_or_replay_http_intent(
            event_id,
            requested_by="analyst-1",
            request_idempotency_key=f"req-http-second:{event_id}",
            request_payload_sha256=payload_hash,
            orchestration_mode="graph",
            include_response_execution=False,
            generate_report=True,
        )


@pytest.mark.asyncio
async def test_dead_http_intent_same_key_replay_rearms_original_intent(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_http_intake_event(session_factory)
    service = InvestigationIntentService(
        session_factory,
        settings=Settings(TASK_MODE="celery"),
    )
    payload_hash = http_investigation_payload_sha256(
        event_id=event_id,
        force_replan=False,
        include_response_execution=False,
        generate_report=True,
        orchestration_mode="graph",
    )
    original = await service.create_or_replay_http_intent(
        event_id,
        requested_by="analyst-dead-replay",
        request_idempotency_key=f"req-http-dead-replay:{event_id}",
        request_payload_sha256=payload_hash,
        orchestration_mode="graph",
        include_response_execution=False,
        generate_report=True,
    )
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.InvestigationIntent, original.intent_id)
            assert row is not None
            row.status = InvestigationIntentStatus.DEAD.value
            row.attempt = 3
            row.last_error = "broker unavailable"

    replay = await service.create_or_replay_http_intent(
        event_id,
        requested_by="analyst-dead-replay",
        request_idempotency_key=f"req-http-dead-replay:{event_id}",
        request_payload_sha256=payload_hash,
        orchestration_mode="graph",
        include_response_execution=False,
        generate_report=True,
    )

    assert replay.created is False
    assert replay.intent_id == original.intent_id
    assert replay.status is InvestigationIntentStatus.RETRY
    assert replay.revision == original.revision + 1
    assert replay.task_id != original.task_id
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, original.intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.RETRY.value
        assert row.attempt == 0
        assert row.broker_task_id == replay.task_id


@pytest.mark.asyncio
async def test_skipped_http_intent_same_key_replay_rearms_original_intent(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_http_intake_event(session_factory)
    service = InvestigationIntentService(
        session_factory,
        settings=Settings(TASK_MODE="celery"),
    )
    payload_hash = http_investigation_payload_sha256(
        event_id=event_id,
        force_replan=False,
        include_response_execution=False,
        generate_report=True,
        orchestration_mode="graph",
    )
    original = await service.create_or_replay_http_intent(
        event_id,
        requested_by="analyst-skipped-replay",
        request_idempotency_key=f"req-http-skipped-replay:{event_id}",
        request_payload_sha256=payload_hash,
        orchestration_mode="graph",
        include_response_execution=False,
        generate_report=True,
    )
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.InvestigationIntent, original.intent_id)
            assert row is not None
            row.status = InvestigationIntentStatus.SKIPPED.value
            row.skip_reason = "inline_execution_stale"

    replay = await service.create_or_replay_http_intent(
        event_id,
        requested_by="analyst-skipped-replay",
        request_idempotency_key=f"req-http-skipped-replay:{event_id}",
        request_payload_sha256=payload_hash,
        orchestration_mode="graph",
        include_response_execution=False,
        generate_report=True,
    )
    assert replay.intent_id == original.intent_id
    assert replay.status is InvestigationIntentStatus.RETRY


@pytest.mark.asyncio
async def test_http_intake_skips_pending_auto_intent_same_event(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_http_intake_event(session_factory)
    service = InvestigationIntentService(
        session_factory,
        settings=Settings(TASK_MODE="celery"),
    )
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.InvestigationIntent(
                    intent_id=f"iin-auto-{event_id[-8:]}",
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.PENDING.value,
                    revision=1,
                    attempt=0,
                    broker_task_id=f"task-auto-{event_id[-8:]}",
                )
            )
    payload_hash = http_investigation_payload_sha256(
        event_id=event_id,
        force_replan=False,
        include_response_execution=False,
        generate_report=True,
        orchestration_mode="graph",
    )
    http_intent = await service.create_or_replay_http_intent(
        event_id,
        requested_by="analyst-http-supersede",
        request_idempotency_key=f"req-http-supersede:{event_id}",
        request_payload_sha256=payload_hash,
        orchestration_mode="graph",
        include_response_execution=False,
        generate_report=True,
    )
    assert http_intent.created is True
    async with session_factory() as session:
        auto = await session.scalar(
            select(orm.InvestigationIntent).where(
                orm.InvestigationIntent.event_id == event_id,
                orm.InvestigationIntent.intent_kind == "auto_investigate",
            )
        )
        assert auto is not None
        assert auto.status == InvestigationIntentStatus.SKIPPED.value
        assert auto.skip_reason == "superseded_by_http_investigate"


@pytest.mark.asyncio
async def test_concurrent_same_key_http_intake_has_one_commit_and_one_replay(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_http_intake_event(session_factory)
    service = InvestigationIntentService(
        session_factory,
        settings=Settings(TASK_MODE="celery"),
    )
    payload_hash = http_investigation_payload_sha256(
        event_id=event_id,
        force_replan=False,
        include_response_execution=False,
        generate_report=True,
        orchestration_mode="graph",
    )

    async def _submit():
        return await service.create_or_replay_http_intent(
            event_id,
            requested_by="analyst-concurrent",
            request_idempotency_key=f"req-http-concurrent:{event_id}",
            request_payload_sha256=payload_hash,
            orchestration_mode="graph",
            include_response_execution=False,
            generate_report=True,
        )

    first, second = await asyncio.gather(_submit(), _submit())
    assert first.intent_id == second.intent_id
    assert first.task_id == second.task_id
    assert sorted([first.created, second.created]) == [False, True]


@pytest.mark.asyncio
async def test_inline_http_intent_claim_persists_started_generation(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_http_intake_event(session_factory)
    service = InvestigationIntentService(
        session_factory,
        settings=Settings(TASK_MODE="background"),
    )
    payload_hash = http_investigation_payload_sha256(
        event_id=event_id,
        force_replan=False,
        include_response_execution=False,
        generate_report=True,
        orchestration_mode="graph",
    )
    intent = await service.create_or_replay_http_intent(
        event_id,
        requested_by="analyst-1",
        request_idempotency_key=f"req-http-inline:{event_id}",
        request_payload_sha256=payload_hash,
        orchestration_mode="graph",
        include_response_execution=False,
        generate_report=True,
    )

    task_id = await service.mark_inline_started(intent.intent_id)
    assert task_id == intent.task_id
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent.intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.STARTED.value
        assert row.broker_task_id == task_id
        assert row.claim_owner is None
        assert row.claim_expires_at is None


@pytest.mark.asyncio
async def test_http_intent_survives_api_restart_and_dispatches(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id = await _seed_http_intake_event(session_factory)
    settings = Settings(TASK_MODE="celery")
    api_process = InvestigationIntentService(session_factory, settings=settings)
    payload_hash = http_investigation_payload_sha256(
        event_id=event_id,
        force_replan=False,
        include_response_execution=False,
        generate_report=True,
        orchestration_mode="graph",
    )
    committed = await api_process.create_or_replay_http_intent(
        event_id,
        requested_by="analyst-1",
        request_idempotency_key=f"req-http-restart:{event_id}",
        request_payload_sha256=payload_hash,
        orchestration_mode="graph",
        include_response_execution=False,
        generate_report=True,
    )

    published: list[dict[str, object]] = []

    async def _register(_task_id: str, _event_id: str) -> None:
        return None

    def _publish(**kwargs: object) -> None:
        published.append(kwargs)

    monkeypatch.setattr("app.tasks.investigation_tasks.register_task_metadata", _register)
    monkeypatch.setattr("app.tasks.investigation_tasks.publish_investigation_for_intent", _publish)

    restarted_worker = InvestigationIntentService(session_factory, settings=settings)

    async def _claim_committed_intent(*, limit: int = 10) -> list[str]:
        del limit
        async with session_factory() as session:
            async with session.begin():
                row = await session.get(
                    orm.InvestigationIntent,
                    committed.intent_id,
                    with_for_update=True,
                )
                assert row is not None
                row.status = InvestigationIntentStatus.CLAIMED.value
                row.claim_owner = "intent-dispatcher-1"
                row.claim_expires_at = datetime.now(UTC) + timedelta(seconds=30)
        return [committed.intent_id]

    monkeypatch.setattr(restarted_worker, "_claim_batch", _claim_committed_intent)
    assert await restarted_worker.claim_and_publish_batch(limit=1) == 1
    assert published == [
        {
            "event_id": event_id,
            "task_id": committed.task_id,
            "intent_id": committed.intent_id,
            "include_response_execution": False,
            "generate_report": True,
            "resume_from_checkpoint": False,
        }
    ]
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, committed.intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.ENQUEUED.value
        assert row.broker_task_id == committed.task_id


@pytest.mark.asyncio
async def test_create_pending_intent_in_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    event_id = f"evt-intent-create-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            event = orm.SecurityEvent(
                event_id=event_id,
                event_type="malicious_process",
                title="Suspicious process",
                description="",
                status=EventStatus.NEW.value,
                severity=Severity.HIGH.value,
                final_verdict="none",
                creation_source_ref={"source_product": "mock_xdr"},
                source_reference_snapshots=[],
                disposition_policy="not_required",
                raw_alert_ids=[],
                source_type="mock_xdr",
            )
            session.add(event)
            await session.flush()
            intent_id = await service.maybe_create_pending_in_session(
                session,
                event,
                link_role="primary",
                source_product="mock_xdr",
                created_or_promoted=True,
            )
            assert intent_id is not None
    async with session_factory() as session:
        row = await session.scalar(
            select(orm.InvestigationIntent).where(orm.InvestigationIntent.intent_id == intent_id)
        )
        assert row is not None
        assert row.status == InvestigationIntentStatus.PENDING.value
        assert row.event_id == event_id


@pytest.mark.asyncio
async def test_lookup_active_for_event_returns_matching_intent(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    event_id = f"evt-intent-lookup-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            event = orm.SecurityEvent(
                event_id=event_id,
                event_type="malicious_process",
                title="Suspicious process",
                description="",
                status=EventStatus.NEW.value,
                severity=Severity.HIGH.value,
                final_verdict="none",
                creation_source_ref={"source_product": "mock_xdr"},
                source_reference_snapshots=[],
                disposition_policy="not_required",
                raw_alert_ids=[],
                source_type="mock_xdr",
            )
            session.add(event)
            await session.flush()
            intent_id = await service.maybe_create_pending_in_session(
                session,
                event,
                link_role="primary",
                source_product="mock_xdr",
                created_or_promoted=True,
            )
            assert intent_id is not None

    found = await service.lookup_active_for_event(event_id)
    assert found is not None
    assert found.intent_id == intent_id
    assert found.event_id == event_id

    missing = await service.lookup_active_for_event(f"evt-missing-{uuid4().hex[:8]}")
    assert missing is None


@pytest.mark.asyncio
async def test_duplicate_intent_unique_by_event(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    event_id = f"evt-intent-dup-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            event = orm.SecurityEvent(
                event_id=event_id,
                event_type="malicious_process",
                title="Suspicious process",
                description="",
                status=EventStatus.NEW.value,
                severity=Severity.HIGH.value,
                final_verdict="none",
                creation_source_ref={"source_product": "mock_xdr"},
                source_reference_snapshots=[],
                disposition_policy="not_required",
                raw_alert_ids=[],
                source_type="mock_xdr",
            )
            session.add(event)
            await session.flush()
            first = await service.maybe_create_pending_in_session(
                session,
                event,
                link_role="primary",
                source_product="mock_xdr",
                created_or_promoted=True,
            )
            second = await service.maybe_create_pending_in_session(
                session,
                event,
                link_role="primary",
                source_product="mock_xdr",
                created_or_promoted=True,
            )
            assert first is not None
            assert second is None


@pytest.mark.asyncio
async def test_mark_started_and_terminal(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    event_id = f"evt-intent-terminal-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            event = orm.SecurityEvent(
                event_id=event_id,
                event_type="malicious_process",
                title="Suspicious process",
                description="",
                status=EventStatus.NEW.value,
                severity=Severity.HIGH.value,
                final_verdict="none",
                creation_source_ref={"source_product": "mock_xdr"},
                source_reference_snapshots=[],
                disposition_policy="not_required",
                raw_alert_ids=[],
                source_type="mock_xdr",
            )
            session.add(event)
            await session.flush()
            intent_id = await service.maybe_create_pending_in_session(
                session,
                event,
                link_role="primary",
                source_product="mock_xdr",
                created_or_promoted=True,
            )
    assert intent_id is not None
    broker_task_id = f"task-123-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.InvestigationIntent, intent_id)
            assert row is not None
            row.status = InvestigationIntentStatus.ENQUEUED.value
            row.broker_task_id = broker_task_id
    await service.mark_started(intent_id, broker_task_id=broker_task_id)
    await service.mark_terminal(intent_id)
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.TERMINAL.value


@pytest.mark.asyncio
async def test_reconcile_stale_enqueued_to_retry(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        TASK_MODE="celery",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=5,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-stale-{uuid4().hex[:8]}"
    event_id = f"evt-intent-stale-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            event = orm.SecurityEvent(
                event_id=event_id,
                event_type="malicious_process",
                title="Suspicious process",
                description="",
                status=EventStatus.NEW.value,
                severity=Severity.HIGH.value,
                final_verdict="none",
                creation_source_ref={"source_product": "mock_xdr"},
                source_reference_snapshots=[],
                disposition_policy="not_required",
                raw_alert_ids=[],
                source_type="mock_xdr",
            )
            session.add(event)
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event.event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.ENQUEUED.value,
                    revision=1,
                    attempt=0,
                    broker_task_id=f"task-stale-{uuid4().hex[:8]}",
                    updated_at=datetime.now(UTC) - timedelta(minutes=10),
                )
            )
    await service.reconcile_stale(limit=100)
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.RETRY.value


@pytest.mark.asyncio
async def test_mark_started_is_idempotent_for_same_broker_task(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-idem-{uuid4().hex[:8]}"
    event_id = f"evt-idem-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.ENQUEUED.value,
                    revision=1,
                    attempt=0,
                    broker_task_id=(broker_task_id := f"task-idem-{uuid4().hex[:8]}"),
                )
            )
    await service.mark_started(intent_id, broker_task_id=broker_task_id)
    again = await service.mark_started(intent_id, broker_task_id=broker_task_id)
    assert again is IntentDeliveryAdmission.ACCEPTED
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.STARTED.value


@pytest.mark.asyncio
async def test_create_pending_intent_never_sets_include_response_execution(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    event_id = f"evt-no-response-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            event = orm.SecurityEvent(
                event_id=event_id,
                event_type="malicious_process",
                title="Suspicious process",
                description="",
                status=EventStatus.NEW.value,
                severity=Severity.HIGH.value,
                final_verdict="none",
                creation_source_ref={"source_product": "mock_xdr"},
                source_reference_snapshots=[],
                disposition_policy="not_required",
                raw_alert_ids=[],
                source_type="mock_xdr",
            )
            session.add(event)
            await session.flush()
            intent_id = await service.maybe_create_pending_in_session(
                session,
                event,
                link_role="primary",
                source_product="mock_xdr",
                created_or_promoted=True,
            )
    assert intent_id is not None
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.include_response_execution is False
        assert row.generate_report is False


@pytest.mark.asyncio
async def test_reconcile_stale_started_event_new_goes_retry(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=5,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-started-{uuid4().hex[:8]}"
    event_id = f"evt-started-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.STARTED.value,
                    revision=1,
                    attempt=0,
                    broker_task_id=f"task-started-{uuid4().hex[:8]}",
                    updated_at=datetime.now(UTC) - timedelta(minutes=15),
                )
            )
    await service.reconcile_stale(limit=100)
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.RETRY.value
        assert row.broker_task_id == deterministic_investigation_task_id(intent_id, 2)


@pytest.mark.asyncio
async def test_reconcile_stale_started_event_triaging_retries_for_resume(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        TASK_MODE="celery",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=5,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-triage-{uuid4().hex[:8]}"
    event_id = f"evt-triage-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.TRIAGING.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.STARTED.value,
                    revision=1,
                    attempt=0,
                    broker_task_id=f"task-triage-{uuid4().hex[:8]}",
                    updated_at=datetime.now(UTC) - timedelta(minutes=15),
                )
            )
    await service.reconcile_stale(limit=100)
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.RETRY.value
        assert row.revision == 2

    published: list[dict[str, object]] = []

    async def _register(_task_id: str, _event_id: str) -> None:
        return None

    monkeypatch.setattr("app.tasks.investigation_tasks.register_task_metadata", _register)
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.publish_investigation_for_intent",
        lambda **kwargs: published.append(kwargs),
    )
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.InvestigationIntent, intent_id, with_for_update=True)
            assert row is not None
            row.status = InvestigationIntentStatus.CLAIMED.value
            row.claim_owner = "intent-dispatcher-1"
            row.claim_expires_at = datetime.now(UTC) + timedelta(seconds=30)
    assert await service._publish_claimed_intent(intent_id) is True
    assert any(
        call["intent_id"] == intent_id and call["resume_from_checkpoint"] is True
        for call in published
    )


@pytest.mark.asyncio
async def test_publish_failure_marks_retry(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from kombu.exceptions import OperationalError

    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=30,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-pubfail-{uuid4().hex[:8]}"
    event_id = f"evt-pubfail-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    claim_owner="test",
                )
            )

    def _boom(**kwargs: object) -> None:
        raise OperationalError("broker unavailable")

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        _noop_register,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        _boom,
    )
    published = await service._publish_claimed_intent(intent_id)
    assert published is False
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.RETRY.value
        assert row.last_error is not None


@pytest.mark.asyncio
async def test_publish_skips_when_event_not_new(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=30,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-skip-{uuid4().hex[:8]}"
    event_id = f"evt-skip-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    claim_owner="test",
                )
            )
    async with session_factory() as session:
        async with session.begin():
            event = await session.get(orm.SecurityEvent, event_id)
            assert event is not None
            event.status = EventStatus.TRIAGING.value

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        _noop_register,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        lambda **_kwargs: None,
    )
    published = await service._publish_claimed_intent(intent_id)
    assert published is False
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.SKIPPED.value
        assert row.skip_reason == "event_not_new"


@pytest.mark.asyncio
async def test_reconcile_stale_enqueued_max_attempts_goes_dead(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=5,
        AUTO_INVESTIGATE_MAX_ATTEMPTS=1,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-dead-enq-{uuid4().hex[:8]}"
    event_id = f"evt-dead-enq-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.ENQUEUED.value,
                    revision=1,
                    attempt=0,
                    broker_task_id=f"task-dead-enq-{uuid4().hex[:8]}",
                    updated_at=datetime.now(UTC) - timedelta(minutes=10),
                )
            )
    await service.reconcile_stale(limit=100)
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.DEAD.value


@pytest.mark.asyncio
async def test_materialize_is_idempotent_when_intent_exists(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client,
) -> None:
    """Provisional rows with an existing intent must not consume materialize batch slots."""
    from app.models.enums import EventType, SourceObjectKind
    from app.models.source import SourceReference
    from app.services.context_service import EventContextStore
    from app.services.degraded_flag_service import DegradedFlagService
    from app.services.event_service import EventService, IngestableSource

    store = EventContextStore(redis_client, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_PROVISIONAL_WINDOW_S=60,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    events = EventService(
        session_factory,
        store,
        degraded_flags=degraded,
        investigation_intent=service,
    )
    ref = SourceReference(
        source_kind=SourceObjectKind.ALERT,
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-mock",
        source_object_id=f"al-mat-idem-{uuid4().hex[:8]}",
        source_updated_at=datetime.now(UTC),
    )
    source = IngestableSource(
        reference=ref,
        title="Suspicious alert",
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.HIGH,
        normalized={"risk_score": 76},
    )
    result = await events.ingest_source_object(source)
    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, result.event_id)
        assert event is not None
        event.created_at = datetime.now(UTC) - timedelta(minutes=10)
        await session.commit()
    first = await service._materialize_provisional_intents(limit=5)
    assert first >= 1
    second = await service._materialize_provisional_intents(limit=5)
    assert second == 0


@pytest.mark.asyncio
async def test_mark_started_accepts_current_revision_task_id(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-rev-{uuid4().hex[:8]}"
    event_id = f"evt-rev-{uuid4().hex[:8]}"
    revision = 3
    current_task = deterministic_investigation_task_id(intent_id, revision)
    stale_task = deterministic_investigation_task_id(intent_id, revision - 1)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.STARTED.value,
                    revision=revision,
                    attempt=1,
                    broker_task_id=stale_task,
                )
            )
    await service.mark_started(intent_id, broker_task_id=current_task)
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.broker_task_id == current_task


def test_beat_schedule_keeps_http_intent_recovery_when_auto_investigate_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import get_settings

    monkeypatch.setenv("AUTO_INVESTIGATE_ENABLED", "false")
    monkeypatch.setenv("TASK_MODE", "celery")
    get_settings.cache_clear()
    from app.core.celery_app import _build_beat_schedule

    schedule = _build_beat_schedule()
    assert "shadowtrace-dispatch-investigation-intents" in schedule
    assert "shadowtrace-reconcile-investigation-intents" in schedule
    get_settings.cache_clear()


def test_beat_schedule_includes_auto_investigate_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import get_settings

    monkeypatch.setenv("AUTO_INVESTIGATE_ENABLED", "true")
    monkeypatch.setenv("TASK_MODE", "celery")
    monkeypatch.setenv("AUTO_INVESTIGATE_DISPATCH_INTERVAL_S", "20")
    monkeypatch.setenv("AUTO_INVESTIGATE_RECONCILE_INTERVAL_S", "90")
    get_settings.cache_clear()
    from app.core.celery_app import _build_beat_schedule

    schedule = _build_beat_schedule()
    assert schedule["shadowtrace-dispatch-investigation-intents"]["schedule"] == 20.0
    assert schedule["shadowtrace-reconcile-investigation-intents"]["schedule"] == 90.0
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_mark_started_returns_stale_for_superseded_enqueued_task(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-stale-enq-{uuid4().hex[:8]}"
    event_id = f"evt-stale-enq-{uuid4().hex[:8]}"
    current_task = "task-current"
    stale_task = "task-stale"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.ENQUEUED.value,
                    revision=1,
                    attempt=0,
                    broker_task_id=current_task,
                )
            )
    admission = await service.mark_started(intent_id, broker_task_id=stale_task)
    assert admission is IntentDeliveryAdmission.STALE_SUPERSEDED
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.ENQUEUED.value
        assert row.broker_task_id == current_task


@pytest.mark.asyncio
async def test_mark_started_returns_stale_for_retry_state_without_dead(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-retry-{uuid4().hex[:8]}"
    event_id = f"evt-retry-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.RETRY.value,
                    revision=2,
                    attempt=1,
                )
            )
    admission = await service.mark_started(intent_id, broker_task_id=f"task-old-{uuid4().hex[:8]}")
    assert admission is IntentDeliveryAdmission.STALE_SUPERSEDED
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.RETRY.value


@pytest.mark.asyncio
async def test_publish_claimed_intent_success(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=30,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-success-{uuid4().hex[:8]}"
    event_id = f"evt-success-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    claim_owner="test",
                )
            )

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        _noop_register,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        lambda **kwargs: None,
    )
    published = await service._publish_claimed_intent(intent_id)
    assert published is True
    expected_task = deterministic_investigation_task_id(intent_id, 1)
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.ENQUEUED.value
        assert row.broker_task_id == expected_task


@pytest.mark.asyncio
async def test_publish_commits_enqueued_before_broker_publish(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=30,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-precommit-{uuid4().hex[:8]}"
    event_id = f"evt-precommit-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    claim_owner="test",
                )
            )

    observed: list[str] = []

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        return None

    real_commit = service._commit_enqueued_publish_target

    async def _tracked_commit(intent_id: str):
        target = await real_commit(intent_id)
        if target is not None:
            observed.append("enqueued")
        return target

    monkeypatch.setattr(service, "_commit_enqueued_publish_target", _tracked_commit)

    def _apply_async(**_kwargs: object) -> None:
        observed.append("publish")
        return None

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        _noop_register,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        _apply_async,
    )
    published = await service._publish_claimed_intent(intent_id)
    assert published is True
    assert observed == ["enqueued", "publish"]


@pytest.mark.asyncio
async def test_reconcile_stale_schedules_dispatch(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        TASK_MODE="celery",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=5,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-dispatch-{uuid4().hex[:8]}"
    event_id = f"evt-dispatch-{uuid4().hex[:8]}"
    broker_task_id = f"task-dispatch-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.ENQUEUED.value,
                    revision=1,
                    attempt=0,
                    broker_task_id=broker_task_id,
                    updated_at=datetime(1970, 1, 1, tzinfo=UTC),
                )
            )
    calls: list[str] = []
    deleted_metadata: list[str] = []

    def _delay() -> None:
        calls.append("dispatch")

    async def _delete_metadata(task_id: str) -> None:
        deleted_metadata.append(task_id)

    monkeypatch.setattr(
        "app.tasks.investigation_intent_tasks.dispatch_pending_investigation_intents.delay",
        _delay,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.delete_task_metadata",
        _delete_metadata,
    )
    assert await service.reconcile_stale(limit=5) >= 1
    assert calls == ["dispatch"]
    assert broker_task_id in deleted_metadata
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status != InvestigationIntentStatus.ENQUEUED.value


@pytest.mark.asyncio
async def test_publish_unexpected_error_marks_dead(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=30,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-unexpected-{uuid4().hex[:8]}"
    event_id = f"evt-unexpected-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    claim_owner="test",
                )
            )

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        return None

    def _boom(**_kwargs: object) -> None:
        raise ValueError("unexpected publish bug")

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        _noop_register,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        _boom,
    )
    published = await service._publish_claimed_intent(intent_id)
    assert published is False
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.DEAD.value


@pytest.mark.asyncio
async def test_skip_active_intents_for_event_in_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    event_id = f"evt-skip-active-{uuid4().hex[:8]}"
    intent_id = f"iin-skip-active-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.PENDING.value,
                    revision=1,
                    attempt=0,
                )
            )
            await session.flush()
            skipped = await service.skip_active_intents_for_event_in_session(
                session,
                event_id,
                reason="event_merged",
            )
            assert skipped == 1
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.SKIPPED.value
        assert row.skip_reason == "event_merged"


def _auto_response_settings(**overrides: object) -> Settings:
    base = {
        "AUTO_INVESTIGATE_ENABLED": True,
        "AUTO_RESPONSE_ENABLED": True,
        "SOURCE_MODE": "mock_xdr",
        "TOOL_MODE": "mock",
        "DISPOSITION_MODE": "mock_xdr",
    }
    base.update(overrides)
    return Settings(**base)


async def _seed_primary_source_link(
    session: AsyncSession,
    *,
    event_id: str,
    connector_id: str = "conn-mock",
) -> str:
    source_record_id = f"src-primary-{uuid4().hex[:8]}"
    if await session.get(orm.SourceConnector, connector_id) is None:
        session.add(
            orm.SourceConnector(
                connector_id=connector_id,
                source_product="mock_xdr",
                display_name="Mock XDR",
            )
        )
    session.add(
        orm.SourceObject(
            source_record_id=source_record_id,
            source_product="mock_xdr",
            source_tenant_id="tenant-demo",
            connector_id=connector_id,
            source_kind=SourceObjectKind.INCIDENT.value,
            source_object_id=f"INC-{uuid4().hex[:8]}",
            next_outbox_sequence=0,
        )
    )
    await session.flush()
    session.add(
        orm.SourceEventLink(
            source_record_id=source_record_id,
            event_id=event_id,
            role=PRIMARY_LINK_ROLE,
        )
    )
    return source_record_id


@pytest.mark.asyncio
async def test_commit_enqueued_sets_include_response_when_policy_matches(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = _auto_response_settings()
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        auto_response_policy=AutoResponsePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-response-{uuid4().hex[:8]}"
    event_id = f"evt-response-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            await _seed_primary_source_link(session, event_id=event_id)
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    include_response_execution=False,
                    claim_owner="test",
                )
            )

    target = await service._commit_enqueued_publish_target(intent_id)
    assert target is not None
    assert target.include_response_execution is True

    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.include_response_execution is True
        audit = (
            await session.scalars(
                select(orm.EventAuditLog).where(
                    orm.EventAuditLog.event_id == event_id,
                    orm.EventAuditLog.operator == "AutoResponsePolicyService",
                )
            )
        ).all()
    assert len(audit) == 1
    assert audit[0].reason == "auto_response:policy_match"


@pytest.mark.asyncio
async def test_commit_enqueued_skips_response_for_provisional_link(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = _auto_response_settings()
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        auto_response_policy=AutoResponsePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-prov-{uuid4().hex[:8]}"
    event_id = f"evt-prov-{uuid4().hex[:8]}"
    source_record_id = f"src-prov-{uuid4().hex[:8]}"
    connector_id = "conn-mock"
    async with session_factory() as session:
        async with session.begin():
            if await session.get(orm.SourceConnector, connector_id) is None:
                session.add(
                    orm.SourceConnector(
                        connector_id=connector_id,
                        source_product="mock_xdr",
                        display_name="Mock XDR",
                    )
                )
            session.add(
                orm.SourceObject(
                    source_record_id=source_record_id,
                    source_product="mock_xdr",
                    source_tenant_id="tenant-demo",
                    connector_id=connector_id,
                    source_kind=SourceObjectKind.INCIDENT.value,
                    source_object_id=f"INC-{uuid4().hex[:8]}",
                    next_outbox_sequence=0,
                )
            )
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.SourceEventLink(
                    source_record_id=source_record_id,
                    event_id=event_id,
                    role=PROVISIONAL_LINK_ROLE,
                )
            )
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    include_response_execution=False,
                    claim_owner="test",
                )
            )

    target = await service._commit_enqueued_publish_target(intent_id)
    assert target is not None
    assert target.include_response_execution is False

    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.include_response_execution is False


@pytest.mark.asyncio
async def test_publish_forwards_include_response_execution_flag(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _auto_response_settings()
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        auto_response_policy=AutoResponsePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-publish-{uuid4().hex[:8]}"
    event_id = f"evt-publish-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            await _seed_primary_source_link(session, event_id=event_id)
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    include_response_execution=False,
                    claim_owner="test",
                )
            )

    captured: dict[str, object] = {}

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        return None

    def _apply_async(**kwargs: object) -> None:
        captured["kwargs"] = kwargs.get("kwargs")

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        _noop_register,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        _apply_async,
    )

    published = await service._publish_claimed_intent(intent_id)
    assert published is True
    assert captured["kwargs"] == {
        "include_response_execution": True,
        "generate_report": True,
        "intent_id": intent_id,
    }


@pytest.mark.asyncio
async def test_auto_response_broker_failure_sets_degraded_flag(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EventContextStore(redis_client, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    settings = _auto_response_settings()
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        auto_response_policy=AutoResponsePolicyService(settings),
        degraded_flags=degraded,
        settings=settings,
    )
    intent_id = f"iin-degraded-{uuid4().hex[:8]}"
    event_id = f"evt-degraded-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            await _seed_primary_source_link(session, event_id=event_id)
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    include_response_execution=False,
                    claim_owner="test",
                    claim_expires_at=datetime.now(UTC) + timedelta(minutes=5),
                )
            )

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        return None

    def _boom(**_kwargs: object) -> None:
        raise ConnectionError("broker down")

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        _noop_register,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        _boom,
    )

    published = await service._publish_claimed_intent(intent_id)
    assert published is False

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
    assert event is not None
    assert any(
        flag.startswith("auto_response_dispatch_unavailable=") for flag in event.degraded_flags
    )


@pytest.mark.asyncio
async def test_commit_enqueued_skips_response_without_source_link(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = _auto_response_settings()
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        auto_response_policy=AutoResponsePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-nolink-{uuid4().hex[:8]}"
    event_id = f"evt-nolink-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    include_response_execution=False,
                    claim_owner="test",
                )
            )

    target = await service._commit_enqueued_publish_target(intent_id)
    assert target is not None
    assert target.include_response_execution is False

    async with session_factory() as session:
        audit = (
            await session.scalars(
                select(orm.EventAuditLog).where(
                    orm.EventAuditLog.event_id == event_id,
                    orm.EventAuditLog.operator == "AutoResponsePolicyService",
                )
            )
        ).all()
    assert len(audit) == 1
    assert audit[0].reason == "auto_response:skipped_link_role_not_primary"


@pytest.mark.asyncio
async def test_commit_enqueued_audit_logs_policy_skip_reason(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = _auto_response_settings(AUTO_RESPONSE_MIN_SEVERITY="critical")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        auto_response_policy=AutoResponsePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-skip-{uuid4().hex[:8]}"
    event_id = f"evt-skip-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            await _seed_primary_source_link(session, event_id=event_id)
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    include_response_execution=False,
                    claim_owner="test",
                )
            )

    target = await service._commit_enqueued_publish_target(intent_id)
    assert target is not None
    assert target.include_response_execution is False

    async with session_factory() as session:
        audit = (
            await session.scalars(
                select(orm.EventAuditLog).where(
                    orm.EventAuditLog.event_id == event_id,
                    orm.EventAuditLog.operator == "AutoResponsePolicyService",
                )
            )
        ).all()
    assert len(audit) == 1
    assert audit[0].reason == "auto_response:skipped_below_min_severity"


@pytest.mark.asyncio
async def test_auto_response_unexpected_publish_failure_sets_degraded_flag(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EventContextStore(redis_client, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    settings = _auto_response_settings()
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        auto_response_policy=AutoResponsePolicyService(settings),
        degraded_flags=degraded,
        settings=settings,
    )
    intent_id = f"iin-unexpected-{uuid4().hex[:8]}"
    event_id = f"evt-unexpected-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            await _seed_primary_source_link(session, event_id=event_id)
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    include_response_execution=False,
                    claim_owner="test",
                    claim_expires_at=datetime.now(UTC) + timedelta(minutes=5),
                )
            )

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        return None

    def _boom(**_kwargs: object) -> None:
        raise RuntimeError("unexpected publish failure")

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        _noop_register,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        _boom,
    )

    published = await service._publish_claimed_intent(intent_id)
    assert published is False

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        row = await session.get(orm.InvestigationIntent, intent_id)
    assert event is not None
    assert row is not None
    assert row.status == InvestigationIntentStatus.DEAD.value
    assert any(
        flag.startswith("auto_response_dispatch_unavailable=") for flag in event.degraded_flags
    )


@pytest.mark.asyncio
async def test_schedule_dispatch_enqueue_failure_is_observable_and_non_fatal(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from unittest.mock import AsyncMock

    from app.core.metrics import (
        dispatch_schedule_health_snapshot,
        investigation_intent_enqueue_health_snapshot,
        reset_dispatch_schedule_metrics_for_tests,
        reset_investigation_intent_enqueue_metrics_for_tests,
    )

    reset_investigation_intent_enqueue_metrics_for_tests()
    reset_dispatch_schedule_metrics_for_tests()
    degraded = MagicMock()
    degraded.set_flag = AsyncMock(return_value=["auto_investigate_dispatch_unavailable=true"])
    service = InvestigationIntentService(
        MagicMock(),
        settings=Settings(TASK_MODE="celery"),
        degraded_flags=degraded,
    )

    def _broker_down() -> None:
        raise ConnectionError("amqp://user:secret@broker:5672/vhost is down")

    monkeypatch.setattr(
        "app.tasks.investigation_intent_tasks.dispatch_pending_investigation_intents.delay",
        _broker_down,
    )

    intent_logger = logging.getLogger("app.services.investigation_intent_service")
    intent_logger.disabled = False
    intent_logger.propagate = True
    with caplog.at_level(
        logging.ERROR,
        logger="app.services.investigation_intent_service",
    ):
        await service.schedule_dispatch_async(
            event_id="evt-enqueue-fail",
            intent_id="iin-enqueue-fail",
            trigger="test",
        )

    snapshot = investigation_intent_enqueue_health_snapshot()
    assert snapshot["enqueue_failure"] == 1
    assert snapshot["enqueue_success"] == 0
    assert (
        dispatch_schedule_health_snapshot().get("investigation_intent:dispatch_enqueue_failed") == 1
    )
    degraded.set_flag.assert_awaited_once_with(
        "evt-enqueue-fail",
        "auto_investigate_dispatch_unavailable",
        True,
        writer="InvestigationIntentService",
    )
    failure_messages = [
        record.getMessage()
        for record in caplog.records
        if "investigation intent dispatch enqueue failed" in record.getMessage()
    ]
    assert failure_messages
    assert "ConnectionError" in failure_messages[0]
    assert "secret" not in failure_messages[0]
    assert "amqp://" not in failure_messages[0]


@pytest.mark.asyncio
async def test_schedule_dispatch_enqueue_failure_pending_recoverable_via_sync_batch(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        TASK_MODE="celery",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=30,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-recover-{uuid4().hex[:8]}"
    event_id = f"evt-recover-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Recover after enqueue failure",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.PENDING.value,
                    revision=1,
                    attempt=0,
                    include_response_execution=False,
                    generate_report=False,
                )
            )

    def _broker_down() -> None:
        raise ConnectionError("broker down")

    monkeypatch.setattr(
        "app.tasks.investigation_intent_tasks.dispatch_pending_investigation_intents.delay",
        _broker_down,
    )
    service.schedule_dispatch(event_id=event_id, intent_id=intent_id, trigger="test")

    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.PENDING.value

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.InvestigationIntent, intent_id, with_for_update=True)
            assert row is not None
            row.status = InvestigationIntentStatus.CLAIMED.value
            row.claim_owner = "intent-dispatcher-1"
            row.claim_expires_at = datetime.now(UTC) + timedelta(seconds=30)

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        return None

    def _noop_publish(**_kwargs: object) -> None:
        return None

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        _noop_register,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        _noop_publish,
    )

    async def _claim_only_test_intent(*, limit: int = 10) -> list[str]:
        del limit
        return [intent_id]

    monkeypatch.setattr(service, "_claim_batch", _claim_only_test_intent)
    result = await service.dispatch_sync_batch(limit=5)
    assert result["published"] == 1
    assert result["claimed"] == 1

    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.ENQUEUED.value


@pytest.mark.asyncio
async def test_pending_dispatch_stats_reports_oldest_age(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    service = InvestigationIntentService(
        session_factory,
        settings=Settings(TASK_MODE="celery"),
    )
    before = await service.pending_dispatch_stats()
    intent_id = f"iin-pending-age-{uuid4().hex[:8]}"
    event_id = f"evt-pending-age-{uuid4().hex[:8]}"
    created_at = datetime.now(UTC) - timedelta(minutes=5)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Pending age probe",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.PENDING.value,
                    revision=1,
                    attempt=0,
                    include_response_execution=False,
                    generate_report=False,
                    created_at=created_at,
                )
            )

    stats = await service.pending_dispatch_stats()
    assert stats["pending_count"] == before["pending_count"] + 1
    assert stats["oldest_pending_age_s"] is not None
    if before["oldest_pending_age_s"] is None:
        assert float(stats["oldest_pending_age_s"]) >= 290.0
    else:
        assert float(stats["oldest_pending_age_s"]) >= min(
            float(before["oldest_pending_age_s"]),
            290.0,
        )


@pytest.mark.asyncio
async def test_schedule_dispatch_soft_time_limit_fallback_publishes_when_broker_down(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-324: one in-process fallback after SoftTimeLimit RECOVERED enqueue failure."""
    from app.core.metrics import (
        dispatch_schedule_health_snapshot,
        reset_dispatch_schedule_metrics_for_tests,
    )

    reset_dispatch_schedule_metrics_for_tests()
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        TASK_MODE="celery",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=30,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-stl-fallback-{uuid4().hex[:8]}"
    event_id = f"evt-stl-fallback-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="SoftTimeLimit fallback",
                    description="",
                    status=EventStatus.ANALYZING.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.RETRY.value,
                    revision=2,
                    attempt=1,
                    include_response_execution=False,
                    generate_report=False,
                )
            )

    def _broker_down() -> None:
        raise ConnectionError("broker down")

    monkeypatch.setattr(
        "app.tasks.investigation_intent_tasks.dispatch_pending_investigation_intents.delay",
        _broker_down,
    )

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        return None

    def _noop_publish(**_kwargs: object) -> None:
        return None

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        _noop_register,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        _noop_publish,
    )

    await service.schedule_dispatch_async(
        event_id=event_id,
        intent_id=intent_id,
        trigger="soft_time_limit_recovered",
    )

    snapshot = dispatch_schedule_health_snapshot()
    assert snapshot.get("investigation_intent:dispatch_enqueue_failed") == 1
    assert snapshot.get("investigation_intent:dispatch_fallback_started") == 1

    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.ENQUEUED.value


@pytest.mark.asyncio
async def test_schedule_dispatch_fallback_binds_target_intent_not_older_backlog(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-324: SoftTimeLimit fallback must publish the recovered intent, not older backlog."""
    from app.core.metrics import (
        dispatch_schedule_health_snapshot,
        reset_dispatch_schedule_metrics_for_tests,
    )

    reset_dispatch_schedule_metrics_for_tests()
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        TASK_MODE="celery",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=30,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    older_intent_id = f"iin-older-{uuid4().hex[:8]}"
    target_intent_id = f"iin-target-{uuid4().hex[:8]}"
    older_event_id = f"evt-older-{uuid4().hex[:8]}"
    target_event_id = f"evt-target-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            for event_id, title in (
                (older_event_id, "older backlog"),
                (target_event_id, "target recovered"),
            ):
                session.add(
                    orm.SecurityEvent(
                        event_id=event_id,
                        event_type="malicious_process",
                        title=title,
                        description="",
                        status=EventStatus.ANALYZING.value,
                        severity=Severity.HIGH.value,
                        final_verdict="none",
                        creation_source_ref={"source_product": "mock_xdr"},
                        source_reference_snapshots=[],
                        disposition_policy="not_required",
                        raw_alert_ids=[],
                        source_type="mock_xdr",
                    )
                )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=older_intent_id,
                    event_id=older_event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.PENDING.value,
                    revision=1,
                    attempt=0,
                    include_response_execution=False,
                    generate_report=False,
                )
            )
            session.add(
                orm.InvestigationIntent(
                    intent_id=target_intent_id,
                    event_id=target_event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.RETRY.value,
                    revision=2,
                    attempt=1,
                    include_response_execution=False,
                    generate_report=False,
                )
            )

    def _broker_down() -> None:
        raise ConnectionError("broker down")

    monkeypatch.setattr(
        "app.tasks.investigation_intent_tasks.dispatch_pending_investigation_intents.delay",
        _broker_down,
    )

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        return None

    def _noop_publish(**_kwargs: object) -> None:
        return None

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        _noop_register,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        _noop_publish,
    )

    await service.schedule_dispatch_async(
        event_id=target_event_id,
        intent_id=target_intent_id,
        trigger="soft_time_limit_recovered",
    )

    snapshot = dispatch_schedule_health_snapshot()
    assert snapshot.get("investigation_intent:dispatch_fallback_started") == 1
    async with session_factory() as session:
        older = await session.get(orm.InvestigationIntent, older_intent_id)
        target = await session.get(orm.InvestigationIntent, target_intent_id)
        assert older is not None and target is not None
        assert older.status == InvestigationIntentStatus.PENDING.value
        assert target.status == InvestigationIntentStatus.ENQUEUED.value


@pytest.mark.asyncio
async def test_schedule_dispatch_fallback_skipped_for_unknown_outbox(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.metrics import (
        dispatch_schedule_health_snapshot,
        reset_dispatch_schedule_metrics_for_tests,
    )
    from app.models.enums import (
        ActionCategory,
        ActionExecutionPhase,
        ActionLevel,
        ActionStatus,
        ExecutionOwner,
        OutboxDeliveryStatus,
        WritebackReadiness,
        WritebackStatus,
    )

    reset_dispatch_schedule_metrics_for_tests()
    settings = Settings(TASK_MODE="celery")
    service = InvestigationIntentService(session_factory, settings=settings)
    intent_id = f"iin-unknown-wb-{uuid4().hex[:8]}"
    event_id = f"evt-unknown-wb-{uuid4().hex[:8]}"
    action_id = f"act-unknown-wb-{uuid4().hex[:8]}"
    source_record_id = f"src-unknown-wb-{uuid4().hex[:8]}"
    connector_id = f"conn-unknown-wb-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="unknown outbox blocks fallback",
                    description="",
                    status=EventStatus.ANALYZING.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            session.add(
                orm.SourceConnector(
                    connector_id=connector_id,
                    source_product="mock_xdr",
                    display_name="unknown-outbox connector",
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
                    writeback_status=WritebackStatus.UNKNOWN.value,
                )
            )
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.RETRY.value,
                    revision=2,
                    attempt=1,
                    include_response_execution=False,
                    generate_report=False,
                )
            )
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-{uuid4().hex[:8]}",
                    writeback_id=f"wb-{uuid4().hex[:8]}",
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
                    delivery_status=OutboxDeliveryStatus.READY.value,
                    latest_writeback_status=WritebackStatus.UNKNOWN.value,
                )
            )

    def _broker_down() -> None:
        raise ConnectionError("broker down")

    monkeypatch.setattr(
        "app.tasks.investigation_intent_tasks.dispatch_pending_investigation_intents.delay",
        _broker_down,
    )
    await service.schedule_dispatch_async(
        event_id=event_id,
        intent_id=intent_id,
        trigger="soft_time_limit_recovered",
    )
    snapshot = dispatch_schedule_health_snapshot()
    assert snapshot.get("investigation_intent:dispatch_enqueue_failed") == 1
    assert snapshot.get("investigation_intent:dispatch_fallback_started", 0) == 0
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.RETRY.value


@pytest.mark.asyncio
async def test_schedule_dispatch_fallback_skipped_for_response_execution(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.metrics import (
        dispatch_schedule_health_snapshot,
        reset_dispatch_schedule_metrics_for_tests,
    )

    reset_dispatch_schedule_metrics_for_tests()
    settings = Settings(TASK_MODE="celery")
    service = InvestigationIntentService(session_factory, settings=settings)
    intent_id = f"iin-no-fallback-{uuid4().hex[:8]}"
    event_id = f"evt-no-fallback-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="No fallback",
                    description="",
                    status=EventStatus.ANALYZING.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.RETRY.value,
                    revision=2,
                    attempt=1,
                    include_response_execution=True,
                    generate_report=False,
                )
            )

    def _broker_down() -> None:
        raise ConnectionError("broker down")

    monkeypatch.setattr(
        "app.tasks.investigation_intent_tasks.dispatch_pending_investigation_intents.delay",
        _broker_down,
    )
    await service.schedule_dispatch_async(
        event_id=event_id,
        intent_id=intent_id,
        trigger="soft_time_limit_recovered",
    )

    snapshot = dispatch_schedule_health_snapshot()
    assert snapshot.get("investigation_intent:dispatch_enqueue_failed") == 1
    assert snapshot.get("investigation_intent:dispatch_fallback_started", 0) == 0

    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.RETRY.value
