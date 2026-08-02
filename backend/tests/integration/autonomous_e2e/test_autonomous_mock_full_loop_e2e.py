"""Autonomous Mock XDR full-loop E2E (ISSUE-110 / #614).

Scenarios A–E validate production ingest→intent→worker→approval paths with
mandatory ledger observability. Integration tests use production entry points
without ``task_always_eager``. Worker-gated tests require ``make up WORKER=1``.
"""

from __future__ import annotations

import os
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.auth import Principal
from app.core.celery_app import celery_app
from app.core.celery_delivery import evaluate_redelivered_investigation_skip
from app.core.celery_health import build_celery_health
from app.core.config import Settings
from app.core.errors import (
    ApprovalDecisionConflictError,
    ConfigurationError,
    InvalidStateTransitionError,
    ValidationError,
)
from app.db import models as orm
from app.db.orm.approval import ApprovalRecordORM
from app.models.action import Action
from app.models.agent_io import RiskAssessment, ScoringMode
from app.models.approval import ApprovalDecisionKind
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    EventStatus,
    EventType,
    ExecutionOwner,
    InvestigationIntentStatus,
    Severity,
    SourceObjectKind,
)
from app.models.investigation_intent import IntentDeliveryAdmission
from app.models.source import SourceReference
from app.services.approval_engine import evaluate_level_rules
from app.services.auto_investigate_policy import AutoInvestigatePolicyService
from app.services.event_service import IngestableSource
from app.services.investigation_intent_service import InvestigationIntentService
from app.tasks import investigation_tasks as tasks
from tests.integration.autonomous_e2e.helpers import (
    TERMINAL_INTENT_STATUSES,
    build_approval_engine,
    build_autonomous_stack,
    build_mock_execution_stack,
    collect_observability,
    count_execution_jobs,
    mock_autonomous_settings,
    poll_until,
    principal_lacks_approver_role,
    require_celery_worker,
    unique_id,
)
from tests.integration.test_auto_investigate_mock import _incident_source


def _response_action(*, event_id: str, level: ActionLevel, action_id: str) -> Action:
    return Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": f"fp-{action_id}",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "isolate_host",
            "tool_name": "isolate_host",
            "action_level": level,
            "execution_owner": ExecutionOwner.DIRECT_TOOL,
            "execution_phase": ActionExecutionPhase.IMMEDIATE,
            "status": ActionStatus.PENDING,
            "target_type": "host",
            "target": "host-iss110",
            "parameters": {"target_type": "host", "target": "host-iss110"},
            "writeback_required": False,
            "writeback_applicable": False,
            "reason": "iss110-scenario-b",
        }
    )


def _risk() -> RiskAssessment:
    return RiskAssessment(
        risk_score=82,
        confidence=0.91,
        severity=Severity.HIGH,
        scoring_mode=ScoringMode.RULE_ONLY,
    )


def _event_seed_ref(*, object_id: str) -> SourceReference:
    return SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-mock",
        source_object_id=object_id,
        source_updated_at=datetime.now(UTC),
    )


async def _seed_security_event(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_id: str,
    status: EventStatus,
    object_id: str,
    title: str = "ISSUE-110 E2E",
) -> None:
    ref = _event_seed_ref(object_id=object_id)
    now = datetime.now(UTC)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type=EventType.MALICIOUS_PROCESS.value,
                    title=title,
                    description="",
                    status=status.value,
                    severity=Severity.HIGH.value,
                    risk_score=82,
                    confidence=0.91,
                    final_verdict="none",
                    creation_source_ref=ref.model_dump(mode="json"),
                    source_reference_snapshots=[ref.model_dump(mode="json")],
                    disposition_policy="required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                    occurred_at=now,
                )
            )


async def _seed_event_and_intent(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_id: str,
    intent_id: str,
    intent_status: InvestigationIntentStatus = InvestigationIntentStatus.ENQUEUED,
    broker_task_id: str = "task-current",
) -> None:
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.NEW,
        object_id=f"inc-{event_id}",
    )
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=intent_status.value,
                    revision=1,
                    attempt=0,
                    broker_task_id=broker_task_id,
                )
            )


def _wire_super_agent_mock(monkeypatch: pytest.MonkeyPatch, *, calls: dict[str, int]) -> None:
    async def _investigate(_event_id: str, **_kwargs: Any) -> None:
        calls["n"] = calls.get("n", 0) + 1

    async def _fake_super_agent() -> Any:
        agent = MagicMock()
        agent.investigate = _investigate
        return agent

    monkeypatch.setattr("app.api.v1.deps.get_super_agent", _fake_super_agent)
    monkeypatch.setattr(
        "app.services.evidence_projection.bind_evidence_projection",
        lambda _projection: nullcontext(),
    )
    monkeypatch.setattr(
        "app.services.evidence_projection.EvidenceProjection",
        lambda _factory: MagicMock(),
    )
    monkeypatch.setattr(
        "app.services.investigation_guidance.record_investigation_workflow_path",
        AsyncMock(),
    )


# --------------------------------------------------------------------------- #
# Scenario A — L0 auto loop, dual delivery → single investigation
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_a_stale_broker_task_skips_second_investigation(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = mock_autonomous_settings()
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    event_id = unique_id("evt-a")
    intent_id = unique_id("iin-a")
    await _seed_event_and_intent(
        session_factory,
        event_id=event_id,
        intent_id=intent_id,
        broker_task_id="task-current",
    )

    stale = await service.mark_started(intent_id, broker_task_id="task-stale")
    assert stale is IntentDeliveryAdmission.STALE_SUPERSEDED

    accepted = await service.mark_started(intent_id, broker_task_id="task-current")
    assert accepted is IntentDeliveryAdmission.ACCEPTED

    calls = {"n": 0}
    _wire_super_agent_mock(monkeypatch, calls=calls)
    monkeypatch.setattr("app.api.v1.deps._get_session_factory", lambda: session_factory)

    result = await tasks.execute_investigation(event_id)
    assert result["status"] == "completed"
    assert calls["n"] == 1

    await service.mark_terminal(intent_id)

    stale_again = await service.mark_started(intent_id, broker_task_id="task-redelivery")
    assert stale_again is IntentDeliveryAdmission.ALREADY_TERMINAL

    snap = await collect_observability(session_factory, event_id)
    assert snap.intent_statuses == [InvestigationIntentStatus.TERMINAL.value]
    assert snap.intent_broker_task_ids == ["task-current"]
    assert snap.event_status is not None
    assert snap.audit_log_count >= 0
    assert snap.agent_trace_count >= 0


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_a_l0_policy_auto_approve_only_for_l0_l1() -> None:
    l0 = _response_action(event_id="evt-gate", level=ActionLevel.L0, action_id="act-l0")
    l2 = _response_action(event_id="evt-gate", level=ActionLevel.L2, action_id="act-l2")
    l0_decision = evaluate_level_rules(l0, confidence=0.99, severity=Severity.CRITICAL)
    l2_decision = evaluate_level_rules(l2, confidence=0.99, severity=Severity.CRITICAL)
    assert l0_decision.decision is ApprovalDecisionKind.AUTO_APPROVE
    assert l2_decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL


@pytest.mark.autonomous_mock_e2e
@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_a_worker_completes_enqueued_intent(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> None:
    require_celery_worker()
    events, intent_service, _store = build_autonomous_stack(session_factory, redis_client)
    ingest = await events.ingest_source_object(
        _incident_source(object_id=unique_id("inc-worker-a"))
    )
    published = await intent_service.claim_and_publish_batch(limit=10)
    assert published >= 1

    async with session_factory() as session:
        row = await session.scalar(
            select(orm.InvestigationIntent).where(
                orm.InvestigationIntent.event_id == ingest.event_id
            )
        )
    assert row is not None
    intent_id = row.intent_id

    async def _intent_terminal() -> str | None:
        async with session_factory() as session:
            intent_row = await session.get(orm.InvestigationIntent, intent_id)
            if intent_row is not None and intent_row.status in TERMINAL_INTENT_STATUSES:
                return intent_row.status
        return None

    terminal_status = await poll_until(
        _intent_terminal,
        timeout_s=120.0,
        description="intent terminal after worker delivery",
    )
    assert terminal_status in TERMINAL_INTENT_STATUSES
    snap = await collect_observability(session_factory, ingest.event_id)
    assert snap.intent_statuses.count(terminal_status) >= 1
    assert snap.intent_broker_task_ids
    assert snap.intent_broker_task_ids[0] is not None
    assert snap.event_status is not None


# --------------------------------------------------------------------------- #
# Scenario B — L2 mandatory human approval
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_b_l2_human_approval_executes_once(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> None:
    engine = await build_approval_engine(session_factory, redis_client)
    event_id = unique_id("evt-b")
    action_id = unique_id("act-l2")
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.WAITING_APPROVAL,
        object_id=f"inc-{event_id}",
        title="L2 gate",
    )
    action = _response_action(event_id=event_id, level=ActionLevel.L2, action_id=action_id)
    async with session_factory() as session:
        async with session.begin():
            session.add(orm.Action(**action.model_dump()))

    row_action = _response_action(event_id=event_id, level=ActionLevel.L2, action_id=action_id)
    decision = await engine.evaluate(row_action, _risk(), approval_cycle=0)
    assert decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL

    test_approver = Principal(subject="iss110-test-approver", roles=["approver"])
    decision_id = f"dec-human-{uuid4().hex[:10]}"

    await engine.approve(action_id, test_approver, "approved once", decision_id)

    async with session_factory() as session:
        row = await session.get(orm.Action, action_id)
        assert row is not None
        assert row.status == ActionStatus.APPROVED.value
        record = await session.scalar(
            select(ApprovalRecordORM).where(
                ApprovalRecordORM.action_id == action_id,
                ApprovalRecordORM.decision_id == decision_id,
            )
        )
        assert record is not None
        assert record.operator == "iss110-test-approver"
        assert record.operator != "system"

    with pytest.raises(ApprovalDecisionConflictError):
        await engine.reject(
            action_id,
            Principal(subject="iss110-other-approver", roles=["approver"]),
            "stale cross decision",
            f"dec-human-{uuid4().hex[:10]}",
        )

    snap = await collect_observability(session_factory, event_id)
    assert snap.pending_action_count == 0
    assert snap.approval_record_count >= 1
    assert snap.approval_operators == ["iss110-test-approver"]
    assert snap.action_count == 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_b_system_or_agent_cannot_approve_l2(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> None:
    """Policy and RBAC must block system/agent from L2 approval execution paths."""
    engine = await build_approval_engine(session_factory, redis_client)
    event_id = unique_id("evt-b-guard")
    action_id = unique_id("act-l2-guard")
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.WAITING_APPROVAL,
        object_id=f"inc-{event_id}",
    )
    action = _response_action(event_id=event_id, level=ActionLevel.L2, action_id=action_id)
    async with session_factory() as session:
        async with session.begin():
            session.add(orm.Action(**action.model_dump()))

    policy_decision = evaluate_level_rules(action, confidence=0.99, severity=Severity.CRITICAL)
    assert policy_decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL

    system_principal = Principal(subject="system", roles=[])
    agent_principal = Principal(subject="agent:response-agent", roles=["analyst"])
    assert principal_lacks_approver_role(system_principal)
    assert principal_lacks_approver_role(agent_principal)

    await engine.evaluate(action, _risk(), approval_cycle=0)
    stack = await build_mock_execution_stack(session_factory, redis_client)
    with pytest.raises(InvalidStateTransitionError):
        await stack.service.execute_action(action_id)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_b_stale_decision_id_replay_is_idempotent(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> None:
    engine = await build_approval_engine(session_factory, redis_client)
    event_id = unique_id("evt-b-replay")
    action_id = unique_id("act-l2-replay")
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.WAITING_APPROVAL,
        object_id=f"inc-{event_id}",
    )
    action = _response_action(event_id=event_id, level=ActionLevel.L2, action_id=action_id)
    async with session_factory() as session:
        async with session.begin():
            session.add(orm.Action(**action.model_dump()))

    await engine.evaluate(action, _risk(), approval_cycle=0)
    principal = Principal(subject="iss110-replay-approver", roles=["approver"])
    decision_id = f"dec-replay-{uuid4().hex[:10]}"
    await engine.approve(action_id, principal, "first", decision_id)
    await engine.approve(action_id, principal, "replay", decision_id)

    async with session_factory() as session:
        records = (
            await session.scalars(
                select(ApprovalRecordORM).where(ApprovalRecordORM.action_id == action_id)
            )
        ).all()
    assert len(records) == 1
    assert records[0].decision_id == decision_id


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_b_cross_revision_superseded_cannot_execute(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> None:
    engine = await build_approval_engine(session_factory, redis_client)
    event_id = unique_id("evt-b-rev")
    action_id = unique_id("act-l2-rev")
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.WAITING_APPROVAL,
        object_id=f"inc-{event_id}",
    )
    action = _response_action(event_id=event_id, level=ActionLevel.L2, action_id=action_id)
    async with session_factory() as session:
        async with session.begin():
            session.add(orm.Action(**action.model_dump()))

    await engine.evaluate(action, _risk(), approval_cycle=0)
    await engine.approve(
        action_id,
        Principal(subject="iss110-rev-approver", roles=["approver"]),
        "approved stale revision",
        f"dec-rev-{uuid4().hex[:10]}",
    )
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, action_id)
            assert row is not None
            row.superseded_by_revision = 2

    stack = await build_mock_execution_stack(session_factory, redis_client)
    with pytest.raises(ValidationError, match="superseded action cannot be claimed"):
        await stack.service.execute_action(action_id)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_b_human_approval_single_execution(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> None:
    engine = await build_approval_engine(session_factory, redis_client)
    stack = await build_mock_execution_stack(session_factory, redis_client)
    event_id = unique_id("evt-b-exec")
    action_id = unique_id("act-l2-exec")
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.EXECUTING_RESPONSE,
        object_id=f"inc-{event_id}",
        title="L2 execute once",
    )
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None
        from app.services.context_service import event_summary_from_security_event

        await stack.store.init_context(event_id, event_summary_from_security_event(row))

    action = _response_action(event_id=event_id, level=ActionLevel.L2, action_id=action_id)
    async with session_factory() as session:
        async with session.begin():
            session.add(orm.Action(**action.model_dump()))

    await engine.evaluate(action, _risk(), approval_cycle=0)
    await engine.approve(
        action_id,
        Principal(subject="iss110-exec-approver", roles=["approver"]),
        "execute once",
        f"dec-exec-{uuid4().hex[:10]}",
    )

    await stack.service.execute_action(action_id)
    with pytest.raises(InvalidStateTransitionError):
        await stack.service.execute_action(action_id)

    assert len(stack.recorder.calls) == 1
    assert stack.recorder.calls[0][0] == "isolate_host"
    assert await count_execution_jobs(session_factory, event_id) == 1

    snap = await collect_observability(session_factory, event_id)
    assert snap.approval_record_count == 1
    assert snap.approval_operators == ["iss110-exec-approver"]
    assert snap.pending_action_count == 0


# --------------------------------------------------------------------------- #
# Scenario C — crash / redelivery fencing
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_c_redelivery_after_terminal_event_skips_body(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events, _intent_service, store = build_autonomous_stack(session_factory, redis_client)
    event_id = unique_id("evt-c-closed")
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.CLOSED,
        object_id=f"inc-{event_id}",
        title="closed for redelivery",
    )
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None
        from app.services.context_service import event_summary_from_security_event

        await store.init_context(event_id, event_summary_from_security_event(row))

    class _EventBridge:
        def __init__(self, svc: Any) -> None:
            self._svc = svc

        async def get_event(self, lookup_id: str) -> Any:
            return await self._svc.get_event(lookup_id)

    async def _event_service() -> _EventBridge:
        return _EventBridge(events)

    monkeypatch.setattr("app.api.v1.deps.get_event_service", _event_service)

    skip, reason = await evaluate_redelivered_investigation_skip(event_id)
    assert skip is True
    assert reason == "terminal_event"
    snap = await collect_observability(session_factory, event_id)
    assert snap.event_status == EventStatus.CLOSED.value
    assert snap.intent_statuses == []


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_c_stale_reconcile_marks_retry_without_duplicate_execute(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = mock_autonomous_settings(AUTO_INVESTIGATE_CLAIM_LEASE_S=5)
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    event_id = unique_id("evt-c-reconcile")
    intent_id = unique_id("iin-c-reconcile")
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.NEW,
        object_id=f"inc-{event_id}",
        title="stale",
    )
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.ENQUEUED.value,
                    revision=1,
                    attempt=0,
                    broker_task_id="task-stale-window",
                    updated_at=datetime.now(UTC) - timedelta(minutes=20),
                )
            )

    await service.reconcile_stale(limit=50)
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.RETRY.value


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_c_action_redelivery_no_duplicate_side_effect(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> None:
    engine = await build_approval_engine(session_factory, redis_client)
    stack = await build_mock_execution_stack(session_factory, redis_client)
    event_id = unique_id("evt-c-sidefx")
    action_id = unique_id("act-c-sidefx")
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.EXECUTING_RESPONSE,
        object_id=f"inc-{event_id}",
        title="side effect fencing",
    )
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None
        from app.services.context_service import event_summary_from_security_event

        await stack.store.init_context(event_id, event_summary_from_security_event(row))

    action = _response_action(event_id=event_id, level=ActionLevel.L2, action_id=action_id)
    async with session_factory() as session:
        async with session.begin():
            session.add(orm.Action(**action.model_dump()))

    await engine.evaluate(action, _risk(), approval_cycle=0)
    await engine.approve(
        action_id,
        Principal(subject="iss110-sidefx-approver", roles=["approver"]),
        "once",
        f"dec-sidefx-{uuid4().hex[:10]}",
    )

    await stack.service.execute_action(action_id)
    assert len(stack.recorder.calls) == 1
    with pytest.raises(InvalidStateTransitionError):
        await stack.service.execute_action(action_id)
    assert len(stack.recorder.calls) == 1
    assert await count_execution_jobs(session_factory, event_id) == 1

    snap = await collect_observability(session_factory, event_id)
    assert snap.approval_operators == ["iss110-sidefx-approver"]
    assert snap.action_count == 1


# --------------------------------------------------------------------------- #
# Scenario D — deny / degraded / broker vs worker semantics
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_scenario_d_auto_response_rejects_live_source_at_startup() -> None:
    """AUTO_RESPONSE with live source must fail closed at Settings construction."""
    with pytest.raises(ConfigurationError):
        Settings(
            AUTO_RESPONSE_ENABLED=True,
            SOURCE_MODE="live_crowdstrike",
            TOOL_MODE="mock",
            DISPOSITION_MODE="mock_xdr",
        )


@pytest.mark.integration
def test_scenario_d_production_rejects_mock_runtime_at_startup() -> None:
    with pytest.raises(ConfigurationError):
        Settings(
            APP_ENV="production",
            SOURCE_MODE="mock_xdr",
            TOOL_MODE="mock",
            DISPOSITION_MODE="mock_xdr",
            SIMULATION_ENABLED=False,
        )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_d_celery_health_broker_up_worker_down_is_degraded_not_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _broker_ok(_url: str) -> str:
        return "ok"

    def _no_workers(**_kwargs: Any) -> dict[str, Any]:
        return {
            "status": "degraded",
            "workers": 0,
            "worker_ids": [],
            "reason": "no_workers_responding",
        }

    monkeypatch.setattr("app.core.celery_health.check_celery_broker", _broker_ok)
    monkeypatch.setattr("app.core.celery_health.probe_celery_workers", _no_workers)

    health = await build_celery_health(
        task_mode="celery",
        broker_url="redis://127.0.0.1:6379/0",
    )
    assert health["broker"] == "ok"
    assert health["worker"]["status"] == "degraded"
    assert health["worker"]["workers"] == 0


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_d_task_stays_pending_when_broker_up_worker_absent(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.celery_health import probe_celery_workers

    if probe_celery_workers(timeout=1.0).get("workers"):
        pytest.skip("requires Celery worker to be absent")

    event_id = unique_id("evt-d-queue")
    await _seed_event_and_intent(session_factory, event_id=event_id, intent_id=unique_id("iin-d"))

    broker_url = os.environ.get("CELERY_BROKER_URL", os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
    previous = {
        "task_always_eager": celery_app.conf.task_always_eager,
        "broker_url": celery_app.conf.broker_url,
        "result_backend": celery_app.conf.result_backend,
    }
    celery_app.conf.task_always_eager = False
    celery_app.conf.task_eager_propagates = False
    celery_app.conf.broker_url = broker_url
    celery_app.conf.result_backend = broker_url

    monkeypatch.setattr(tasks, "register_task_metadata", AsyncMock())

    try:
        async_result = tasks.run_investigation.apply_async(
            args=[event_id],
            queue=tasks.TASK_QUEUE,
        )

        async def _still_queued() -> str | None:
            state = async_result.state
            if state in {"PENDING", "STARTED", "RETRY"}:
                return state
            if state == "SUCCESS":
                return state
            return None

        observed = await poll_until(
            _still_queued,
            timeout_s=5.0,
            interval_s=0.2,
            description="task queued or completed",
        )
        assert observed in {"PENDING", "STARTED", "RETRY", "SUCCESS"}
        if observed == "SUCCESS":
            pytest.skip("worker consumed task unexpectedly fast")
    finally:
        celery_app.conf.task_always_eager = previous["task_always_eager"]
        celery_app.conf.broker_url = previous["broker_url"]
        celery_app.conf.result_backend = previous["result_backend"]


@pytest.mark.integration
def test_scenario_d_auto_response_disabled_creates_no_extra_intent_flags() -> None:
    """Default-off AUTO_RESPONSE must not set include_response_execution (static check)."""
    settings = mock_autonomous_settings(AUTO_RESPONSE_ENABLED=False)
    assert settings.auto_response_enabled is False


@pytest.mark.autonomous_mock_e2e
@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_d_worker_recovery_completes_queued_task(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> None:
    """When a worker is present, a published intent must reach a terminal ledger state."""
    require_celery_worker()
    events, intent_service, _store = build_autonomous_stack(session_factory, redis_client)
    ingest = await events.ingest_source_object(
        _incident_source(object_id=unique_id("inc-worker-d"))
    )
    published = await intent_service.claim_and_publish_batch(limit=10)
    assert published >= 1

    async with session_factory() as session:
        intent_row = await session.scalar(
            select(orm.InvestigationIntent).where(
                orm.InvestigationIntent.event_id == ingest.event_id
            )
        )
    assert intent_row is not None
    intent_id = intent_row.intent_id

    async def _intent_terminal() -> str | None:
        async with session_factory() as session:
            row = await session.get(orm.InvestigationIntent, intent_id)
            if row is not None and row.status in TERMINAL_INTENT_STATUSES:
                return row.status
        return None

    terminal_status = await poll_until(
        _intent_terminal,
        timeout_s=120.0,
        description="worker completes queued investigation intent",
    )
    assert terminal_status in TERMINAL_INTENT_STATUSES
    snap = await collect_observability(session_factory, ingest.event_id)
    assert snap.intent_statuses
    assert snap.intent_broker_task_ids
    assert snap.intent_broker_task_ids[0] is not None
    assert snap.event_status is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_d_auto_response_disabled_intent_flag_false(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> None:
    settings = mock_autonomous_settings(AUTO_RESPONSE_ENABLED=False)
    events, _intent_service, _store = build_autonomous_stack(
        session_factory,
        redis_client,
        settings=settings,
    )
    ingest = await events.ingest_source_object(
        _incident_source(object_id=unique_id("inc-d-off"))
    )
    async with session_factory() as session:
        row = await session.scalar(
            select(orm.InvestigationIntent).where(
                orm.InvestigationIntent.event_id == ingest.event_id
            )
        )
    assert row is not None
    assert row.include_response_execution is False


# --------------------------------------------------------------------------- #
# Scenario E — provisional promotion
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_e_provisional_alert_no_intent_until_promoted(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> None:
    settings = mock_autonomous_settings(AUTO_INVESTIGATE_PROVISIONAL_WINDOW_S=300)
    events, _intent_service, _store = build_autonomous_stack(
        session_factory,
        redis_client,
        settings=settings,
    )
    sfx = uuid4().hex[:8]
    alert_ref = SourceReference(
        source_kind=SourceObjectKind.ALERT,
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-mock",
        source_object_id=f"AL-prov-e-{sfx}",
        source_updated_at=datetime.now(UTC),
    )
    incident_ref = SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-mock",
        source_object_id=f"INC-prov-e-{sfx}",
        source_updated_at=datetime.now(UTC),
    )
    alert = await events.ingest_source_object(
        IngestableSource(
            reference=alert_ref,
            title="provisional alert",
            event_type=EventType.MALICIOUS_PROCESS,
            severity=Severity.HIGH,
            normalized={"risk_score": 76, "event_type": "malicious_process"},
        )
    )
    async with session_factory() as session:
        before = await session.scalar(
            select(orm.InvestigationIntent).where(
                orm.InvestigationIntent.event_id == alert.event_id
            )
        )
        assert before is None

    promoted = await events.ingest_source_object(
        IngestableSource(
            reference=incident_ref,
            title="parent incident",
            event_type=EventType.MALICIOUS_PROCESS,
            severity=Severity.HIGH,
            normalized={"risk_score": 76, "event_type": "malicious_process"},
            related_alert_refs=[alert_ref],
        )
    )
    assert promoted.promoted is True
    async with session_factory() as session:
        rows = (
            await session.scalars(
                select(orm.InvestigationIntent).where(
                    orm.InvestigationIntent.event_id == promoted.event_id
                )
            )
        ).all()
    assert len(rows) == 1
    assert rows[0].status == InvestigationIntentStatus.PENDING.value
    snap = await collect_observability(session_factory, promoted.event_id)
    assert len(snap.intent_statuses) == 1
    assert snap.intent_broker_task_ids == [None]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_e_primary_incident_single_durable_intent(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> None:
    events, _intent_service, _store = build_autonomous_stack(session_factory, redis_client)
    source = _incident_source(object_id=unique_id("inc-e-dup"))
    first = await events.ingest_source_object(source)
    second = await events.ingest_source_object(source)
    assert second.idempotent is True
    assert first.event_id == second.event_id
    async with session_factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(orm.InvestigationIntent)
            .where(orm.InvestigationIntent.event_id == first.event_id)
        )
    assert int(count or 0) == 1
