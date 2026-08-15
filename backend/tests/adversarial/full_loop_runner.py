"""Production-path adversarial full loop (no ``run_full_response_chain`` helper).

Runs SuperAgent + LangGraph with ``include_response_execution=True`` so
ResponseAgent, ApprovalEngine, ActionExecution, VerifyAgent, and
DispositionSync all participate.  Pending L2+ actions are approved via
production ``get_approval_engine()`` (resume hook + impact assessment).

ISSUE-203: no verify-tail / writeback-activation shims — the loop must reach
``REPORTING``/``CLOSED`` through graph resume (#196) and production wiring.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.auth import Principal
from app.core.config import get_settings, is_mock_disposition_mode
from app.db import models as orm
from app.models.action import TERMINAL_DISPOSITION_TOOL, Action
from app.models.agent_io import ResponsePlanGeneratedBy
from app.models.enums import (
    ActionExecutionPhase,
    ActionStatus,
    DispositionIntentKind,
    EventStatus,
    ExecutionJobStatus,
    OutboxDeliveryStatus,
    WritebackStatus,
)
from app.services.event_service import EventService
from app.services.investigation_guidance import record_investigation_workflow_path
from app.services.report_input_builder import (
    _coerce_response_plan,
    _load_actions_from_orm,
    overlay_response_plan_from_orm,
)
from tests.adversarial.audit_report import evaluate_writeback_confirmed
from tests.adversarial.helpers import mock_writeback_cert_strict_enabled
from tests.integration.autonomous_e2e.helpers import (
    ObservabilitySnapshot,
    collect_observability,
    patch_production_session_factory,
)
from tests.system.helpers import seed_source_object_for_event

logger = logging.getLogger(__name__)

# Sunset registry — must never reappear in ``sunset_shims_used``.
_REMOVED_SHIMS = (
    "_sanitize_actions_for_verify",
    "_ensure_writeback_activation_ready",
    "_drive_verify_and_writeback_tail",
    "seed_minimum_disposition_audit",
)
_DEFAULT_MOCK_TIMEOUT_S = 120.0
_DEFAULT_LIVE_TIMEOUT_S = 600.0
_ADVERSARIAL_DI_OVERRIDES = ("XdrManagedVerifyToolExecutor",)


@dataclass(frozen=True, slots=True)
class TerminalWritebackSnapshot:
    """Terminal EVENT_STATUS_UPDATE receipt facts for adversarial scorecards."""

    writeback_confirmed: bool
    terminal_outbox_enqueued: bool
    confirmation_evidence: str | None
    simulated: bool | None
    receipt_status: str | None
    disposition_is_mock: bool
    mock_cert_strict: bool


def resolve_disposition_is_mock() -> bool:
    """Match production CLOSED projection: disposition_mode allowlist only (ISSUE-227/333/351)."""
    return is_mock_disposition_mode(get_settings().disposition_mode)


def resolve_full_loop_timeout_s() -> float:
    """Runner wall-clock budget; override via ``ADVERSARIAL_FULL_LOOP_TIMEOUT_S``."""
    raw = os.environ.get("ADVERSARIAL_FULL_LOOP_TIMEOUT_S", "").strip()
    if raw:
        return max(30.0, float(raw))
    llm_mode = os.environ.get("LLM_MODE", "mock").strip().lower()
    if llm_mode == "openai_compatible":
        return _DEFAULT_LIVE_TIMEOUT_S
    return _DEFAULT_MOCK_TIMEOUT_S


@dataclass(frozen=True)
class ProductionFullLoopResult:
    """Observed production full-loop outcomes for adversarial audits."""

    investigate_status: str
    approval_rounds: int
    approved_action_ids: tuple[str, ...]
    observability: ObservabilitySnapshot
    writeback_confirmed: bool
    terminal_outbox_enqueued: bool
    writeback_confirmation_evidence: str | None
    writeback_simulated: bool | None
    writeback_receipt_status: str | None
    disposition_is_mock: bool
    mock_cert_strict: bool
    response_plan_present: bool
    verification_present: bool
    response_agent_traced: bool
    verify_agent_traced: bool
    approval_records: int
    tool_call_count: int
    llm_call_count: int
    execution_ran: bool
    resume_attempts: int
    elapsed_s: float
    response_plan_actions: tuple[dict[str, Any], ...]
    response_plan_generated_by: str | None
    response_plan_strategy_summary: str | None
    sunset_shims_used: tuple[str, ...]
    adversarial_di_overrides: tuple[str, ...]
    notes: list[str] = field(default_factory=list)


def _wire_production_monkeypatches(
    monkeypatch: Any,
    *,
    session_factory: async_sessionmaker[AsyncSession],
    adversarial_disposition_sync_service: Any,
    adversarial_event_disposition_service: Any,
    e2e_tool_executor: Any,
    resume_hook: Any,
) -> None:
    """Point production DI at integration/adversarial services."""
    from app.api.v1.deps import reset_deps, reset_investigation_stack_cache

    patch_production_session_factory(monkeypatch, session_factory)

    monkeypatch.setenv("ORCHESTRATION_MODE", "graph")
    get_settings.cache_clear()

    from app.services.tool_call_log_service import ToolCallLogService

    audit_service = ToolCallLogService(session_factory)
    e2e_tool_executor.audit_service = audit_service
    inner_executor = getattr(e2e_tool_executor, "_inner", e2e_tool_executor)
    inner_executor.audit_service = audit_service
    monkeypatch.setattr("app.tools.executor.get_tool_executor", lambda: e2e_tool_executor)

    reset_deps()
    reset_investigation_stack_cache()

    adversarial_disposition_sync_service._resume = resume_hook  # noqa: SLF001

    async def _disposition_sync() -> Any:
        return adversarial_disposition_sync_service

    async def _event_disposition() -> Any:
        return adversarial_event_disposition_service

    monkeypatch.setattr("app.api.v1.deps.get_disposition_sync", _disposition_sync)
    monkeypatch.setattr("app.api.v1.deps.get_event_disposition_service", _event_disposition)


async def _resume_investigation_graph(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> None:
    """Resume LangGraph from checkpoint after approval or outbox delivery."""
    from app.api.v1.deps import _get_workflow_runtime, get_super_agent
    from app.orchestration.graph_resume import resume_investigation_from_checkpoint

    await resume_investigation_from_checkpoint(
        session_factory,
        event_id,
        get_super_agent=get_super_agent,
        get_workflow_runtime=_get_workflow_runtime,
    )


async def _approve_all_pending(
    engine: Any,
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> list[str]:
    """Approve pending actions through the production approval/resume callback."""
    approver = Principal(subject="adversarial-approver", roles=["approver"])
    approved: list[str] = []
    async with session_factory() as session:
        rows = list(
            await session.scalars(
                select(orm.Action).where(
                    orm.Action.event_id == event_id,
                    orm.Action.status == ActionStatus.WAITING_APPROVAL.value,
                )
            )
        )
    for row in rows:
        decision_id = f"dec-adv-{uuid.uuid4().hex[:12]}"
        await engine.approve(
            row.action_id,
            approver,
            "adversarial production full-loop approval",
            decision_id,
        )
        approved.append(row.action_id)
    return approved


async def _context_flag(context_store: Any, event_id: str, key: str) -> bool:
    try:
        payload = await context_store.get(event_id, key)
    except Exception:
        return False
    return bool(payload)


async def _count_tool_and_llm_calls(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> tuple[int, int]:
    async with session_factory() as session:
        tool_count = int(
            await session.scalar(
                select(func.count())
                .select_from(orm.ToolCallLog)
                .where(orm.ToolCallLog.event_id == event_id)
            )
            or 0
        )
        llm_count = int(
            await session.scalar(
                select(func.count())
                .select_from(orm.LLMCallLog)
                .where(orm.LLMCallLog.event_id == event_id)
            )
            or 0
        )
    return tool_count, llm_count


async def _terminal_writeback_snapshot(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> TerminalWritebackSnapshot:
    disposition_is_mock = resolve_disposition_is_mock()
    mock_cert_strict = mock_writeback_cert_strict_enabled()
    async with session_factory() as session:
        current_revision = await session.scalar(
            select(func.max(orm.Action.plan_revision)).where(
                orm.Action.event_id == event_id,
                orm.Action.superseded_by_revision.is_(None),
            )
        )
        if current_revision is None:
            return TerminalWritebackSnapshot(
                writeback_confirmed=False,
                terminal_outbox_enqueued=False,
                confirmation_evidence=None,
                simulated=None,
                receipt_status=None,
                disposition_is_mock=disposition_is_mock,
                mock_cert_strict=mock_cert_strict,
            )
        active_terminal_filters = (
            orm.DispositionOutbox.event_id == event_id,
            orm.DispositionOutbox.intent_kind == DispositionIntentKind.EVENT_STATUS_UPDATE.value,
            orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
            orm.Action.plan_revision == current_revision,
            orm.Action.superseded_by_revision.is_(None),
        )
        terminal_outbox_count = int(
            await session.scalar(
                select(func.count())
                .select_from(orm.DispositionOutbox)
                .join(orm.Action, orm.Action.action_id == orm.DispositionOutbox.action_id)
                .where(*active_terminal_filters)
            )
            or 0
        )
        delivered_terminal_count = int(
            await session.scalar(
                select(func.count())
                .select_from(orm.DispositionOutbox)
                .join(
                    orm.Action,
                    orm.Action.action_id == orm.DispositionOutbox.action_id,
                )
                .where(
                    *active_terminal_filters,
                    orm.DispositionOutbox.delivery_status == OutboxDeliveryStatus.DELIVERED.value,
                )
            )
            or 0
        )
        receipt_row = await session.scalar(
            select(orm.DispositionReceipt)
            .join(
                orm.DispositionOutbox,
                orm.DispositionOutbox.writeback_id == orm.DispositionReceipt.writeback_id,
            )
            .join(orm.Action, orm.Action.action_id == orm.DispositionOutbox.action_id)
            .where(
                *active_terminal_filters,
                orm.DispositionOutbox.delivery_status == OutboxDeliveryStatus.DELIVERED.value,
                orm.DispositionReceipt.status == WritebackStatus.CONFIRMED.value,
            )
            .order_by(
                orm.DispositionReceipt.writeback_id,
                orm.DispositionReceipt.sequence.desc(),
            )
            .limit(1)
        )
    confirmation_evidence = receipt_row.confirmation_evidence if receipt_row is not None else None
    simulated = receipt_row.simulated if receipt_row is not None else None
    receipt_status = receipt_row.status if receipt_row is not None else None
    terminal_delivered = delivered_terminal_count == 1 and terminal_outbox_count == 1
    confirmed_receipt = receipt_row is not None
    writeback_confirmed = evaluate_writeback_confirmed(
        terminal_delivered=terminal_delivered,
        confirmed_receipt=confirmed_receipt,
        confirmation_evidence=confirmation_evidence,
        simulated=simulated,
        disposition_is_mock=disposition_is_mock,
        mock_cert_strict=mock_cert_strict,
    )
    return TerminalWritebackSnapshot(
        writeback_confirmed=writeback_confirmed,
        terminal_outbox_enqueued=terminal_outbox_count == 1,
        confirmation_evidence=confirmation_evidence,
        simulated=simulated,
        receipt_status=receipt_status,
        disposition_is_mock=disposition_is_mock,
        mock_cert_strict=mock_cert_strict,
    )


def _loop_quiescent(
    snap: ObservabilitySnapshot,
    *,
    waiting_approval_count: int,
    pending_outbox_count: int,
) -> bool:
    """Return True when the production loop has no further progress to make."""
    terminal_statuses = {EventStatus.CLOSED.value, EventStatus.FAILED.value}
    if snap.pending_action_count != 0:
        return False
    if waiting_approval_count > 0:
        return False
    if snap.event_status not in terminal_statuses:
        return False
    if pending_outbox_count > 0:
        return False
    return True


async def _count_pending_outboxes(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> int:
    async with session_factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(
                orm.DispositionOutbox.event_id == event_id,
                orm.DispositionOutbox.delivery_status.in_(
                    (
                        OutboxDeliveryStatus.READY.value,
                        OutboxDeliveryStatus.LEASED.value,
                        OutboxDeliveryStatus.WAITING_RETRY.value,
                    )
                ),
            )
        )
    return int(count or 0)


async def _wait_for_containment_actions_success(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    *,
    timeout_s: float = 60.0,
) -> None:
    """Wait until immediate containment response actions reach terminal success."""
    containment_tools = ("block_ip", "disable_account", "isolate_host")
    terminal_statuses = (
        ActionStatus.SUCCESS.value,
        ActionStatus.PARTIAL_SUCCESS.value,
        ActionStatus.FAILED.value,
    )
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        async with session_factory() as session:
            pending = await session.scalar(
                select(func.count())
                .select_from(orm.Action)
                .where(
                    orm.Action.event_id == event_id,
                    orm.Action.execution_phase == ActionExecutionPhase.IMMEDIATE.value,
                    orm.Action.tool_name.in_(containment_tools),
                    orm.Action.status.notin_(terminal_statuses),
                )
            )
        if int(pending or 0) == 0:
            return
        await asyncio.sleep(0.25)


async def _deliver_all_ready_outboxes(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    adversarial_disposition_sync_service: Any,
    notes: list[str],
    deadline: float,
) -> int:
    """Deliver ready outboxes without resuming the graph (pre-verify staging)."""
    delivered_total = 0
    while time.monotonic() < deadline:
        if await _count_pending_outboxes(session_factory, event_id) == 0:
            break
        delivered = await _drain_disposition_outboxes(
            session_factory=session_factory,
            event_id=event_id,
            adversarial_disposition_sync_service=adversarial_disposition_sync_service,
            notes=notes,
        )
        if delivered == 0:
            break
        delivered_total += delivered
    return delivered_total


async def _wait_for_execution_settle(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    *,
    timeout_s: float = 60.0,
) -> None:
    """Wait until immediate response actions and execution jobs finish."""
    deadline = time.monotonic() + timeout_s
    active_job_statuses = (
        ExecutionJobStatus.QUEUED.value,
        ExecutionJobStatus.RUNNING.value,
    )
    while time.monotonic() < deadline:
        async with session_factory() as session:
            executing_actions = await session.scalar(
                select(func.count())
                .select_from(orm.Action)
                .where(
                    orm.Action.event_id == event_id,
                    orm.Action.execution_phase == ActionExecutionPhase.IMMEDIATE.value,
                    orm.Action.tool_name != TERMINAL_DISPOSITION_TOOL,
                    orm.Action.status.in_(
                        (
                            ActionStatus.EXECUTING.value,
                            ActionStatus.APPROVED.value,
                        )
                    ),
                )
            )
            active_jobs = await session.scalar(
                select(func.count())
                .select_from(orm.ActionExecutionJob)
                .where(
                    orm.ActionExecutionJob.event_id == event_id,
                    orm.ActionExecutionJob.status.in_(active_job_statuses),
                )
            )
        if int(executing_actions or 0) == 0 and int(active_jobs or 0) == 0:
            return
        await asyncio.sleep(0.25)


async def _drain_outboxes_until_stable(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    adversarial_disposition_sync_service: Any,
    notes: list[str],
    deadline: float,
) -> int:
    """Drain observable outbox progress; service callbacks own graph resume."""
    delivered_total = 0
    while time.monotonic() < deadline:
        if await _count_pending_outboxes(session_factory, event_id) == 0:
            break
        delivered = await _drain_disposition_outboxes(
            session_factory=session_factory,
            event_id=event_id,
            adversarial_disposition_sync_service=adversarial_disposition_sync_service,
            notes=notes,
        )
        if delivered == 0:
            break
        delivered_total += delivered
    return delivered_total


async def _count_waiting_approval(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> int:
    async with session_factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(orm.Action)
            .where(
                orm.Action.event_id == event_id,
                orm.Action.status == ActionStatus.WAITING_APPROVAL.value,
            )
        )
    return int(count or 0)


async def _drain_disposition_outboxes(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    adversarial_disposition_sync_service: Any,
    notes: list[str],
) -> int:
    """Deliver ready disposition outboxes via production DispositionSync."""
    pending = await _count_pending_outboxes(session_factory, event_id)
    if pending <= 0:
        return 0
    try:
        delivered = await adversarial_disposition_sync_service.process_ready_outboxes(limit=10)
    except Exception as exc:
        notes.append(f"outbox_delivery_failed={type(exc).__name__}")
        logger.exception("process_ready_outboxes failed event=%s", event_id)
        raise
    if delivered:
        notes.append(f"delivered_outboxes={delivered}")
    return int(delivered)


@dataclass(frozen=True)
class ArtifactResponsePlanView:
    """Audit-facing response plan projection for full-loop artifacts (ISSUE-342)."""

    actions: tuple[dict[str, Any], ...]
    generated_by: str | None
    strategy_summary: str | None


def _normalize_action_rows(raw: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(raw, dict):
        return ()
    actions = raw.get("actions")
    if not isinstance(actions, list):
        return ()
    rows: list[dict[str, Any]] = []
    for item in actions[:50]:
        if isinstance(item, dict):
            rows.append(dict(item))
    return tuple(rows)


def _actions_to_rows(actions: list[Action]) -> tuple[dict[str, Any], ...]:
    return tuple(action.model_dump(mode="json") for action in actions[:50])


def build_artifact_response_plan_view(
    response_plan_raw: Any,
    *,
    orm_actions: list[Action] | None = None,
) -> ArtifactResponsePlanView:
    """Project generation snapshot + runtime Action statuses for audit artifacts.

    Preserves ``ResponsePlan.actions`` generation-time snapshot semantics in the
    context store while overlaying execution fields from persisted Action rows,
    matching the ISSUE-329 report builder path.
    """
    plan = _coerce_response_plan(response_plan_raw)
    if plan is None:
        return ArtifactResponsePlanView(
            actions=_normalize_action_rows(response_plan_raw),
            generated_by=None,
            strategy_summary=None,
        )

    generated_by = plan.generated_by.value
    strategy_summary = plan.strategy_summary or None
    if orm_actions is not None and plan.generated_by is not ResponsePlanGeneratedBy.RECOVERED:
        plan = overlay_response_plan_from_orm(plan, orm_actions)

    return ArtifactResponsePlanView(
        actions=_actions_to_rows(plan.actions),
        generated_by=generated_by,
        strategy_summary=strategy_summary,
    )


async def _load_plan_actions_from_orm(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    *,
    action_ids: set[str],
) -> list[Action]:
    if not action_ids:
        return []
    async with session_factory() as session:
        return await _load_actions_from_orm(session, event_id, action_ids=action_ids)


async def _resolve_artifact_response_plan_view(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    response_plan_raw: Any,
) -> ArtifactResponsePlanView:
    plan = _coerce_response_plan(response_plan_raw)
    if plan is None:
        return build_artifact_response_plan_view(response_plan_raw)

    orm_actions = await _load_plan_actions_from_orm(
        session_factory,
        event_id,
        action_ids={action.action_id for action in plan.actions},
    )
    return build_artifact_response_plan_view(response_plan_raw, orm_actions=orm_actions)


async def run_production_full_loop(
    *,
    monkeypatch: Any,
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    event_service: EventService,
    context_store: Any,
    adversarial_disposition_sync_service: Any,
    adversarial_event_disposition_service: Any,
    e2e_tool_executor: Any,
    event_id: str,
    timeout_s: float | None = None,
) -> ProductionFullLoopResult:
    """Execute investigate(full_loop) + approval drains until quiescent or timeout."""
    from app.api.v1.deps import get_approval_engine
    from app.tasks.investigation_tasks import execute_investigation

    if timeout_s is None:
        timeout_s = resolve_full_loop_timeout_s()

    sunset_shims_used: list[str] = []
    notes: list[str] = [
        f"shim_sunset: removed={list(_REMOVED_SHIMS)}",
        f"timeout_s={timeout_s}",
    ]
    resume_attempts = 0

    async def _resume_hook(resume_event_id: str) -> None:
        nonlocal resume_attempts
        resume_attempts += 1
        await _resume_investigation_graph(session_factory, resume_event_id)

    _wire_production_monkeypatches(
        monkeypatch,
        session_factory=session_factory,
        adversarial_disposition_sync_service=adversarial_disposition_sync_service,
        adversarial_event_disposition_service=adversarial_event_disposition_service,
        e2e_tool_executor=e2e_tool_executor,
        resume_hook=_resume_hook,
    )

    started = time.perf_counter()

    event = await event_service.get_event(event_id)
    if event is None:
        raise AssertionError(f"event not found: {event_id}")
    await seed_source_object_for_event(session_factory, event)

    await record_investigation_workflow_path(
        session_factory,
        event_id,
        workflow_path="full_loop",
        include_response_execution=True,
    )

    investigate_result = await execute_investigation(
        event_id,
        include_response_execution=True,
    )
    investigate_status = str(investigate_result.get("status") or "")

    engine = await get_approval_engine()
    approved_ids: list[str] = []
    approval_rounds = 0
    deadline = time.monotonic() + timeout_s

    while time.monotonic() < deadline:
        newly_approved = await _approve_all_pending(
            engine,
            session_factory,
            event_id,
        )
        if newly_approved:
            approval_rounds += 1
            approved_ids.extend(newly_approved)
            notes.append(f"approval_round_{approval_rounds}: {len(newly_approved)} action(s)")
            notes.append("approval_resume: production callback")
            await _wait_for_execution_settle(session_factory, event_id)
            await _wait_for_containment_actions_success(session_factory, event_id)
            await _deliver_all_ready_outboxes(
                session_factory=session_factory,
                event_id=event_id,
                adversarial_disposition_sync_service=adversarial_disposition_sync_service,
                notes=notes,
                deadline=deadline,
            )
            await _drain_outboxes_until_stable(
                session_factory=session_factory,
                event_id=event_id,
                adversarial_disposition_sync_service=adversarial_disposition_sync_service,
                notes=notes,
                deadline=deadline,
            )
            while time.monotonic() < deadline:
                snap = await collect_observability(session_factory, event_id)
                if snap.pending_action_count == 0:
                    break
                await asyncio.sleep(0.25)
            continue

        delivered = await _drain_disposition_outboxes(
            session_factory=session_factory,
            event_id=event_id,
            adversarial_disposition_sync_service=adversarial_disposition_sync_service,
            notes=notes,
        )
        if delivered:
            continue

        waiting_approval = await _count_waiting_approval(session_factory, event_id)
        pending_outboxes = await _count_pending_outboxes(session_factory, event_id)
        snap = await collect_observability(session_factory, event_id)
        if _loop_quiescent(
            snap,
            waiting_approval_count=waiting_approval,
            pending_outbox_count=pending_outboxes,
        ):
            break

        await asyncio.sleep(0.5)
    else:
        snap = await collect_observability(session_factory, event_id)
        notes.append(
            "loop_timeout: "
            f"status={snap.event_status}, pending_actions={snap.pending_action_count}, "
            f"waiting_approval={await _count_waiting_approval(session_factory, event_id)}, "
            f"pending_outboxes={await _count_pending_outboxes(session_factory, event_id)}"
        )

    await _drain_outboxes_until_stable(
        session_factory=session_factory,
        event_id=event_id,
        adversarial_disposition_sync_service=adversarial_disposition_sync_service,
        notes=notes,
        deadline=deadline,
    )

    observability = await collect_observability(session_factory, event_id)
    writeback_snapshot = await _terminal_writeback_snapshot(session_factory, event_id)
    tool_calls, llm_calls = await _count_tool_and_llm_calls(session_factory, event_id)

    async with session_factory() as session:
        trace_names = list(
            await session.scalars(
                select(orm.AgentTrace.agent_name).where(orm.AgentTrace.event_id == event_id)
            )
        )

    response_plan_raw = await context_store.get(event_id, "response_plan")
    response_plan_present = bool(response_plan_raw)
    response_plan_view = await _resolve_artifact_response_plan_view(
        session_factory,
        event_id,
        response_plan_raw,
    )
    verification_present = await _context_flag(context_store, event_id, "verification_result")
    response_agent_traced = "response_agent" in trace_names
    verify_agent_traced = "verify_agent" in trace_names

    elapsed = time.perf_counter() - started
    return ProductionFullLoopResult(
        investigate_status=investigate_status,
        approval_rounds=approval_rounds,
        approved_action_ids=tuple(approved_ids),
        observability=observability,
        writeback_confirmed=writeback_snapshot.writeback_confirmed,
        terminal_outbox_enqueued=writeback_snapshot.terminal_outbox_enqueued,
        writeback_confirmation_evidence=writeback_snapshot.confirmation_evidence,
        writeback_simulated=writeback_snapshot.simulated,
        writeback_receipt_status=writeback_snapshot.receipt_status,
        disposition_is_mock=writeback_snapshot.disposition_is_mock,
        mock_cert_strict=writeback_snapshot.mock_cert_strict,
        response_plan_present=response_plan_present,
        verification_present=verification_present,
        response_agent_traced=response_agent_traced,
        verify_agent_traced=verify_agent_traced,
        approval_records=observability.approval_record_count,
        tool_call_count=tool_calls,
        llm_call_count=llm_calls,
        execution_ran=observability.execution_job_count > 0,
        resume_attempts=resume_attempts,
        elapsed_s=elapsed,
        response_plan_actions=response_plan_view.actions,
        response_plan_generated_by=response_plan_view.generated_by,
        response_plan_strategy_summary=response_plan_view.strategy_summary,
        sunset_shims_used=tuple(sunset_shims_used),
        adversarial_di_overrides=_ADVERSARIAL_DI_OVERRIDES,
        notes=notes,
    )
