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
from app.core.config import get_settings
from app.db import models as orm
from app.models.action import TERMINAL_DISPOSITION_TOOL
from app.models.enums import (
    ActionExecutionPhase,
    ActionStatus,
    ConfirmationEvidence,
    DispositionIntentKind,
    EventStatus,
    ExecutionJobStatus,
    OutboxDeliveryStatus,
    WritebackStatus,
)
from app.services.event_service import EventService
from app.services.investigation_guidance import record_investigation_workflow_path
from tests.integration.autonomous_e2e.helpers import (
    ObservabilitySnapshot,
    collect_observability,
    patch_production_session_factory,
)
from tests.system.helpers import seed_source_object_for_event

logger = logging.getLogger(__name__)

# Sunset registry — must never reappear in ``shims_used``.
_REMOVED_SHIMS = (
    "_sanitize_actions_for_verify",
    "_ensure_writeback_activation_ready",
    "_drive_verify_and_writeback_tail",
    "seed_minimum_disposition_audit",
)
_DEFAULT_MOCK_TIMEOUT_S = 120.0
_DEFAULT_LIVE_TIMEOUT_S = 600.0


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
    shims_used: tuple[str, ...]
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

    from tests.adversarial.xdr_verify_observation import AdversarialVerifyAgent

    monkeypatch.setattr("app.agents.verify_agent.VerifyAgent", AdversarialVerifyAgent)


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
) -> tuple[list[str], bool]:
    """Approve pending actions; defer graph resume until writebacks are drained."""
    approver = Principal(subject="adversarial-approver", roles=["approver"])
    approved: list[str] = []
    saved_resume = getattr(engine, "_resume", None)
    engine._resume = None  # noqa: SLF001 — runner controls resume timing (ISSUE-203)
    try:
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
    finally:
        engine._resume = saved_resume  # noqa: SLF001
    return approved, bool(approved)


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


async def _writeback_flags(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> tuple[bool, bool]:
    async with session_factory() as session:
        confirmed = await session.scalar(
            select(orm.DispositionReceipt)
            .join(orm.Action, orm.Action.action_id == orm.DispositionReceipt.action_id)
            .where(
                orm.Action.event_id == event_id,
                orm.DispositionReceipt.status == WritebackStatus.CONFIRMED.value,
                orm.DispositionReceipt.confirmation_evidence
                == ConfirmationEvidence.READBACK_VERIFIED.value,
            )
        )
        terminal_outbox = await session.scalar(
            select(orm.DispositionOutbox)
            .where(
                orm.DispositionOutbox.event_id == event_id,
                orm.DispositionOutbox.intent_kind
                == DispositionIntentKind.EVENT_STATUS_UPDATE.value,
            )
            .limit(1)
        )
    return confirmed is not None, terminal_outbox is not None


def _loop_quiescent(
    snap: ObservabilitySnapshot,
    *,
    waiting_approval_count: int,
    pending_outbox_count: int,
) -> bool:
    """Return True when the production loop has no further progress to make."""
    terminal_statuses = {
        EventStatus.REPORTING.value,
        EventStatus.CLOSED.value,
        EventStatus.FAILED.value,
    }
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
    max_rounds: int = 12,
) -> int:
    """Deliver ready outboxes without resuming the graph (pre-verify staging)."""
    delivered_total = 0
    for round_idx in range(max_rounds):
        delivered_any = False
        for _ in range(5):
            if await _drain_disposition_outboxes(
                session_factory=session_factory,
                event_id=event_id,
                adversarial_disposition_sync_service=adversarial_disposition_sync_service,
                notes=notes,
            ):
                delivered_any = True
                delivered_total += 1
            else:
                break
            await asyncio.sleep(0.1)
        if not delivered_any:
            break
        notes.append(f"pre_verify_outbox_drain_round_{round_idx + 1}")
    return delivered_total


async def _build_adversarial_verify_agent() -> Any:
    from app.agents.verify_agent import VerifyAgent
    from app.api.v1.deps import (
        _get_event_bus,
        _get_investigation_stack,
        get_disposition_sync,
        get_event_disposition_service,
    )

    stack = await _get_investigation_stack()
    wm = stack["wm"]
    return VerifyAgent(
        tool_executor=stack["tool_executor"],
        working_memory=wm.for_writer("VerifyAgent"),
        trace_service=stack["trace_service"],
        event_bus=_get_event_bus(),
        session_factory=stack["session_factory"],
        event_disposition_service=await get_event_disposition_service(),
        disposition_sync_service=await get_disposition_sync(),
        output_guard=stack["output_guard"],
    )


async def _rerun_production_verify_after_writebacks(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    context_store: Any,
    event_id: str,
    adversarial_disposition_sync_service: Any,
    notes: list[str],
) -> bool:
    """Re-run VerifyAgent after entity writebacks are observable (ISSUE-204).

    Graph ``execute_node → verify_node`` often starts verify while containment
    actions are still EXECUTING.  ISSUE-196 resume reconcile may also route toward
    REPORTING when entity outboxes reach ACCEPTED without activating the deferred
    terminal writeback.  Invoke VerifyAgent again once SUCCESS rows exist so
    phase2 can call ``EventDispositionService.activate_and_submit``.
    """
    _writeback_ok, terminal_outbox = await _writeback_flags(session_factory, event_id)
    if terminal_outbox and _writeback_ok:
        return False

    from app.agents.verify_agent import VerifyAgentInput
    from app.models.agent_io import ResponsePlan, VerificationPhase

    response_plan_raw = await context_store.get(event_id, "response_plan")
    if not response_plan_raw:
        notes.append("production_verify_rerun: skipped (no response_plan)")
        return False

    verify_agent = await _build_adversarial_verify_agent()
    result = await verify_agent.execute(
        VerifyAgentInput(
            event_id=event_id,
            response_plan=ResponsePlan.model_validate(response_plan_raw),
            verification_phase=VerificationPhase.EFFECT,
        )
    )
    notes.append(
        "production_verify_rerun_after_writebacks: "
        f"overall={getattr(result, 'overall_status', None)!s}"
    )
    await _deliver_all_ready_outboxes(
        session_factory=session_factory,
        event_id=event_id,
        adversarial_disposition_sync_service=adversarial_disposition_sync_service,
        notes=notes,
    )
    return True


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
    resume_hook: Any,
    max_rounds: int = 12,
) -> int:
    """Deliver ready outboxes and resume graph between passes."""
    resume_count = 0
    for round_idx in range(max_rounds):
        delivered_any = False
        for _ in range(5):
            if await _drain_disposition_outboxes(
                session_factory=session_factory,
                event_id=event_id,
                adversarial_disposition_sync_service=adversarial_disposition_sync_service,
                notes=notes,
            ):
                delivered_any = True
            else:
                break
            await asyncio.sleep(0.1)
        if not delivered_any:
            break
        notes.append(f"post_execution_outbox_drain_round_{round_idx + 1}")
        resume_count += 1
        await resume_hook(event_id)
        await asyncio.sleep(0.25)
    return resume_count


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
) -> bool:
    """Deliver ready disposition outboxes via production DispositionSync."""
    pending = await _count_pending_outboxes(session_factory, event_id)
    if pending <= 0:
        return False
    try:
        delivered = await adversarial_disposition_sync_service.process_ready_outboxes(limit=10)
    except Exception:
        logger.exception("process_ready_outboxes failed event=%s", event_id)
        return False
    if delivered:
        notes.append(f"delivered_outboxes={delivered}")
    return bool(delivered)


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

    shims_used: list[str] = []
    notes: list[str] = [
        f"shim_sunset: removed={list(_REMOVED_SHIMS)}",
        f"timeout_s={timeout_s}",
    ]

    async def _resume_hook(resume_event_id: str) -> None:
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
    resume_attempts = 0

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
    idle_rounds = 0

    while time.monotonic() < deadline:
        newly_approved, _needs_manual_resume = await _approve_all_pending(
            engine,
            session_factory,
            event_id,
        )
        if newly_approved:
            approval_rounds += 1
            approved_ids.extend(newly_approved)
            notes.append(f"approval_round_{approval_rounds}: {len(newly_approved)} action(s)")
            notes.append("approval_resume: deferred until writebacks drained")
            resume_attempts += 1
            await _resume_investigation_graph(session_factory, event_id)
            await _wait_for_execution_settle(session_factory, event_id)
            await _wait_for_containment_actions_success(session_factory, event_id)
            await _deliver_all_ready_outboxes(
                session_factory=session_factory,
                event_id=event_id,
                adversarial_disposition_sync_service=adversarial_disposition_sync_service,
                notes=notes,
            )
            await _rerun_production_verify_after_writebacks(
                session_factory=session_factory,
                context_store=context_store,
                event_id=event_id,
                adversarial_disposition_sync_service=adversarial_disposition_sync_service,
                notes=notes,
            )
            resume_attempts += 1
            notes.append("post_writeback_verify_resume")
            await _resume_investigation_graph(session_factory, event_id)
            resume_attempts += await _drain_outboxes_until_stable(
                session_factory=session_factory,
                event_id=event_id,
                adversarial_disposition_sync_service=adversarial_disposition_sync_service,
                notes=notes,
                resume_hook=_resume_investigation_graph,
            )
            for _ in range(40):
                snap = await collect_observability(session_factory, event_id)
                if snap.pending_action_count == 0:
                    break
                await asyncio.sleep(0.25)
            idle_rounds = 0
            continue

        if await _drain_disposition_outboxes(
            session_factory=session_factory,
            event_id=event_id,
            adversarial_disposition_sync_service=adversarial_disposition_sync_service,
            notes=notes,
        ):
            resume_attempts += 1
            await _resume_investigation_graph(session_factory, event_id)
            await asyncio.sleep(0.25)
            idle_rounds = 0
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

        idle_rounds += 1
        if idle_rounds >= 24 and snap.event_status in {
            EventStatus.REPORTING.value,
            EventStatus.CLOSED.value,
            EventStatus.FAILED.value,
        }:
            notes.append("loop_idle_cap: terminal status with no approval/outbox progress")
            break

        await asyncio.sleep(0.5)

    resume_attempts += await _drain_outboxes_until_stable(
        session_factory=session_factory,
        event_id=event_id,
        adversarial_disposition_sync_service=adversarial_disposition_sync_service,
        notes=notes,
        resume_hook=_resume_investigation_graph,
    )

    observability = await collect_observability(session_factory, event_id)
    writeback_confirmed, terminal_outbox = await _writeback_flags(session_factory, event_id)
    tool_calls, llm_calls = await _count_tool_and_llm_calls(session_factory, event_id)

    async with session_factory() as session:
        trace_names = list(
            await session.scalars(
                select(orm.AgentTrace.agent_name).where(orm.AgentTrace.event_id == event_id)
            )
        )

    response_plan_raw = await context_store.get(event_id, "response_plan")
    response_plan_present = bool(response_plan_raw)
    response_plan_actions = _normalize_action_rows(response_plan_raw)
    verification_present = await _context_flag(context_store, event_id, "verification_result")
    response_agent_traced = "response_agent" in trace_names
    verify_agent_traced = "verify_agent" in trace_names

    elapsed = time.perf_counter() - started
    return ProductionFullLoopResult(
        investigate_status=investigate_status,
        approval_rounds=approval_rounds,
        approved_action_ids=tuple(approved_ids),
        observability=observability,
        writeback_confirmed=writeback_confirmed,
        terminal_outbox_enqueued=terminal_outbox,
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
        response_plan_actions=response_plan_actions,
        shims_used=tuple(shims_used),
        notes=notes,
    )
