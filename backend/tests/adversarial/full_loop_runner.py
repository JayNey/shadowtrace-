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
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.auth import Principal
from app.core.config import get_settings
from app.db import models as orm
from app.models.enums import (
    ActionStatus,
    ConfirmationEvidence,
    DispositionIntentKind,
    EventStatus,
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

# Sunset registry — must stay empty once ISSUE-195/196/198/202 are on main.
_REMOVED_SHIMS = (
    "_sanitize_actions_for_verify",
    "_ensure_writeback_activation_ready",
    "_drive_verify_and_writeback_tail",
    "seed_minimum_disposition_audit",
)


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

    reset_deps()
    reset_investigation_stack_cache()
    get_settings.cache_clear()
    patch_production_session_factory(monkeypatch, session_factory)

    monkeypatch.setenv("ORCHESTRATION_MODE", "graph")
    get_settings.cache_clear()

    adversarial_disposition_sync_service._resume = resume_hook  # noqa: SLF001

    async def _disposition_sync() -> Any:
        return adversarial_disposition_sync_service

    async def _event_disposition() -> Any:
        return adversarial_event_disposition_service

    monkeypatch.setattr("app.api.v1.deps.get_disposition_sync", _disposition_sync)
    monkeypatch.setattr("app.api.v1.deps.get_event_disposition_service", _event_disposition)

    from app.services.tool_call_log_service import ToolCallLogService

    if getattr(e2e_tool_executor, "audit_service", None) is not None:
        e2e_tool_executor.audit_service = ToolCallLogService(session_factory)
    monkeypatch.setattr("app.tools.executor.get_tool_executor", lambda: e2e_tool_executor)


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


def _loop_quiescent(snap: ObservabilitySnapshot) -> bool:
    """Quality gate: terminal investigation status only (ISSUE-203).

    ``writeback_confirmed`` alone is insufficient — VERIFYING with empty report
    must not count as success.
    """
    terminal_statuses = {
        EventStatus.REPORTING.value,
        EventStatus.CLOSED.value,
        EventStatus.FAILED.value,
    }
    return snap.pending_action_count == 0 and snap.event_status in terminal_statuses


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
    timeout_s: float = 900.0,
) -> ProductionFullLoopResult:
    """Execute investigate(full_loop) + approval drains until quiescent or timeout."""
    from app.api.v1.deps import get_approval_engine
    from app.tasks.investigation_tasks import execute_investigation

    shims_used: list[str] = []
    notes: list[str] = [f"shim_sunset: removed={list(_REMOVED_SHIMS)}"]

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

    while time.monotonic() < deadline:
        newly_approved = await _approve_all_pending(engine, session_factory, event_id)
        if newly_approved:
            approval_rounds += 1
            approved_ids.extend(newly_approved)
            notes.append(f"approval_round_{approval_rounds}: {len(newly_approved)} action(s)")
            resume_attempts += 1
            await asyncio.sleep(2.0)
            continue

        snap = await collect_observability(session_factory, event_id)
        if _loop_quiescent(snap):
            break

        if snap.disposition_outbox_count > 0:
            try:
                delivered = await adversarial_disposition_sync_service.process_ready_outboxes(
                    limit=5
                )
                if delivered:
                    notes.append(f"delivered_outboxes={delivered}")
                    resume_attempts += 1
                    await _resume_investigation_graph(session_factory, event_id)
            except Exception:
                logger.exception("process_ready_outboxes failed event=%s", event_id)

        await asyncio.sleep(0.5)

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
