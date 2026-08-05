"""Checkpoint resume helpers for LangGraph investigation (ISSUE-059 / ISSUE-192).

Production ``resume_investigation`` hooks must continue from the saved
checkpoint after ``approval_wait_node`` or writeback halt — not restart via
``SuperAgent.investigate()`` with fresh initial state.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import models as orm
from app.models.enums import EventStatus, ExecutionSubstate, WritebackStatus
from app.orchestration.workflow_graph import (
    NODE_APPROVAL,
    NODE_VERIFY,
    invoke_investigation_graph,
)
from app.services.evidence_projection import EvidenceProjection, bind_evidence_projection

logger = logging.getLogger(__name__)

GetSuperAgent = Callable[[], Awaitable[Any]]
GetWorkflowRuntime = Callable[[], Awaitable[Any]]

# Resume may delegate to Celery only when the event never entered the graph.
_GRAPH_NEVER_STARTED_STATUSES = frozenset(
    {
        EventStatus.NEW.value,
        EventStatus.TRIAGING.value,
    }
)

# Manual holds that must survive VERIFYING resume even when writebacks confirm.
_LEGITIMATE_MANUAL_DEGRADED_PREFIXES = frozenset(
    {
        "missing_response_plan_for_required_policy",
        "disposition_activation_failed",
        "execution_failed_unverified",
    }
)


def _degraded_flag_name(raw: Any) -> str:
    return str(raw).split("=", 1)[0]


def _has_legitimate_manual_hold(degraded_flags: list[Any]) -> bool:
    return any(
        _degraded_flag_name(flag) in _LEGITIMATE_MANUAL_DEGRADED_PREFIXES for flag in degraded_flags
    )


def _strip_stale_verify_degraded(degraded_flags: list[Any]) -> list[Any]:
    return [flag for flag in degraded_flags if _degraded_flag_name(flag) != "verify_degraded"]


async def _active_outbox_writeback_statuses(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> list[str | None]:
    async with session_factory() as session:
        return list(
            await session.scalars(
                select(orm.DispositionOutbox.latest_writeback_status).where(
                    orm.DispositionOutbox.event_id == event_id,
                    orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
                )
            )
        )


# Non-failed outbox statuses that allow VERIFYING resume to route toward REPORTING.
# CLOSED gate still requires CONFIRMED separately (workflow.validate_closed_gate).
_RESUME_ROUTING_TERMINAL_STATUSES = frozenset(
    {
        WritebackStatus.CONFIRMED.value,
        WritebackStatus.ACCEPTED.value,
    }
)


def _writebacks_resolved_for_resume_routing(statuses: list[str | None]) -> bool:
    """Return True when every active outbox reached a non-failed terminal status."""
    if not statuses:
        return False
    return all(status in _RESUME_ROUTING_TERMINAL_STATUSES for status in statuses)


async def _reconcile_verify_resume_patch(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    values: dict[str, Any],
) -> dict[str, Any]:
    """Re-evaluate verify routing flags after external writeback/resume (ISSUE-196).

    Production resume previously cleared only ``halted``, leaving stale
    ``verify_need_manual_resolution`` / ``verify_need_writeback_recovery`` that
    routed back to ``manual_hold`` despite confirmed writebacks.
    """
    patch: dict[str, Any] = {}
    if values.get("halted"):
        patch["halted"] = False

    need_writeback = bool(values.get("verify_need_writeback_recovery"))
    need_manual = bool(values.get("verify_need_manual_resolution"))
    failed_writebacks = list(values.get("verify_failed_writebacks") or [])
    if not (need_writeback or need_manual or values.get("halted")):
        return patch

    degraded_flags = list(values.get("degraded_flags") or [])
    legitimate_manual = _has_legitimate_manual_hold(degraded_flags)
    wb_statuses = await _active_outbox_writeback_statuses(session_factory, event_id)
    writebacks_resolved = not failed_writebacks and _writebacks_resolved_for_resume_routing(
        wb_statuses
    )

    if need_writeback and writebacks_resolved:
        patch["verify_need_writeback_recovery"] = False
        patch["verify_failed_writebacks"] = []
        patch["execution_substate"] = ExecutionSubstate.NONE.value

    if need_manual and not legitimate_manual and writebacks_resolved:
        patch["verify_need_manual_resolution"] = False
        patch.setdefault("execution_substate", ExecutionSubstate.NONE.value)
        stripped = _strip_stale_verify_degraded(degraded_flags)
        if stripped != degraded_flags:
            patch["degraded_flags"] = stripped

    return patch


async def _read_event_status(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> str:
    async with session_factory() as session:
        event_status = await session.scalar(
            select(orm.SecurityEvent.status).where(orm.SecurityEvent.event_id == event_id)
        )
    return str(event_status or "")


async def prepare_graph_resume_state(
    session_factory: async_sessionmaker[AsyncSession],
    graph: Any,
    event_id: str,
    runtime: Any,
) -> bool:
    """Clear halt flags on the checkpoint so ``ainvoke(None)`` can continue.

    Re-reads DB event status before patching (idempotent). Returns ``True`` when
    a checkpoint exists (even if no patch was required).
    """
    config = {"configurable": {"thread_id": event_id}}
    snapshot = await graph.aget_state(config)
    if snapshot is None or not snapshot.values:
        return False

    status_value = await _read_event_status(session_factory, event_id)
    values = snapshot.values

    if status_value == EventStatus.VERIFYING.value:
        resume_patch = await _reconcile_verify_resume_patch(
            session_factory,
            event_id,
            values,
        )
        if resume_patch:
            await graph.aupdate_state(
                config,
                resume_patch,
                as_node=NODE_VERIFY,
            )
            values = {**values, **resume_patch}
        if values.get("execution_substate") == ExecutionSubstate.WAITING_WRITEBACK.value:
            await runtime.set_execution_substate(
                event_id,
                ExecutionSubstate.WAITING_WRITEBACK,
                event_status=EventStatus.VERIFYING,
            )
        return True

    if status_value == EventStatus.REPORTING.value:
        await runtime.set_execution_substate(
            event_id,
            ExecutionSubstate.NONE,
            event_status=EventStatus.REPORTING,
        )
        needs_patch = bool(
            values.get("halted")
            or values.get("needs_approval_wait")
            or values.get("execution_substate") == ExecutionSubstate.WAITING_APPROVAL.value
        )
        if needs_patch:
            await graph.aupdate_state(
                config,
                {
                    "halted": False,
                    "needs_approval_wait": False,
                    "execution_substate": ExecutionSubstate.NONE.value,
                    "event_status": EventStatus.REPORTING.value,
                },
                as_node=NODE_APPROVAL,
            )
        return True

    if status_value != EventStatus.EXECUTING_RESPONSE.value:
        logger.warning(
            "prepare_graph_resume: unexpected DB status=%s event=%s; skipping checkpoint patch",
            status_value,
            event_id,
        )
        return True

    await runtime.set_execution_substate(
        event_id,
        ExecutionSubstate.NONE,
        event_status=EventStatus.EXECUTING_RESPONSE,
    )

    needs_patch = bool(
        values.get("halted")
        or values.get("needs_approval_wait")
        or values.get("execution_substate") == ExecutionSubstate.WAITING_APPROVAL.value
    )
    if not needs_patch:
        return True

    await graph.aupdate_state(
        config,
        {
            "halted": False,
            "needs_approval_wait": False,
            "execution_substate": ExecutionSubstate.NONE.value,
            "event_status": EventStatus.EXECUTING_RESPONSE.value,
        },
        as_node=NODE_APPROVAL,
    )
    return True


async def resume_investigation_from_checkpoint(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    *,
    get_super_agent: GetSuperAgent,
    get_workflow_runtime: GetWorkflowRuntime,
) -> None:
    """Resume LangGraph from checkpoint after approval or writeback."""
    agent = await get_super_agent()
    graph = getattr(agent, "_investigation_graph", None)
    if graph is None:
        from app.services.investigation_guidance import (
            resolve_include_response_execution_for_resume,
        )
        from app.tasks.investigation_tasks import execute_investigation

        include_response = await resolve_include_response_execution_for_resume(
            session_factory,
            event_id,
        )
        await execute_investigation(
            event_id,
            include_response_execution=include_response,
        )
        return

    config = {"configurable": {"thread_id": event_id}}
    runtime = await get_workflow_runtime()
    has_checkpoint = await prepare_graph_resume_state(
        session_factory,
        graph,
        event_id,
        runtime,
    )
    if not has_checkpoint:
        status_value = await _read_event_status(session_factory, event_id)
        if status_value in _GRAPH_NEVER_STARTED_STATUSES:
            from app.services.investigation_guidance import (
                resolve_include_response_execution_for_resume,
            )
            from app.tasks.investigation_tasks import execute_investigation

            include_response = await resolve_include_response_execution_for_resume(
                session_factory,
                event_id,
            )
            await execute_investigation(
                event_id,
                include_response_execution=include_response,
            )
            return
        from app.orchestration.graph_resume_observability import GraphResumeFailedError

        raise GraphResumeFailedError(
            f"no checkpoint for event in status {status_value}",
            event_id=event_id,
            error_type="checkpoint_missing",
        )

    projection = EvidenceProjection(session_factory)
    with bind_evidence_projection(projection):
        await invoke_investigation_graph(graph, None, config)


__all__ = [
    "prepare_graph_resume_state",
    "resume_investigation_from_checkpoint",
]
