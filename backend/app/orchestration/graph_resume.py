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
from app.models.enums import EventStatus, ExecutionSubstate
from app.orchestration.workflow_graph import (
    NODE_APPROVAL,
    NODE_VERIFY,
    invoke_investigation_graph,
)
from app.services.evidence_projection import EvidenceProjection, bind_evidence_projection

logger = logging.getLogger(__name__)

GetSuperAgent = Callable[[], Awaitable[Any]]
GetWorkflowRuntime = Callable[[], Awaitable[Any]]


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

    async with session_factory() as session:
        event_status = await session.scalar(
            select(orm.SecurityEvent.status).where(orm.SecurityEvent.event_id == event_id)
        )
    status_value = str(event_status or "")
    values = snapshot.values

    if status_value == EventStatus.VERIFYING.value:
        if values.get("halted"):
            await graph.aupdate_state(
                config,
                {"halted": False},
                as_node=NODE_VERIFY,
            )
        if values.get("execution_substate") == ExecutionSubstate.WAITING_WRITEBACK.value:
            await runtime.set_execution_substate(
                event_id,
                ExecutionSubstate.WAITING_WRITEBACK,
                event_status=EventStatus.VERIFYING,
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
        logger.warning(
            "resume_investigation: no checkpoint for event=%s; skipping full restart",
            event_id,
        )
        return

    projection = EvidenceProjection(session_factory)
    with bind_evidence_projection(projection):
        await invoke_investigation_graph(graph, None, config)


__all__ = [
    "prepare_graph_resume_state",
    "resume_investigation_from_checkpoint",
]
