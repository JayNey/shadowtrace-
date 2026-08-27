"""CLOSED → MemoryAgent consolidation (graph, HTTP close, and legacy SuperAgent).

SuperAgent schedules memory only when ``investigate()`` itself returns CLOSED
and no investigation graph is wired. Approval resume continues the LangGraph
checkpoint and never re-enters that epilogue, so ``close_node`` (and HTTP
close) must own the same best-effort pass.

Callers must spawn, not await, so MemoryAgent LLM work cannot consume the
parent request time budget. Celery ``asyncio.run`` wrappers drain spawned
tasks before the loop tears down; HTTP keeps the long-lived event loop.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.models.agent_io import MemoryAgentInput
from app.models.enums import EventStatus

logger = logging.getLogger(__name__)

_MEMORY_TASKS: set[asyncio.Task[None]] = set()
_MEMORY_DRAIN_TIMEOUT_S = 180.0


def _event_status(context: Any) -> EventStatus | None:
    event = getattr(context, "event", None)
    if event is None:
        return None
    status = getattr(event, "status", None)
    if isinstance(status, EventStatus):
        return status
    if isinstance(status, str):
        try:
            return EventStatus(status)
        except ValueError:
            return None
    return None


async def consolidate_memory_after_close(
    event_id: str,
    *,
    memory_agent: Any,
    context_store: Any,
    degraded_flags: Any | None = None,
    writer: str = "InvestigationGraph",
) -> None:
    """Run MemoryAgent after a durable CLOSED transition. Failures never reopen the event."""
    if memory_agent is None or context_store is None:
        return
    try:
        refresh = getattr(context_store, "refresh_closed_snapshot", None)
        if callable(refresh):
            try:
                context = await refresh(event_id)
            except Exception:
                logger.warning(
                    "memory_after_close snapshot refresh failed event=%s",
                    event_id,
                    exc_info=True,
                )
                context = await context_store.get_full_context(event_id)
        else:
            context = await context_store.get_full_context(event_id)
        status = _event_status(context)
        if status is not EventStatus.CLOSED:
            logger.info(
                "memory_after_close skipped; snapshot not CLOSED event=%s status=%s",
                event_id,
                status.value if isinstance(status, EventStatus) else status,
            )
            return
        from app.agents.super_agent import _investigation_result_from_context

        result = _investigation_result_from_context(context)
        await memory_agent.execute(
            MemoryAgentInput(event_id=event_id, investigation_result=result)
        )
    except Exception as exc:
        logger.warning(
            "memory_after_close consolidation failed event=%s",
            event_id,
            exc_info=True,
        )
        if degraded_flags is not None:
            try:
                await degraded_flags.set_flag(
                    event_id,
                    "memory_after_close_failed",
                    type(exc).__name__,
                    writer=writer,
                )
            except Exception:
                logger.warning(
                    "memory_after_close failed to record degraded flag event=%s",
                    event_id,
                    exc_info=True,
                )


def spawn_memory_after_close(
    event_id: str,
    *,
    memory_agent: Any,
    context_store: Any,
    degraded_flags: Any | None = None,
    writer: str = "InvestigationGraph",
) -> asyncio.Task[None] | None:
    """Fire-and-forget consolidation; holds a task ref so the loop cannot GC it."""
    if memory_agent is None or context_store is None:
        return None
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        logger.warning(
            "memory_after_close spawn skipped; no running loop event=%s",
            event_id,
        )
        return None
    task = loop.create_task(
        consolidate_memory_after_close(
            event_id,
            memory_agent=memory_agent,
            context_store=context_store,
            degraded_flags=degraded_flags,
            writer=writer,
        ),
        name=f"memory:{event_id}",
    )
    _MEMORY_TASKS.add(task)
    task.add_done_callback(_MEMORY_TASKS.discard)
    return task


async def drain_memory_after_close_tasks(*, timeout_s: float = _MEMORY_DRAIN_TIMEOUT_S) -> None:
    """Finish spawned consolidations before a short-lived asyncio.run() tears down."""
    pending = [task for task in tuple(_MEMORY_TASKS) if not task.done()]
    if not pending:
        return
    _done, still = await asyncio.wait(pending, timeout=timeout_s)
    for task in still:
        logger.warning("memory_after_close drain timed out task=%s", task.get_name())
