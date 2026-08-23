"""Track active LangGraph investigation invocations (ISSUE-296).

Nested ``resume_investigation`` / checkpoint continuation must not re-enter the
same event graph while a node is still on the call stack — otherwise approval
and resume hooks fork duplicate execution and amplify failed→failed loops.
Deferred nested resumes are flushed after the active bind exits so writeback
and approval wakeups are not dropped.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from contextvars import ContextVar

logger = logging.getLogger(__name__)

_active_graph_event_id: ContextVar[str | None] = ContextVar(
    "investigation_graph_event_id",
    default=None,
)
_deferred_graph_resumes: ContextVar[set[str] | None] = ContextVar(
    "deferred_graph_resumes",
    default=None,
)

NestedResumeRunner = Callable[[str], Awaitable[None]]
_nested_resume_runner: NestedResumeRunner | None = None


def set_nested_resume_runner(runner: NestedResumeRunner | None) -> None:
    """Install the post-bind flusher used for nested resume wakeups."""
    global _nested_resume_runner
    _nested_resume_runner = runner


def active_graph_event_id() -> str | None:
    return _active_graph_event_id.get()


def is_in_investigation_graph(*, event_id: str | None = None) -> bool:
    active = _active_graph_event_id.get()
    if active is None:
        return False
    if event_id is None:
        return True
    return active == event_id


def defer_nested_graph_resume(event_id: str) -> bool:
    """Remember *event_id* to resume after the active graph unbinds.

    Returns ``True`` when the event is currently bound and the wakeup was
    queued. Returns ``False`` when no graph is active for this event.
    """
    if not is_in_investigation_graph(event_id=event_id):
        return False
    pending = _deferred_graph_resumes.get()
    if pending is None:
        pending = set()
        _deferred_graph_resumes.set(pending)
    pending.add(event_id)
    return True


@asynccontextmanager
async def bind_investigation_graph(event_id: str) -> AsyncIterator[None]:
    token = _active_graph_event_id.set(event_id)
    deferred_token = _deferred_graph_resumes.set(set())
    try:
        yield
    finally:
        pending = list(_deferred_graph_resumes.get() or ())
        _active_graph_event_id.reset(token)
        _deferred_graph_resumes.reset(deferred_token)
        runner = _nested_resume_runner
        if runner is None:
            if pending:
                logger.warning(
                    "nested graph resume deferred with no runner event=%s pending=%s",
                    event_id,
                    pending,
                )
        else:
            for resume_event_id in pending:
                try:
                    await runner(resume_event_id)
                except Exception:
                    logger.exception(
                        "deferred nested graph resume failed event=%s",
                        resume_event_id,
                    )


__all__ = [
    "active_graph_event_id",
    "bind_investigation_graph",
    "defer_nested_graph_resume",
    "is_in_investigation_graph",
    "set_nested_resume_runner",
]
