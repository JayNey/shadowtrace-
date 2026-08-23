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
NestedResumeFailureHandler = Callable[[str, BaseException, list[str]], Awaitable[None]]
_nested_resume_runner: NestedResumeRunner | None = None
_nested_resume_failure_handler: NestedResumeFailureHandler | None = None


class NestedGraphResumeError(RuntimeError):
    """Deferred nested resume could not be flushed fail-closed."""

    def __init__(self, message: str, *, event_id: str, pending: list[str]) -> None:
        super().__init__(message)
        self.event_id = event_id
        self.pending = pending


def set_nested_resume_runner(runner: NestedResumeRunner | None) -> None:
    """Install the post-bind flusher used for nested resume wakeups."""
    global _nested_resume_runner
    _nested_resume_runner = runner


def get_nested_resume_runner() -> NestedResumeRunner | None:
    return _nested_resume_runner


def set_nested_resume_failure_handler(
    handler: NestedResumeFailureHandler | None,
) -> None:
    """Install observability for nested-resume flush failures."""
    global _nested_resume_failure_handler
    _nested_resume_failure_handler = handler


def get_nested_resume_failure_handler() -> NestedResumeFailureHandler | None:
    return _nested_resume_failure_handler


async def _notify_nested_resume_failure(
    event_id: str,
    exc: BaseException,
    pending: list[str],
) -> None:
    handler = _nested_resume_failure_handler
    if handler is None:
        return
    try:
        await handler(event_id, exc, pending)
    except Exception:
        logger.exception(
            "nested resume failure handler failed event=%s",
            event_id,
        )


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


async def _flush_deferred_graph_resumes(event_id: str, pending: list[str]) -> None:
    if not pending:
        return
    runner = _nested_resume_runner
    if runner is None:
        logger.error(
            "nested graph resume deferred with no runner event=%s pending=%s",
            event_id,
            pending,
        )
        error = NestedGraphResumeError(
            "nested graph resume deferred with no runner",
            event_id=event_id,
            pending=pending,
        )
        await _notify_nested_resume_failure(event_id, error, pending)
        raise error
    flush_error: BaseException | None = None
    for resume_event_id in pending:
        try:
            await runner(resume_event_id)
        except Exception as exc:
            logger.exception(
                "deferred nested graph resume failed event=%s",
                resume_event_id,
            )
            if flush_error is None:
                flush_error = exc
    if flush_error is not None:
        await _notify_nested_resume_failure(event_id, flush_error, pending)
        raise flush_error


@asynccontextmanager
async def bind_investigation_graph(event_id: str) -> AsyncIterator[None]:
    token = _active_graph_event_id.set(event_id)
    deferred_token = _deferred_graph_resumes.set(set())
    yield_error: BaseException | None = None
    try:
        yield
    except BaseException as exc:
        yield_error = exc
        raise
    finally:
        pending = list(_deferred_graph_resumes.get() or ())
        _active_graph_event_id.reset(token)
        _deferred_graph_resumes.reset(deferred_token)
        try:
            await _flush_deferred_graph_resumes(event_id, pending)
        except Exception as flush_error:
            if yield_error is None:
                raise flush_error
            logger.error(
                "nested graph resume flush failed after graph error event=%s",
                event_id,
            )


__all__ = [
    "NestedGraphResumeError",
    "active_graph_event_id",
    "bind_investigation_graph",
    "defer_nested_graph_resume",
    "get_nested_resume_failure_handler",
    "get_nested_resume_runner",
    "is_in_investigation_graph",
    "set_nested_resume_failure_handler",
    "set_nested_resume_runner",
]
