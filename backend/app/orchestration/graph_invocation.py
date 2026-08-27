"""Track active LangGraph investigation invocations (ISSUE-296).

Nested ``resume_investigation`` / checkpoint continuation must not re-enter the
same event graph while a node is still on the call stack — otherwise approval
and resume hooks fork duplicate execution and amplify failed→failed loops.
Deferred nested resumes are flushed after the active bind exits so writeback
and approval wakeups are not dropped.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from contextvars import ContextVar

from celery.exceptions import SoftTimeLimitExceeded

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
NestedResumeDurabilityWriter = Callable[[str, str], Awaitable[None]]
LeaseHeldProbe = Callable[[str], Awaitable[bool]]
NestedWakeupKicker = Callable[[str], Awaitable[None]]
_nested_resume_runner: NestedResumeRunner | None = None
_nested_resume_failure_handler: NestedResumeFailureHandler | None = None
_nested_resume_durability_writer: NestedResumeDurabilityWriter | None = None
_lease_held_probe: LeaseHeldProbe | None = None
_nested_wakeup_kicker: NestedWakeupKicker | None = None


class NestedGraphResumeError(RuntimeError):
    """Deferred nested resume could not be flushed fail-closed."""

    def __init__(
        self,
        message: str,
        *,
        event_id: str,
        pending: list[str],
        error_type: str = "nested_resume_no_runner",
    ) -> None:
        super().__init__(message)
        self.event_id = event_id
        self.pending = pending
        self.error_type = error_type


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


def set_nested_resume_durability_writer(
    writer: NestedResumeDurabilityWriter | None,
) -> None:
    """Install durable nested-wakeup persistence (graph_resume_intent)."""
    global _nested_resume_durability_writer
    _nested_resume_durability_writer = writer


def get_nested_resume_durability_writer() -> NestedResumeDurabilityWriter | None:
    return _nested_resume_durability_writer


def set_investigation_lease_held_probe(probe: LeaseHeldProbe | None) -> None:
    """Install Redis EventLease ownership probe for nested wakeup gating."""
    global _lease_held_probe
    _lease_held_probe = probe


def get_investigation_lease_held_probe() -> LeaseHeldProbe | None:
    return _lease_held_probe


def set_nested_wakeup_lease_release_kicker(kicker: NestedWakeupKicker | None) -> None:
    """Install post-release dispatcher for PENDING/RETRY nested wakeups."""
    global _nested_wakeup_kicker
    _nested_wakeup_kicker = kicker


def get_nested_wakeup_lease_release_kicker() -> NestedWakeupKicker | None:
    return _nested_wakeup_kicker


def clear_nested_resume_hooks() -> None:
    """Drop process-level nested-resume hooks (tests / reset_deps)."""
    set_nested_resume_runner(None)
    set_nested_resume_failure_handler(None)
    set_nested_resume_durability_writer(None)
    set_investigation_lease_held_probe(None)
    set_nested_wakeup_lease_release_kicker(None)


async def investigation_lease_is_held(event_id: str) -> bool:
    """True when Redis EventLease is held for *event_id*.

    Missing probe (unit tests without deps) is treated as not held so existing
    in-process fixtures keep dispatching. Probe errors fail-closed as held so
    a second graph cannot start while ownership is unknown.
    """
    probe = _lease_held_probe
    if probe is None:
        return False
    try:
        return bool(await probe(event_id))
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.warning(
            "investigation lease probe failed event=%s; treating as held",
            event_id,
            exc_info=True,
        )
        return True


async def kick_nested_wakeup_after_lease_release(event_id: str) -> None:
    """Dispatch a durable nested wakeup now that EventLease is gone.

    No-op when the production kicker is not installed. Failures are logged
    rather than raised so lease-release ``finally`` blocks cannot poison the
    parent investigation.
    """
    kicker = _nested_wakeup_kicker
    if kicker is None:
        return
    try:
        await kicker(event_id)
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception(
            "nested wakeup kick after lease release failed event=%s",
            event_id,
        )


async def persist_nested_graph_wakeup(
    event_id: str,
    reason: str = "nested_wakeup",
) -> bool:
    """Enqueue a durable nested graph wakeup.

    Ordinary writer failures are logged and return ``False``.
    ``CancelledError`` always propagates so bind/cancel cannot drop a wakeup
    by swallowing cancellation.
    """
    writer = _nested_resume_durability_writer
    if writer is None:
        logger.error(
            "nested graph wakeup has no durability writer event=%s reason=%s",
            event_id,
            reason,
        )
        return False
    try:
        await writer(event_id, reason)
        return True
    except asyncio.CancelledError:
        logger.warning(
            "nested graph wakeup persist cancelled event=%s reason=%s",
            event_id,
            reason,
        )
        raise
    except Exception:
        logger.exception(
            "nested graph wakeup persist failed event=%s reason=%s",
            event_id,
            reason,
        )
        return False


async def _persist_pending_nested_wakeups(pending: list[str], reason: str) -> None:
    for resume_event_id in pending:
        await persist_nested_graph_wakeup(resume_event_id, reason)


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


def _is_task_cancellation(exc: BaseException | None) -> bool:
    """True for CancelledError / KeyboardInterrupt / SystemExit unwind."""
    if exc is None:
        return False
    if isinstance(exc, asyncio.CancelledError):
        return True
    return not isinstance(exc, Exception)


def _persist_without_flush_reason(exc: BaseException | None) -> str | None:
    """Return a durable-wakeup reason when flush would be unsafe.

    SoftTimeLimit / worker revoke leave little time for an in-process resume;
    persist an intent so the dispatcher can replay after unbind.
    """
    if _is_task_cancellation(exc):
        return "nested_resume_cancelled"
    if isinstance(exc, SoftTimeLimitExceeded):
        return "nested_resume_soft_time_limit"
    return None


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
        await _persist_pending_nested_wakeups(pending, "nested_resume_no_runner")
        error = NestedGraphResumeError(
            "nested graph resume deferred with no runner",
            event_id=event_id,
            pending=pending,
        )
        for resume_event_id in pending:
            await _notify_nested_resume_failure(resume_event_id, error, [resume_event_id])
        return
    for resume_event_id in pending:
        if await investigation_lease_is_held(resume_event_id):
            logger.warning(
                "persist nested graph resume without flush; event lease held event=%s",
                resume_event_id,
            )
            await persist_nested_graph_wakeup(
                resume_event_id,
                "investigation_in_progress",
            )
            continue
        try:
            await runner(resume_event_id)
        except Exception as exc:
            from app.orchestration.graph_resume_observability import GraphResumeDeferredError

            if isinstance(exc, GraphResumeDeferredError):
                logger.warning(
                    "deferred nested graph resume not ready event=%s error_type=%s",
                    resume_event_id,
                    exc.error_type,
                )
                await persist_nested_graph_wakeup(resume_event_id, exc.error_type)
                continue
            logger.exception(
                "deferred nested graph resume failed event=%s",
                resume_event_id,
            )
            await persist_nested_graph_wakeup(resume_event_id, "nested_resume_flush_failed")
            await _notify_nested_resume_failure(resume_event_id, exc, [resume_event_id])
        except BaseException:
            remaining = pending[pending.index(resume_event_id) :]
            logger.warning(
                "deferred nested graph resume cancelled during flush event=%s remaining=%s",
                resume_event_id,
                remaining,
            )
            await asyncio.shield(
                _persist_pending_nested_wakeups(remaining, "nested_resume_cancelled")
            )
            raise


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
        persist_reason = _persist_without_flush_reason(yield_error)
        if pending and persist_reason is not None:
            logger.warning(
                "persist nested graph resume without flush event=%s reason=%s pending=%s",
                event_id,
                persist_reason,
                pending,
            )
            await asyncio.shield(_persist_pending_nested_wakeups(pending, persist_reason))
        else:
            try:
                await _flush_deferred_graph_resumes(event_id, pending)
            except BaseException as flush_error:
                flush_persist = _persist_without_flush_reason(flush_error)
                if pending and flush_persist is not None:
                    logger.warning(
                        "persist nested graph resume after flush cancel event=%s "
                        "reason=%s pending=%s",
                        event_id,
                        flush_persist,
                        pending,
                    )
                    await asyncio.shield(
                        _persist_pending_nested_wakeups(pending, flush_persist)
                    )
                if not isinstance(flush_error, Exception):
                    raise
                logger.exception(
                    "nested graph resume flush failed event=%s parent_graph_error=%s",
                    event_id,
                    yield_error is not None,
                )


__all__ = [
    "NestedGraphResumeError",
    "active_graph_event_id",
    "bind_investigation_graph",
    "clear_nested_resume_hooks",
    "defer_nested_graph_resume",
    "get_investigation_lease_held_probe",
    "get_nested_resume_durability_writer",
    "get_nested_resume_failure_handler",
    "get_nested_resume_runner",
    "get_nested_wakeup_lease_release_kicker",
    "investigation_lease_is_held",
    "is_in_investigation_graph",
    "kick_nested_wakeup_after_lease_release",
    "persist_nested_graph_wakeup",
    "set_investigation_lease_held_probe",
    "set_nested_resume_durability_writer",
    "set_nested_resume_failure_handler",
    "set_nested_resume_runner",
    "set_nested_wakeup_lease_release_kicker",
]
