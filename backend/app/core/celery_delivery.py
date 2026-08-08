"""Celery redelivery + lease fencing helpers (ISSUE-117 / ISSUE-275).

When ``task_acks_late`` and ``task_reject_on_worker_lost`` are enabled, a worker
crash before ack requeues the task.  Investigation tasks use a **stable**
lease owner derived from the Celery ``task_id`` so redeliveries of the same
task compete fairly with the original delivery via ``EventLease`` fencing.

ISSUE-275: redelivery must distinguish three outcomes — terminal ACK,
transient lookup retry/reject, and intermediate resume/defer — without mixing
semantics into a single ``skip`` boolean.
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from app.core.errors import DependencyUnavailableError
from app.models.enums import EventStatus

logger = logging.getLogger(__name__)

RedeliverySkipReason = Literal["terminal_event"]

# Celery states that require manual/event lookup rather than trusting task result.
_UNKNOWN_LOOKUP_STATES: frozenset[str] = frozenset({"RETRY", "REVOKED"})

# Event statuses that are safe to ACK on broker redelivery without re-running work.
REDELIVERY_ACK_TERMINAL_STATUSES: frozenset[EventStatus] = frozenset(
    {
        EventStatus.CLOSED,
        EventStatus.FAILED,
        EventStatus.REPORTING,
        EventStatus.CONTAINED,
    }
)

# Backward-compatible alias for tests that still reference the old name.
REDELIVERY_TERMINAL_EVENT_STATUSES = REDELIVERY_ACK_TERMINAL_STATUSES

# Intermediate statuses that require durable handoff / checkpoint resume.
REDELIVERY_RESUME_STATUSES: frozenset[EventStatus] = frozenset(
    {
        EventStatus.WAITING_APPROVAL,
        EventStatus.EXECUTING_RESPONSE,
        EventStatus.VERIFYING,
        EventStatus.REPLANNING,
    }
)

LOOKUP_RETRY_MAX_ATTEMPTS = 5
DEFER_RETRY_MAX_ATTEMPTS = 8
LOOKUP_RETRY_BASE_SECONDS = 2.0
DEFER_RETRY_BASE_SECONDS = 5.0
LOOKUP_RETRY_HEADER = "x-redelivery-lookup-retries"
DEFER_RETRY_HEADER = "x-redelivery-defer-retries"

REDELIVERY_RECOVERY_FLAG = "celery_redelivery_recovery_needed"
REDELIVERY_RECOVERY_OPERATOR = "CeleryRedeliveryService"


class RedeliveryDecision(StrEnum):
    """Strongly typed redelivery outcome bound to Celery ack/retry behaviour."""

    ACK_TERMINAL = "ack_terminal"
    RETRY_LOOKUP = "retry_lookup"
    RESUME_OR_DEFER = "resume_or_defer"


class RedeliveryHandoffAction(StrEnum):
    """Handoff verification result for intermediate redelivery."""

    RESUME = "resume"
    RETRY_DEFER = "retry_defer"
    ACK_SKIP = "ack_skip"


@dataclass(frozen=True)
class RedeliveryHandoffVerdict:
    action: RedeliveryHandoffAction
    reason: str | None = None
    event_status: EventStatus | None = None


class RedeliveryLookupRetry(Exception):
    """Transient event lookup failure — Celery must retry/reject, not ack."""

    def __init__(self, event_id: str, *, attempt: int, cause: BaseException | None = None) -> None:
        super().__init__(f"redelivery lookup retry for event={event_id} attempt={attempt}")
        self.event_id = event_id
        self.attempt = attempt
        self.cause = cause


class RedeliveryDeferRetry(Exception):
    """Lease/contention deferral — Celery must retry/reject, not ack."""

    def __init__(
        self,
        event_id: str,
        *,
        reason: str,
        attempt: int,
    ) -> None:
        super().__init__(
            f"redelivery defer retry for event={event_id} reason={reason} attempt={attempt}"
        )
        self.event_id = event_id
        self.reason = reason
        self.attempt = attempt


def celery_task_owner_id(task_id: str) -> str:
    """Return a stable lease owner for a Celery task id (survives redelivery)."""
    normalized = (task_id or "").strip()
    if not normalized:
        raise ValueError("task_id is required for celery lease owner")
    return f"celery-{normalized}"


def normalize_public_task_state(celery_state: str) -> str:
    """Map internal Celery states to the public task status contract.

    ``UNKNOWN`` means the broker/task backend cannot confirm completion;
    callers should inspect ``event_id`` investigation status manually.
    """
    state = (celery_state or "PENDING").strip().upper()
    if state in _UNKNOWN_LOOKUP_STATES:
        return "UNKNOWN"
    return state


def _retry_header_count(headers: dict[str, object] | None, key: str) -> int:
    if not headers:
        return 0
    raw = headers.get(key, 0)
    try:
        return int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def lookup_retry_count(headers: dict[str, object] | None) -> int:
    return _retry_header_count(headers, LOOKUP_RETRY_HEADER)


def defer_retry_count(headers: dict[str, object] | None) -> int:
    return _retry_header_count(headers, DEFER_RETRY_HEADER)


def lookup_retry_countdown(attempt: int) -> float:
    """Bounded exponential backoff with jitter for lookup retries."""
    base = min(60.0, LOOKUP_RETRY_BASE_SECONDS * (2 ** max(attempt - 1, 0)))
    return base + random.uniform(0.0, base * 0.3)


def defer_retry_countdown(attempt: int) -> float:
    """Bounded exponential backoff with jitter for lease/contention deferrals."""
    base = min(120.0, DEFER_RETRY_BASE_SECONDS * (2 ** max(attempt - 1, 0)))
    return base + random.uniform(0.0, base * 0.3)


async def checkpoint_exists_for_event(event_id: str) -> bool:
    """Return True when a durable LangGraph checkpoint exists for *event_id*."""
    from app.api.v1.deps import _get_redis
    from app.orchestration.checkpointer import checkpoint_key_for_event

    redis_client = _get_redis()
    if not await redis_client.ping():
        return False
    raw = await redis_client.get_client().get(checkpoint_key_for_event(event_id))
    return raw is not None


async def evaluate_redelivered_investigation_decision(
    event_id: str,
) -> tuple[RedeliveryDecision, EventStatus | None]:
    """Classify broker redelivery without conflating terminal, lookup, and resume."""
    from app.api.v1.deps import get_event_service

    try:
        event_service = await get_event_service()
        event = await event_service.get_event(event_id)
    except DependencyUnavailableError as exc:
        logger.warning(
            "redelivery lookup degraded for event=%s — will retry (no ack)",
            event_id,
        )
        raise RedeliveryLookupRetry(event_id, attempt=0, cause=exc) from exc
    except RedeliveryLookupRetry:
        raise
    except Exception as exc:
        logger.warning(
            "redelivery lookup failed for event=%s — will retry (no ack)",
            event_id,
            exc_info=True,
        )
        raise RedeliveryLookupRetry(event_id, attempt=0, cause=exc) from exc

    if event is None:
        return RedeliveryDecision.RESUME_OR_DEFER, None
    if event.status in REDELIVERY_ACK_TERMINAL_STATUSES:
        return RedeliveryDecision.ACK_TERMINAL, event.status
    return RedeliveryDecision.RESUME_OR_DEFER, event.status


async def evaluate_redelivery_handoff(
    event_id: str,
    *,
    task_id: str,
    owner_id: str,
    event_status: EventStatus | None,
) -> RedeliveryHandoffVerdict:
    """Verify durable handoff before acking an intermediate redelivery."""
    from app.api.v1.deps import get_event_lease

    del task_id  # stable owner_id already binds to Celery task delivery id
    lease = get_event_lease()
    current_owner = await lease.get_owner(event_id)

    if current_owner == owner_id:
        return RedeliveryHandoffVerdict(
            RedeliveryHandoffAction.RESUME,
            reason="lease_owned_by_delivery",
            event_status=event_status,
        )

    if current_owner is not None:
        return RedeliveryHandoffVerdict(
            RedeliveryHandoffAction.RETRY_DEFER,
            reason="lease_held_by_other",
            event_status=event_status,
        )

    if event_status in REDELIVERY_RESUME_STATUSES:
        if await checkpoint_exists_for_event(event_id):
            return RedeliveryHandoffVerdict(
                RedeliveryHandoffAction.RESUME,
                reason="checkpoint_present",
                event_status=event_status,
            )
        return RedeliveryHandoffVerdict(
            RedeliveryHandoffAction.RETRY_DEFER,
            reason="checkpoint_missing",
            event_status=event_status,
        )

    try:
        acquired = await lease.acquire(event_id, owner_id)
    except DependencyUnavailableError:
        return RedeliveryHandoffVerdict(
            RedeliveryHandoffAction.RETRY_DEFER,
            reason="lease_store_unavailable",
            event_status=event_status,
        )

    if acquired:
        return RedeliveryHandoffVerdict(
            RedeliveryHandoffAction.RESUME,
            reason="lease_acquired",
            event_status=event_status,
        )

    return RedeliveryHandoffVerdict(
        RedeliveryHandoffAction.RETRY_DEFER,
        reason="lease_contention",
        event_status=event_status,
    )


async def record_redelivery_recovery_needed(
    event_id: str,
    *,
    task_id: str,
    reason: str,
) -> None:
    """Persist durable manual-recovery signal when redelivery retries exhaust."""
    from sqlalchemy import select

    from app.api.v1.deps import _get_degraded_flags, _get_session_factory
    from app.db import models as orm

    flag_value = f"{reason}|task_id={task_id}"
    degraded_flags = _get_degraded_flags()
    if degraded_flags is not None:
        try:
            await degraded_flags.set_flag(
                event_id,
                REDELIVERY_RECOVERY_FLAG,
                flag_value,
                writer=REDELIVERY_RECOVERY_OPERATOR,
            )
        except Exception:
            logger.exception(
                "failed to set %s degraded flag event=%s",
                REDELIVERY_RECOVERY_FLAG,
                event_id,
            )

    session_factory = _get_session_factory()
    audit_reason = (
        f"celery_redelivery_recovery_needed:reason={reason[:200]}:task_id={task_id}"
    )
    async with session_factory() as session:
        async with session.begin():
            event_status = await session.scalar(
                select(orm.SecurityEvent.status).where(
                    orm.SecurityEvent.event_id == event_id
                )
            )
            session.add(
                orm.EventAuditLog(
                    event_id=event_id,
                    from_status=str(event_status) if event_status else None,
                    to_status=str(event_status) if event_status else None,
                    operator=REDELIVERY_RECOVERY_OPERATOR,
                    reason=audit_reason[:4096],
                )
            )
    logger.error(
        "celery redelivery recovery needed event=%s task=%s reason=%s",
        event_id,
        task_id,
        reason,
    )


# --------------------------------------------------------------------------- #
# Legacy helpers — retained for incremental migration; prefer typed decision API.
# --------------------------------------------------------------------------- #


async def evaluate_redelivered_investigation_skip(
    event_id: str,
) -> tuple[bool, RedeliverySkipReason | None]:
    """Return whether broker redelivery must skip, and a stable skip reason."""
    try:
        decision, _status = await evaluate_redelivered_investigation_decision(event_id)
    except RedeliveryLookupRetry:
        raise
    if decision is RedeliveryDecision.ACK_TERMINAL:
        return True, "terminal_event"
    return False, None


async def should_skip_redelivered_investigation(event_id: str) -> bool:
    """Return True when broker redelivery must not re-run investigation."""
    skip, _reason = await evaluate_redelivered_investigation_skip(event_id)
    return skip


__all__ = [
    "DEFER_RETRY_HEADER",
    "DEFER_RETRY_MAX_ATTEMPTS",
    "LOOKUP_RETRY_HEADER",
    "LOOKUP_RETRY_MAX_ATTEMPTS",
    "REDELIVERY_ACK_TERMINAL_STATUSES",
    "REDELIVERY_RECOVERY_FLAG",
    "REDELIVERY_RECOVERY_OPERATOR",
    "REDELIVERY_RESUME_STATUSES",
    "REDELIVERY_TERMINAL_EVENT_STATUSES",
    "RedeliveryDecision",
    "RedeliveryDeferRetry",
    "RedeliveryHandoffAction",
    "RedeliveryHandoffVerdict",
    "RedeliveryLookupRetry",
    "RedeliverySkipReason",
    "celery_task_owner_id",
    "checkpoint_exists_for_event",
    "defer_retry_count",
    "defer_retry_countdown",
    "evaluate_redelivered_investigation_decision",
    "evaluate_redelivered_investigation_skip",
    "evaluate_redelivery_handoff",
    "lookup_retry_count",
    "lookup_retry_countdown",
    "normalize_public_task_state",
    "record_redelivery_recovery_needed",
    "should_skip_redelivered_investigation",
]
