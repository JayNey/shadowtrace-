"""Celery redelivery + lease fencing helpers (ISSUE-117 / #622 Phase B).

When ``task_acks_late`` and ``task_reject_on_worker_lost`` are enabled, a worker
crash before ack requeues the task.  Investigation tasks use a **stable**
lease owner derived from the Celery ``task_id`` so redeliveries of the same
task compete fairly with the original delivery via ``EventLease`` fencing.
"""

from __future__ import annotations

import logging

from app.core.errors import DependencyUnavailableError
from app.models.enums import EventStatus

logger = logging.getLogger(__name__)

# Celery states that require manual/event lookup rather than trusting task result.
_UNKNOWN_LOOKUP_STATES: frozenset[str] = frozenset({"RETRY", "REVOKED"})

# Event statuses that must not re-run investigation on broker redelivery.
# Covers analysis-only completion (REPORTING) and post-response phases when
# ``include_response_execution=true`` (WAITING_APPROVAL / EXECUTING_RESPONSE / VERIFYING).
REDELIVERY_TERMINAL_EVENT_STATUSES: frozenset[EventStatus] = frozenset(
    {
        EventStatus.CLOSED,
        EventStatus.FAILED,
        EventStatus.REPORTING,
        EventStatus.CONTAINED,
        EventStatus.WAITING_APPROVAL,
        EventStatus.EXECUTING_RESPONSE,
        EventStatus.VERIFYING,
    }
)


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


async def should_skip_redelivered_investigation(event_id: str) -> bool:
    """Return True when broker redelivery must not re-run investigation.

    Covers crash-after-complete-before-ack: the first delivery finished and
    released the lease, but the worker died before Celery acked the task.

    When event lookup is unavailable, returns True (fail-safe skip) so a
    redelivery does not blindly re-run SuperAgent.
    """
    from app.api.v1.deps import get_event_service

    try:
        event_service = await get_event_service()
        event = await event_service.get_event(event_id)
    except DependencyUnavailableError:
        logger.warning(
            "redelivery skip lookup degraded for event=%s — skipping re-run (fail-safe)",
            event_id,
        )
        return True
    except Exception:
        logger.warning(
            "redelivery skip lookup failed for event=%s — skipping re-run (fail-safe)",
            event_id,
            exc_info=True,
        )
        return True
    if event is None:
        return False
    return event.status in REDELIVERY_TERMINAL_EVENT_STATUSES


__all__ = [
    "REDELIVERY_TERMINAL_EVENT_STATUSES",
    "celery_task_owner_id",
    "normalize_public_task_state",
    "should_skip_redelivered_investigation",
]
