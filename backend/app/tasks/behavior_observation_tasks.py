"""Celery periodic retry for BehaviorObservation projection failures (ISSUE-156)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from sqlalchemy import func, select

from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.db import models as orm
from app.db.session import get_session_factory
from app.models.behavior_observation import BehaviorObservationProjectionStatus
from app.services.behavior_observation_service import BehaviorObservationService

logger = logging.getLogger(__name__)

RETRY_PENDING_TASK = "shadowtrace.behavior_observation.retry_pending"
INGESTION_QUEUE = "ingestion"


async def _snapshot_failure_counts() -> tuple[int, int]:
    """Return global (pending_retry, dead_letter) counts in one query."""
    factory = get_session_factory()
    open_statuses = (
        BehaviorObservationProjectionStatus.PENDING_RETRY.value,
        BehaviorObservationProjectionStatus.DEAD_LETTER.value,
    )
    async with factory() as session:
        rows = await session.execute(
            select(
                orm.BehaviorObservationProjectionFailure.status,
                func.count(),
            )
            .where(orm.BehaviorObservationProjectionFailure.status.in_(open_statuses))
            .group_by(orm.BehaviorObservationProjectionFailure.status)
        )
    by_status = {str(status): int(count) for status, count in rows.all()}
    return (
        by_status.get(BehaviorObservationProjectionStatus.PENDING_RETRY.value, 0),
        by_status.get(BehaviorObservationProjectionStatus.DEAD_LETTER.value, 0),
    )


async def _retry_pending_async(*, limit: int) -> dict[str, Any]:
    factory = get_session_factory()
    service = BehaviorObservationService(factory)
    pending_before, dead_letter_before = await _snapshot_failure_counts()
    retried = await service.retry_pending(limit=limit)
    pending_after, dead_letter_after = await _snapshot_failure_counts()
    result = {
        "retried": retried,
        "limit": limit,
        "pending_retry_before": pending_before,
        "pending_retry_after": pending_after,
        "dead_letter_before": dead_letter_before,
        "dead_letter_after": dead_letter_after,
    }
    logger.info(
        "behavior_observation.retry_pending completed retried=%s pending=%s->%s dead_letter=%s->%s",
        retried,
        pending_before,
        pending_after,
        dead_letter_before,
        dead_letter_after,
    )
    return result


@celery_app.task(  # type: ignore[untyped-decorator]
    name=RETRY_PENDING_TASK,
    acks_late=True,
    soft_time_limit=120,
    queue=INGESTION_QUEUE,
)
def retry_behavior_observation_pending(limit: int | None = None) -> dict[str, Any]:
    """Periodic retry for transient BehaviorObservation projection failures."""
    settings = get_settings()
    batch_limit = limit if limit is not None else settings.behavior_observation_retry_batch_limit
    return asyncio.run(_retry_pending_async(limit=batch_limit))


__all__ = ["INGESTION_QUEUE", "RETRY_PENDING_TASK", "retry_behavior_observation_pending"]
