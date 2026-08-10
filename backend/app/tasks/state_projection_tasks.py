"""Celery tasks for ISSUE-285 post-commit projection repair."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.core.celery_app import celery_app
from app.core.redis_client import RedisClient
from app.db.session import get_session_factory
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import create_degraded_flag_service
from app.services.event_audit_log_service import EventAuditLogService
from app.services.state_machine_service import StateMachineService

logger = logging.getLogger(__name__)

REPAIR_STATE_TRANSITION_PROJECTIONS_TASK = "shadowtrace.repair_state_transition_projections"
EXECUTION_QUEUE = "investigation"


async def _build_state_machine() -> StateMachineService:
    factory = get_session_factory()
    redis = RedisClient()
    store = EventContextStore(redis, factory)
    degraded = create_degraded_flag_service(store, factory)
    audit = EventAuditLogService(factory)
    return StateMachineService(
        factory,
        store,
        audit_log=audit,
        degraded_flags=degraded,
    )


async def _repair_once_async(*, limit: int = 20) -> dict[str, Any]:
    redis = RedisClient()
    try:
        service = await _build_state_machine()
        result = await service.repair_degraded_projections(limit=limit)
        logger.info(
            "repair_state_transition_projections scanned=%s repaired=%s exhausted=%s",
            result["scanned"],
            result["repaired"],
            result["exhausted"],
        )
        return result
    finally:
        await redis.aclose()


@celery_app.task(  # type: ignore[untyped-decorator]
    name=REPAIR_STATE_TRANSITION_PROJECTIONS_TASK,
    acks_late=True,
    soft_time_limit=120,
    queue=EXECUTION_QUEUE,
)
def repair_state_transition_projections(limit: int = 20) -> dict[str, Any]:
    """Scan ``state_transition_projection_degraded`` markers and repair projections."""
    return asyncio.run(_repair_once_async(limit=limit))


__all__ = [
    "EXECUTION_QUEUE",
    "REPAIR_STATE_TRANSITION_PROJECTIONS_TASK",
    "repair_state_transition_projections",
]
