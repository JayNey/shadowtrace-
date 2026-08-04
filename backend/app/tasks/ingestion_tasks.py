"""Celery ingestion scheduler tasks (ISSUE-107 / #611)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.core.celery_app import celery_app
from app.core.redis_client import RedisClient
from app.db.session import get_session_factory
from app.ingestion.ingestion_scheduler import IngestionScheduler
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import create_degraded_flag_service
from app.services.event_service import EventService

logger = logging.getLogger(__name__)

POLL_SOURCES_TASK = "shadowtrace.poll_sources"
INGESTION_QUEUE = "ingestion"


async def _run_poll_sources_async() -> dict[str, Any]:
    factory = get_session_factory()
    redis = RedisClient()
    try:
        store = EventContextStore(redis, factory)
        degraded = create_degraded_flag_service(store, factory)
        from app.services.auto_investigate_policy import AutoInvestigatePolicyService
        from app.services.investigation_intent_service import InvestigationIntentService

        intent_service = InvestigationIntentService(
            factory,
            policy=AutoInvestigatePolicyService(),
            degraded_flags=degraded,
        )
        events = EventService(
            factory,
            store,
            degraded_flags=degraded,
            investigation_intent=intent_service,
        )
        scheduler = IngestionScheduler(
            session_factory=factory,
            event_service=events,
            redis_client=redis,
        )
        result = await scheduler.run_once()
        return result.model_dump(mode="json")
    finally:
        await redis.aclose()


@celery_app.task(  # type: ignore[untyped-decorator]
    name=POLL_SOURCES_TASK,
    acks_late=True,
    soft_time_limit=120,
    queue=INGESTION_QUEUE,
)
def poll_sources() -> dict[str, Any]:
    """Periodic Mock XDR poll — ingestion only, no investigate (ISSUE-108)."""
    return asyncio.run(_run_poll_sources_async())


__all__ = ["INGESTION_QUEUE", "POLL_SOURCES_TASK", "poll_sources"]
