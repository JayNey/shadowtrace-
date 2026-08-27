"""Celery tasks for durable auto-investigate intent dispatch (ISSUE-108 / #612)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.core.celery_app import celery_app
from app.core.celery_health import stamp_investigation_intent_beat_heartbeat
from app.core.redis_client import RedisClient
from app.db.session import get_session_factory
from app.services.auto_investigate_policy import AutoInvestigatePolicyService
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import create_degraded_flag_service
from app.services.investigation_intent_service import InvestigationIntentService

logger = logging.getLogger(__name__)

DISPATCH_INTENTS_TASK = "shadowtrace.dispatch_investigation_intents"
RECONCILE_INTENTS_TASK = "shadowtrace.reconcile_investigation_intents"
INTENT_QUEUE = "investigation"


async def _dispatch_once_async() -> dict[str, Any]:
    factory = get_session_factory()
    redis = RedisClient()
    try:
        store = EventContextStore(redis, factory)
        degraded = create_degraded_flag_service(store, factory)
        service = InvestigationIntentService(
            factory,
            policy=AutoInvestigatePolicyService(),
            degraded_flags=degraded,
        )
        published = await service.claim_and_publish_batch(limit=10)
        await stamp_investigation_intent_beat_heartbeat(redis)
        return {"published": published}
    finally:
        await redis.aclose()


async def _reconcile_once_async() -> dict[str, Any]:
    factory = get_session_factory()
    redis = RedisClient()
    try:
        store = EventContextStore(redis, factory)
        degraded = create_degraded_flag_service(store, factory)
        service = InvestigationIntentService(
            factory,
            policy=AutoInvestigatePolicyService(),
            degraded_flags=degraded,
        )
        reconciled = await service.reconcile_stale(limit=20)
        await stamp_investigation_intent_beat_heartbeat(redis)
        return {"reconciled": reconciled}
    finally:
        await redis.aclose()


@celery_app.task(  # type: ignore[untyped-decorator]
    name=DISPATCH_INTENTS_TASK,
    acks_late=True,
    soft_time_limit=120,
    queue=INTENT_QUEUE,
)
def dispatch_pending_investigation_intents() -> dict[str, Any]:
    """Claim pending auto-investigate intents and publish to the broker."""
    return asyncio.run(_dispatch_once_async())


@celery_app.task(  # type: ignore[untyped-decorator]
    name=RECONCILE_INTENTS_TASK,
    acks_late=True,
    soft_time_limit=120,
    queue=INTENT_QUEUE,
)
def reconcile_investigation_intents() -> dict[str, Any]:
    """Recover stale intents and materialize aged provisional events."""
    return asyncio.run(_reconcile_once_async())


__all__ = [
    "DISPATCH_INTENTS_TASK",
    "INTENT_QUEUE",
    "RECONCILE_INTENTS_TASK",
    "dispatch_pending_investigation_intents",
    "reconcile_investigation_intents",
]
