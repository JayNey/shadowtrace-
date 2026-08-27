"""Celery tasks for durable graph resume intent dispatch (ISSUE-277 / #873)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.core.celery_app import celery_app

logger = logging.getLogger(__name__)

DISPATCH_GRAPH_RESUME_INTENTS_TASK = "shadowtrace.dispatch_graph_resume_intents"
RECONCILE_GRAPH_RESUME_INTENTS_TASK = "shadowtrace.reconcile_graph_resume_intents"
GRAPH_RESUME_QUEUE = "investigation"


async def _get_service() -> Any:
    from app.api.v1.deps import ensure_nested_resume_runner, get_manual_resolution_service

    ensure_nested_resume_runner()
    return await get_manual_resolution_service()


async def _dispatch_once_async() -> dict[str, Any]:
    service = await _get_service()
    ran = await service.claim_and_run_batch(limit=20)
    return {"ran": ran}


async def _reconcile_once_async() -> dict[str, Any]:
    service = await _get_service()
    reconciled = await service.reconcile_stale(limit=50)
    ran = await service.claim_and_run_batch(limit=20)
    return {"reconciled": reconciled, "ran": ran}


@celery_app.task(  # type: ignore[untyped-decorator]
    name=DISPATCH_GRAPH_RESUME_INTENTS_TASK,
    acks_late=True,
    soft_time_limit=120,
    queue=GRAPH_RESUME_QUEUE,
)
def dispatch_pending_graph_resume_intents() -> dict[str, Any]:
    """Claim PENDING/RETRY graph resume intents and run fenced resume."""
    return asyncio.run(_dispatch_once_async())


@celery_app.task(  # type: ignore[untyped-decorator]
    name=RECONCILE_GRAPH_RESUME_INTENTS_TASK,
    acks_late=True,
    soft_time_limit=120,
    queue=GRAPH_RESUME_QUEUE,
)
def reconcile_graph_resume_intents() -> dict[str, Any]:
    """Recover stale CLAIMED/STARTED intents then drain PENDING/RETRY."""
    return asyncio.run(_reconcile_once_async())


__all__ = [
    "DISPATCH_GRAPH_RESUME_INTENTS_TASK",
    "GRAPH_RESUME_QUEUE",
    "RECONCILE_GRAPH_RESUME_INTENTS_TASK",
    "dispatch_pending_graph_resume_intents",
    "reconcile_graph_resume_intents",
]
