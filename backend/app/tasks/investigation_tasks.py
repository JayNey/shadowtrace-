"""Celery investigation task (ISSUE-056)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from celery import uuid as celery_uuid
from celery.exceptions import SoftTimeLimitExceeded
from kombu.exceptions import OperationalError

from app.core.celery_app import celery_app
from app.core.celery_delivery import (
    celery_task_owner_id,
    normalize_public_task_state,
    should_skip_redelivered_investigation,
)
from app.core.errors import DependencyUnavailableError, InvestigationInProgressError
from app.core.redis_client import RedisClient

logger = logging.getLogger(__name__)

TASK_NAME = "shadowtrace.run_investigation"
TASK_QUEUE = "investigation"
TASK_META_PREFIX = "shadowtrace:celery:task:"
TASK_META_TTL_SECONDS = 86_400


def _task_meta_key(task_id: str) -> str:
    return f"{TASK_META_PREFIX}{task_id}"


async def register_task_metadata(
    task_id: str,
    event_id: str,
    *,
    redis_url: str | None = None,
) -> None:
    """Persist ``task_id → event_id`` so status queries can resolve unknown tasks."""
    from app.core.config import get_settings

    url = redis_url or get_settings().redis_url
    client = RedisClient(url=url)
    try:
        if not await client.ping():
            raise DependencyUnavailableError(
                message="task metadata store unavailable",
                error_code="dependency_unavailable",
                details={"dependency": "redis"},
            )
        redis = client.get_client()
        await redis.set(_task_meta_key(task_id), event_id, ex=TASK_META_TTL_SECONDS)
    finally:
        await client.aclose()


async def delete_task_metadata(task_id: str, *, redis_url: str | None = None) -> None:
    """Best-effort cleanup when Celery dispatch fails after metadata registration."""
    from app.core.config import get_settings

    url = redis_url or get_settings().redis_url
    client = RedisClient(url=url)
    try:
        if await client.ping():
            redis = client.get_client()
            await redis.delete(_task_meta_key(task_id))
    finally:
        await client.aclose()


async def lookup_task_event_id(task_id: str) -> str | None:
    from app.core.config import get_settings

    client = RedisClient(url=get_settings().redis_url)
    try:
        if not await client.ping():
            return None
        redis = client.get_client()
        value = await redis.get(_task_meta_key(task_id))
        if value is None:
            return None
        return value.decode() if isinstance(value, bytes) else str(value)
    finally:
        await client.aclose()


async def execute_investigation(
    event_id: str,
    *,
    include_response_execution: bool = False,
    owner_id: str | None = None,
) -> dict[str, str]:
    """Run SuperAgent investigation (called from Celery worker via ``asyncio.run``)."""
    from app.api.v1.deps import _get_session_factory, get_super_agent
    from app.services.evidence_projection import EvidenceProjection, bind_evidence_projection

    try:
        agent = await get_super_agent()
        projection = EvidenceProjection(_get_session_factory())
        with bind_evidence_projection(projection):
            await agent.investigate(
                event_id,
                owner_id=owner_id,
                include_response_execution=include_response_execution,
            )
        return {"status": "completed", "event_id": event_id}
    except InvestigationInProgressError:
        logger.info(
            "run_investigation skipped for event=%s — lease already held",
            event_id,
        )
        return {"status": "skipped", "event_id": event_id}


async def dispatch_investigation(
    event_id: str,
    *,
    include_response_execution: bool = False,
) -> str:
    """Enqueue ``run_investigation`` and return the Celery task id."""
    task_id = str(celery_uuid())
    await register_task_metadata(task_id, event_id)
    try:
        run_investigation.apply_async(
            args=[event_id],
            kwargs={"include_response_execution": include_response_execution},
            task_id=task_id,
            queue=TASK_QUEUE,
        )
    except (OperationalError, OSError, ConnectionError) as exc:
        await delete_task_metadata(task_id)
        raise DependencyUnavailableError(
            message="celery broker unavailable",
            error_code="task_unavailable",
            details={"dependency": "celery_broker", "event_id": event_id},
        ) from exc
    return task_id


async def resolve_task_state(task_id: str) -> tuple[str, str | None]:
    """Return Celery state and optional event_id for a dispatched task."""
    from celery.result import AsyncResult

    result = AsyncResult(task_id, app=celery_app)
    event_id = await lookup_task_event_id(task_id)
    if event_id is None and isinstance(result.info, dict):
        event_id = result.info.get("event_id")
    if event_id is None and result.args:
        event_id = str(result.args[0])
    return normalize_public_task_state(result.state), event_id


async def _run_investigation_body(
    event_id: str,
    *,
    include_response_execution: bool,
    owner_id: str,
    redelivered: bool,
) -> dict[str, str]:
    if redelivered:
        if await should_skip_redelivered_investigation(event_id):
            logger.info(
                "run_investigation redelivery skipped — event already terminal event=%s",
                event_id,
            )
            return {"status": "skipped", "event_id": event_id, "reason": "terminal_event"}
    return await execute_investigation(
        event_id,
        include_response_execution=include_response_execution,
        owner_id=owner_id,
    )


@celery_app.task(  # type: ignore[untyped-decorator]
    name=TASK_NAME,
    bind=True,
    acks_late=True,
    max_retries=2,
    retry_backoff=True,
    soft_time_limit=600,
    queue=TASK_QUEUE,
)
def run_investigation(
    self: Any,
    event_id: str,
    include_response_execution: bool = False,
) -> dict[str, str]:
    """Execute SuperAgent investigation for *event_id* (idempotent when lease held)."""
    owner_id = celery_task_owner_id(str(self.request.id))
    redelivered = bool(getattr(self.request, "delivery_info", {}).get("redelivered"))
    if redelivered:
        logger.info(
            "run_investigation redelivery for event=%s task=%s owner=%s",
            event_id,
            self.request.id,
            owner_id,
        )
    try:
        return asyncio.run(
            _run_investigation_body(
                event_id,
                include_response_execution=bool(include_response_execution),
                owner_id=owner_id,
                redelivered=redelivered,
            )
        )
    except SoftTimeLimitExceeded:
        logger.warning("run_investigation soft time limit exceeded for event=%s", event_id)
        raise
    except (DependencyUnavailableError, OperationalError, OSError, ConnectionError) as exc:
        logger.warning(
            "run_investigation transient failure for event=%s; retry=%s",
            event_id,
            self.request.retries,
            exc_info=True,
        )
        raise self.retry(exc=exc) from exc


__all__ = [
    "TASK_NAME",
    "TASK_QUEUE",
    "delete_task_metadata",
    "dispatch_investigation",
    "execute_investigation",
    "lookup_task_event_id",
    "register_task_metadata",
    "resolve_task_state",
    "run_investigation",
]
