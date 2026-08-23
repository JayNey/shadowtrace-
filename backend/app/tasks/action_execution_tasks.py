"""Celery tasks for stale action execution lease reclaim (ISSUE-173 / #699)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.adapters.registry import DispositionAdapterRegistry
from app.core.celery_app import celery_app
from app.core.guardrails import OutboundDispositionGuard
from app.core.redis_client import RedisClient
from app.db.session import get_session_factory
from app.services.action_execution_service import ActionExecutionService
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import create_degraded_flag_service
from app.services.disposition_sync_service import DispositionSyncService
from app.services.event_audit_log_service import EventAuditLogService
from app.services.state_machine_service import StateMachineService
from app.tools.executor import ToolExecutor
from app.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

RECONCILE_STALE_EXECUTIONS_TASK = "shadowtrace.reconcile_stale_executions"
EXECUTION_QUEUE = "investigation"


async def _build_execution_service(redis: RedisClient) -> ActionExecutionService:
    factory = get_session_factory()
    store = EventContextStore(redis, factory)
    degraded = create_degraded_flag_service(store, factory)
    audit = EventAuditLogService(factory)
    registry = DispositionAdapterRegistry()
    return ActionExecutionService(
        factory,
        disposition_sync=DispositionSyncService(
            factory,
            context_store=store,
            adapter_registry=registry,
            outbound_guard=OutboundDispositionGuard(),
        ),
        tool_executor=ToolExecutor(registry=await _mock_registry()),
        state_machine=StateMachineService(
            factory,
            store,
            audit_log=audit,
            degraded_flags=degraded,
        ),
        context_store=store,
    )


async def _mock_registry() -> ToolRegistry:
    registry = ToolRegistry()
    await registry.auto_discover_for_mode(tool_mode="mock")
    return registry


async def _reconcile_once_async() -> dict[str, Any]:
    redis = RedisClient()
    try:
        service = await _build_execution_service(redis)
        reconciled = await service.reconcile_stale_executions(limit=20)
        return {"reconciled": reconciled}
    finally:
        await redis.aclose()


@celery_app.task(  # type: ignore[untyped-decorator]
    name=RECONCILE_STALE_EXECUTIONS_TASK,
    acks_late=True,
    soft_time_limit=120,
    queue=EXECUTION_QUEUE,
)
def reconcile_stale_executions() -> dict[str, Any]:
    """Reclaim lease-expired action execution jobs and stale EXECUTING actions."""
    return asyncio.run(_reconcile_once_async())


__all__ = [
    "EXECUTION_QUEUE",
    "RECONCILE_STALE_EXECUTIONS_TASK",
    "reconcile_stale_executions",
]
