"""Shared helpers for ISSUE-110 autonomous mock full-loop E2E."""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, TypeVar
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.db import models as orm
from app.db.orm.approval import ApprovalRecordORM
from app.models.enums import InvestigationIntentStatus
from app.services.auto_investigate_policy import AutoInvestigatePolicyService
from app.services.auto_response_policy import AutoResponsePolicyService
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService
from app.services.event_service import EventService
from app.services.investigation_intent_service import InvestigationIntentService

T = TypeVar("T")


def mock_autonomous_settings(**overrides: Any) -> Settings:
    """Mock-only autonomous pipeline defaults for ISSUE-110."""
    base: dict[str, Any] = {
        "AUTO_INVESTIGATE_ENABLED": True,
        "AUTO_RESPONSE_ENABLED": False,
        "SOURCE_MODE": "mock_xdr",
        "TOOL_MODE": "mock",
        "DISPOSITION_MODE": "mock_xdr",
        "LLM_MODE": "mock",
        "TASK_MODE": "celery",
        "SIMULATION_ENABLED": True,
    }
    base.update(overrides)
    return Settings(**base)


def build_autonomous_stack(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    settings: Settings | None = None,
) -> tuple[EventService, InvestigationIntentService, EventContextStore]:
    cfg = settings or mock_autonomous_settings()
    store = EventContextStore(redis_client, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    intent_service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(cfg),
        auto_response_policy=AutoResponsePolicyService(cfg),
        degraded_flags=degraded,
        settings=cfg,
    )
    events = EventService(
        session_factory,
        store,
        degraded_flags=degraded,
        investigation_intent=intent_service,
    )
    return events, intent_service, store


async def poll_until(
    probe: Callable[[], Awaitable[T | None]],
    *,
    timeout_s: float = 30.0,
    interval_s: float = 0.25,
    description: str = "condition",
) -> T:
    """Poll until *probe* returns non-None (no fixed sleep assertions)."""
    deadline = time.monotonic() + timeout_s
    last: T | None = None
    while time.monotonic() < deadline:
        last = await probe()
        if last is not None:
            return last
        await asyncio.sleep(interval_s)
    raise TimeoutError(f"timed out waiting for {description} after {timeout_s}s")


def celery_worker_responding() -> bool:
    """True when at least one Celery worker answers inspect ping."""
    if os.environ.get("TASK_MODE", "").strip().lower() not in {"", "celery"}:
        pass
    from app.core.celery_health import probe_celery_workers

    payload = probe_celery_workers(timeout=2.0)
    return payload.get("status") == "ok" and int(payload.get("workers") or 0) > 0


def require_celery_worker() -> None:
    import pytest

    if not celery_worker_responding():
        pytest.skip("ISSUE-110 worker E2E requires live Celery worker (make up WORKER=1)")


@dataclass(frozen=True)
class ObservabilitySnapshot:
    """Ledger snapshot for ISSUE-110 mandatory observability."""

    event_id: str
    event_status: str | None
    intent_statuses: list[str] = field(default_factory=list)
    intent_broker_task_ids: list[str | None] = field(default_factory=list)
    agent_trace_count: int = 0
    action_count: int = 0
    pending_action_count: int = 0
    approval_record_count: int = 0
    approval_operators: list[str] = field(default_factory=list)
    disposition_outbox_count: int = 0
    audit_log_count: int = 0


async def collect_observability(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> ObservabilitySnapshot:
    async with session_factory() as session:
        event_status = await session.scalar(
            select(orm.SecurityEvent.status).where(orm.SecurityEvent.event_id == event_id)
        )
        intents = (
            await session.scalars(
                select(orm.InvestigationIntent)
                .where(orm.InvestigationIntent.event_id == event_id)
                .order_by(orm.InvestigationIntent.created_at.asc())
            )
        ).all()
        agent_trace_count = int(
            await session.scalar(
                select(func.count())
                .select_from(orm.AgentTrace)
                .where(orm.AgentTrace.event_id == event_id)
            )
            or 0
        )
        actions = (
            await session.scalars(select(orm.Action).where(orm.Action.event_id == event_id))
        ).all()
        pending_actions = [a for a in actions if a.status == "waiting_approval"]
        approval_rows = (
            await session.scalars(
                select(ApprovalRecordORM).where(ApprovalRecordORM.event_id == event_id)
            )
        ).all()
        outbox_count = int(
            await session.scalar(
                select(func.count())
                .select_from(orm.DispositionOutbox)
                .where(orm.DispositionOutbox.event_id == event_id)
            )
            or 0
        )
        audit_count = int(
            await session.scalar(
                select(func.count())
                .select_from(orm.EventAuditLog)
                .where(orm.EventAuditLog.event_id == event_id)
            )
            or 0
        )
    return ObservabilitySnapshot(
        event_id=event_id,
        event_status=str(event_status) if event_status is not None else None,
        intent_statuses=[row.status for row in intents],
        intent_broker_task_ids=[row.broker_task_id for row in intents],
        agent_trace_count=agent_trace_count,
        action_count=len(actions),
        pending_action_count=len(pending_actions),
        approval_record_count=len(approval_rows),
        approval_operators=[str(r.operator or "") for r in approval_rows if r.decided_at],
        disposition_outbox_count=outbox_count,
        audit_log_count=audit_count,
    )


def unique_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:10]}"


def utc_now() -> datetime:
    return datetime.now(UTC)


TERMINAL_INTENT_STATUSES = frozenset(
    {
        InvestigationIntentStatus.TERMINAL.value,
        InvestigationIntentStatus.SKIPPED.value,
        InvestigationIntentStatus.DEAD.value,
    }
)
