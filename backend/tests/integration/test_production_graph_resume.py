"""Production approval_wait → END → resume_investigation regression (ISSUE-192)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1.deps import get_approval_engine, get_super_agent, reset_deps
from app.core.auth import Principal
from app.core.config import get_settings
from app.db import models as orm
from app.models.enums import ActionStatus, EventStatus, ExecutionSubstate
from app.services.context_service import EventContextStore
from app.services.event_service import EventService
from app.tasks import investigation_tasks as tasks
from tests.adversarial.helpers import ingest_true_positive_event
from tests.integration.autonomous_e2e.helpers import patch_production_session_factory

pytestmark = [
    pytest.mark.integration,
    pytest.mark.e2e_response,
    pytest.mark.usefixtures("clean_state"),
]


async def _checkpoint_snapshot(event_id: str) -> dict[str, Any]:
    agent = await get_super_agent()
    graph = getattr(agent, "_investigation_graph", None)
    if graph is None:
        return {"graph_wired": False}
    config = {"configurable": {"thread_id": event_id}}
    snap = await graph.aget_state(config)
    if snap is None or not snap.values:
        return {"graph_wired": True, "checkpoint_present": False}
    return {
        "graph_wired": True,
        "checkpoint_present": True,
        "halted": snap.values.get("halted"),
        "needs_approval_wait": snap.values.get("needs_approval_wait"),
        "execution_substate": snap.values.get("execution_substate"),
        "event_status": snap.values.get("event_status"),
        "next": list(snap.next or ()),
        "node_trace": list(snap.values.get("node_trace") or []),
        "node_trace_tail": (snap.values.get("node_trace") or [])[-3:],
    }


@pytest.mark.asyncio
async def test_production_resume_after_approval_wait(
    monkeypatch: pytest.MonkeyPatch,
    adversarial_source_adapter,
    source_ingester,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
) -> None:
    """Production path: graph halts at approval_wait, then deps resume hook continues."""
    reset_deps()
    get_settings.cache_clear()
    monkeypatch.setenv("ORCHESTRATION_MODE", "graph")
    get_settings.cache_clear()
    patch_production_session_factory(monkeypatch, session_factory)

    event_id = await ingest_true_positive_event(
        adversarial_source_adapter,
        source_ingester,
        event_service,
    )

    await tasks.execute_investigation(event_id, include_response_execution=True)

    async with session_factory() as session:
        pending = list(
            await session.scalars(
                select(orm.Action).where(
                    orm.Action.event_id == event_id,
                    orm.Action.status == ActionStatus.WAITING_APPROVAL.value,
                )
            )
        )
    assert pending, "expected pending action after investigate"
    pre_checkpoint = await _checkpoint_snapshot(event_id)
    assert pre_checkpoint.get("checkpoint_present") is True
    assert pre_checkpoint.get("halted") is True
    assert pre_checkpoint.get("execution_substate") == ExecutionSubstate.WAITING_APPROVAL.value
    assert pre_checkpoint.get("next") == []

    engine = await get_approval_engine()
    action_id = pending[0].action_id
    await engine.approve(
        action_id,
        Principal(subject="probe-approver", roles=["approver"]),
        "production resume regression",
        f"dec-probe-{uuid.uuid4().hex[:10]}",
    )

    async with session_factory() as session:
        db_status_after = await session.scalar(
            select(orm.SecurityEvent.status).where(orm.SecurityEvent.event_id == event_id)
        )
        verify_trace = await session.scalar(
            select(orm.AgentTrace.trace_id).where(
                orm.AgentTrace.event_id == event_id,
                orm.AgentTrace.agent_name == "VerifyAgent",
            )
        )
    post_checkpoint = await _checkpoint_snapshot(event_id)
    verification = await context_store.get(event_id, "verification_result")
    node_trace = post_checkpoint.get("node_trace") or []

    assert db_status_after != EventStatus.FAILED.value, (
        f"status={db_status_after} trace={node_trace}"
    )
    assert post_checkpoint.get("needs_approval_wait") is False, post_checkpoint
    assert post_checkpoint.get("halted") is False, post_checkpoint
    assert "execute_node" in node_trace, node_trace
    assert "verify_node" in node_trace or verify_trace is not None or bool(verification), (
        f"resume must reach verify tail after approval; trace={node_trace}"
    )
