"""ISSUE-220 unit tests: duplicate-idempotency-key attach logic (no DB).

``ActionExecutionService._attach_existing_job`` decides what happens when a
job already exists for an action's idempotency_key (e.g. after lease
reclaim): terminal jobs map the action to the final status, non-terminal
(QUEUED/RUNNING) jobs move the action to UNKNOWN for human confirmation —
never a blind re-invocation of the Provider.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from app.db import models as orm
from app.models.action import Action
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    ExecutionJobStatus,
    ExecutionOwner,
)
from app.services.action_execution_service import ActionExecutionService

_NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)


def _action(action_id: str = "act-1", *, status: ActionStatus) -> Action:
    return Action(
        action_id=action_id,
        event_id="evt-1",
        plan_revision=1,
        action_fingerprint=f"fp-{action_id}",
        action_category=ActionCategory.RESPONSE,
        action_name="block ip",
        tool_name="block_ip",
        action_level=ActionLevel.L2,
        execution_owner=ExecutionOwner.DIRECT_TOOL,
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        status=status,
        target_type="ip",
        target="203.0.113.88",
        parameters={"target_type": "ip", "target": "203.0.113.88"},
        writeback_required=False,
        writeback_applicable=False,
        writeback_readiness="not_required",
    )


def _job(status: ExecutionJobStatus, job_id: str = "job-prior") -> orm.ActionExecutionJob:
    return orm.ActionExecutionJob(
        job_id=job_id,
        event_id="evt-1",
        action_id="act-1",
        provider_name="mock_tool_provider",
        idempotency_key="idem-act-1",
        status=status.value,
        claimed_by=None,
        lease_expires_at=None,
        attempt=2,
    )


class _FakeActionRow:
    def __init__(self, *, status: ActionStatus) -> None:
        self.action_id = "act-1"
        self.event_id = "evt-1"
        self.action_category = ActionCategory.RESPONSE.value
        self.status = status.value
        self.execution_job_id: str | None = "job-new"
        self.executed_at: datetime | None = None
        self.updated_at: datetime | None = None


class _FakeSession:
    def __init__(self, row: _FakeActionRow) -> None:
        self.row = row
        self.added: list[Any] = []

    async def get(self, model: Any, pk: Any, *, with_for_update: bool = False) -> Any:
        assert model is orm.Action
        return self.row

    def add(self, obj: Any) -> None:
        self.added.append(obj)


def _service() -> ActionExecutionService:
    return ActionExecutionService.__new__(ActionExecutionService)


@pytest.mark.asyncio
async def test_attach_running_job_moves_action_to_unknown() -> None:
    """ISSUE-220: a non-terminal (reclaimed) job cannot prove side-effects —
    the action is attached and moved to UNKNOWN for human resolution."""
    action = _action(status=ActionStatus.EXECUTING)
    row = _FakeActionRow(status=ActionStatus.EXECUTING)
    session = _FakeSession(row)

    await _service()._attach_existing_job(
        session,
        action,
        _job(ExecutionJobStatus.RUNNING),
        now=_NOW,
    )

    assert row.execution_job_id == "job-prior"
    assert row.status == ActionStatus.UNKNOWN.value
    assert row.executed_at is None
    audit = session.added[0]
    assert audit.reason == "duplicate_idempotency_key_reclaim:attached_existing_job"
    assert audit.to_status == ActionStatus.UNKNOWN.value


@pytest.mark.asyncio
async def test_attach_queued_job_moves_action_to_unknown() -> None:
    action = _action(status=ActionStatus.EXECUTING)
    row = _FakeActionRow(status=ActionStatus.EXECUTING)
    session = _FakeSession(row)

    await _service()._attach_existing_job(
        session,
        action,
        _job(ExecutionJobStatus.QUEUED),
        now=_NOW,
    )

    assert row.execution_job_id == "job-prior"
    assert row.status == ActionStatus.UNKNOWN.value


@pytest.mark.asyncio
async def test_attach_terminal_job_maps_action_status() -> None:
    """ISSUE-220: a terminal job drives the action to the mapped final status."""
    action = _action(status=ActionStatus.EXECUTING)
    row = _FakeActionRow(status=ActionStatus.EXECUTING)
    session = _FakeSession(row)

    await _service()._attach_existing_job(
        session,
        action,
        _job(ExecutionJobStatus.SUCCESS),
        now=_NOW,
    )

    assert row.execution_job_id == "job-prior"
    assert row.status == ActionStatus.SUCCESS.value
    assert row.executed_at == _NOW
    assert len(session.added) == 1
    assert session.added[0].reason == "duplicate_idempotency_key_reclaim:attached_terminal_job"


@pytest.mark.asyncio
async def test_attach_terminal_failed_job_maps_action_failed() -> None:
    action = _action(status=ActionStatus.EXECUTING)
    row = _FakeActionRow(status=ActionStatus.EXECUTING)
    session = _FakeSession(row)

    await _service()._attach_existing_job(
        session,
        action,
        _job(ExecutionJobStatus.TIMED_OUT),
        now=_NOW,
    )

    assert row.status == ActionStatus.FAILED.value
    assert row.executed_at == _NOW
    assert len(session.added) == 1
    assert session.added[0].reason == "duplicate_idempotency_key_reclaim:attached_terminal_job"


@pytest.mark.asyncio
async def test_attach_terminal_failed_status_maps_action_failed() -> None:
    action = _action(status=ActionStatus.EXECUTING)
    row = _FakeActionRow(status=ActionStatus.EXECUTING)
    session = _FakeSession(row)

    await _service()._attach_existing_job(
        session,
        action,
        _job(ExecutionJobStatus.FAILED),
        now=_NOW,
    )

    assert row.status == ActionStatus.FAILED.value
    assert row.executed_at == _NOW


@pytest.mark.asyncio
async def test_attach_terminal_cancelled_job_maps_action_failed() -> None:
    action = _action(status=ActionStatus.EXECUTING)
    row = _FakeActionRow(status=ActionStatus.EXECUTING)
    session = _FakeSession(row)

    await _service()._attach_existing_job(
        session,
        action,
        _job(ExecutionJobStatus.CANCELLED),
        now=_NOW,
    )

    assert row.status == ActionStatus.FAILED.value
    assert row.executed_at == _NOW
