"""Unit tests for action execution lease reclaim transitions (ISSUE-173 / #699)."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.errors import InvalidStateTransitionError
from app.models.enums import ActionCategory, ActionStatus, ExecutionJobStatus
from app.models.workflow import validate_action_status_transition, validate_job_status_transition

_BACKEND_DIR = Path(__file__).resolve().parents[2]
_ACTION_EXECUTION_SERVICE = _BACKEND_DIR / "app" / "services" / "action_execution_service.py"


def test_executing_to_approved_requires_lease_expired_reclaim_gate() -> None:
    with pytest.raises(InvalidStateTransitionError, match="lease-expired reclaim"):
        validate_action_status_transition(
            ActionCategory.RESPONSE,
            ActionStatus.EXECUTING,
            ActionStatus.APPROVED,
        )
    validate_action_status_transition(
        ActionCategory.RESPONSE,
        ActionStatus.EXECUTING,
        ActionStatus.APPROVED,
        lease_expired_reclaim=True,
    )


def test_running_to_queued_requires_lease_expired_reclaim_gate() -> None:
    with pytest.raises(InvalidStateTransitionError, match="lease-expired reclaim"):
        validate_job_status_transition(
            ExecutionJobStatus.RUNNING,
            ExecutionJobStatus.QUEUED,
        )
    validate_job_status_transition(
        ExecutionJobStatus.RUNNING,
        ExecutionJobStatus.QUEUED,
        lease_expired_reclaim=True,
    )


def test_queued_to_timed_out_requires_lease_expired_reclaim_gate() -> None:
    with pytest.raises(InvalidStateTransitionError, match="lease-expired reclaim"):
        validate_job_status_transition(
            ExecutionJobStatus.QUEUED,
            ExecutionJobStatus.TIMED_OUT,
        )
    validate_job_status_transition(
        ExecutionJobStatus.QUEUED,
        ExecutionJobStatus.TIMED_OUT,
        lease_expired_reclaim=True,
    )


def test_executing_to_failed_remains_valid_without_reclaim_gate() -> None:
    validate_action_status_transition(
        ActionCategory.RESPONSE,
        ActionStatus.EXECUTING,
        ActionStatus.FAILED,
    )


def test_direct_tool_persists_running_job_before_provider_call() -> None:
    """ISSUE-177: PG path must not revert to QUEUED-first before Provider call."""
    source = _ACTION_EXECUTION_SERVICE.read_text(encoding="utf-8")
    start = source.index("async def _execute_direct_tool")
    end = source.index("\n    async def ", start + 1)
    direct_tool_body = source[start:end]
    pre_provider = direct_tool_body.split("await self._executor.call", maxsplit=1)[0]
    assert "ExecutionJobStatus.RUNNING.value" in pre_provider
    assert "ExecutionJobStatus.QUEUED.value" not in pre_provider
    assert "lease_expires_at" in pre_provider
