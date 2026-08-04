"""Unit tests for action execution lease reclaim transitions (ISSUE-173 / #699)."""

from __future__ import annotations

import pytest

from app.core.errors import InvalidStateTransitionError
from app.models.enums import ActionCategory, ActionStatus, ExecutionJobStatus
from app.models.workflow import validate_action_status_transition, validate_job_status_transition


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


def test_executing_to_failed_remains_valid_without_reclaim_gate() -> None:
    validate_action_status_transition(
        ActionCategory.RESPONSE,
        ActionStatus.EXECUTING,
        ActionStatus.FAILED,
    )
