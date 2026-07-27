"""Sync unit tests for VerifyAgent DB/plan Action merge helpers (ISSUE-564)."""

from __future__ import annotations

from app.agents.verify_agent import _merge_db_action_with_plan
from app.models.action import Action
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    ExecutionOwner,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.ids import new_action_id


def _action(
    *,
    action_id: str | None = None,
    writeback_status: WritebackStatus | None = None,
) -> Action:
    return Action(
        action_id=action_id or new_action_id(),
        event_id="evt-20260725-00000001",
        plan_revision=1,
        action_fingerprint="fp:block_ip",
        action_category=ActionCategory.RESPONSE,
        action_name="block_ip_action",
        tool_name="block_ip",
        action_level=ActionLevel.L2,
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        target_type="ip",
        target="10.0.0.1",
        status=ActionStatus.SUCCESS,
        execution_owner=ExecutionOwner.DIRECT_TOOL,
        writeback_required=True,
        writeback_applicable=True,
        writeback_readiness=WritebackReadiness.READY,
        writeback_status=writeback_status,
    )


class TestMergeDbActionWithPlan:
    def test_overlays_null_db_writeback_status_from_plan(self) -> None:
        plan = _action(writeback_status=WritebackStatus.CONFIRMED)
        db = plan.model_copy(update={"writeback_status": None})
        merged = _merge_db_action_with_plan(db, plan)
        assert merged.writeback_status is WritebackStatus.CONFIRMED

    def test_prefers_non_null_db_writeback_status(self) -> None:
        plan = _action(writeback_status=WritebackStatus.CONFIRMED)
        db = plan.model_copy(update={"writeback_status": WritebackStatus.PENDING})
        merged = _merge_db_action_with_plan(db, plan)
        assert merged.writeback_status is WritebackStatus.PENDING
