"""Unit tests for adversarial full-loop artifact projection (ISSUE-342)."""

from __future__ import annotations

from app.models.action import Action
from app.models.agent_io import ResponsePlan, ResponsePlanGeneratedBy
from app.models.enums import ActionCategory, ActionLevel, ActionStatus, ExecutionOwner
from tests.adversarial.full_loop_runner import (
    ArtifactResponsePlanView,
    build_artifact_response_plan_view,
)


def _response_action(
    *,
    action_id: str = "act-1",
    status: ActionStatus = ActionStatus.PENDING,
) -> Action:
    return Action(
        action_id=action_id,
        event_id="evt-test",
        plan_revision=1,
        action_fingerprint=f"fp-{action_id}",
        action_category=ActionCategory.RESPONSE,
        action_name="Disable account",
        tool_name="disable_account",
        target="svc-analytics-47",
        action_level=ActionLevel.L3,
        status=status,
        execution_owner=ExecutionOwner.XDR_MANAGED,
    )


def test_build_artifact_response_plan_view_exports_generated_by_and_strategy() -> None:
    plan = ResponsePlan(
        plan_id="plan-1",
        actions=[_response_action()],
        strategy_summary="rule fallback containment",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )
    view = build_artifact_response_plan_view(plan.model_dump(mode="json"))
    assert view.generated_by == ResponsePlanGeneratedBy.TEMPLATE.value
    assert view.strategy_summary == "rule fallback containment"
    assert len(view.actions) == 1


def test_build_artifact_response_plan_view_overlays_runtime_status() -> None:
    pending_plan = ResponsePlan(
        plan_id="plan-overlay",
        actions=[_response_action(action_id="act-run", status=ActionStatus.PENDING)],
        strategy_summary="keep snapshot",
        generated_by=ResponsePlanGeneratedBy.LLM,
    )
    runtime_action = _response_action(action_id="act-run", status=ActionStatus.SUCCESS)
    view = build_artifact_response_plan_view(
        pending_plan.model_dump(mode="json"),
        orm_actions=[runtime_action],
    )
    assert view.actions[0]["status"] == ActionStatus.SUCCESS.value
    assert view.generated_by == ResponsePlanGeneratedBy.LLM.value
    assert view.strategy_summary == "keep snapshot"


def test_build_artifact_response_plan_view_skips_recovered_overlay() -> None:
    plan = ResponsePlan(
        plan_id="plan-recovered",
        actions=[_response_action(action_id="act-rec", status=ActionStatus.PENDING)],
        strategy_summary="from actions",
        generated_by=ResponsePlanGeneratedBy.RECOVERED,
    )
    runtime_action = _response_action(action_id="act-rec", status=ActionStatus.SUCCESS)
    view = build_artifact_response_plan_view(
        plan.model_dump(mode="json"),
        orm_actions=[runtime_action],
    )
    assert view.actions[0]["status"] == ActionStatus.PENDING.value
    assert view.generated_by == ResponsePlanGeneratedBy.RECOVERED.value


def test_build_artifact_response_plan_view_falls_back_for_invalid_payload() -> None:
    view = build_artifact_response_plan_view(
        {"actions": [{"target": "host-1", "status": "pending"}]}
    )
    assert isinstance(view, ArtifactResponsePlanView)
    assert view.generated_by is None
    assert view.actions[0]["target"] == "host-1"


def test_build_artifact_response_plan_view_empty_orm_keeps_pending() -> None:
    plan = ResponsePlan(
        plan_id="plan-no-execute",
        actions=[_response_action(action_id="act-idle", status=ActionStatus.PENDING)],
        strategy_summary="not executed",
        generated_by=ResponsePlanGeneratedBy.LLM,
    )
    view = build_artifact_response_plan_view(
        plan.model_dump(mode="json"),
        orm_actions=[],
    )
    assert view.actions[0]["status"] == ActionStatus.PENDING.value
    assert view.generated_by == ResponsePlanGeneratedBy.LLM.value


def test_build_artifact_response_plan_view_mismatched_orm_id_keeps_pending() -> None:
    plan = ResponsePlan(
        plan_id="plan-mismatch",
        actions=[_response_action(action_id="act-plan", status=ActionStatus.PENDING)],
        strategy_summary="id miss",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )
    view = build_artifact_response_plan_view(
        plan.model_dump(mode="json"),
        orm_actions=[_response_action(action_id="act-other", status=ActionStatus.SUCCESS)],
    )
    assert view.actions[0]["status"] == ActionStatus.PENDING.value
