"""Investigation guidance derivation tests (ISSUE-103)."""

from __future__ import annotations

import pytest

from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    ExecutionSubstate,
    NextRecommendedAction,
    ResponsePhaseState,
)
from app.services.investigation_guidance import (
    can_continue_response_execution,
    derive_investigation_guidance,
    full_loop_available,
    workflow_path_from_request,
)


def test_full_loop_available_blocks_analysis_only_mode() -> None:
    assert full_loop_available("graph") is True
    assert full_loop_available("analysis_only") is False


def test_workflow_path_from_request() -> None:
    assert workflow_path_from_request(include_response_execution=False) == "analysis_only"
    assert workflow_path_from_request(include_response_execution=True) == "full_loop"


def test_reporting_analysis_only_deferred_suggests_start_response() -> None:
    guidance = derive_investigation_guidance(
        status=EventStatus.REPORTING,
        disposition_policy=DispositionPolicy.REQUIRED,
        context_snapshot={"analysis_only_complete": True},
        orchestration_mode="graph",
    )
    assert guidance.response_phase_state is ResponsePhaseState.ANALYSIS_COMPLETE_DEFERRED
    assert guidance.next_recommended_action is NextRecommendedAction.START_RESPONSE_EXECUTION
    assert guidance.response_execution_deferred is True
    assert guidance.analysis_only_complete is True
    assert guidance.phase_message is not None


def test_can_continue_response_execution_on_deferred_reporting() -> None:
    assert can_continue_response_execution(
        status=EventStatus.REPORTING,
        disposition_policy=DispositionPolicy.REQUIRED,
        context_snapshot={"analysis_only_complete": True},
        orchestration_mode="graph",
    )
    assert not can_continue_response_execution(
        status=EventStatus.NEW,
        disposition_policy=DispositionPolicy.REQUIRED,
        context_snapshot=None,
        orchestration_mode="graph",
    )


def test_reporting_not_required_suggests_close() -> None:
    guidance = derive_investigation_guidance(
        status=EventStatus.REPORTING,
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
        context_snapshot={"analysis_only_complete": True},
        orchestration_mode="graph",
    )
    assert guidance.next_recommended_action is NextRecommendedAction.CLOSE


def test_waiting_approval_suggests_approve() -> None:
    guidance = derive_investigation_guidance(
        status=EventStatus.WAITING_APPROVAL,
        disposition_policy=DispositionPolicy.REQUIRED,
        context_snapshot={
            "analysis_only_complete": False,
            "execution_substate": ExecutionSubstate.WAITING_APPROVAL.value,
        },
        orchestration_mode="graph",
    )
    assert guidance.response_phase_state is ResponsePhaseState.AWAITING_APPROVAL
    assert guidance.next_recommended_action is NextRecommendedAction.APPROVE_ACTIONS


def test_new_event_not_started() -> None:
    guidance = derive_investigation_guidance(
        status=EventStatus.NEW,
        disposition_policy=DispositionPolicy.REQUIRED,
        context_snapshot=None,
        orchestration_mode="graph",
    )
    assert guidance.response_phase_state is ResponsePhaseState.NOT_STARTED
