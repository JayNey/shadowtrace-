"""Investigation phase guidance for analysis-only vs full-loop UX (ISSUE-103)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    ExecutionSubstate,
    NextRecommendedAction,
    ResponsePhaseState,
)
from app.services.agent_trace_service import AgentTraceService

WorkflowPath = Literal["analysis_only", "full_loop"]

_ANALYSIS_STATUSES = frozenset(
    {
        EventStatus.TRIAGING,
        EventStatus.COLLECTING_EVIDENCE,
        EventStatus.ANALYZING,
        EventStatus.SCORING,
    }
)


@dataclass(frozen=True)
class InvestigationGuidance:
    analysis_only_complete: bool
    response_execution_deferred: bool
    execution_substate: ExecutionSubstate
    response_phase_state: ResponsePhaseState
    next_recommended_action: NextRecommendedAction
    full_loop_available: bool
    phase_message: str | None = None


def full_loop_available(orchestration_mode: str | None) -> bool:
    return (orchestration_mode or "graph").strip().lower() != "analysis_only"


def workflow_path_from_request(
    *,
    include_response_execution: bool,
    continue_response_execution: bool = False,
) -> WorkflowPath:
    if include_response_execution or continue_response_execution:
        return "full_loop"
    return "analysis_only"


def can_continue_response_execution(
    *,
    status: EventStatus,
    disposition_policy: DispositionPolicy,
    context_snapshot: dict[str, Any] | None,
    orchestration_mode: str | None,
) -> bool:
    """True when deferred analysis at REPORTING may resume into ResponseAgent."""
    if status is not EventStatus.REPORTING:
        return False
    guidance = derive_investigation_guidance(
        status=status,
        disposition_policy=disposition_policy,
        context_snapshot=context_snapshot,
        orchestration_mode=orchestration_mode,
    )
    return guidance.response_execution_deferred and guidance.full_loop_available


def _execution_substate_from_snapshot(snapshot: dict[str, Any] | None) -> ExecutionSubstate:
    if not isinstance(snapshot, dict):
        return ExecutionSubstate.NONE
    raw = snapshot.get("execution_substate")
    if raw is None:
        return ExecutionSubstate.NONE
    try:
        return ExecutionSubstate(str(raw).lower())
    except ValueError:
        return ExecutionSubstate.NONE


def _analysis_only_complete_from_snapshot(snapshot: dict[str, Any] | None) -> bool:
    if not isinstance(snapshot, dict):
        return False
    return bool(snapshot.get("analysis_only_complete"))


def derive_investigation_guidance(
    *,
    status: EventStatus,
    disposition_policy: DispositionPolicy,
    context_snapshot: dict[str, Any] | None,
    orchestration_mode: str | None,
) -> InvestigationGuidance:
    """Derive operator-facing phase hints from authoritative event + context."""
    analysis_only_complete = _analysis_only_complete_from_snapshot(context_snapshot)
    execution_substate = _execution_substate_from_snapshot(context_snapshot)
    loop_available = full_loop_available(orchestration_mode)

    response_deferred = (
        status is EventStatus.REPORTING
        and analysis_only_complete
        and disposition_policy is not DispositionPolicy.NOT_REQUIRED
    )

    if status is EventStatus.NEW:
        return InvestigationGuidance(
            analysis_only_complete=False,
            response_execution_deferred=False,
            execution_substate=ExecutionSubstate.NONE,
            response_phase_state=ResponsePhaseState.NOT_STARTED,
            next_recommended_action=NextRecommendedAction.NONE,
            full_loop_available=loop_available,
        )

    if status in _ANALYSIS_STATUSES:
        return InvestigationGuidance(
            analysis_only_complete=analysis_only_complete,
            response_execution_deferred=False,
            execution_substate=execution_substate,
            response_phase_state=ResponsePhaseState.ANALYSIS_IN_PROGRESS,
            next_recommended_action=NextRecommendedAction.NONE,
            full_loop_available=loop_available,
        )

    if response_deferred:
        next_action = (
            NextRecommendedAction.START_RESPONSE_EXECUTION
            if loop_available
            else NextRecommendedAction.NONE
        )
        message = (
            "分析已完成，处置方案未生成或未执行。"
            "可点击下方「生成处置方案并提交审批」继续 ResponseAgent 与审批流程。"
        )
        if not loop_available:
            message += "（当前部署 ORCHESTRATION_MODE=analysis_only，完整处置链路不可用。）"
        return InvestigationGuidance(
            analysis_only_complete=True,
            response_execution_deferred=True,
            execution_substate=execution_substate,
            response_phase_state=ResponsePhaseState.ANALYSIS_COMPLETE_DEFERRED,
            next_recommended_action=next_action,
            full_loop_available=loop_available,
            phase_message=message,
        )

    if status is EventStatus.REPORTING and analysis_only_complete:
        return InvestigationGuidance(
            analysis_only_complete=True,
            response_execution_deferred=False,
            execution_substate=execution_substate,
            response_phase_state=ResponsePhaseState.ANALYSIS_COMPLETE_DEFERRED,
            next_recommended_action=NextRecommendedAction.CLOSE,
            full_loop_available=loop_available,
        )

    if status is EventStatus.PLANNING_RESPONSE:
        return InvestigationGuidance(
            analysis_only_complete=analysis_only_complete,
            response_execution_deferred=False,
            execution_substate=execution_substate,
            response_phase_state=ResponsePhaseState.RESPONSE_PLANNING,
            next_recommended_action=NextRecommendedAction.NONE,
            full_loop_available=loop_available,
        )

    if status is EventStatus.WAITING_APPROVAL:
        return InvestigationGuidance(
            analysis_only_complete=analysis_only_complete,
            response_execution_deferred=False,
            execution_substate=execution_substate,
            response_phase_state=ResponsePhaseState.AWAITING_APPROVAL,
            next_recommended_action=NextRecommendedAction.APPROVE_ACTIONS,
            full_loop_available=loop_available,
        )

    if status in {
        EventStatus.EXECUTING_RESPONSE,
        EventStatus.VERIFYING,
        EventStatus.REPLANNING,
    }:
        return InvestigationGuidance(
            analysis_only_complete=analysis_only_complete,
            response_execution_deferred=False,
            execution_substate=execution_substate,
            response_phase_state=ResponsePhaseState.EXECUTING,
            next_recommended_action=NextRecommendedAction.NONE,
            full_loop_available=loop_available,
        )

    if status in {EventStatus.CLOSED, EventStatus.CONTAINED}:
        return InvestigationGuidance(
            analysis_only_complete=analysis_only_complete,
            response_execution_deferred=False,
            execution_substate=execution_substate,
            response_phase_state=ResponsePhaseState.COMPLETE,
            next_recommended_action=NextRecommendedAction.NONE,
            full_loop_available=loop_available,
        )

    return InvestigationGuidance(
        analysis_only_complete=analysis_only_complete,
        response_execution_deferred=False,
        execution_substate=execution_substate,
        response_phase_state=ResponsePhaseState.NOT_STARTED,
        next_recommended_action=NextRecommendedAction.NONE,
        full_loop_available=loop_available,
    )


async def record_investigation_workflow_path(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    *,
    workflow_path: WorkflowPath,
    include_response_execution: bool,
) -> None:
    """Persist workflow_path for decision trace aggregation (ISSUE-103)."""
    now = datetime.now(UTC)
    trace_service = AgentTraceService(session_factory)
    await trace_service.log_trace(
        event_id,
        "super_agent",
        {
            "workflow_path": workflow_path,
            "include_response_execution": include_response_execution,
        },
        {"workflow_path": workflow_path},
        "completed",
        now,
        now,
    )


__all__ = [
    "InvestigationGuidance",
    "WorkflowPath",
    "can_continue_response_execution",
    "derive_investigation_guidance",
    "full_loop_available",
    "record_investigation_workflow_path",
    "workflow_path_from_request",
]
