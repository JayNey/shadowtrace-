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
    execution_substate: ExecutionSubstate
    response_phase_state: ResponsePhaseState
    next_recommended_action: NextRecommendedAction
    full_loop_available: bool
    phase_message: str | None = None


def full_loop_available(orchestration_mode: str | None) -> bool:
    return (orchestration_mode or "graph").strip().lower() != "analysis_only"


def workflow_path_from_request(*, include_response_execution: bool) -> WorkflowPath:
    return "full_loop" if include_response_execution else "analysis_only"


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

    if status is EventStatus.NEW:
        return InvestigationGuidance(
            analysis_only_complete=False,
            execution_substate=ExecutionSubstate.NONE,
            response_phase_state=ResponsePhaseState.NOT_STARTED,
            next_recommended_action=NextRecommendedAction.NONE,
            full_loop_available=loop_available,
        )

    if status in _ANALYSIS_STATUSES:
        return InvestigationGuidance(
            analysis_only_complete=analysis_only_complete,
            execution_substate=execution_substate,
            response_phase_state=ResponsePhaseState.ANALYSIS_IN_PROGRESS,
            next_recommended_action=NextRecommendedAction.NONE,
            full_loop_available=loop_available,
        )

    if status is EventStatus.REPORTING and analysis_only_complete:
        next_action = (
            NextRecommendedAction.CLOSE
            if disposition_policy is DispositionPolicy.NOT_REQUIRED
            else NextRecommendedAction.NONE
        )
        message = (
            "分析已完成，未生成/执行处置方案。"
            "当前为仅分析路径；如需生成安全处置方案，请在事件 NEW 状态选择"
            "「分析并生成处置方案」发起调查。"
        )
        if not loop_available:
            message += "（当前部署 ORCHESTRATION_MODE=analysis_only，完整处置链路不可用。）"
        return InvestigationGuidance(
            analysis_only_complete=True,
            execution_substate=execution_substate,
            response_phase_state=ResponsePhaseState.ANALYSIS_COMPLETE_DEFERRED,
            next_recommended_action=next_action,
            full_loop_available=loop_available,
            phase_message=message,
        )

    if status is EventStatus.PLANNING_RESPONSE:
        return InvestigationGuidance(
            analysis_only_complete=analysis_only_complete,
            execution_substate=execution_substate,
            response_phase_state=ResponsePhaseState.RESPONSE_PLANNING,
            next_recommended_action=NextRecommendedAction.NONE,
            full_loop_available=loop_available,
        )

    if status is EventStatus.WAITING_APPROVAL:
        return InvestigationGuidance(
            analysis_only_complete=analysis_only_complete,
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
            execution_substate=execution_substate,
            response_phase_state=ResponsePhaseState.EXECUTING,
            next_recommended_action=NextRecommendedAction.NONE,
            full_loop_available=loop_available,
        )

    if status in {EventStatus.CLOSED, EventStatus.CONTAINED}:
        return InvestigationGuidance(
            analysis_only_complete=analysis_only_complete,
            execution_substate=execution_substate,
            response_phase_state=ResponsePhaseState.COMPLETE,
            next_recommended_action=NextRecommendedAction.NONE,
            full_loop_available=loop_available,
        )

    return InvestigationGuidance(
        analysis_only_complete=analysis_only_complete,
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
    "derive_investigation_guidance",
    "full_loop_available",
    "record_investigation_workflow_path",
    "workflow_path_from_request",
]
