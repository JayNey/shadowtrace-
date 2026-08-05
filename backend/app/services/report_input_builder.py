"""Unified ReportAgentInput construction with response/verification backfill (ISSUE-205).

Every ReportAgent call site (graph ``report_node`` / ``close_node``,
``AnalysisOnlyPipeline``, SuperAgent, and the future ``POST /report``) must
build its input through :func:`build_report_agent_input` so existing response
plans and verification results are backfilled instead of silently degrading
to 「暂无处置动作」/「暂无验证结果」 placeholders.

Backfill order: InvestigationState / EventContext → EventContextStore →
ORM (``event_context_journal``, then Action rows as the last resort for the
plan). The builder never fabricates execution results: Action statuses are
carried over verbatim, a phase that never ran stays ``NOT_EXECUTED``, and a
read failure surfaces as ``UNAVAILABLE`` so the report chapter is marked
degraded with an explicit 「数据不可用」 note instead of a silent placeholder.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any, Protocol

from pydantic import ValidationError
from sqlalchemy import select

from app.agents.response_agent import generate_response_plan_id
from app.db import models as orm
from app.models.action import Action
from app.models.agent_io import (
    EvidenceOutput,
    ReportAgentInput,
    ReportPhaseStatus,
    ResponsePlan,
    ResponsePlanGeneratedBy,
    RiskAssessment,
    VerificationResult,
)
from app.models.context import EventContext
from app.models.enums import ActionCategory
from app.services.action_mapper import action_from_orm
from app.services.context_service import unwrap_journal_value

logger = logging.getLogger(__name__)

JOURNAL_FIELD_RESPONSE_PLAN = "response_plan"
JOURNAL_FIELD_VERIFICATION_RESULT = "verification_result"


class _ContextStoreLike(Protocol):
    async def get(self, event_id: str, key: str) -> Any: ...


def _coerce_response_plan(raw: Any) -> ResponsePlan | None:
    """Validate a stored plan payload; ``None`` means present-but-unusable."""
    if isinstance(raw, ResponsePlan):
        return raw
    if isinstance(raw, Mapping):
        try:
            return ResponsePlan.model_validate(dict(raw))
        except ValidationError:
            logger.warning("report input builder: response_plan payload failed validation")
            return None
    return None


def _coerce_verification_result(raw: Any) -> VerificationResult | None:
    """Validate a stored verification payload; ``None`` means present-but-unusable."""
    if isinstance(raw, VerificationResult):
        return raw
    if isinstance(raw, Mapping):
        try:
            return VerificationResult.model_validate(dict(raw))
        except ValidationError:
            logger.warning("report input builder: verification_result payload failed validation")
            return None
    return None


def _plan_from_actions(event_id: str, actions: list[Action]) -> ResponsePlan:
    """Re-derive a plan snapshot from persisted Action rows.

    Only used when the original plan payload is lost. Statuses are preserved
    verbatim from the Action table — never re-interpreted as success.
    """
    plan_revision = max(action.plan_revision for action in actions)
    response_count = sum(
        1 for action in actions if action.action_category is ActionCategory.RESPONSE
    )
    return ResponsePlan(
        plan_id=generate_response_plan_id(event_id, plan_revision),
        actions=actions,
        strategy_summary=(
            f"从 Action 表恢复的处置计划摘要：actions={len(actions)}，"
            f"response={response_count}，plan_revision={plan_revision}；"
            "执行状态以 Action 记录为准，未重新生成或改写结果。"
        ),
        generated_by=ResponsePlanGeneratedBy.RECOVERED,
    )


async def _load_journal_field(session: Any, event_id: str, field_name: str) -> Any:
    result = await session.execute(
        select(orm.EventContextJournal.value)
        .where(
            orm.EventContextJournal.event_id == event_id,
            orm.EventContextJournal.field_name == field_name,
        )
        .order_by(orm.EventContextJournal.version.desc())
        .limit(1)
    )
    row = result.first()
    if row is None:
        return None
    return unwrap_journal_value(row[0])


async def _load_actions_from_orm(session: Any, event_id: str) -> list[Action]:
    result = await session.execute(
        select(orm.Action)
        .where(orm.Action.event_id == event_id)
        .order_by(orm.Action.plan_revision, orm.Action.created_at, orm.Action.action_id)
    )
    return [action_from_orm(row) for row in result.scalars().all()]


async def _resolve_response_plan(
    event_id: str,
    *,
    state: Mapping[str, Any] | None,
    event_context: EventContext | None,
    context_store: _ContextStoreLike | None,
    session: Any | None,
) -> tuple[ResponsePlan | None, ReportPhaseStatus]:
    raw: Any = None
    if state is not None:
        raw = state.get("response_plan")
    if raw is None and event_context is not None:
        raw = event_context.response_plan
    if raw is None and context_store is not None:
        try:
            raw = await context_store.get(event_id, JOURNAL_FIELD_RESPONSE_PLAN)
        except Exception:
            logger.warning(
                "report input builder: response_plan context read failed event=%s",
                event_id,
                exc_info=True,
            )
            return None, ReportPhaseStatus.UNAVAILABLE
    if raw is not None:
        plan = _coerce_response_plan(raw)
        if plan is None:
            # Fail closed: data exists but is unusable — never swallow it
            # into a silent 「暂无」 placeholder.
            return None, ReportPhaseStatus.INCOMPLETE
        return plan, ReportPhaseStatus.EXECUTED

    if session is not None:
        try:
            journal_raw = await _load_journal_field(session, event_id, JOURNAL_FIELD_RESPONSE_PLAN)
        except Exception:
            logger.warning(
                "report input builder: response_plan journal read failed event=%s",
                event_id,
                exc_info=True,
            )
            return None, ReportPhaseStatus.UNAVAILABLE
        if journal_raw is not None:
            plan = _coerce_response_plan(journal_raw)
            if plan is None:
                return None, ReportPhaseStatus.INCOMPLETE
            return plan, ReportPhaseStatus.EXECUTED
        try:
            actions = await _load_actions_from_orm(session, event_id)
        except Exception:
            logger.warning(
                "report input builder: Action table read failed event=%s",
                event_id,
                exc_info=True,
            )
            return None, ReportPhaseStatus.UNAVAILABLE
        if actions:
            return _plan_from_actions(event_id, actions), ReportPhaseStatus.EXECUTED

    return None, ReportPhaseStatus.NOT_EXECUTED


async def _resolve_verification_result(
    event_id: str,
    *,
    state: Mapping[str, Any] | None,
    event_context: EventContext | None,
    context_store: _ContextStoreLike | None,
    session: Any | None,
) -> tuple[VerificationResult | None, ReportPhaseStatus]:
    raw: Any = None
    if state is not None:
        raw = state.get(JOURNAL_FIELD_VERIFICATION_RESULT)
    if raw is None and event_context is not None:
        raw = event_context.verification_result
    if raw is None and context_store is not None:
        try:
            raw = await context_store.get(event_id, JOURNAL_FIELD_VERIFICATION_RESULT)
        except Exception:
            logger.warning(
                "report input builder: verification_result context read failed event=%s",
                event_id,
                exc_info=True,
            )
            return None, ReportPhaseStatus.UNAVAILABLE
    if raw is not None:
        verification = _coerce_verification_result(raw)
        if verification is None:
            return None, ReportPhaseStatus.INCOMPLETE
        return verification, ReportPhaseStatus.EXECUTED

    if session is not None:
        try:
            journal_raw = await _load_journal_field(
                session, event_id, JOURNAL_FIELD_VERIFICATION_RESULT
            )
        except Exception:
            logger.warning(
                "report input builder: verification_result journal read failed event=%s",
                event_id,
                exc_info=True,
            )
            return None, ReportPhaseStatus.UNAVAILABLE
        if journal_raw is not None:
            verification = _coerce_verification_result(journal_raw)
            if verification is None:
                return None, ReportPhaseStatus.INCOMPLETE
            return verification, ReportPhaseStatus.EXECUTED

    return None, ReportPhaseStatus.NOT_EXECUTED


async def build_report_agent_input(
    event_id: str,
    *,
    evidence_output: EvidenceOutput,
    risk_assessment: RiskAssessment,
    escalated: bool = False,
    replan_count: int = 0,
    state: Mapping[str, Any] | None = None,
    event_context: EventContext | None = None,
    context_store: _ContextStoreLike | None = None,
    session: Any | None = None,
) -> ReportAgentInput:
    """Build the sole authoritative ``ReportAgentInput`` for ``event_id``.

    Backfill order: InvestigationState / EventContext → EventContextStore →
    ORM (journal, then Action rows). Sources are consulted lazily and only
    while the payload is still missing; the first present value wins. Read
    failures never fall back silently — they surface as
    ``ReportPhaseStatus.UNAVAILABLE`` so the report chapter is degraded with
    an explicit 「数据不可用」 note.
    """
    response_plan, response_phase_status = await _resolve_response_plan(
        event_id,
        state=state,
        event_context=event_context,
        context_store=context_store,
        session=session,
    )
    verification_result, verification_phase_status = await _resolve_verification_result(
        event_id,
        state=state,
        event_context=event_context,
        context_store=context_store,
        session=session,
    )
    return ReportAgentInput(
        event_id=event_id,
        evidence_output=evidence_output,
        risk_assessment=risk_assessment,
        response_plan=response_plan,
        verification_result=verification_result,
        escalated=escalated,
        replan_count=replan_count,
        response_phase_status=response_phase_status,
        verification_phase_status=verification_phase_status,
    )


__all__ = [
    "JOURNAL_FIELD_RESPONSE_PLAN",
    "JOURNAL_FIELD_VERIFICATION_RESULT",
    "build_report_agent_input",
]
