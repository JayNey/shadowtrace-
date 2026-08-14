"""ISSUE-205: unified ReportAgentInput builder backfill tests.

Covers the acceptance criteria:
- existing response_plan / verification_result are backfilled (never the
  silent 「暂无…」 placeholders);
- analysis-only style calls without any persisted phase render 「本调查未执行…」;
- ORM/context read failures degrade explicitly instead of swallowing data;
- the ORM fallback never fabricates execution results.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from app.agents.report_section_builder import (
    INCOMPLETE_ACTIONS_PLACEHOLDER,
    INCOMPLETE_VERIFICATION_PLACEHOLDER,
    NOT_EXECUTED_ACTIONS,
    NOT_EXECUTED_VERIFICATION,
    PLACEHOLDER_NO_ACTIONS,
    PLACEHOLDER_NO_VERIFICATION,
    UNAVAILABLE_ACTIONS,
    UNAVAILABLE_VERIFICATION,
    ReportSectionBuilder,
    build_actions_status_summary,
)
from app.agents.response_agent import generate_response_plan_id
from app.models.action import Action
from app.models.agent_io import (
    CollectionStatus,
    EffectStatus,
    EvidenceOutput,
    ReportAgentInput,
    ReportPhaseStatus,
    ResponsePlan,
    ResponsePlanGeneratedBy,
    RiskAssessment,
    ScoringMode,
    Severity,
    VerificationActionResult,
    VerificationOverallStatus,
    VerificationPhase,
    VerificationResult,
    WritebackReadiness,
)
from app.models.context import EventContext
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    ExecutionOwner,
    WritebackStatus,
)
from app.models.enums import (
    WritebackReadiness as WritebackReadinessEnum,
)
from app.services.analysis_only_pipeline import AnalysisOnlyPipeline
from app.services.report_input_builder import (
    build_report_agent_input,
    overlay_response_plan_from_orm,
    refresh_response_plan_snapshot,
)

EVENT_ID = "evt-report-builder-205"


def _evidence() -> EvidenceOutput:
    return EvidenceOutput(collection_status=CollectionStatus.COMPLETED)


def _risk() -> RiskAssessment:
    return RiskAssessment(
        risk_score=55,
        severity=Severity.MEDIUM,
        confidence=0.7,
        scoring_mode=ScoringMode.RULE_ONLY,
    )


def _response_action(
    *,
    action_id: str = "act-205-001",
    status: ActionStatus = ActionStatus.SUCCESS,
    plan_revision: int = 1,
) -> Action:
    return Action(
        action_id=action_id,
        event_id=EVENT_ID,
        plan_revision=plan_revision,
        action_fingerprint=f"fp-{action_id}",
        action_category=ActionCategory.RESPONSE,
        action_name="Block IP",
        tool_name="block_ip",
        action_level=ActionLevel.L3,
        status=status,
        execution_owner=ExecutionOwner.XDR_MANAGED,
    )


def _plan(*, plan_id: str = "plan-205") -> ResponsePlan:
    return ResponsePlan(
        plan_id=plan_id,
        actions=[_response_action()],
        strategy_summary="contain exfiltration",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )


def _verification() -> VerificationResult:
    return VerificationResult(
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
        results=[
            VerificationActionResult(
                action_id="act-205-001",
                effect_status=EffectStatus.VERIFIED,
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            )
        ],
    )


class _FakeContextStore:
    def __init__(
        self,
        data: dict[str, Any] | None = None,
        *,
        error: Exception | None = None,
    ) -> None:
        self.data = data or {}
        self.error = error
        self.reads: list[str] = []

    async def get(self, event_id: str, key: str) -> Any:
        assert event_id == EVENT_ID
        self.reads.append(key)
        if self.error is not None:
            raise self.error
        return self.data.get(key)


class _JournalResult:
    def __init__(self, value: Any) -> None:
        self._value = value

    def first(self) -> Any:
        if self._value is None:
            return None
        return (self._value,)


class _Scalars:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows


class _ActionsResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> _Scalars:
        return _Scalars(self._rows)


class _FakeSession:
    """Scripted stand-in for AsyncSession; returns queued results in call order."""

    def __init__(self, results: list[Any], *, error: Exception | None = None) -> None:
        self._results = list(results)
        self.error = error
        self.calls = 0

    async def execute(self, _statement: Any) -> Any:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self._results.pop(0)


def _orm_action_row(
    *,
    action_id: str = "act-orm-001",
    status: str = ActionStatus.PENDING.value,
    plan_revision: int = 1,
) -> SimpleNamespace:
    return SimpleNamespace(
        action_id=action_id,
        event_id=EVENT_ID,
        plan_revision=plan_revision,
        action_fingerprint=f"fp-{action_id}",
        action_category=ActionCategory.RESPONSE.value,
        action_name="Isolate host",
        tool_name="isolate_host",
        action_level=ActionLevel.L4.value,
        execution_phase="immediate",
        activation_condition=None,
        approved_operation_template_hash=None,
        approved_terminal_dispositions=[],
        target_type="host",
        target="PC-FIN-023",
        parameters={},
        status=status,
        auto_execute=False,
        reason=None,
        impact_assessment=None,
        playbook_id=None,
        playbook_ref=None,
        action_template_snapshot=None,
        provider_name=None,
        execution_owner=ExecutionOwner.XDR_MANAGED.value,
        execution_job_id=None,
        tool_call_id=None,
        idempotency_key=None,
        writeback_required=False,
        writeback_applicable=False,
        writeback_readiness=WritebackReadinessEnum.NOT_REQUIRED.value,
        writeback_block_reason=None,
        writeback_status=None,
        disposition_source_ref=None,
        superseded_by_revision=None,
        executed_at=None,
        effect_verification_status=None,
        rollback_status=None,
        source_action_id=None,
        updated_at=None,
    )


async def _build(**kwargs: Any) -> ReportAgentInput:
    return await build_report_agent_input(
        EVENT_ID,
        evidence_output=_evidence(),
        risk_assessment=_risk(),
        **kwargs,
    )


# --------------------------------------------------------------------------- #
# Backfill resolution
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_backfills_plan_from_state_and_verification_from_store() -> None:
    store = _FakeContextStore({"verification_result": _verification().model_dump(mode="json")})
    result = await _build(
        state={"response_plan": _plan().model_dump(mode="json")},
        context_store=store,
        escalated=True,
        replan_count=2,
    )
    assert result.response_plan is not None
    assert result.response_plan.plan_id == "plan-205"
    assert result.response_phase_status is ReportPhaseStatus.EXECUTED
    assert result.verification_result is not None
    assert result.verification_phase_status is ReportPhaseStatus.EXECUTED
    assert result.escalated is True
    assert result.replan_count == 2
    # The plan was satisfied from state — the store is only read for verify.
    assert store.reads == ["verification_result"]


@pytest.mark.asyncio
async def test_backfills_from_event_context() -> None:
    ec = EventContext(
        response_plan=_plan().model_dump(mode="json"),
        verification_result=_verification().model_dump(mode="json"),
    )
    result = await _build(event_context=ec)
    assert result.response_plan is not None
    assert result.verification_result is not None
    assert result.response_phase_status is ReportPhaseStatus.EXECUTED
    assert result.verification_phase_status is ReportPhaseStatus.EXECUTED


@pytest.mark.asyncio
async def test_state_takes_precedence_over_event_context() -> None:
    ec = EventContext(response_plan=_plan(plan_id="plan-from-ec").model_dump(mode="json"))
    result = await _build(
        state={"response_plan": _plan(plan_id="plan-from-state").model_dump(mode="json")},
        event_context=ec,
    )
    assert result.response_plan is not None
    assert result.response_plan.plan_id == "plan-from-state"


@pytest.mark.asyncio
async def test_state_snapshot_pending_overlaid_from_orm_terminal_status() -> None:
    """ISSUE-329: stale PENDING snapshot must reflect Action table terminal status."""
    pending_plan = ResponsePlan(
        plan_id="plan-stale-pending",
        actions=[
            _response_action(action_id="act-orm-001", status=ActionStatus.PENDING),
            _response_action(action_id="act-orm-002", status=ActionStatus.PENDING),
        ],
        strategy_summary="stale snapshot",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )
    session = _FakeSession(
        [
            _ActionsResult(
                [
                    _orm_action_row(
                        action_id="act-orm-001",
                        status=ActionStatus.SUCCESS.value,
                        plan_revision=1,
                    ),
                    _orm_action_row(
                        action_id="act-orm-002",
                        status=ActionStatus.FAILED.value,
                        plan_revision=1,
                    ),
                ]
            ),
        ]
    )
    result = await _build(
        state={"response_plan": pending_plan.model_dump(mode="json")},
        session=session,
    )
    plan = result.response_plan
    assert plan is not None
    assert plan.plan_id == "plan-stale-pending"
    assert plan.generated_by is ResponsePlanGeneratedBy.TEMPLATE
    assert plan.actions[0].status is ActionStatus.SUCCESS
    assert plan.actions[1].status is ActionStatus.FAILED
    assert result.response_phase_status is ReportPhaseStatus.EXECUTED

    by_key = _sections(
        response_plan=plan,
        response_phase_status=result.response_phase_status,
    )
    executed = by_key["executed_actions"].content
    assert "status=success" in executed
    assert "status=failed" in executed
    assert "pending=2" not in executed
    summary = build_actions_status_summary(
        response_actions=[a for a in plan.actions],
        response_phase_status=result.response_phase_status,
    )
    assert "处置阶段状态=executed。" in summary
    assert "success=1" in summary
    assert "failed=1" in summary
    assert "pending=2" not in summary


def test_overlay_response_plan_from_orm_preserves_plan_and_never_fabricates() -> None:
    plan = ResponsePlan(
        plan_id="plan-overlay",
        actions=[_response_action(action_id="act-missing", status=ActionStatus.PENDING)],
        strategy_summary="keep me",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )
    unchanged = overlay_response_plan_from_orm(plan, [])
    assert unchanged is plan
    overlaid = overlay_response_plan_from_orm(
        plan,
        [_response_action(action_id="act-other", status=ActionStatus.SUCCESS)],
    )
    assert overlaid is plan
    assert overlaid.actions[0].status is ActionStatus.PENDING


def test_overlay_preserves_policy_fields_and_plan_structure() -> None:
    """ISSUE-329: overlay copies execution fields only, never writeback policy."""
    snapshot_action = _response_action(
        action_id="act-keep",
        status=ActionStatus.PENDING,
    ).model_copy(
        update={
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadinessEnum.READY,
            "reason": "policy snapshot",
        }
    )
    plan = ResponsePlan(
        plan_id="plan-keep",
        actions=[snapshot_action],
        strategy_summary="keep me",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )
    orm_action = _response_action(
        action_id="act-keep",
        status=ActionStatus.SUCCESS,
    ).model_copy(
        update={
            "execution_job_id": "job-1",
            "writeback_required": False,
            "writeback_applicable": False,
            "writeback_readiness": WritebackReadinessEnum.NOT_REQUIRED,
        }
    )
    overlaid = overlay_response_plan_from_orm(plan, [orm_action])
    assert overlaid.plan_id == "plan-keep"
    assert overlaid.strategy_summary == "keep me"
    assert overlaid.generated_by is ResponsePlanGeneratedBy.TEMPLATE
    action = overlaid.actions[0]
    assert action.status is ActionStatus.SUCCESS
    assert action.execution_job_id == "job-1"
    assert action.writeback_required is True
    assert action.writeback_applicable is True
    assert action.writeback_readiness is WritebackReadinessEnum.READY
    assert action.reason == "policy snapshot"


def test_overlay_skips_recovered_plans() -> None:
    """RECOVERED plans already came from Action rows; overlay must not rewrite them."""
    plan = ResponsePlan(
        plan_id="plan-recovered",
        actions=[_response_action(action_id="act-rec", status=ActionStatus.PENDING)],
        strategy_summary="from actions",
        generated_by=ResponsePlanGeneratedBy.RECOVERED,
    )
    overlaid = overlay_response_plan_from_orm(
        plan,
        [_response_action(action_id="act-rec", status=ActionStatus.SUCCESS)],
    )
    assert overlaid is plan
    assert overlaid.actions[0].status is ActionStatus.PENDING


@pytest.mark.asyncio
async def test_state_pending_plan_empty_orm_keeps_pending_not_fabricated() -> None:
    """ISSUE-205 first-wins: overlay with no ORM rows must not fabricate SUCCESS."""
    pending_plan = ResponsePlan(
        plan_id="plan-empty-orm",
        actions=[_response_action(action_id="act-missing-orm", status=ActionStatus.PENDING)],
        strategy_summary="stale snapshot",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )
    session = _FakeSession([_ActionsResult([])])
    result = await _build(
        state={"response_plan": pending_plan.model_dump(mode="json")},
        session=session,
    )
    assert result.response_plan is not None
    assert result.response_plan.plan_id == "plan-empty-orm"
    assert all(action.status is ActionStatus.PENDING for action in result.response_plan.actions)
    assert result.response_phase_status is ReportPhaseStatus.EXECUTED


class _SessionFactory:
    def __init__(self, session: Any) -> None:
        self._session = session

    def __call__(self) -> Any:
        return self

    async def __aenter__(self) -> Any:
        return self._session

    async def __aexit__(self, *_args: Any) -> None:
        return None


@pytest.mark.asyncio
async def test_overlay_action_read_failure_is_unavailable_not_stale_pending() -> None:
    """ISSUE-329: overlay read failure must not claim executed + pending=all."""
    pending_plan = ResponsePlan(
        plan_id="plan-stale-pending",
        actions=[
            _response_action(action_id="act-orm-001", status=ActionStatus.PENDING),
            _response_action(action_id="act-orm-002", status=ActionStatus.PENDING),
        ],
        strategy_summary="stale snapshot",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )
    session = _FakeSession([], error=RuntimeError("action overlay unavailable"))
    result = await _build(
        state={"response_plan": pending_plan.model_dump(mode="json")},
        session=session,
    )
    assert result.response_plan is not None
    assert result.response_plan.plan_id == "plan-stale-pending"
    assert all(action.status is ActionStatus.PENDING for action in result.response_plan.actions)
    assert result.response_phase_status is ReportPhaseStatus.UNAVAILABLE
    summary = build_actions_status_summary(
        response_actions=list(result.response_plan.actions),
        response_phase_status=result.response_phase_status,
    )
    assert "处置阶段状态=unavailable。" in summary
    assert "处置阶段状态=executed" not in summary
    executed = _sections(
        response_plan=result.response_plan,
        response_phase_status=result.response_phase_status,
    )["executed_actions"].content
    assert "处置阶段状态=executed" not in executed
    assert "unavailable" in executed


@pytest.mark.asyncio
async def test_refresh_response_plan_snapshot_returns_none_when_unchanged() -> None:
    plan = _plan()
    session = _FakeSession(
        [
            _ActionsResult(
                [
                    _orm_action_row(
                        action_id=plan.actions[0].action_id,
                        status=ActionStatus.SUCCESS.value,
                    )
                ]
            )
        ]
    )
    dumped = await refresh_response_plan_snapshot(
        EVENT_ID,
        plan_raw=plan.model_dump(mode="json"),
        session_factory=_SessionFactory(session),
    )
    assert dumped is None


@pytest.mark.asyncio
async def test_refresh_response_plan_snapshot_returns_updated_dump() -> None:
    pending = ResponsePlan(
        plan_id="plan-refresh",
        actions=[_response_action(action_id="act-refresh-001", status=ActionStatus.PENDING)],
        strategy_summary="stale",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )
    session = _FakeSession(
        [
            _ActionsResult(
                [
                    _orm_action_row(
                        action_id="act-refresh-001",
                        status=ActionStatus.SUCCESS.value,
                    )
                ]
            )
        ]
    )
    dumped = await refresh_response_plan_snapshot(
        EVENT_ID,
        plan_raw=pending.model_dump(mode="json"),
        session_factory=_SessionFactory(session),
    )
    assert dumped is not None
    assert dumped["plan_id"] == "plan-refresh"
    assert dumped["actions"][0]["status"] == ActionStatus.SUCCESS.value


@pytest.mark.asyncio
async def test_refresh_response_plan_snapshot_returns_none_on_overlay_read_failure() -> None:
    pending = ResponsePlan(
        plan_id="plan-refresh-fail",
        actions=[_response_action(status=ActionStatus.PENDING)],
        strategy_summary="stale",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )
    dumped = await refresh_response_plan_snapshot(
        EVENT_ID,
        plan_raw=pending.model_dump(mode="json"),
        session_factory=_SessionFactory(_FakeSession([], error=RuntimeError("db timeout"))),
    )
    assert dumped is None


def test_build_actions_status_summary_splits_phase_and_counts() -> None:
    actions = [
        _response_action(action_id="a1", status=ActionStatus.SUCCESS),
        _response_action(action_id="a2", status=ActionStatus.PENDING),
    ]
    summary = build_actions_status_summary(
        response_actions=actions,
        response_phase_status=ReportPhaseStatus.EXECUTED,
    )
    assert summary.startswith("处置阶段状态=executed。")
    assert "\nRESPONSE 动作共 2 个（" in summary
    assert "pending=1" in summary
    assert "success=1" in summary
    assert "；RESPONSE" not in summary


@pytest.mark.asyncio
async def test_no_sources_defaults_to_not_executed() -> None:
    result = await _build()
    assert result.response_plan is None
    assert result.verification_result is None
    assert result.response_phase_status is ReportPhaseStatus.NOT_EXECUTED
    assert result.verification_phase_status is ReportPhaseStatus.NOT_EXECUTED


@pytest.mark.asyncio
async def test_context_store_read_failure_is_unavailable_not_placeholder() -> None:
    store = _FakeContextStore(error=RuntimeError("context store unavailable"))
    result = await _build(context_store=store)
    assert result.response_plan is None
    assert result.verification_result is None
    assert result.response_phase_status is ReportPhaseStatus.UNAVAILABLE
    assert result.verification_phase_status is ReportPhaseStatus.UNAVAILABLE


@pytest.mark.asyncio
async def test_invalid_state_plan_fails_closed_to_incomplete() -> None:
    result = await _build(state={"response_plan": {"plan_id": "broken"}})
    assert result.response_plan is None
    assert result.response_phase_status is ReportPhaseStatus.INCOMPLETE


@pytest.mark.asyncio
async def test_invalid_store_verification_fails_closed_to_incomplete() -> None:
    store = _FakeContextStore({"verification_result": {"overall_status": "not-a-status"}})
    result = await _build(context_store=store)
    assert result.verification_result is None
    assert result.verification_phase_status is ReportPhaseStatus.INCOMPLETE


# --------------------------------------------------------------------------- #
# ORM (session) fallback
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_session_journal_fallback_restores_plan_and_verification() -> None:
    session = _FakeSession(
        [
            _JournalResult(_plan(plan_id="plan-journal").model_dump(mode="json")),
            _ActionsResult([]),  # ISSUE-329: overlay refresh after journal plan
            _JournalResult(_verification().model_dump(mode="json")),
        ]
    )
    result = await _build(session=session)
    assert result.response_plan is not None
    assert result.response_plan.plan_id == "plan-journal"
    assert result.response_phase_status is ReportPhaseStatus.EXECUTED
    assert result.verification_result is not None
    assert result.verification_phase_status is ReportPhaseStatus.EXECUTED


@pytest.mark.asyncio
async def test_session_action_table_fallback_derives_plan_without_fabrication() -> None:
    session = _FakeSession(
        [
            _JournalResult(None),  # response_plan journal: absent
            _ActionsResult(
                [
                    _orm_action_row(action_id="act-orm-001", plan_revision=1),
                    _orm_action_row(
                        action_id="act-orm-002",
                        status=ActionStatus.PENDING.value,
                        plan_revision=2,
                    ),
                ]
            ),
            _JournalResult(None),  # verification_result journal: absent
        ]
    )
    result = await _build(session=session)
    plan = result.response_plan
    assert plan is not None
    assert result.response_phase_status is ReportPhaseStatus.EXECUTED
    assert plan.generated_by is ResponsePlanGeneratedBy.RECOVERED
    assert plan.plan_id == generate_response_plan_id(EVENT_ID, 2)
    assert [a.action_id for a in plan.actions] == ["act-orm-001", "act-orm-002"]
    # Never fabricate success: pending rows stay pending.
    assert plan.actions[1].status is ActionStatus.PENDING
    assert "Action 表恢复" in plan.strategy_summary
    # No verification data exists anywhere — honest NOT_EXECUTED.
    assert result.verification_result is None
    assert result.verification_phase_status is ReportPhaseStatus.NOT_EXECUTED


@pytest.mark.asyncio
async def test_session_factory_opens_session_for_action_recovery() -> None:
    """Production call sites pass session_factory; builder must open it for ORM."""
    session = _FakeSession(
        [
            _JournalResult(None),
            _ActionsResult([_orm_action_row(action_id="act-factory-001", plan_revision=1)]),
            _JournalResult(None),
        ]
    )

    class _Factory:
        def __init__(self) -> None:
            self.entered = 0

        def __call__(self) -> Any:
            factory = self

            class _Ctx:
                async def __aenter__(self) -> _FakeSession:
                    factory.entered += 1
                    return session

                async def __aexit__(self, *_args: Any) -> None:
                    return None

            return _Ctx()

    factory = _Factory()
    result = await _build(session_factory=factory)
    assert factory.entered == 1
    assert result.response_plan is not None
    assert result.response_plan.actions[0].action_id == "act-factory-001"
    assert result.response_phase_status is ReportPhaseStatus.EXECUTED
    assert result.response_plan.generated_by is ResponsePlanGeneratedBy.RECOVERED


@pytest.mark.asyncio
async def test_session_failure_marks_unavailable() -> None:
    session = _FakeSession([], error=RuntimeError("db unavailable"))
    result = await _build(session=session)
    assert result.response_plan is None
    assert result.verification_result is None
    assert result.response_phase_status is ReportPhaseStatus.UNAVAILABLE
    assert result.verification_phase_status is ReportPhaseStatus.UNAVAILABLE


@pytest.mark.asyncio
async def test_empty_session_leaves_not_executed() -> None:
    session = _FakeSession(
        [
            _JournalResult(None),  # response_plan journal
            _ActionsResult([]),  # Action table
            _JournalResult(None),  # verification_result journal
        ]
    )
    result = await _build(session=session)
    assert result.response_plan is None
    assert result.verification_result is None
    assert result.response_phase_status is ReportPhaseStatus.NOT_EXECUTED
    assert result.verification_phase_status is ReportPhaseStatus.NOT_EXECUTED


# --------------------------------------------------------------------------- #
# Section rendering contract (builder status → chapter wording)
# --------------------------------------------------------------------------- #


def _sections(**kwargs: Any) -> dict[str, Any]:
    sections = ReportSectionBuilder().build(
        event_id=EVENT_ID,
        evidence_output=_evidence(),
        risk_assessment=_risk(),
        **kwargs,
    )
    return {s.key: s for s in sections}


def test_sections_default_to_not_executed_wording() -> None:
    by_key = _sections()
    executed = by_key["executed_actions"].content
    assert NOT_EXECUTED_ACTIONS in executed
    assert executed.endswith(NOT_EXECUTED_ACTIONS)
    assert "actions_status_summary:" in executed
    assert by_key["verification_results"].content == NOT_EXECUTED_VERIFICATION
    assert PLACEHOLDER_NO_ACTIONS not in executed
    assert PLACEHOLDER_NO_VERIFICATION not in by_key["verification_results"].content


def test_sections_list_actions_when_plan_backfilled() -> None:
    by_key = _sections(
        response_plan=_plan(),
        response_phase_status=ReportPhaseStatus.EXECUTED,
        verification_result=_verification(),
        verification_phase_status=ReportPhaseStatus.EXECUTED,
    )
    executed = by_key["executed_actions"].content
    verification = by_key["verification_results"].content
    assert "act-205-001" in executed
    assert PLACEHOLDER_NO_ACTIONS not in executed
    assert NOT_EXECUTED_ACTIONS not in executed
    assert PLACEHOLDER_NO_VERIFICATION not in verification
    assert NOT_EXECUTED_VERIFICATION not in verification
    assert "overall_status=success" in verification


def test_unavailable_status_marks_sections_degraded() -> None:
    by_key = _sections(
        response_phase_status=ReportPhaseStatus.UNAVAILABLE,
        verification_phase_status=ReportPhaseStatus.UNAVAILABLE,
    )
    executed = by_key["executed_actions"].content
    assert UNAVAILABLE_ACTIONS in executed
    assert executed.endswith(UNAVAILABLE_ACTIONS)
    assert "actions_status_summary:" in executed
    assert by_key["verification_results"].content == UNAVAILABLE_VERIFICATION
    assert by_key["executed_actions"].data.get("degraded") is True
    assert by_key["verification_results"].data.get("degraded") is True


def test_incomplete_status_uses_incomplete_placeholder() -> None:
    for status in (ReportPhaseStatus.EXECUTED, ReportPhaseStatus.INCOMPLETE):
        by_key = _sections(
            response_phase_status=status,
            verification_phase_status=status,
        )
        executed = by_key["executed_actions"].content
        assert INCOMPLETE_ACTIONS_PLACEHOLDER in executed
        assert executed.endswith(INCOMPLETE_ACTIONS_PLACEHOLDER)
        assert "actions_status_summary:" in executed
        assert by_key["verification_results"].content == INCOMPLETE_VERIFICATION_PLACEHOLDER


def test_backfilled_data_wins_even_with_default_status() -> None:
    # Callers that pass data without an explicit status must never see the
    # NOT_EXECUTED wording — present data always renders.
    by_key = _sections(response_plan=_plan(), verification_result=_verification())
    assert "act-205-001" in by_key["executed_actions"].content
    assert "overall_status=success" in by_key["verification_results"].content


# --------------------------------------------------------------------------- #
# Call-site wiring regressions
# --------------------------------------------------------------------------- #


class _CapturingReportAgent:
    def __init__(self) -> None:
        self.inputs: list[ReportAgentInput] = []

    async def execute(self, input: ReportAgentInput) -> None:
        self.inputs.append(input)
        return None


@pytest.mark.asyncio
async def test_analysis_only_pipeline_report_input_is_not_executed() -> None:
    """Analysis-only never runs response/verify → chapters say 「未执行」."""
    report_agent = _CapturingReportAgent()
    pipeline = AnalysisOnlyPipeline(
        triage_agent=MagicMock(),
        evidence_agent=MagicMock(),
        rag_agent=MagicMock(),
        risk_agent=MagicMock(),
        report_agent=report_agent,
        context_store=_FakeContextStore(),
    )
    await pipeline._run_report(EVENT_ID, _evidence(), _risk())
    assert len(report_agent.inputs) == 1
    captured = report_agent.inputs[0]
    assert captured.response_plan is None
    assert captured.verification_result is None
    assert captured.response_phase_status is ReportPhaseStatus.NOT_EXECUTED
    assert captured.verification_phase_status is ReportPhaseStatus.NOT_EXECUTED


@pytest.mark.asyncio
async def test_analysis_only_pipeline_backfills_existing_context() -> None:
    report_agent = _CapturingReportAgent()
    store = _FakeContextStore(
        {
            "response_plan": _plan().model_dump(mode="json"),
            "verification_result": _verification().model_dump(mode="json"),
        }
    )
    pipeline = AnalysisOnlyPipeline(
        triage_agent=MagicMock(),
        evidence_agent=MagicMock(),
        rag_agent=MagicMock(),
        risk_agent=MagicMock(),
        report_agent=report_agent,
        context_store=store,
    )
    await pipeline._run_report(EVENT_ID, _evidence(), _risk())
    captured = report_agent.inputs[0]
    assert captured.response_plan is not None
    assert captured.verification_result is not None
    assert captured.response_phase_status is ReportPhaseStatus.EXECUTED


@pytest.mark.asyncio
async def test_builder_rejects_unknown_fields_via_model() -> None:
    """ReportAgentInput stays extra=forbid — the builder must not smuggle fields."""
    with pytest.raises(ValidationError):
        ReportAgentInput(
            event_id=EVENT_ID,
            evidence_output=_evidence(),
            risk_assessment=_risk(),
            response_phase_status="bogus",  # type: ignore[arg-type]
        )


def test_report_executed_actions_splits_writeback_obligation_and_applicability() -> None:
    """ISSUE-331: entity actions keep required=true/applicable=false in report prose."""
    builder = ReportSectionBuilder()
    entity = Action(
        action_id="act-entity-331",
        event_id=EVENT_ID,
        plan_revision=1,
        action_fingerprint="fp-entity",
        action_category=ActionCategory.RESPONSE,
        action_name="Block IP",
        tool_name="block_ip",
        action_level=ActionLevel.L3,
        status=ActionStatus.SUCCESS,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        writeback_required=True,
        writeback_applicable=False,
        writeback_readiness=WritebackReadiness.NOT_REQUIRED,
    )
    terminal = Action(
        action_id="act-terminal-331",
        event_id=EVENT_ID,
        plan_revision=1,
        action_fingerprint="fp-terminal",
        action_category=ActionCategory.RESPONSE,
        action_name="Update disposition",
        tool_name="update_source_event_disposition",
        action_level=ActionLevel.L1,
        execution_phase=ActionExecutionPhase.POST_VERIFY,
        activation_condition="after_effect_resolution",
        status=ActionStatus.APPROVED,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        writeback_required=True,
        writeback_applicable=True,
        writeback_readiness=WritebackReadiness.READY,
    )
    text = builder._executed_actions([entity, terminal], ReportPhaseStatus.EXECUTED)
    entity_line = next(line for line in text.splitlines() if line.startswith("act-entity-331"))
    terminal_line = next(line for line in text.splitlines() if line.startswith("act-terminal-331"))
    assert "writeback_required=true | writeback_applicable=false" in entity_line
    assert "writeback_not_applicable_reason=entity_side_effect" in entity_line
    assert "writeback_required=false" not in entity_line
    assert "writeback_required=true | writeback_applicable=true" in terminal_line
    assert "writeback_status=null" in terminal_line


def test_report_verification_results_marks_writeback_not_applicable() -> None:
    """ISSUE-331: verification chapter must not imply entity row completed terminal wb."""
    builder = ReportSectionBuilder()
    verification = VerificationResult(
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.DISPOSITION,
        results=[
            VerificationActionResult(
                action_id="act-entity-331",
                effect_status=EffectStatus.SKIPPED,
                writeback_required=True,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
                writeback_status=None,
                detail="writeback_not_applicable",
                verification_phase=VerificationPhase.DISPOSITION,
            )
        ],
    )
    text = builder._verification_results(verification, ReportPhaseStatus.EXECUTED)
    assert "writeback_applicable=false" in text
    assert "writeback_not_applicable_reason=entity_side_effect" in text
    assert "detail=writeback_not_applicable" in text
    assert "writeback_applicable=true" not in text


def test_report_verification_phase1_entity_not_executed_does_not_claim_applicable() -> None:
    """ISSUE-331: Phase 1 entity rows must not invent writeback_applicable=true."""
    builder = ReportSectionBuilder()
    verification = VerificationResult(
        overall_status=VerificationOverallStatus.PARTIAL,
        verification_phase=VerificationPhase.EFFECT,
        results=[
            VerificationActionResult(
                action_id="act-entity-331",
                effect_status=EffectStatus.SKIPPED,
                writeback_required=True,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
                writeback_status=None,
                detail="action_not_executed",
                verification_phase=VerificationPhase.EFFECT,
            )
        ],
    )
    text = builder._verification_results(verification, ReportPhaseStatus.EXECUTED)
    entity_line = next(line for line in text.splitlines() if line.startswith("act-entity-331"))
    assert "writeback_required=true" in entity_line
    assert "writeback_applicable=true" not in entity_line
    assert "writeback_not_applicable_reason" not in entity_line


def test_report_verification_ready_row_does_not_invent_applicable_from_readiness() -> None:
    """ISSUE-331: READY without an Action join must not invent applicable=true."""
    builder = ReportSectionBuilder()
    verification = VerificationResult(
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.DISPOSITION,
        results=[
            VerificationActionResult(
                action_id="act-terminal-331",
                effect_status=EffectStatus.VERIFIED,
                writeback_required=True,
                writeback_readiness=WritebackReadiness.READY,
                writeback_status=WritebackStatus.CONFIRMED,
                verification_phase=VerificationPhase.DISPOSITION,
            )
        ],
    )
    text = builder._verification_results(verification, ReportPhaseStatus.EXECUTED)
    terminal_line = next(line for line in text.splitlines() if line.startswith("act-terminal-331"))
    assert "writeback_required=true" in terminal_line
    assert "writeback_status=confirmed" in terminal_line
    assert "writeback_applicable=true" not in terminal_line


@pytest.mark.parametrize(
    "readiness",
    [
        WritebackReadiness.SOURCE_UNRESOLVED,
        WritebackReadiness.CAPABILITY_UNKNOWN,
        WritebackReadiness.PERMISSION_DENIED,
    ],
)
def test_report_verification_blocked_readiness_does_not_invent_applicable(
    readiness: WritebackReadiness,
) -> None:
    builder = ReportSectionBuilder()
    verification = VerificationResult(
        overall_status=VerificationOverallStatus.PARTIAL,
        verification_phase=VerificationPhase.DISPOSITION,
        results=[
            VerificationActionResult(
                action_id="act-blocked-331",
                effect_status=EffectStatus.UNVERIFIABLE,
                writeback_required=True,
                writeback_readiness=readiness,
                writeback_status=None,
                detail=f"writeback_blocked_{readiness.value}",
                verification_phase=VerificationPhase.DISPOSITION,
            )
        ],
    )
    text = builder._verification_results(verification, ReportPhaseStatus.EXECUTED)
    line = next(item for item in text.splitlines() if item.startswith("act-blocked-331"))
    assert "writeback_required=true" in line
    assert "writeback_applicable=true" not in line


def test_report_verification_joins_action_applicable_for_entity_and_terminal() -> None:
    """ISSUE-331: joined Action fields are the only source of applicable=true."""
    builder = ReportSectionBuilder()
    entity = Action(
        action_id="act-entity-331",
        event_id=EVENT_ID,
        plan_revision=1,
        action_fingerprint="fp-entity",
        action_category=ActionCategory.RESPONSE,
        action_name="Block IP",
        tool_name="block_ip",
        action_level=ActionLevel.L3,
        status=ActionStatus.SUCCESS,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        writeback_required=True,
        writeback_applicable=False,
        writeback_readiness=WritebackReadiness.NOT_REQUIRED,
    )
    terminal = Action(
        action_id="act-terminal-331",
        event_id=EVENT_ID,
        plan_revision=1,
        action_fingerprint="fp-terminal",
        action_category=ActionCategory.RESPONSE,
        action_name="Update disposition",
        tool_name="update_source_event_disposition",
        action_level=ActionLevel.L1,
        execution_phase=ActionExecutionPhase.POST_VERIFY,
        activation_condition="after_effect_resolution",
        status=ActionStatus.APPROVED,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        writeback_required=True,
        writeback_applicable=True,
        writeback_readiness=WritebackReadiness.READY,
        writeback_status=WritebackStatus.CONFIRMED,
    )
    verification = VerificationResult(
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.DISPOSITION,
        results=[
            VerificationActionResult(
                action_id="act-entity-331",
                effect_status=EffectStatus.SKIPPED,
                writeback_required=True,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
                writeback_status=None,
                detail="action_not_executed",
                verification_phase=VerificationPhase.EFFECT,
            ),
            VerificationActionResult(
                action_id="act-terminal-331",
                effect_status=EffectStatus.VERIFIED,
                writeback_required=True,
                writeback_readiness=WritebackReadiness.READY,
                writeback_status=WritebackStatus.CONFIRMED,
                verification_phase=VerificationPhase.DISPOSITION,
            ),
        ],
    )
    text = builder._verification_results(
        verification,
        ReportPhaseStatus.EXECUTED,
        [entity, terminal],
    )
    entity_line = next(line for line in text.splitlines() if line.startswith("act-entity-331"))
    terminal_line = next(line for line in text.splitlines() if line.startswith("act-terminal-331"))
    assert "writeback_required=true | writeback_applicable=false" in entity_line
    assert "writeback_not_applicable_reason=entity_side_effect" in entity_line
    assert "writeback_required=false" not in entity_line
    assert "writeback_required=true | writeback_applicable=true" in terminal_line
    assert "writeback_status=confirmed" in terminal_line


def test_report_section_data_persists_writeback_applicability() -> None:
    """ISSUE-331: executed_actions.data.writeback_rows survives LLM rewrite."""
    entity = Action(
        action_id="act-entity-331",
        event_id=EVENT_ID,
        plan_revision=1,
        action_fingerprint="fp-entity-data",
        action_category=ActionCategory.RESPONSE,
        action_name="Block IP",
        tool_name="block_ip",
        action_level=ActionLevel.L3,
        status=ActionStatus.SUCCESS,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        writeback_required=True,
        writeback_applicable=False,
        writeback_readiness=WritebackReadiness.NOT_REQUIRED,
    )
    terminal = Action(
        action_id="act-terminal-331",
        event_id=EVENT_ID,
        plan_revision=1,
        action_fingerprint="fp-terminal-data",
        action_category=ActionCategory.RESPONSE,
        action_name="Update disposition",
        tool_name="update_source_event_disposition",
        action_level=ActionLevel.L1,
        execution_phase=ActionExecutionPhase.POST_VERIFY,
        activation_condition="after_effect_resolution",
        status=ActionStatus.SUCCESS,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        writeback_required=True,
        writeback_applicable=True,
        writeback_readiness=WritebackReadiness.READY,
        writeback_status=WritebackStatus.CONFIRMED,
    )
    sections = ReportSectionBuilder().build(
        event_id=EVENT_ID,
        evidence_output=_evidence(),
        risk_assessment=_risk(),
        response_plan=ResponsePlan(
            plan_id="plan-331",
            actions=[entity, terminal],
            strategy_summary="contain exfiltration",
            generated_by=ResponsePlanGeneratedBy.TEMPLATE,
        ),
        verification_result=VerificationResult(
            overall_status=VerificationOverallStatus.SUCCESS,
            verification_phase=VerificationPhase.DISPOSITION,
            results=[
                VerificationActionResult(
                    action_id="act-entity-331",
                    effect_status=EffectStatus.SKIPPED,
                    writeback_required=True,
                    writeback_readiness=WritebackReadiness.NOT_REQUIRED,
                    detail="writeback_not_applicable",
                    verification_phase=VerificationPhase.DISPOSITION,
                ),
                VerificationActionResult(
                    action_id="act-terminal-331",
                    effect_status=EffectStatus.VERIFIED,
                    writeback_required=True,
                    writeback_readiness=WritebackReadiness.READY,
                    writeback_status=WritebackStatus.CONFIRMED,
                    verification_phase=VerificationPhase.DISPOSITION,
                ),
            ],
        ),
        response_phase_status=ReportPhaseStatus.EXECUTED,
        verification_phase_status=ReportPhaseStatus.EXECUTED,
    )
    executed = next(section for section in sections if section.key == "executed_actions")
    rows = {row["action_id"]: row for row in executed.data["writeback_rows"]}
    assert rows["act-entity-331"]["writeback_required"] is True
    assert rows["act-entity-331"]["writeback_applicable"] is False
    assert rows["act-terminal-331"]["writeback_applicable"] is True
    verification = next(section for section in sections if section.key == "verification_results")
    entity_line = next(
        line for line in verification.content.splitlines() if line.startswith("act-entity-331")
    )
    terminal_line = next(
        line for line in verification.content.splitlines() if line.startswith("act-terminal-331")
    )
    assert "writeback_applicable=false" in entity_line
    assert "writeback_applicable=true" in terminal_line
    assert "writeback_required=false" not in entity_line
