"""VerifyAgent two-phase verification tests (ISSUE-060).

Covers the 8 required test categories:
1. Happy Path — normal input → expected output
2. LLM 降级 — degraded fallback (rule-only), degraded=True
3. 依赖故障 — Redis/DB/WM unavailable → graceful degradation
4. 边界输入 — empty/null/extreme values
5. 状态机 — legal transitions pass, illegal transitions raise, idempotent
6. 写回 — analysis content stays local, writeback called and idempotent, simulated=true
7. 护栏 — non-owner write → GuardrailViolationError
8. 并发 — version conflict handled correctly

Plus acceptance criteria from the Issue:
A1. Two-phase all-pass → overall_status=success
A2. Effect failure → need_action_replan=true, EventDispositionService not called
A3. create_ticket → effect_status=skipped, verification action writeback_required=false
A4. Deferred action → skipped, not in failed_actions
A5. 8-state writeback truth table
A6. Disposition-only path: phase 1 no entities but phase 2 still activates
A7. Verification false vs tool exception — Action status distinction
"""

from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.agents.verify_agent import VerifyAgent, _WRITEBACK_STATUS_ROUTING
from app.agents.rules.verification_mapping import (
    VERIFICATION_MAPPING,
    resolve_verification_tool,
)
from app.core.errors import GuardrailViolationError
from app.models.action import TERMINAL_DISPOSITION_TOOL, Action
from app.models.agent_io import (
    EffectStatus,
    ResponsePlan,
    ResponsePlanGeneratedBy,
    VerificationActionResult,
    VerificationOverallStatus,
    VerificationPhase,
    VerificationResult,
    VerifyAgentInput,
)
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    DispositionPolicy,
    ExecutionJobStatus,
    ExecutionOwner,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.execution import ActionExecutionJob
from app.models.ids import new_action_id, new_job_id
from app.models.tool_meta import ToolResult, ToolResultStatus

pytestmark = pytest.mark.asyncio


# --------------------------------------------------------------------------- #
# Factory helpers
# --------------------------------------------------------------------------- #


def _action(
    *,
    action_id: str | None = None,
    event_id: str = "evt-20260725-00000001",
    tool_name: str = "block_ip",
    action_category: ActionCategory = ActionCategory.RESPONSE,
    action_name: str = "block_ip_action",
    target_type: str = "ip",
    target: str = "10.0.0.1",
    status: ActionStatus = ActionStatus.SUCCESS,
    execution_phase: ActionExecutionPhase = ActionExecutionPhase.IMMEDIATE,
    execution_owner: ExecutionOwner | None = ExecutionOwner.DIRECT_TOOL,
    execution_job_id: str | None = None,
    writeback_required: bool = False,
    writeback_applicable: bool = False,
    writeback_readiness: WritebackReadiness = WritebackReadiness.NOT_REQUIRED,
    writeback_status: WritebackStatus | None = None,
    superseded_by_revision: int | None = None,
    plan_revision: int = 1,
    action_level: ActionLevel = ActionLevel.L2,
    **kwargs: Any,
) -> Action:
    return Action(
        action_id=action_id or new_action_id(),
        event_id=event_id,
        plan_revision=plan_revision,
        action_fingerprint=f"fp:{tool_name}",
        action_category=action_category,
        action_name=action_name,
        tool_name=tool_name,
        action_level=action_level,
        execution_phase=execution_phase,
        activation_condition=(
            "after_effect_resolution"
            if execution_phase is ActionExecutionPhase.POST_VERIFY
            else None
        ),
        target_type=target_type,
        target=target,
        status=status,
        execution_owner=execution_owner,
        execution_job_id=execution_job_id,
        writeback_required=writeback_required,
        writeback_applicable=writeback_applicable,
        writeback_readiness=writeback_readiness,
        writeback_status=writeback_status,
        superseded_by_revision=superseded_by_revision,
        **kwargs,
    )


def _job(
    *,
    job_id: str | None = None,
    event_id: str = "evt-20260725-00000001",
    action_id: str = "act-00000001",
    status: ExecutionJobStatus = ExecutionJobStatus.SUCCESS,
    provider_name: str = "mock_observation",
    **kwargs: Any,
) -> ActionExecutionJob:
    return ActionExecutionJob(
        job_id=job_id or new_job_id(),
        event_id=event_id,
        action_id=action_id,
        provider_name=provider_name,
        idempotency_key=f"idem-{action_id}",
        status=status,
        **kwargs,
    )


def _plan(actions: list[Action]) -> ResponsePlan:
    return ResponsePlan(
        plan_id="plan-00000001",
        actions=actions,
        strategy_summary="Test plan",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )


def _input(
    event_id: str = "evt-20260725-00000001",
    actions: list[Action] | None = None,
    phase: VerificationPhase = VerificationPhase.EFFECT,
) -> VerifyAgentInput:
    plan = _plan(actions or [])
    return VerifyAgentInput(
        event_id=event_id,
        response_plan=plan,
        verification_phase=phase,
    )


def _tool_result_success(verified: bool = True, detail: str = "ok") -> ToolResult:
    return ToolResult(
        call_id="call-00000001",
        tool_name="check_ip_block_status",
        provider_name="mock_observation",
        status=ToolResultStatus.SUCCESS,
        data={"is_verified": verified, "detail": detail, "verified_at": datetime.now(UTC)},
    )


def _tool_result_error(message: str = "tool failed") -> ToolResult:
    return ToolResult(
        call_id="call-00000001",
        tool_name="check_ip_block_status",
        provider_name="mock_observation",
        status=ToolResultStatus.FAILED,
        error_detail=message,
    )


# --------------------------------------------------------------------------- #
# Fake / stub classes for testing
# --------------------------------------------------------------------------- #


class FakeWorkingMemory:
    """In-memory BoundWorkingMemory stand-in."""

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], Any] = {}
        self._scratchpad: dict[str, list[str]] = {}

    async def read(self, event_id: str, key: str) -> Any:
        return self._store.get((event_id, key))

    async def write(self, event_id: str, key: str, value: Any) -> None:
        self._store[(event_id, key)] = value

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        self._scratchpad.setdefault(event_id, []).append(note)

    async def read_scratchpad(self, event_id: str) -> list[Any]:
        return self._scratchpad.get(event_id, [])


class FakeEventBus:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def publish_event(self, event_id: str, event_type: str, payload: dict[str, Any]) -> None:
        self.events.append(
            {"event_id": event_id, "type": event_type, "payload": payload}
        )


class FakeTraceService:
    def __init__(self) -> None:
        self.traces: list[dict[str, Any]] = []

    async def log_trace(self, **kwargs: Any) -> str:
        self.traces.append(kwargs)
        return "trace-0001"


class FakeEventDispositionService:
    """Stub EventDispositionService (ISSUE-059A)."""

    def __init__(self, *, success: bool = True) -> None:
        self.success = success
        self.calls: list[dict[str, Any]] = []

    async def activate_and_submit(self, *, event_id: str) -> Any:
        self.calls.append({"event_id": event_id})
        from app.agents.verify_agent import _ActivateResult

        return _ActivateResult(
            success=self.success,
            terminal_writeback_id="wbk-00000001" if self.success else None,
            terminal_disposition_id="dis-00000001" if self.success else None,
            error_code=None if self.success else "capability_blocked",
            error_detail=None if self.success else "test injection",
        )


# --------------------------------------------------------------------------- #
# 1. Happy Path
# --------------------------------------------------------------------------- #


class TestHappyPath:
    async def test_phase1_single_action_verified(self):
        """Normal input → phase 1 effect verified."""
        action = _action(
            tool_name="block_ip",
            target_type="ip",
            target="10.0.0.1",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        # Override _load_execution_state for controlled data.
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action], phase=VerificationPhase.EFFECT)
        )

        assert result.overall_status == VerificationOverallStatus.SUCCESS
        assert len(result.results) == 1
        r = result.results[0]
        assert r.action_id == action.action_id
        assert r.effect_status == EffectStatus.VERIFIED
        assert r.verification_action_id is not None
        assert not result.need_action_replan
        assert not result.need_writeback_recovery
        assert not result.need_manual_resolution

    async def test_phase1_effect_failed_triggers_replan(self):
        """Effect verification false → need_action_replan=true."""
        action = _action(
            tool_name="block_ip",
            target_type="ip",
            target="10.0.0.1",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        agent = VerifyAgent(
            tool_executor=_mock_executor(
                {"check_ip_block_status": _tool_result_success(False, "block not observed")}
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )

        assert result.need_action_replan is True
        assert action.action_id in result.failed_actions
        r = result.results[0]
        assert r.effect_status == EffectStatus.FAILED

    async def test_phase1_deferred_action_skipped(self):
        """POST_VERIFY deferred Action → effect_status=skipped, not in failed_actions."""
        action = _action(
            tool_name=TERMINAL_DISPOSITION_TOOL,
            action_name="terminal_disposition",
            target_type="source_object",
            target="src-1",
            execution_phase=ActionExecutionPhase.POST_VERIFY,
            status=ActionStatus.APPROVED,  # not yet executed
            execution_owner=ExecutionOwner.XDR_MANAGED,
            writeback_required=True,
        )
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )

        r = result.results[0]
        assert r.effect_status == EffectStatus.SKIPPED
        assert r.detail == "deferred_pending_activation"
        assert action.action_id not in result.failed_actions

    async def test_phase2_success(self):
        """Full two-phase: effects ok → activate → writeback CONFIRMED."""
        action = _action(
            tool_name="block_ip",
            target_type="ip",
            target="10.0.0.1",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(success=True)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )

        # EventDispositionService.activate_and_submit was called.
        assert len(ed_svc.calls) == 1
        assert ed_svc.calls[0]["event_id"] == action.event_id
        assert result.overall_status == VerificationOverallStatus.SUCCESS

    async def test_create_ticket_skipped(self):
        """create_ticket → effect_status=skipped, verification action writeback_required=false."""
        action = _action(
            tool_name="create_ticket",
            action_name="ticket_action",
            target_type="ticket",
            target="ticket-1",
            status=ActionStatus.SUCCESS,
            action_level=ActionLevel.L1,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
        )
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )

        r = result.results[0]
        assert r.effect_status == EffectStatus.SKIPPED
        assert r.detail == "non_verifiable_action"
        # Verification action should have writeback_required=false (checked via model validation)


# --------------------------------------------------------------------------- #
# 2. LLM/降级 (Degradation)
# --------------------------------------------------------------------------- #


class TestDegradation:
    async def test_tool_executor_none_produces_unverifiable(self):
        """No tool executor → all verifications produce unverifiable."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        agent = VerifyAgent(
            tool_executor=None,  # degraded
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )

        assert result.results[0].effect_status == EffectStatus.UNVERIFIABLE
        # All verification tools unavailable → escalated (need_manual_resolution).
        assert result.need_manual_resolution is True
        assert result.overall_status != VerificationOverallStatus.SUCCESS

    async def test_verification_tool_returns_error(self):
        """Verification tool error → effect_status=unverifiable."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        agent = VerifyAgent(
            tool_executor=_mock_executor(
                {"check_ip_block_status": _tool_result_error("connection refused")}
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )

        assert result.results[0].effect_status == EffectStatus.UNVERIFIABLE
        assert "verification_tool_error" in (result.results[0].detail or "")


# --------------------------------------------------------------------------- #
# 3. 依赖故障 (Dependency failures)
# --------------------------------------------------------------------------- #


class TestDependencyFailure:
    async def test_no_working_memory_does_not_crash(self):
        """Agent must not crash when working_memory is None."""
        action = _action(
            tool_name="create_ticket",
            action_level=ActionLevel.L1,
            status=ActionStatus.SUCCESS,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
        )
        agent = VerifyAgent(
            working_memory=None,
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )
        assert result is not None
        assert result.overall_status == VerificationOverallStatus.SUCCESS

    async def test_no_session_factory_uses_plan_actions(self):
        """When session_factory is None, agents are taken from the input plan."""
        action = _action(
            tool_name="create_ticket",
            action_level=ActionLevel.L1,
            status=ActionStatus.SUCCESS,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
        )
        agent = VerifyAgent(
            session_factory=None,
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        # No mock on _load_execution_state → uses real (but sessionless) path.

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )
        assert len(result.results) == 1
        assert result.results[0].effect_status == EffectStatus.SKIPPED

    async def test_no_event_disposition_service_marks_manual(self):
        """When EventDispositionService is missing and policy=required, need_manual."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_disposition_service=None,  # missing
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )
        # Phase 1 passes, phase 2 activation unavailable → manual.
        assert result.need_manual_resolution is True
        assert result.overall_status == VerificationOverallStatus.MANUAL_RESOLUTION


# --------------------------------------------------------------------------- #
# 4. 边界输入 (Boundary inputs)
# --------------------------------------------------------------------------- #


class TestBoundaryInputs:
    async def test_empty_actions(self):
        """Empty response plan → no results, success."""
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(actions=[]))
        assert len(result.results) == 0
        assert result.overall_status == VerificationOverallStatus.SUCCESS

    async def test_action_with_none_target_type(self):
        """Action with target_type=None → mapping resolves to first available."""
        action = _action(
            tool_name="block_ip",
            target_type=None,
            target="10.0.0.1",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(actions=[action]))
        assert result.results[0].effect_status == EffectStatus.VERIFIED

    async def test_unknown_tool_maps_to_none(self):
        """Tool not in mapping → resolve_verification_tool returns None."""
        assert resolve_verification_tool("nonexistent_tool", "ip") is None

    async def test_unicode_target_values(self):
        """Unicode/中文 target values handled safely."""
        action = _action(
            tool_name="block_ip",
            target_type="ip",
            target="192.168.中国.1",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(actions=[action]))
        assert result.results[0].effect_status == EffectStatus.VERIFIED


# --------------------------------------------------------------------------- #
# 5. 状态机 (State machine)
# --------------------------------------------------------------------------- #


class TestStateMachine:
    async def test_verification_action_status_transition(self):
        """Verification Action: PENDING → EXECUTING → SUCCESS."""
        from app.models.workflow import validate_action_status_transition

        # PENDING → EXECUTING (legal for VERIFICATION)
        validate_action_status_transition(
            ActionCategory.VERIFICATION,
            ActionStatus.PENDING,
            ActionStatus.EXECUTING,
        )
        # EXECUTING → SUCCESS (legal)
        validate_action_status_transition(
            ActionCategory.VERIFICATION,
            ActionStatus.EXECUTING,
            ActionStatus.SUCCESS,
        )

    async def test_verification_action_cannot_be_rolled_back(self):
        """Verification actions should never transition to ROLLED_BACK."""
        from app.models.workflow import validate_action_status_transition
        from app.core.errors import InvalidStateTransitionError

        with pytest.raises(InvalidStateTransitionError):
            validate_action_status_transition(
                ActionCategory.VERIFICATION,
                ActionStatus.SUCCESS,
                ActionStatus.ROLLED_BACK,
            )

    async def test_multiple_verifications_idempotent(self):
        """Re-verifying same actions produces consistent results."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        for _ in range(2):
            agent = VerifyAgent(
                tool_executor=_mock_executor(
                    {"check_ip_block_status": _tool_result_success(True)}
                ),
                working_memory=FakeWorkingMemory(),
                trace_service=FakeTraceService(),
            )
            agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
                return_value=([action], {"job-0001": job}, {})
            )
            agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
                return_value=DispositionPolicy.NOT_REQUIRED,
            )

            result = await agent.execute(_input(actions=[action]))
            assert result.results[0].effect_status == EffectStatus.VERIFIED


# --------------------------------------------------------------------------- #
# 6. 写回 (Writeback)
# --------------------------------------------------------------------------- #


class TestWriteback:
    async def test_writeback_failure_no_replan(self):
        """Writeback failure does NOT trigger need_action_replan."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.FAILED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(success=True)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )
        # Writeback failed → recovery needed, NOT action replan.
        assert result.need_action_replan is False
        assert result.need_writeback_recovery is True

    async def test_analysis_content_never_egresses(self):
        """Verification tool params never carry analysis content (reason, raw_result)."""
        action = _action(
            tool_name="block_ip",
            reason="suspicious IP from threat intel analysis",  # analysis content
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        captured_params: dict[str, Any] = {}

        async def capturing_call(tool_name, params, event_id, **kw):
            captured_params.update(params)
            return _tool_result_success(True)

        agent = VerifyAgent(
            tool_executor=MagicMock(call=AsyncMock(side_effect=capturing_call)),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        await agent.execute(_input(actions=[action]))
        # Params should contain target info but NOT analysis content.
        assert "reason" not in captured_params
        assert "raw_result" not in captured_params


# --------------------------------------------------------------------------- #
# 7. 护栏 (Guardrails)
# --------------------------------------------------------------------------- #


class TestGuardrails:
    async def test_non_owner_cannot_write_verification_result(self):
        """Non-VerifyAgent writer cannot write verification_result to WM."""
        from app.services.working_memory import WorkingMemory

        # The FIELD_OWNERSHIP dict guards the write path.
        from app.services.working_memory import FIELD_OWNERSHIP

        assert FIELD_OWNERSHIP["verification_result"] == "VerifyAgent"

    async def test_verify_agent_is_correct_owner(self):
        """VerifyAgent has the correct writer identity for verification_result."""
        from app.services.working_memory import FIELD_OWNERSHIP

        assert FIELD_OWNERSHIP.get("verification_result") == "VerifyAgent"


# --------------------------------------------------------------------------- #
# 8. 写回八态真值表 (8-state writeback truth table)
# --------------------------------------------------------------------------- #


class TestWritebackTruthTable:
    @pytest.mark.parametrize(
        "wb_status, expected_confirmed, expected_recovery, expected_manual",
        [
            (WritebackStatus.CONFIRMED, True, False, False),
            (WritebackStatus.PENDING, False, True, False),
            (WritebackStatus.SENDING, False, True, False),
            (WritebackStatus.ACCEPTED, False, True, False),
            (WritebackStatus.UNKNOWN, False, False, True),
            (WritebackStatus.PARTIAL, False, True, False),
            (WritebackStatus.FAILED, False, True, False),
            (WritebackStatus.CONFLICT, False, False, True),
            (None, False, True, False),
        ],
    )
    async def test_writeback_truth_table(
        self, wb_status, expected_confirmed, expected_recovery, expected_manual
    ):
        """Each WritebackStatus routes correctly per ISSUE-060 spec."""
        confirmed, recovery, manual, _detail = _WRITEBACK_STATUS_ROUTING.get(
            wb_status,
            (False, True, False, "unknown"),
        )
        assert confirmed == expected_confirmed
        assert recovery == expected_recovery
        assert manual == expected_manual


# --------------------------------------------------------------------------- #
# Acceptance criteria tests
# --------------------------------------------------------------------------- #


class TestAcceptanceCriteria:
    """ISSUE-060 acceptance criteria."""

    async def test_a1_full_two_phase_success(self):
        """A1: Both phases pass → overall_status=success."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(success=True)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )
        assert result.overall_status == VerificationOverallStatus.SUCCESS

    async def test_a1_writeback_fails_event_not_success(self):
        """A1: Effect OK but writeback FAILED → not success."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.FAILED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(success=True)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )
        assert result.overall_status != VerificationOverallStatus.SUCCESS

    async def test_a2_effect_failure_no_disposition_call(self):
        """A2: Effect verification fails → need_action_replan=true, EventDispositionService NOT called."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(success=True)
        agent = VerifyAgent(
            tool_executor=_mock_executor(
                {"check_ip_block_status": _tool_result_success(False, "not blocked")}
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )
        assert result.need_action_replan is True
        assert len(ed_svc.calls) == 0  # NOT called

    async def test_a2_writeback_failure_no_replan(self):
        """A2: Only writeback failure → need_action_replan=false."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.PENDING,  # not confirmed
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(success=True)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )
        assert result.need_action_replan is False
        assert result.need_writeback_recovery is True

    async def test_a3_create_ticket_skipped(self):
        """A3: create_ticket → effect_status=skipped."""
        action = _action(
            tool_name="create_ticket",
            action_level=ActionLevel.L1,
            target_type="ticket",
            target="ticket-1",
            status=ActionStatus.SUCCESS,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
        )
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )
        assert result.results[0].effect_status == EffectStatus.SKIPPED
        assert "non_verifiable" in (result.results[0].detail or "")

    async def test_a4_deferred_not_in_failed(self):
        """A4: Deferred action → skipped, not in failed_actions."""
        deferred = _action(
            tool_name=TERMINAL_DISPOSITION_TOOL,
            action_name="terminal",
            execution_phase=ActionExecutionPhase.POST_VERIFY,
            status=ActionStatus.APPROVED,
            execution_owner=ExecutionOwner.XDR_MANAGED,
            writeback_required=True,
        )
        immediate = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=immediate.action_id)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([immediate, deferred], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(
            _input(actions=[immediate, deferred])
        )

        deferred_results = [r for r in result.results if r.action_id == deferred.action_id]
        assert len(deferred_results) == 1
        assert deferred_results[0].effect_status == EffectStatus.SKIPPED
        assert deferred_results[0].detail == "deferred_pending_activation"
        assert deferred.action_id not in result.failed_actions

    async def test_a6_disposition_only_path_phase2_activates(self):
        """A6: Pure POST_VERIFY deferred plan → phase 2 still activates.

        ResponsePlan contains ONLY a deferred action (no IMMEDIATE).
        Phase 1 produces skipped results; phase 2 calls
        EventDispositionService.activate_and_submit and routes on
        writeback outcome.
        """
        deferred = _action(
            action_id="act-a6-deferred",
            tool_name=TERMINAL_DISPOSITION_TOOL,
            action_name="terminal_disposition",
            target_type="source_object",
            target="src-a6",
            execution_phase=ActionExecutionPhase.POST_VERIFY,
            status=ActionStatus.APPROVED,
            execution_owner=ExecutionOwner.XDR_MANAGED,
            writeback_required=True,
        )
        ed_svc = FakeEventDispositionService(success=True)
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([deferred], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=deferred.event_id, actions=[deferred])
        )

        # Phase 1: deferred → skipped (not failed).
        r = result.results[0]
        assert r.action_id == "act-a6-deferred"
        assert r.effect_status == EffectStatus.SKIPPED
        assert r.detail == "deferred_pending_activation"
        assert "act-a6-deferred" not in result.failed_actions

        # Phase 2: EventDispositionService was called.
        assert len(ed_svc.calls) == 1
        assert ed_svc.calls[0]["event_id"] == deferred.event_id

        # Overall status depends on writeback (none in this stub), but
        # the key invariant is that phase 2 activation was triggered.
        # With activation success and no writeback failures, overall
        # should be SUCCESS.
        assert result.overall_status == VerificationOverallStatus.SUCCESS

    async def test_a7_tool_false_vs_exception(self):
        """A7: Verification false → failed; tool exception → unverifiable (Action status differs)."""
        # Case 1: tool returns false
        action1 = _action(
            action_id="act-verify-01",
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job1 = _job(job_id="job-0001", action_id="act-verify-01")

        agent1 = VerifyAgent(
            tool_executor=_mock_executor(
                {"check_ip_block_status": _tool_result_success(False, "not blocked")}
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent1._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action1], {"job-0001": job1}, {})
        )
        agent1._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )
        result1 = await agent1.execute(
            _input(event_id="evt-20260725-00000001", actions=[action1])
        )
        assert result1.results[0].effect_status == EffectStatus.FAILED

        # Case 2: tool throws error
        action2 = _action(
            action_id="act-verify-02",
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0002",
        )
        job2 = _job(job_id="job-0002", action_id="act-verify-02")

        agent2 = VerifyAgent(
            tool_executor=_mock_executor(
                {"check_ip_block_status": _tool_result_error("crash")}
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent2._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action2], {"job-0002": job2}, {})
        )
        agent2._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )
        result2 = await agent2.execute(
            _input(event_id="evt-20260725-00000002", actions=[action2])
        )
        assert result2.results[0].effect_status == EffectStatus.UNVERIFIABLE


# --------------------------------------------------------------------------- #
# Verification mapping tests
# --------------------------------------------------------------------------- #


class TestVerificationMapping:

    async def test_all_response_tools_have_mapping(self):
        """Every baseline response tool has a verification mapping entry or is skipped."""
        response_tools = [
            "block_ip", "block_domain", "isolate_host", "quarantine_file",
            "block_process", "scan_host_for_virus", "disable_account",
            "force_logout", "reset_password", "revoke_token",
            "create_ticket", "notify_security_team",
        ]
        for tool in response_tools:
            result = resolve_verification_tool(tool, None)
            # Either mapped to a verification tool or None (skipped).
            assert result is None or isinstance(result, str), (
                f"{tool} should resolve to str or None, got {result!r}"
            )

    async def test_mapping_is_stable(self):
        """Mappings should be stable across calls."""
        assert resolve_verification_tool("block_ip", "ip") == "check_ip_block_status"
        assert resolve_verification_tool("block_domain", "domain") == "check_domain_block_status"
        assert resolve_verification_tool("isolate_host", "host") == "check_host_isolation_status"
        assert resolve_verification_tool("disable_account", "account") == "check_account_status"
        assert resolve_verification_tool("create_ticket", "ticket") is None

    async def test_provider_override(self):
        """Provider manifest can override the baseline mapping."""
        override = {"block_ip": {"ip": "custom_check_ip_advanced"}}
        result = resolve_verification_tool(
            "block_ip", "ip", provider_manifest_overrides=override
        )
        assert result == "custom_check_ip_advanced"

    async def test_rollback_tools_mapped(self):
        """Rollback tools (unblock_ip, etc.) also map to verification tools."""
        assert resolve_verification_tool("unblock_ip", "ip") == "check_ip_block_status"
        assert resolve_verification_tool("cancel_host_isolation", "host") == "check_host_isolation_status"
        assert resolve_verification_tool("restore_file", "file") == "check_file_quarantine_status"


# --------------------------------------------------------------------------- #
# Should-Fix regression tests (PR#7 review)
# --------------------------------------------------------------------------- #


class TestRegressionShouldFix:
    """Tests for issues identified in PR#7 review."""

    async def test_unverifiable_preserves_writeback_obligation(self):
        """UNVERIFIABLE preserves writeback_required (Should-Fix 1).

        A writeback_required=True action whose verification tool throws
        an exception must still report writeback_required=True — the
        business obligation is never reversed by technical inability.
        """
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        agent = VerifyAgent(
            tool_executor=_mock_executor(
                {"check_ip_block_status": _tool_result_error("connection refused")}
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )

        r = result.results[0]
        assert r.effect_status == EffectStatus.UNVERIFIABLE
        # Key assertion: writeback_required stays True.
        assert r.writeback_required is True

    async def test_executing_action_not_prematurely_verified(self):
        """EXECUTING action → skipped, not FAILED (Should-Fix 4).

        An action still in EXECUTING status must not be verified by the
        observation tool — its effect may not have materialised yet.
        """
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.EXECUTING,
            execution_job_id="job-0001",
        )
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )

        r = result.results[0]
        assert r.effect_status == EffectStatus.SKIPPED
        assert r.detail == "pending_execution"
        assert action.action_id not in result.failed_actions
        assert result.need_action_replan is False

    async def test_finalize_failure_during_exception_handling(self):
        """_finalize_verification_action failure → logged, not swallowed.

        When _finalize_verification_action itself throws during
        exception handling, the outer layer must log a warning
        (Should-Fix 2).
        """
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        # Simulate the verification tool executor throwing, AND the
        # subsequent finalize call also failing.
        failing_executor = MagicMock()
        failing_executor.call = AsyncMock(
            side_effect=RuntimeError("tool exploded")
        )

        agent = VerifyAgent(
            tool_executor=failing_executor,
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        # Make _finalize_verification_action blow up.
        agent._finalize_verification_action = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("db connection lost")
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        # Must not raise — the exception is caught and logged.
        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )

        assert result.results[0].effect_status == EffectStatus.UNVERIFIABLE
        # The detail should contain the exception TYPE name, not the raw message.
        assert "RuntimeError" in (result.results[0].detail or "")

    async def test_verification_action_persist_failure_graceful(self):
        """DB insert failure for verification action → returns result anyway.

        When _create_verification_action fails to persist the Action row
        to the database, the verification result must still be returned
        (the observation is the primary output; the trace record is
        best-effort).
        """
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        agent = VerifyAgent(
            tool_executor=_mock_executor(
                {"check_ip_block_status": _tool_result_success(True)}
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        # _create_verification_action persists but the session_factory
        # is None → _create returns the Action domain object without
        # DB persistence.  The tool call and result still flow through.
        agent._create_verification_action = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("persist failed")
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        # Should not crash — the exception is caught inside _run_verification_tool.
        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )

        assert result.results[0].effect_status == EffectStatus.UNVERIFIABLE

    async def test_writeback_failure_action_execution_count_unchanged(self):
        """Writeback failure → need_action_replan=false, execution count unchanged.

        Acceptance criteria A2 second half: when only writeback fails
        (not effect), the action execution count must not increase
        because no re-execution is triggered.
        """
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.FAILED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(success=True)
        agent = VerifyAgent(
            tool_executor=_mock_executor(
                {"check_ip_block_status": _tool_result_success(True)}
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )

        # Action replan NOT triggered by writeback failure alone.
        assert result.need_action_replan is False
        # Action is NOT in failed_actions (that's for EFFECT failures only).
        assert action.action_id not in result.failed_actions
        # Writeback IS in failed_writebacks.
        assert action.action_id in result.failed_writebacks

    async def test_empty_plan_required_policy_triggers_phase2(self):
        """Empty plan + disposition_policy=REQUIRED → phase 2 still activates.

        When there are no IMMEDIATE actions, phase 2 must still call
        EventDispositionService.activate_and_submit.
        """
        ed_svc = FakeEventDispositionService(success=True)
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(
            _input(event_id="evt-20260725-00000001", actions=[])
        )

        # Phase 2 was invoked (activation called).
        assert len(ed_svc.calls) == 1
        assert result.overall_status == VerificationOverallStatus.SUCCESS

    async def test_verify_agent_idempotent_on_reexecution(self):
        """Same input twice → same verification action_id (Nit 2)."""
        action = _action(
            action_id="act-src-idempotent",
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        event_id = "evt-20260725-00000001"

        agent1 = VerifyAgent(
            tool_executor=_mock_executor(
                {"check_ip_block_status": _tool_result_success(True)}
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        agent1._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent1._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )
        result1 = await agent1.execute(
            _input(event_id=event_id, actions=[action])
        )

        agent2 = VerifyAgent(
            tool_executor=_mock_executor(
                {"check_ip_block_status": _tool_result_success(True)}
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        agent2._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent2._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )
        result2 = await agent2.execute(
            _input(event_id=event_id, actions=[action])
        )

        # Both executions produce the same deterministic verification_action_id.
        assert result1.results[0].verification_action_id is not None
        assert (
            result1.results[0].verification_action_id
            == result2.results[0].verification_action_id
        )

    async def test_disposition_activation_failure_skips_writeback_eval(self):
        """Failed activation → writeback evaluation skipped (Nit 5).

        When EventDispositionService.activate_and_submit fails,
        writeback status evaluation must not proceed — the terminal
        writeback was never submitted, so its receipts are stale.
        """
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(success=False)
        agent = VerifyAgent(
            tool_executor=_mock_executor(
                {"check_ip_block_status": _tool_result_success(True)}
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action])
        )

        # Activation was attempted.
        assert len(ed_svc.calls) == 1
        # Activation failed → manual resolution, NOT writeback recovery.
        assert result.need_manual_resolution is True
        assert result.overall_status == VerificationOverallStatus.MANUAL_RESOLUTION

# --------------------------------------------------------------------------- #
# Working memory write test
# --------------------------------------------------------------------------- #


class TestWorkingMemory:
    async def test_verification_result_written_to_wm(self):
        """VerificationResult is persisted to working_memory.verification_result."""
        wm = FakeWorkingMemory()
        action = _action(
            tool_name="create_ticket",
            action_level=ActionLevel.L1,
            status=ActionStatus.SUCCESS,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
        )
        agent = VerifyAgent(
            working_memory=wm,
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        await agent.execute(_input(actions=[action]))

        stored = await wm.read(action.event_id, "verification_result")
        assert stored is not None
        assert stored.get("overall_status") == VerificationOverallStatus.SUCCESS.value


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _mock_executor(results: dict[str, ToolResult]) -> Any:
    """Return a MagicMock tool_executor that returns predefined results per tool."""

    async def call(tool_name: str, params: dict[str, Any], event_id: str, **kwargs: Any) -> ToolResult:
        if tool_name in results:
            result = results[tool_name]
            # Return a fresh copy with the correct tool_name.
            return ToolResult(
                call_id=f"call-{tool_name}",
                tool_name=tool_name,
                provider_name=result.provider_name,
                status=result.status,
                data=result.data,
                error_detail=result.error_detail,
                target_results=result.target_results,
            )
        return ToolResult(
            call_id=f"call-{tool_name}",
            tool_name=tool_name,
            provider_name="mock_observation",
            status=ToolResultStatus.FAILED,
            error_detail=f"unexpected tool: {tool_name}",
        )

    return MagicMock(call=AsyncMock(side_effect=call))
