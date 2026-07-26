"""ISSUE-062 writeback recovery tests — WritebackRecoveryHandler and integration."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    ExecutionSubstate,
    Severity,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.workflow import WRITEBACK_MAX_RETRIES
from app.orchestration.graph_state import InvestigationState
from app.orchestration.writeback_recovery_handler import (
    VERIFY_UNKNOWN_MAX_LOOKUPS,
    WritebackRecoveryAction,
    WritebackRecoveryHandler,
    WritebackState,
    writeback_recovery_graph_node,
)

# ── Helpers ────────────────────────────────────────────────────────────────


def _base_state(**overrides: Any) -> InvestigationState:
    state: InvestigationState = {
        "event_id": "evt-test-wb-001",
        "event_status": EventStatus.VERIFYING.value,
        "disposition_policy": DispositionPolicy.REQUIRED.value,
        "severity": Severity.HIGH.value,
        "final_verdict": None,
        "confidence": 0.0,
        "need_investigation": True,
        "execution_substate": ExecutionSubstate.NONE.value,
        "event_status_update_readiness": WritebackReadiness.READY.value,
        "degraded_flags": [],
        "node_trace": [],
        "halted": False,
        "disposition_only_intent": False,
        "report_generated": False,
        "needs_approval_wait": False,
        "plan_revision": 1,
        "replan_count": 0,
        "escalated": False,
        "verify_need_action_replan": False,
        "verify_need_writeback_recovery": True,
        "verify_need_manual_resolution": False,
    }
    state.update(overrides)  # type: ignore[typeddict-item]
    return state


class FakeRuntime:
    """Fake WorkflowRuntimeService for tests."""

    def __init__(self) -> None:
        self.substate_calls: list[tuple[str, ExecutionSubstate, EventStatus]] = []

    async def set_execution_substate(
        self,
        event_id: str,
        substate: ExecutionSubstate,
        *,
        event_status: EventStatus,
    ) -> None:
        self.substate_calls.append((event_id, substate, event_status))


class FakeStateMachine:
    """Fake StateMachineService for tests."""

    def __init__(self) -> None:
        self.transitions: list[tuple[str, EventStatus, str]] = []

    async def transition(
        self,
        event_id: str,
        target: EventStatus,
        *,
        context: Any = None,
        operator: str | None = None,
        reason: str | None = None,
    ) -> Any:
        self.transitions.append((event_id, target, reason or ""))
        return SimpleNamespace(status=target.value)

    async def get_current_status(self, event_id: str) -> EventStatus:
        return EventStatus.VERIFYING


class FakeDispositionSync:
    """Fake DispositionSyncService for tests."""

    def __init__(self) -> None:
        self.retries: list[tuple[str, str]] = []
        self.resolutions: list[tuple[str, str, str, str]] = []
        self.lookups: list[str] = []
        self._lookup_result: WritebackStatus | None = None
        self._retry_raises: Exception | None = None
        self._lookup_raises: Exception | None = None

    async def retry_writeback(self, writeback_id: str, operator: str) -> Any:
        self.retries.append((writeback_id, operator))
        if self._retry_raises is not None:
            raise self._retry_raises
        return SimpleNamespace(writeback_id=writeback_id)

    async def resolve_writeback(
        self, writeback_id: str, resolution: str, principal: str, comment: str
    ) -> Any:
        self.resolutions.append((writeback_id, resolution, principal, comment))
        return SimpleNamespace(writeback_id=writeback_id)

    async def lookup_writeback_status(self, writeback_id: str) -> WritebackStatus | None:
        self.lookups.append(writeback_id)
        if self._lookup_raises is not None:
            raise self._lookup_raises
        return self._lookup_result


# ── Tests: WritebackRecoveryHandler.evaluate ─────────────────────────────────


class TestWritebackRecoveryEvaluate:
    """Unit tests for WritebackRecoveryHandler.evaluate()."""

    def _handler(self) -> WritebackRecoveryHandler:
        return WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )

    # ── Terminal / None ──

    def test_confirmed_returns_noop(self):
        """CONFIRMED writeback → NOOP."""
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.CONFIRMED)
        result = self._handler().evaluate(wb)
        assert result.action == WritebackRecoveryAction.NOOP
        assert result.escalated is False

    def test_none_status_returns_noop(self):
        """None writeback status → NOOP."""
        wb = WritebackState(writeback_id="wbk-001", current_status=None)
        result = self._handler().evaluate(wb)
        assert result.action == WritebackRecoveryAction.NOOP

    # ── Waiting states ──

    @pytest.mark.parametrize(
        "status",
        [WritebackStatus.PENDING, WritebackStatus.SENDING, WritebackStatus.ACCEPTED],
    )
    def test_waiting_status_returns_wait(self, status: WritebackStatus):
        """PENDING/SENDING/ACCEPTED → WAIT."""
        wb = WritebackState(writeback_id="wbk-001", current_status=status)
        result = self._handler().evaluate(wb)
        assert result.action == WritebackRecoveryAction.WAIT
        assert result.escalated is False

    # ── UNKNOWN → LOOKUP ──

    def test_unknown_status_returns_lookup(self):
        """UNKNOWN writeback → LOOKUP (first attempt)."""
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.UNKNOWN)
        result = self._handler().evaluate(wb)
        assert result.action == WritebackRecoveryAction.LOOKUP
        assert result.lookup_attempt == 1

    def test_unknown_exhausted_returns_manual(self):
        """UNKNOWN with lookup_count == max → MANUAL (escalated)."""
        wb = WritebackState(
            writeback_id="wbk-001",
            current_status=WritebackStatus.UNKNOWN,
            lookup_count=VERIFY_UNKNOWN_MAX_LOOKUPS,
        )
        result = self._handler().evaluate(wb)
        assert result.action == WritebackRecoveryAction.MANUAL
        assert result.escalated is True

    # ── FAILED → RETRY ──

    def test_failed_status_returns_retry(self):
        """FAILED writeback → RETRY (first attempt)."""
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.FAILED)
        result = self._handler().evaluate(wb)
        assert result.action == WritebackRecoveryAction.RETRY
        assert result.retry_attempt == 1

    def test_failed_exhausted_returns_manual(self):
        """FAILED with retry_count == max → MANUAL (escalated)."""
        wb = WritebackState(
            writeback_id="wbk-001",
            current_status=WritebackStatus.FAILED,
            retry_count=WRITEBACK_MAX_RETRIES,
        )
        result = self._handler().evaluate(wb)
        assert result.action == WritebackRecoveryAction.MANUAL
        assert result.escalated is True

    # ── PARTIAL → RETRY ──

    def test_partial_status_returns_retry(self):
        """PARTIAL writeback → RETRY (first attempt)."""
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.PARTIAL)
        result = self._handler().evaluate(wb)
        assert result.action == WritebackRecoveryAction.RETRY
        assert result.retry_attempt == 1

    def test_partial_exhausted_returns_manual(self):
        """PARTIAL with retry_count == max → MANUAL (escalated)."""
        wb = WritebackState(
            writeback_id="wbk-001",
            current_status=WritebackStatus.PARTIAL,
            retry_count=WRITEBACK_MAX_RETRIES,
        )
        result = self._handler().evaluate(wb)
        assert result.action == WritebackRecoveryAction.MANUAL
        assert result.escalated is True

    # ── CONFLICT → MANUAL ──

    def test_conflict_always_manual(self):
        """CONFLICT writeback → MANUAL immediately (no retries)."""
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.CONFLICT)
        result = self._handler().evaluate(wb)
        assert result.action == WritebackRecoveryAction.MANUAL
        assert result.escalated is True


# ── Tests: WritebackRecoveryHandler.execute ──────────────────────────────────


class TestWritebackRecoveryExecute:
    """Integration tests for WritebackRecoveryHandler.execute()."""

    async def test_execute_wait_sets_substate(self):
        """WAIT action persists WAITING_WRITEBACK substate."""
        rt = FakeRuntime()
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=rt,
        )
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.PENDING)
        result = await handler.execute("evt-001", wb)
        assert result.action == WritebackRecoveryAction.WAIT
        assert rt.substate_calls[-1][1] == ExecutionSubstate.WAITING_WRITEBACK
        assert rt.substate_calls[-1][2] == EventStatus.VERIFYING

    async def test_execute_lookup_success_resolves(self):
        """LOOKUP that resolves → NOOP."""
        ds = FakeDispositionSync()
        ds._lookup_result = WritebackStatus.CONFIRMED
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
            disposition_sync=ds,
        )
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.UNKNOWN)
        result = await handler.execute("evt-001", wb)
        assert result.action == WritebackRecoveryAction.NOOP
        assert result.writeback_status == WritebackStatus.CONFIRMED

    async def test_execute_lookup_still_unknown(self):
        """LOOKUP that returns UNKNOWN → stays in recovery."""
        ds = FakeDispositionSync()
        ds._lookup_result = WritebackStatus.UNKNOWN
        rt = FakeRuntime()
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=rt,
            disposition_sync=ds,
        )
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.UNKNOWN)
        await handler.execute("evt-001", wb)
        assert rt.substate_calls[-1][1] == ExecutionSubstate.WAITING_WRITEBACK

    async def test_execute_lookup_exhausted_escalates(self):
        """LOOKUP exhausted → MANUAL."""
        rt = FakeRuntime()
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=rt,
        )
        wb = WritebackState(
            writeback_id="wbk-001",
            current_status=WritebackStatus.UNKNOWN,
            lookup_count=VERIFY_UNKNOWN_MAX_LOOKUPS,
        )
        result = await handler.execute("evt-001", wb)
        assert result.escalated is True
        assert rt.substate_calls[-1][1] == ExecutionSubstate.MANUAL_RESOLUTION

    async def test_execute_retry_enqueues(self):
        """RETRY action enqueues the same outbox."""
        ds = FakeDispositionSync()
        rt = FakeRuntime()
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=rt,
            disposition_sync=ds,
        )
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.FAILED)
        result = await handler.execute("evt-001", wb)
        assert result.action == WritebackRecoveryAction.RETRY
        assert len(ds.retries) == 1
        assert ds.retries[0][0] == "wbk-001"

    async def test_execute_retry_failure_escalates(self):
        """RETRY that fails when exhausted → MANUAL."""
        ds = FakeDispositionSync()
        ds._retry_raises = RuntimeError("adapter down")
        rt = FakeRuntime()
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=rt,
            disposition_sync=ds,
        )
        wb = WritebackState(
            writeback_id="wbk-001",
            current_status=WritebackStatus.FAILED,
            retry_count=WRITEBACK_MAX_RETRIES - 1,
        )
        result = await handler.execute("evt-001", wb)
        assert result.escalated is True

    async def test_execute_no_disposition_sync_escalates(self):
        """No disposition_sync port → escalate on LOOKUP."""
        rt = FakeRuntime()
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=rt,
            disposition_sync=None,
        )
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.UNKNOWN)
        result = await handler.execute("evt-001", wb)
        assert result.escalated is True


# ── Tests: writeback_recovery_graph_node ─────────────────────────────────────


class TestWritebackRecoveryGraphNode:
    """Tests for the writeback_recovery_graph_node graph helper."""

    async def test_no_failed_writebacks(self):
        """No failed writebacks → recovery disabled."""
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )
        state = _base_state(
            verify_need_writeback_recovery=True,
            verify_failed_writebacks=[],
        )
        result = await writeback_recovery_graph_node(state, handler=handler)
        assert result["verify_need_writeback_recovery"] is False
        assert result["execution_substate"] == ExecutionSubstate.NONE.value

    async def test_wait_sets_halted(self):
        """WAIT action → halted=True for graph pause."""
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )
        state = _base_state(
            verify_failed_writebacks=["wbk-001"],
            verify_writeback_status="pending",
        )
        result = await writeback_recovery_graph_node(state, handler=handler)
        assert result["halted"] is True

    async def test_escalated_sets_manual(self):
        """Escalated writeback → need_manual_resolution=True."""
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )
        state = _base_state(
            verify_failed_writebacks=["wbk-001"],
            verify_writeback_status="conflict",
        )
        result = await writeback_recovery_graph_node(state, handler=handler)
        assert result["verify_need_manual_resolution"] is True


# ── Tests: WritebackRecoveryHandler static helpers ───────────────────────────


class TestWritebackRecoveryStaticHelpers:
    """Tests for static helper methods."""

    def test_needs_recovery_true(self):
        state = {"verify_need_writeback_recovery": True}
        assert WritebackRecoveryHandler.needs_recovery(state) is True

    def test_needs_recovery_false(self):
        state = {"verify_need_writeback_recovery": False}
        assert WritebackRecoveryHandler.needs_recovery(state) is False

    def test_needs_recovery_missing(self):
        assert WritebackRecoveryHandler.needs_recovery({}) is False

    def test_needs_manual_true(self):
        state = {"verify_need_manual_resolution": True}
        assert WritebackRecoveryHandler.needs_manual(state) is True

    def test_needs_manual_false(self):
        state = {"verify_need_manual_resolution": False}
        assert WritebackRecoveryHandler.needs_manual(state) is False


# ── Tests: degradation (no disposition_sync) ─────────────────────────────────


class TestWritebackRecoveryDegradation:
    """Tests for WritebackRecoveryHandler degradation paths."""

    async def test_retry_without_port_escalates(self):
        """RETRY without disposition_sync → escalate."""
        rt = FakeRuntime()
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=rt,
            disposition_sync=None,
        )
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.FAILED)
        result = await handler.execute("evt-001", wb)
        assert result.escalated is True
        assert rt.substate_calls[-1][1] == ExecutionSubstate.MANUAL_RESOLUTION


# ── Tests: boundary inputs ──────────────────────────────────────────────────


class TestWritebackRecoveryBoundary:
    """Boundary input tests for WritebackRecoveryHandler."""

    def test_max_lookups_zero(self):
        """max_lookups=0 → immediately escalated for UNKNOWN."""
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )
        wb = WritebackState(
            writeback_id="wbk-001",
            current_status=WritebackStatus.UNKNOWN,
            max_lookups=0,
        )
        result = handler.evaluate(wb)
        assert result.action == WritebackRecoveryAction.MANUAL
        assert result.escalated is True

    def test_max_retries_zero(self):
        """max_retries=0 → immediately escalated for FAILED."""
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )
        wb = WritebackState(
            writeback_id="wbk-001",
            current_status=WritebackStatus.FAILED,
            max_retries=0,
        )
        result = handler.evaluate(wb)
        assert result.action == WritebackRecoveryAction.MANUAL
        assert result.escalated is True


# ── Tests: WritebackReoveryHandler never enters REPLANNING ──────────────────


class TestWritebackNeverReplans:
    """Verify writeback recovery NEVER transitions to REPLANNING."""

    @pytest.mark.parametrize(
        "status",
        [
            WritebackStatus.PENDING,
            WritebackStatus.SENDING,
            WritebackStatus.ACCEPTED,
            WritebackStatus.UNKNOWN,
            WritebackStatus.FAILED,
            WritebackStatus.PARTIAL,
            WritebackStatus.CONFLICT,
        ],
    )
    async def test_writeback_status_never_replans(self, status: WritebackStatus):
        """Any writeback status → no REPLANNING transition, no replan_count consumption."""
        sm = FakeStateMachine()
        handler = WritebackRecoveryHandler(
            state_machine=sm,
            runtime=FakeRuntime(),
        )
        wb = WritebackState(writeback_id="wbk-001", current_status=status)
        await handler.execute("evt-001", wb)
        # Verify no REPLANNING transition occurred
        replan_transitions = [t for t in sm.transitions if t[1] == EventStatus.REPLANNING]
        assert len(replan_transitions) == 0, (
            f"Writeback status {status.value} must not enter REPLANNING"
        )
