"""Shared fixtures for orchestration integration tests (ISSUE-055).

Provides stub agent factories, retry wrappers, state builders, and
helpers for validating audit log transition sequences.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast

from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    RiskAssessment,
    ScoringMode,
    TriageResult,
)
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    ExecutionSubstate,
    FinalVerdict,
    Severity,
    WritebackReadiness,
)
from app.models.security_event import EventSummary
from app.models.workflow import (
    STATE_TRANSITIONS,
)
from app.orchestration.graph_state import InvestigationState

# --------------------------------------------------------------------------- #
# State builder
# --------------------------------------------------------------------------- #


def make_investigation_state(**overrides: Any) -> InvestigationState:
    """Build a valid InvestigationState with sensible P0 defaults."""
    base: dict[str, Any] = {
        "event_id": "evt-orch-0001",
        "event_status": EventStatus.TRIAGING.value,
        "disposition_policy": DispositionPolicy.NOT_REQUIRED.value,
        "severity": Severity.HIGH.value,
        "final_verdict": None,
        "confidence": 0.0,
        "need_investigation": True,
        "execution_substate": ExecutionSubstate.NONE.value,
        "event_status_update_readiness": WritebackReadiness.NOT_REQUIRED.value,
        "degraded_flags": [],
        "node_trace": [],
        "halted": False,
        "disposition_only_intent": False,
        "report_generated": False,
        "needs_approval_wait": False,
    }
    base.update(overrides)
    return cast(InvestigationState, {**base})


# --------------------------------------------------------------------------- #
# Stub agents
# --------------------------------------------------------------------------- #


@dataclass
class StubAgent:
    """Returns a fixed result from every call to ``execute``."""

    result: Any
    calls: list[Any] = field(default_factory=list)

    async def execute(self, input: Any) -> Any:
        self.calls.append(input)
        return self.result


class FlakyStubAgent:
    """Fails a configurable number of times, then succeeds.

    Each call to ``execute`` increments an internal counter. Calls where
    ``counter <= fail_count`` raise ``RuntimeError``; subsequent calls
    return ``result``.

    When *trace_service* and *event_id* are both provided, the agent
    records a trace entry on every execute call (failed and successful),
    mirroring the production ``BaseAgent._record_trace`` contract.  This
    allows Scenario 2 to validate that agent traces originate from the
    real ``execute()`` path rather than manual ``log_trace()`` calls.
    """

    def __init__(
        self,
        result: Any,
        fail_count: int = 1,
        *,
        agent_name: str = "flaky_stub",
        trace_service: Any = None,
        event_id: str | None = None,
    ) -> None:
        self.result = result
        self.fail_count = fail_count
        self.calls: list[Any] = []
        self.attempt = 0
        self.agent_name = agent_name
        self._trace_service = trace_service
        self._event_id = event_id

    async def execute(self, input: Any) -> Any:
        self.calls.append(input)
        self.attempt += 1
        started_at = datetime.now(UTC)

        if self.attempt <= self.fail_count:
            # Record failed trace before raising
            if self._trace_service is not None and self._event_id is not None:
                await self._trace_service.log_trace(
                    event_id=self._event_id,
                    agent_name=self.agent_name,
                    input_data={"event_id": self._event_id, "call": f"attempt-{self.attempt}"},
                    output_data=None,
                    status="failed",
                    started_at=started_at,
                    completed_at=datetime.now(UTC),
                    error_detail=f"FlakyStubAgent failure on attempt {self.attempt}",
                )
            raise RuntimeError(f"FlakyStubAgent failure on attempt {self.attempt}")

        # Record successful trace
        if self._trace_service is not None and self._event_id is not None:
            await self._trace_service.log_trace(
                event_id=self._event_id,
                agent_name=self.agent_name,
                input_data={"event_id": self._event_id, "call": f"attempt-{self.attempt}"},
                output_data=self.result,
                status="completed",
                started_at=started_at,
                completed_at=datetime.now(UTC),
            )
        return self.result


class RetryingAgentWrapper:
    """Wraps an agent with MAX_AGENT_RETRIES retry logic.

    Simulates what the eventual SuperAgent orchestration layer will do
    when an agent raises during ``execute``.
    """

    def __init__(self, inner: Any, max_retries: int = 2) -> None:
        self._inner = inner
        self._max_retries = max_retries
        self.attempts: list[bool] = []  # True = success

    @property
    def agent_name(self) -> str:
        return getattr(self._inner, "agent_name", "retrying_wrapper")

    async def execute(self, input: Any) -> Any:
        last_exc: Exception | None = None
        for attempt in range(1, self._max_retries + 2):  # initial + N retries
            try:
                result = await self._inner.execute(input)
                self.attempts.append(True)
                return result
            except Exception as exc:
                last_exc = exc
                self.attempts.append(False)
                if attempt > self._max_retries:
                    raise
        raise last_exc  # type: ignore[union-attr]  # unreachable — loop always raises


# --------------------------------------------------------------------------- #
# Convenience agent builders
# --------------------------------------------------------------------------- #


def make_triage_stub(
    *,
    event_type: EventType = EventType.DATA_EXFILTRATION,
    severity: Severity = Severity.HIGH,
    need_investigation: bool = True,
    reasoning: str = "integration test",
) -> StubAgent:
    return StubAgent(
        TriageResult(
            event_type=event_type,
            severity=severity,
            need_investigation=need_investigation,
            reasoning=reasoning,
        )
    )


def make_evidence_stub(
    *,
    confidence: float = 0.85,
    collection_status: CollectionStatus = CollectionStatus.COMPLETED,
) -> StubAgent:
    return StubAgent(
        EvidenceOutput(
            collection_status=collection_status,
            overall_confidence=confidence,
        )
    )


def make_risk_stub(
    *,
    risk_score: int = 80,
    severity: Severity = Severity.HIGH,
    confidence: float = 0.9,
    scoring_mode: ScoringMode = ScoringMode.RULE_ONLY,
) -> StubAgent:
    return StubAgent(
        RiskAssessment(
            risk_score=risk_score,
            severity=severity,
            confidence=confidence,
            scoring_mode=scoring_mode,
        )
    )


def make_report_stub(report_id: str = "rpt-stub") -> StubAgent:
    return StubAgent(SimpleNamespace(report_id=report_id))


# --------------------------------------------------------------------------- #
# Audit log validation helper
# --------------------------------------------------------------------------- #


async def assert_audit_log_transitions_valid(
    audit_log_service: Any,
    event_id: str,
    *,
    expected_min_count: int = 1,
) -> Any:
    """Read audit log for *event_id* and validate every recorded transition.

    Returns the list of log rows so callers can assert further properties
    (order, specific statuses, etc.).
    """
    rows = await audit_log_service.get_logs_by_event(event_id)
    assert len(rows) >= expected_min_count, (
        f"expected at least {expected_min_count} audit log entries for {event_id}, got {len(rows)}"
    )
    for row in rows:
        from_status_raw = row.from_status
        to_status_raw = row.to_status
        if from_status_raw is None or to_status_raw is None:
            continue
        try:
            current = EventStatus(from_status_raw)
            target = EventStatus(to_status_raw)
        except ValueError:
            continue

        allowed = STATE_TRANSITIONS.get(current, set())
        assert target in allowed, (
            f"illegal audit log transition: {current.value} → {target.value} "
            f"(event={event_id}, log_id={row.id})"
        )
    return cast(Any, rows)


# --------------------------------------------------------------------------- #
# Evidence stubs with partial failure (for Scenario 2)
# --------------------------------------------------------------------------- #


def make_flaky_evidence_stub(
    *,
    fail_count: int = 1,
    confidence: float = 0.85,
    agent_name: str = "evidence_agent",
    trace_service: Any = None,
    event_id: str | None = None,
) -> FlakyStubAgent:
    return FlakyStubAgent(
        EvidenceOutput(
            collection_status=CollectionStatus.COMPLETED,
            overall_confidence=confidence,
        ),
        fail_count=fail_count,
        agent_name=agent_name,
        trace_service=trace_service,
        event_id=event_id,
    )


# --------------------------------------------------------------------------- #
# EventSummary factory for test ingestion
# --------------------------------------------------------------------------- #


def make_event_summary(
    event_id: str,
    *,
    disposition_policy: DispositionPolicy = DispositionPolicy.NOT_REQUIRED,
    severity: Severity = Severity.HIGH,
    status: EventStatus = EventStatus.NEW,
) -> EventSummary:
    return EventSummary(
        event_id=event_id,
        event_type=EventType.DATA_EXFILTRATION,
        title=f"Orchestration test event {event_id}",
        status=status,
        severity=severity,
        risk_score=0,
        final_verdict=FinalVerdict.NONE,
        writeback_required=disposition_policy == DispositionPolicy.REQUIRED,
        writeback_readiness=(
            WritebackReadiness.NOT_REQUIRED
            if disposition_policy == DispositionPolicy.NOT_REQUIRED
            else WritebackReadiness.CAPABILITY_UNKNOWN
        ),
        writeback_overall_status=None,
        pending_writeback_count=0,
        disposition_policy=disposition_policy,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        occurred_at=datetime.now(UTC),
    )
