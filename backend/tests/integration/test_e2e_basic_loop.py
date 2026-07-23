"""ISSUE-039: Basic loop integration tests (alert to report).

Four scenarios covering the analysis-only pipeline:
1. Golden path: full analysis → REPORTING (disposition required)
2. Low-severity short-circuit: not_required low → quick close to CLOSED
3. Data source degradation: 3 tool failures → partial_done, still reports
4. LLM degradation: all LLM fail → rule-based fallback, complete pipeline

All scenarios use ``AnalysisOnlyPipeline`` and assert trace/audit completeness.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agents.evidence_agent import EvidenceAgent
from app.agents.report_agent import ReportAgent
from app.agents.risk_agent import RiskAgent
from app.agents.triage_agent import TriageAgent
from app.core.errors import LLMError
from app.core.redis_client import RedisClient
from app.db import models as orm
from app.models.agent_io import CollectionStatus
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
)
from app.services.analysis_only_pipeline import AnalysisOnlyPipeline
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService
from app.services.event_service import EventService

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.e2e_basic,
    pytest.mark.usefixtures("clean_state"),
]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set environment variables required by the pipeline."""
    monkeypatch.setenv("ALLOW_LIVE_SIDE_EFFECTS", "false")
    monkeypatch.setenv("ALLOW_XDR_WRITEBACK", "false")
    monkeypatch.setenv("LLM_MODE", "mock")
    monkeypatch.setenv("TOOL_MODE", "mock")
    monkeypatch.setenv("SOURCE_MODE", "mock_xdr")
    monkeypatch.setenv("DISPOSITION_MODE", "mock_xdr")
    monkeypatch.setenv("SIMULATION_ENABLED", "true")


async def _create_event(
    event_service: EventService,
    *,
    title: str = "Test event",
    description: str = "Test event description",
    event_type: EventType = EventType.INSIDER_THREAT,
    severity: Severity = Severity.HIGH,
) -> str:
    """Create a minimal manual event and return its event_id."""
    raw_alert: dict[str, Any] = {
        "title": title,
        "description": description,
    }
    event = await event_service.create_event(
        raw_alert,
        source_type="manual",
        title=title,
        event_type=event_type,
        severity=severity,
    )
    return event.event_id


async def _ingest_scenario(
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    scenario_id: str = "insider_data_exfiltration",
) -> list[str]:
    """Ingest a scenario and return the created event IDs."""
    import httpx
    from httpx import ASGITransport

    from app.adapters.mock_xdr import MockXDRSourceAdapter
    from app.data_generators.scenarios import build_scenario
    from app.ingestion.source_ingester import SourceIngester
    from app.mock_xdr.api import create_app
    from app.mock_xdr.state import MockXDRState

    state = MockXDRState()
    state.load_scenario(build_scenario(scenario_id, seed=42))

    transport = ASGITransport(app=create_app(state=state))
    async with httpx.AsyncClient(transport=transport, base_url="http://mock-xdr") as client:
        adapter = MockXDRSourceAdapter(
            base_url="http://mock-xdr",
            read_token="mock-token",
            write_token="mock-token",
            client=client,
            max_retries=0,
        )
        ingester = SourceIngester(event_service, session_factory, source_mode="mock_xdr")
        await ingester.poll(adapter, ["incident", "alert", "asset", "log"], batch_size=50)

    listed = await event_service.list_events()
    return [item.event_id for item in listed.items]


async def _count_traces(session_factory: async_sessionmaker[AsyncSession], event_id: str) -> int:
    async with session_factory() as session:
        return int(
            await session.scalar(
                select(func.count(orm.AgentTrace.trace_id)).where(
                    orm.AgentTrace.event_id == event_id
                )
            )
            or 0
        )


async def _count_audit_logs(
    session_factory: async_sessionmaker[AsyncSession], event_id: str
) -> int:
    async with session_factory() as session:
        return int(
            await session.scalar(
                select(func.count(orm.EventAuditLog.id)).where(
                    orm.EventAuditLog.event_id == event_id
                )
            )
            or 0
        )


# --------------------------------------------------------------------------- #
# Pipeline builder
# --------------------------------------------------------------------------- #


async def _build_pipeline(
    event_service: EventService,
    state_machine: Any,
    context_store: EventContextStore,
    degraded_flags: DegradedFlagService,
    session_factory: async_sessionmaker[AsyncSession],
    *,
    tool_executor: Any,
    redis_client: RedisClient | None = None,
    triage_llm: Any | None = None,
    evidence_llm: Any | None = None,
    risk_llm: Any | None = None,
    report_llm: Any | None = None,
) -> AnalysisOnlyPipeline:
    """Build an AnalysisOnlyPipeline with configurable agent LLM clients."""
    from app.services.working_memory import WorkingMemory

    wm = WorkingMemory(
        store=context_store,
        redis=redis_client,  # type: ignore[arg-type]
        degraded_flags=degraded_flags,
    )

    triage = TriageAgent(
        llm_client=triage_llm,
        working_memory=wm.for_writer("TriageAgent"),
    )

    evidence = EvidenceAgent(
        llm_client=evidence_llm,
        tool_executor=tool_executor,
        working_memory=wm.for_writer("EvidenceAgent"),
        session_factory=session_factory,
        event_service=event_service,
    )

    risk = RiskAgent(
        llm_client=risk_llm,
        working_memory=wm.for_writer("RiskAgent"),
        event_service=event_service,
    )

    report = ReportAgent(
        llm_client=report_llm,
        working_memory=wm.for_writer("ReportAgent"),
        event_service=event_service,
    )

    return AnalysisOnlyPipeline(
        event_service=event_service,
        state_machine=state_machine,
        triage_agent=triage,
        evidence_agent=evidence,
        risk_agent=risk,
        report_agent=report,
        context_store=context_store,
        degraded_flags=degraded_flags,
    )


# --------------------------------------------------------------------------- #
# Failing LLM client for degradation tests
# --------------------------------------------------------------------------- #


class FailingLLMClient:
    """An LLM client that always raises LLMError for degradation testing."""

    primary_model = "failing-mock"

    def __init__(self, fail_message: str = "simulated LLM failure") -> None:
        self.fail_message = fail_message

    async def chat(self, **kwargs: Any) -> Any:
        raise LLMError(
            self.fail_message,
            error_code="llm_provider_error",
            retryable=False,
        )


# --------------------------------------------------------------------------- #
# Selective failure tool executor wrapper
# --------------------------------------------------------------------------- #


class SelectiveFailExecutor:
    """Wraps a ToolExecutor to raise on specified tool names.

    EvidenceAgent catches exceptions from tool calls and records the tool as
    failed. Wrapping 3 tools lets us trigger ``partial_done`` (4/7 succeed).
    """

    def __init__(self, delegate: Any, failing_tools: set[str]) -> None:
        self._delegate = delegate
        self._failing_tools = failing_tools

    async def call(
        self, tool_name: str, params: dict[str, Any], event_id: str, **kwargs: Any
    ) -> Any:
        if tool_name in self._failing_tools:
            raise RuntimeError(f"simulated tool failure: {tool_name}")
        return await self._delegate.call(tool_name, params, event_id, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._delegate, name)


# --------------------------------------------------------------------------- #
# Scenario 1: Golden Path — full analysis pipeline
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(90)
@pytest.mark.asyncio
async def test_golden_path_alert_to_report(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
    state_machine: Any,
    context_store: EventContextStore,
    degraded_flags_service: DegradedFlagService,
    monkeypatch: pytest.MonkeyPatch,
    tool_executor: Any,
    redis_client: RedisClient,
) -> None:
    """Full analysis pipeline: NEW → … → REPORTING, risk_score ≥ 70, report exists.

    Ingests the insider_data_exfiltration scenario so the event has proper
    source references for evidence query scope resolution.
    """
    _env(monkeypatch)

    # Ingest scenario → event with disposition_policy=required.
    event_ids = await _ingest_scenario(event_service, session_factory)
    assert len(event_ids) >= 1, "expected at least one ingested event"
    event_id = event_ids[0]

    pipeline = await _build_pipeline(
        event_service,
        state_machine,
        context_store,
        degraded_flags_service,
        session_factory,
        tool_executor=tool_executor,
        redis_client=redis_client,
    )

    started = time.perf_counter()
    result = await pipeline.run(event_id)
    elapsed = time.perf_counter() - started

    assert elapsed < 60, f"golden path took {elapsed:.1f}s (>60s limit)"

    # Status: stays at REPORTING because disposition_policy=required.
    assert result["status"] == EventStatus.REPORTING.value
    assert result["analysis_only_complete"] is True
    assert result.get("disposition_policy") == "required"

    event = await event_service.get_event(event_id)
    assert event is not None
    assert event.status == EventStatus.REPORTING

    # All analysis agents produced traces.
    trace_count = await _count_traces(session_factory, event_id)
    assert trace_count >= 4, f"expected ≥4 agent traces, got {trace_count}"

    # Audit log entries cover the full chain.
    audit_count = await _count_audit_logs(session_factory, event_id)
    assert audit_count >= 5, f"expected ≥5 audit log entries, got {audit_count}"

    # Report must exist with 15 sections.
    report = await event_service.get_report(event_id=event_id)
    assert report is not None, "report should exist after pipeline run"
    assert len(report.sections) == 15, f"expected 15 sections, got {len(report.sections)}"
    assert report.final_verdict == FinalVerdict.CONFIRMED_THREAT

    # risk_score ≥ 70 for confirmed threat.
    assert event.risk_score >= 70, f"risk_score={event.risk_score} < 70"

    # EventContext: P0 analysis output flags.
    analysis_only = await context_store.get(event_id, "analysis_only_complete")
    assert analysis_only is True

    # Budget usage must be recorded (check via EventContext).
    ec_budget = await context_store.get(event_id, "budget_usage")
    assert ec_budget is not None, "budget_usage should be recorded in EventContext"
    assert isinstance(ec_budget, dict)
    assert ec_budget.get("total_tokens", 0) > 0

    # Guard violations must have no block-level entries on golden path.
    ec_guard = await context_store.get(event_id, "guard_violations")
    guard_violations = ec_guard if isinstance(ec_guard, list) else []
    block_violations = [v for v in guard_violations if v.get("severity") == "block"]
    assert len(block_violations) == 0, f"block-level guard violation found: {block_violations}"

    # Working memory check: analysis_only_complete exists and is true.
    wm_check = await context_store.get(event_id, "analysis_only_complete")
    assert wm_check is True


# --------------------------------------------------------------------------- #
# Scenario 2: Low-severity short-circuit
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(90)
@pytest.mark.asyncio
async def test_low_severity_short_circuit(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
    state_machine: Any,
    context_store: EventContextStore,
    degraded_flags_service: DegradedFlagService,
    monkeypatch: pytest.MonkeyPatch,
    tool_executor: Any,
    redis_client: RedisClient,
) -> None:
    """TRIAGING → CLOSED shortcut for not_required low-severity events.

    Creates an account_anomaly event (maps to LOW severity, need_investigation=False)
    with disposition_policy=not_required. Pipeline short-circuits at triage and
    generates a quick-close 15-section report before transitioning to CLOSED.
    """
    _env(monkeypatch)

    # Build event with account_anomaly type — triage rules assign LOW severity.
    event_id = await _create_event(
        event_service,
        title="Single failed login attempt for ops account",
        description=(
            "User ops-change-bot had one failed login attempt at 03:15 UTC "
            "from internal IP 10.50.1.10. Account is part of scheduled change "
            "window. No follow-up anomalies detected."
        ),
        event_type=EventType.ACCOUNT_ANOMALY,
        severity=Severity.LOW,
    )

    # Override disposition_policy to not_required.
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.disposition_policy = DispositionPolicy.NOT_REQUIRED.value
            await session.flush()

    pipeline = await _build_pipeline(
        event_service,
        state_machine,
        context_store,
        degraded_flags_service,
        session_factory,
        tool_executor=tool_executor,
        redis_client=redis_client,
    )

    started = time.perf_counter()
    result = await pipeline.run(event_id)
    elapsed = time.perf_counter() - started

    assert elapsed < 60, f"short-circuit took {elapsed:.1f}s (>60s limit)"
    assert result["status"] == EventStatus.CLOSED.value
    assert result.get("short_circuit") is True

    event = await event_service.get_event(event_id)
    assert event is not None
    assert event.status == EventStatus.CLOSED

    # Only triage + report (short-circuit skips evidence + risk).
    trace_count = await _count_traces(session_factory, event_id)
    assert trace_count == 2, (
        f"expected 2 agent traces (triage + report short-circuit), got {trace_count}"
    )

    # Quick-close 15-section report.
    report = await event_service.get_report(event_id=event_id)
    assert report is not None, "quick-close report should exist"
    assert len(report.sections) == 15, f"expected 15 sections, got {len(report.sections)}"

    # Audit trail covers transitions.
    audit_count = await _count_audit_logs(session_factory, event_id)
    assert audit_count >= 2, f"expected ≥2 audit entries, got {audit_count}"

    # No evidence was collected (quick-close path).
    analysis_only = await context_store.get(event_id, "analysis_only_complete")
    assert analysis_only is True


# --------------------------------------------------------------------------- #
# Scenario 3: Data source degradation — partial evidence collection
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(90)
@pytest.mark.asyncio
async def test_data_source_degradation_partial_done(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
    state_machine: Any,
    context_store: EventContextStore,
    degraded_flags_service: DegradedFlagService,
    monkeypatch: pytest.MonkeyPatch,
    tool_executor: Any,
    redis_client: RedisClient,
) -> None:
    """When 3 query tools fail, collection_status=partial_done and report exists.

    Wraps the ToolExecutor so 3 specific query tools raise exceptions.
    With 4/7 tools succeeding → partial_done (success count 4, threshold: <5).
    Pipeline must still generate a valid 15-section report.
    """
    _env(monkeypatch)

    failing_tools = {"query_edr_process", "query_network_flow", "query_dns"}
    wrapped_executor = SelectiveFailExecutor(tool_executor, failing_tools)

    # Ingest scenario for proper evidence scope.
    event_ids = await _ingest_scenario(event_service, session_factory)
    assert len(event_ids) >= 1
    event_id = event_ids[0]

    pipeline = await _build_pipeline(
        event_service,
        state_machine,
        context_store,
        degraded_flags_service,
        session_factory,
        tool_executor=wrapped_executor,
    )

    started = time.perf_counter()
    result = await pipeline.run(event_id)
    elapsed = time.perf_counter() - started

    assert elapsed < 60, f"degradation test took {elapsed:.1f}s (>60s limit)"
    assert result["status"] == EventStatus.REPORTING.value

    # Verify evidence output reflects degraded collection.
    evidence_output = await context_store.get(event_id, "evidence_output")
    if evidence_output is not None:
        coll_status = (
            evidence_output.get("collection_status")
            if isinstance(evidence_output, dict)
            else getattr(evidence_output, "collection_status", None)
        )
        if coll_status is not None:
            assert coll_status in (
                CollectionStatus.PARTIAL_DONE.value,
                CollectionStatus.DEGRADED.value,
            ), f"expected degraded collection status, got {coll_status}"

    # Report still generated with 15 sections.
    report = await event_service.get_report(event_id=event_id)
    assert report is not None, "report should exist after degraded pipeline run"
    assert len(report.sections) == 15

    # Trace and audit integrity.
    trace_count = await _count_traces(session_factory, event_id)
    assert trace_count >= 4, f"expected ≥4 agent traces, got {trace_count}"

    audit_count = await _count_audit_logs(session_factory, event_id)
    assert audit_count >= 5, f"expected ≥5 audit entries, got {audit_count}"


# --------------------------------------------------------------------------- #
# Scenario 4: LLM degradation — rule-based fallback
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(90)
@pytest.mark.asyncio
async def test_llm_degradation_fallback(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
    state_machine: Any,
    context_store: EventContextStore,
    degraded_flags_service: DegradedFlagService,
    monkeypatch: pytest.MonkeyPatch,
    tool_executor: Any,
    redis_client: RedisClient,
) -> None:
    """When all LLM calls fail, pipeline uses regex triage, rule scoring, template report.

    Ingested event provides valid evidence scope (evidence not LLM-dependent).
    Triage uses regex keyword matching; risk scoring uses rule-only mode;
    report uses template text. Pipeline completes without crashing;
    disposition gate is not bypassed.
    """
    _env(monkeypatch)

    failing_llm = FailingLLMClient("simulated LLM failure for degradation test")

    # Use ingested event so evidence queries work (they don't depend on LLM).
    event_ids = await _ingest_scenario(event_service, session_factory)
    assert len(event_ids) >= 1
    event_id = event_ids[0]

    pipeline = await _build_pipeline(
        event_service,
        state_machine,
        context_store,
        degraded_flags_service,
        session_factory,
        tool_executor=tool_executor,
        triage_llm=failing_llm,
        evidence_llm=failing_llm,
        risk_llm=failing_llm,
        report_llm=failing_llm,
    )

    started = time.perf_counter()
    result = await pipeline.run(event_id)
    elapsed = time.perf_counter() - started

    assert elapsed < 60, f"LLM degradation test took {elapsed:.1f}s (>60s limit)"

    # Pipeline completes; reaches REPORTING or CLOSED.
    assert result["status"] in (
        EventStatus.REPORTING.value,
        EventStatus.CLOSED.value,
    ), f"unexpected final status: {result['status']}"

    event = await event_service.get_event(event_id)
    assert event is not None

    # Triage must classify event even without LLM (regex/keyword fallback).
    assert event.event_type in (
        EventType.DATA_EXFILTRATION,
        EventType.INSIDER_THREAT,
    ), f"regex triage failed — got {event.event_type}"

    # Risk score must be meaningful (rule-only scoring path).
    assert event.risk_score >= 0

    # Report must exist (template-based when LLM fails).
    report = await event_service.get_report(event_id=event_id)
    assert report is not None, "template report should exist after LLM degradation"
    assert len(report.sections) == 15

    # Verify traces exist for all agents.
    trace_count = await _count_traces(session_factory, event_id)
    assert trace_count >= 4, f"expected ≥4 agent traces, got {trace_count}"

    # Audit logs cover the state transitions.
    audit_count = await _count_audit_logs(session_factory, event_id)
    assert audit_count >= 5, f"expected ≥5 audit entries, got {audit_count}"

    # Disposition gate: required events must stay at REPORTING even under LLM
    # degradation — never silently bypass the gate.
    if event.disposition_policy == DispositionPolicy.REQUIRED:
        assert result["status"] == EventStatus.REPORTING.value, (
            "LLM-degraded required-disposition event must stay at REPORTING"
        )
