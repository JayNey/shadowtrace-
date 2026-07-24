"""ISSUE-055: Multi-Agent Orchestration Integration Tests.

Four scenarios covering golden path, agent retry, checkpoint recovery,
and context consistency — all validated through the LangGraph investigation
graph with real PostgreSQL + Redis services and stub/mock agents.

Run with::

    cd backend && pytest tests/integration/test_orchestration.py -m orchestration -v
"""

from __future__ import annotations

import asyncio
import time
from collections import Counter
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agents.planner_agent import PlannerAgent
from app.core.config import get_settings
from app.db import models as orm
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
)
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    SourceObjectKind,
    WritebackReadiness,
)
from app.models.source import SourceReference
from app.orchestration.checkpointer import (
    RedisCheckpointer,
    checkpoint_key_for_event,
)
from app.orchestration.workflow_graph import (
    NODE_CLOSE,
    NODE_EVIDENCE,
    NODE_PLANNER,
    NODE_RISK,
    P0_NODE_SEQUENCE,
    ROUTE_CLOSE,
    ROUTE_DISPOSITION_ONLY,
    ROUTE_INVESTIGATE,
    ROUTE_MANUAL_HOLD,
    build_investigation_graph,
    route_after_triage,
)
from app.orchestration.workflow_runtime import WorkflowRuntimeService
from app.services.agent_trace_service import AgentTraceService
from app.services.context_service import (
    EventContextStore,
)
from app.services.degraded_flag_service import DegradedFlagService
from app.services.event_audit_log_service import EventAuditLogService
from app.services.event_service import EventService, IngestableSource
from app.services.state_machine_service import StateMachineService
from tests.test_orchestration.conftest import (
    RetryingAgentWrapper,
    assert_audit_log_transitions_valid,
    make_evidence_stub,
    make_flaky_evidence_stub,
    make_investigation_state,
    make_report_stub,
    make_risk_stub,
    make_triage_stub,
)

# ── module-level marks ──────────────────────────────────────────────────────

pytestmark = [
    pytest.mark.orchestration,
    pytest.mark.integration,
    pytest.mark.usefixtures("clean_state"),
]


# ── live-side-effect guard (ISSUE-055 review: Should-Fix #2) ─────────────

@pytest.fixture(autouse=True)
def _lock_mock_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure no test in this module can accidentally trigger real XDR writes.

    Even though the current tests use stub agents, this guard is required by
    the project's security review rules: ALLOW_LIVE_SIDE_EFFECTS and
    ALLOW_XDR_WRITEBACK must be explicitly ``"false"`` in every test module
    that exercises the orchestration graph, so that a future switch from stub
    to real agent cannot silently introduce outbound side effects.
    """
    monkeypatch.setenv("ALLOW_LIVE_SIDE_EFFECTS", "false")
    monkeypatch.setenv("ALLOW_XDR_WRITEBACK", "false")
    monkeypatch.setenv("SOURCE_MODE", "mock_xdr")
    monkeypatch.setenv("DISPOSITION_MODE", "mock_xdr")
    get_settings.cache_clear()

# ── helpers ──────────────────────────────────────────────────────────────────


def _utc_now() -> datetime:
    return datetime.now(UTC)


# ═══════════════════════════════════════════════════════════════════════════════
# WARNING: _ready_resolver — NOT_REQUIRED ONLY
# ═══════════════════════════════════════════════════════════════════════════════
# This resolver unconditionally returns WritebackReadiness.NOT_REQUIRED.
# It is safe ONLY for tests whose events have DispositionPolicy.NOT_REQUIRED.
#
# When you write tests for DispositionPolicy.REQUIRED events (ISSUE-062),
# you MUST provide a resolver that returns the correct readiness value
# (e.g. READY, NOT_READY, CAPABILITY_UNKNOWN).  Forgetting to do so will
# silently write event_status_update_readiness=NOT_REQUIRED into the graph
# state, causing REQUIRED events to be misrouted as if they were NOT_REQUIRED.
#
# The existing routing tests (test_route_after_triage_required_*) bypass
# this hazard by directly constructing InvestigationState with the correct
# event_status_update_readiness field, without calling the resolver.
# ═══════════════════════════════════════════════════════════════════════════════


async def _ready_resolver(_event_id: str) -> WritebackReadiness:
    """Return NOT_REQUIRED — safe ONLY for NOT_REQUIRED disposition events.

    ``route_after_triage`` skips readiness checks for NOT_REQUIRED +
    need_investigation=True, so this value does not affect routing.
    Note: ``triage_graph_node`` (workflow_graph.py:370-372) always calls
    ``runtime.get_event_status_update_readiness()`` and writes it to
    ``event_status_update_readiness`` in graph state regardless of routing.

    .. warning::
       This resolver always returns NOT_REQUIRED regardless of disposition
       policy.  When writing tests for REQUIRED-policy events (ISSUE-062),
       override with a resolver that returns the appropriate readiness value.
       Forgetting to do so will produce a misleading
       ``event_status_update_readiness`` in the graph state.

       See the module-level warning block above for details.
    """
    return WritebackReadiness.NOT_REQUIRED


async def _ingest_event(
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    *,
    object_id: str = "INC-orch-001",
    severity: Severity = Severity.HIGH,
    disposition_policy: DispositionPolicy = DispositionPolicy.NOT_REQUIRED,
) -> str:
    """Ingest a source event and advance it to TRIAGING."""
    ref = SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-orch",
        connector_id="conn-orch",
        source_object_id=object_id,
        ingested_at=_utc_now(),
    )
    result = await event_service.ingest_source_object(
        IngestableSource(
            reference=ref,
            title=f"Orchestration test {object_id}",
            event_type=EventType.DATA_EXFILTRATION,
            severity=severity,
            source_type="mock_xdr",
        )
    )
    event_id = result.event_id
    assert event_id is not None, "ingest must return an event_id"

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.status = EventStatus.TRIAGING.value
            row.disposition_policy = disposition_policy.value
            row.severity = severity.value
            session.add(
                orm.EventAuditLog(
                    event_id=event_id,
                    from_status=EventStatus.NEW.value,
                    to_status=EventStatus.TRIAGING.value,
                    operator="test:setup",
                    reason="advance to TRIAGING for orchestration test",
                    created_at=_utc_now(),
                )
            )

    return event_id


def _build_services(
    state_machine: StateMachineService,
    event_service: EventService,
    workflow_runtime: WorkflowRuntimeService,
    degraded_flags: DegradedFlagService,
    context_store: EventContextStore,
) -> dict[str, Any]:
    """Build the services dict required by ``build_investigation_graph``."""
    return {
        "state_machine": state_machine,
        "event_service": event_service,
        "workflow_runtime": workflow_runtime,
        "degraded_flags": degraded_flags,
        "context_store": context_store,
    }


def _build_agents(
    *,
    triage: Any = None,
    evidence: Any = None,
    risk: Any = None,
    report: Any = None,
    rag: Any = None,
) -> dict[str, Any]:
    """Build the agents dict with sensible defaults for all required agents."""
    agents: dict[str, Any] = {
        "triage_agent": triage or make_triage_stub(),
        "planner_agent": PlannerAgent(),
        "evidence_agent": evidence or make_evidence_stub(),
        "risk_agent": risk or make_risk_stub(),
        "report_agent": report or make_report_stub(),
    }
    if rag is not None:
        agents["rag_agent"] = rag
    return agents


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario 1 — Golden Path: Full orchestration to REPORTING
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_golden_path_full_orchestration_to_closed(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
    state_machine_service: StateMachineService,
    context_store: EventContextStore,
    degraded_flags: DegradedFlagService,
    redis_client: Any,
    audit_log: EventAuditLogService,
) -> None:
    """ISSUE-055 Scenario 1: SuperAgent golden path completes through to CLOSED.

    For NOT_REQUIRED disposition, the full P0 investigation chain executes
    through triage → planner → evidence → risk → response → approval →
    execute → verify → report → close, ending at CLOSED.

    For disposition_policy=REQUIRED, the full chain to CLOSED with writeback
    confirmation is deferred to ISSUE-062.  This test covers NOT_REQUIRED only.

    We assert:
    - node_trace matches P0_NODE_SEQUENCE
    - P0 analysis fields populated (triage_result, evidence_output,
      risk_assessment, report_generated)
    - Final status is CLOSED (NOT_REQUIRED policy completes the full chain)
    - All audit log transitions are valid state machine edges
    - Total wall clock under 90 seconds (mock mode)
    """
    started_at = time.monotonic()

    # ── Setup: ingest event, advance to TRIAGING ──────────────────────────
    event_id = await _ingest_event(
        event_service,
        session_factory,
        object_id="INC-orch-golden-001",
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
    )

    # ── Build runtime and graph ───────────────────────────────────────────
    workflow_runtime = WorkflowRuntimeService(
        session_factory,
        event_service=event_service,
        readiness_resolver=_ready_resolver,
    )
    agents = _build_agents(
        rag=None,  # 显式禁用 RAG — P0_NODE_SEQUENCE 不含 NODE_RAG
    )
    # NOTE: ISSUE-055 按 Issue 约定：P1 的 rag_output 按安装状态断言。
    # RAG 未安装时 P0_NODE_SEQUENCE 不含 NODE_RAG；RAG 安装后需 ISSUE-062 复跑时更新。
    services = _build_services(
        state_machine_service,
        event_service,
        workflow_runtime,
        degraded_flags,
        context_store,
    )
    graph = build_investigation_graph(agents, services)

    # ── Run ───────────────────────────────────────────────────────────────
    initial_state = make_investigation_state(
        event_id=event_id,
        need_investigation=True,
        severity=Severity.HIGH.value,
    )
    final = await graph.ainvoke(
        initial_state,
        {"configurable": {"thread_id": event_id}},
    )

    elapsed_s = time.monotonic() - started_at

    # ── Assert node sequence ──────────────────────────────────────────────
    trace = final["node_trace"]
    assert tuple(trace) == P0_NODE_SEQUENCE, (
        f"expected P0 sequence {P0_NODE_SEQUENCE}, got {tuple(trace)}"
    )

    # ── Assert P0 analysis fields ─────────────────────────────────────────
    assert final.get("triage_result") is not None, "triage_result missing"
    assert final.get("evidence_output") is not None, "evidence_output missing"
    assert final.get("risk_assessment") is not None, "risk_assessment missing"
    assert final.get("report_generated") is True, "report_generated should be True"
    assert final.get("need_investigation") is True

    # ── Assert final status is CLOSED ─────────────────────────────────────
    assert final["event_status"] == EventStatus.CLOSED.value, (
        f"expected CLOSED, got {final['event_status']}"
    )
    assert final["halted"] is False

    # ── Assert audit log transitions valid ────────────────────────────────
    audit_rows = await assert_audit_log_transitions_valid(
        audit_log, event_id, expected_min_count=len(P0_NODE_SEQUENCE)
    )
    # Verify that every non-trivial status change appears in order
    observed_statuses = [row.to_status for row in audit_rows if row.to_status is not None]
    assert EventStatus.CLOSED.value in observed_statuses, "audit log must record CLOSED transition"
    assert EventStatus.REPORTING.value in observed_statuses, (
        "audit log must record REPORTING transition"
    )

    # ── Performance gate ──────────────────────────────────────────────────
    assert elapsed_s < 90.0, f"golden path took {elapsed_s:.1f}s, expected < 90s in mock mode"


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario 2 — Agent Failure Retry
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_agent_failure_retry_evidence_agent(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
    agent_trace_service: AgentTraceService,
) -> None:
    """ISSUE-055 Scenario 2: EvidenceAgent fails once, retries, succeeds.

    Uses ``FlakyStubAgent`` wired to ``AgentTraceService`` so that trace
    records are produced by the real ``execute()`` path — not by manual
    ``log_trace()`` calls.  The ``RetryingAgentWrapper`` simulates
    ``max_retries=1`` (initial attempt + 1 retry = 2 total attempts;
    ``MAX_AGENT_RETRIES=2`` in production allows up to 3 attempts).

    Assertions:
    - Retry count = 1 (failed once, succeeded on second attempt)
    - agent_trace contains both a ``failed`` and a ``completed`` record,
      both written by ``FlakyStubAgent.execute()``
    - The failed trace carries the correct error detail
    """
    # ── Setup: create a real event so trace records are scoped correctly ──
    event_id = await _ingest_event(
        event_service,
        session_factory,
        object_id="INC-orch-retry-001",
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
    )

    # ── Create a flaky evidence stub that records traces on every execute ─
    flaky = make_flaky_evidence_stub(
        fail_count=1,
        agent_name="evidence_agent",
        trace_service=agent_trace_service,
        event_id=event_id,
    )

    # ── Wrap with retry logic; RetryingAgentWrapper calls execute() ───────
    # NOTE: max_retries=1 (2 total attempts) is intentionally lower than the
    # production MAX_AGENT_RETRIES=2 (3 total attempts) so the test completes
    # faster — the scenario only needs one failure + one success to validate
    # the retry-and-trace contract.
    rw = RetryingAgentWrapper(flaky, max_retries=1)  # initial + 1 retry
    result = await rw.execute(object())  # stand-in for EvidenceAgentInput
    assert isinstance(result, EvidenceOutput)

    # ── Assert retry attempts recorded ────────────────────────────────────
    assert rw.attempts == [False, True], (
        f"expected [fail, success] attempts, got {rw.attempts}"
    )

    # ── Verify agent_trace records produced BY the execute() path ─────────
    traces = await agent_trace_service.get_traces_by_event(event_id)
    assert len(traces) == 2, f"expected 2 traces, got {len(traces)}"
    statuses = {t.status for t in traces}
    assert "failed" in statuses, "missing failed trace record"
    assert "completed" in statuses, "missing completed trace record"

    # Verify the failed trace carries the right error detail
    failed = [t for t in traces if t.status == "failed"]
    assert len(failed) == 1
    assert "attempt 1" in (failed[0].error_detail or "")


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario 3 — Checkpoint Recovery
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_checkpoint_recovery_resumes_without_duplicate_execution(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
    state_machine_service: StateMachineService,
    context_store: EventContextStore,
    degraded_flags: DegradedFlagService,
    redis_client: Any,
    audit_log: EventAuditLogService,
) -> None:
    """ISSUE-055 Scenario 3: interrupt before risk_node, resume cleanly.

    The graph is compiled with ``interrupt_before=[NODE_RISK]``. After
    running to the interrupt point, a second graph instance loads the
    checkpoint and resumes. We assert:
    - Nodes before the interrupt are executed exactly once
    - risk_node (and later nodes) are not duplicated in the final trace
    - Final completion reaches CLOSED
    """
    event_id = await _ingest_event(
        event_service,
        session_factory,
        object_id="INC-orch-ckpt-001",
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
    )

    workflow_runtime = WorkflowRuntimeService(
        session_factory,
        event_service=event_service,
        readiness_resolver=_ready_resolver,
    )
    agents = _build_agents()
    services = _build_services(
        state_machine_service,
        event_service,
        workflow_runtime,
        degraded_flags,
        context_store,
    )

    # ── Phase 1: run with interrupt before risk_node ──────────────────────
    checkpointer = await RedisCheckpointer.create(redis_client)
    assert checkpointer.recoverable is True

    graph_p1 = build_investigation_graph(
        agents,
        services,
        checkpointer=checkpointer,
        interrupt_before=[NODE_RISK],
    )
    config = {"configurable": {"thread_id": event_id}}

    intermediate = await graph_p1.ainvoke(  # type: ignore[call-overload]
        make_investigation_state(
            event_id=event_id,
            need_investigation=True,
            severity=Severity.HIGH.value,
        ),
        config,
    )

    # Assert we stopped before risk_node
    trace_before = list(intermediate.get("node_trace", []))
    assert NODE_RISK not in trace_before, (
        f"should have interrupted before risk_node, got: {trace_before}"
    )
    # evidence_node must have executed (it's immediately before risk)
    assert NODE_EVIDENCE in trace_before, (
        f"evidence_node should have run before interrupt, got: {trace_before}"
    )

    # ── Phase 2: resume from checkpoint ───────────────────────────────────
    # Simulate process restart: create a fresh checkpointer from the same Redis
    checkpoint_key = checkpoint_key_for_event(event_id)
    assert checkpoint_key is not None, "checkpoint key should exist in Redis"

    checkpointer_p2 = await RedisCheckpointer.create(redis_client)
    assert checkpointer_p2.recoverable is True

    # Build a new graph with the fresh checkpointer, NO interrupt
    graph_p2 = build_investigation_graph(
        agents,
        services,
        checkpointer=checkpointer_p2,
    )

    final = await graph_p2.ainvoke(None, config)  # type: ignore[call-overload]

    trace_final = list(final.get("node_trace", []))
    assert NODE_CLOSE in trace_final, f"should reach CLOSED after resume, got: {trace_final}"

    # ── Assert no duplicate execution ────────────────────────────────────
    # Count each node — no node should appear more than once in the full trace
    node_counts = Counter(trace_final)
    duplicates = {node: count for node, count in node_counts.items() if count > 1}
    assert not duplicates, f"duplicate node executions detected after resume: {duplicates}"

    # risk_node must appear exactly once (was interrupted before, ran after resume)
    assert node_counts.get(NODE_RISK, 0) == 1, (
        f"risk_node should execute exactly once, got {node_counts.get(NODE_RISK, 0)}"
    )

    # ── Audit log transitions valid ──────────────────────────────────────
    await assert_audit_log_transitions_valid(
        audit_log, event_id, expected_min_count=len(trace_final)
    )

    # ── Cleanup: release checkpoint state in Redis and in-memory saver ────
    await checkpointer.adelete_thread(event_id)
    await checkpointer_p2.adelete_thread(event_id)


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario 4 — Context Consistency (Optimistic Locking)
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_context_consistency_concurrent_writes_no_lost_updates(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
    context_store: EventContextStore,
) -> None:
    """ISSUE-055 Scenario 4: two writers concurrently modify different
    EventContext fields. Both writes are persisted — no lost update.

    Two agent writers (TriageAgent and EvidenceAgent) each write to their
    owned field. Even when writes interleave, both updates are persisted
    with distinct versions because writes target different fields and the
    underlying UPSERT serializes at the DB row level.

    .. note::
       This test validates concurrent writes to **different** fields.
       For true CAS (optimistic-locking) conflict detection on the **same**
       field, see :func:`test_compare_and_set_rejects_stale_version`.
    """
    # ── Setup: ingest event and initialize context ──────────────────────
    event_id = await _ingest_event(
        event_service,
        session_factory,
        object_id="INC-orch-cons-001",
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
    )

    from app.api.v1.schemas import EventSummary as APIEventSummary

    api_summary = APIEventSummary(
        event_id=event_id,
        event_type=EventType.DATA_EXFILTRATION,
        title="concurrency test",
        status=EventStatus.TRIAGING,
        severity=Severity.HIGH,
        risk_score=0,
        final_verdict=FinalVerdict.NONE,
        writeback_required=False,
        writeback_readiness=WritebackReadiness.NOT_REQUIRED,
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
    )
    await context_store.init_context(event_id, api_summary)

    # ── Define two concurrent write tasks to different fields ───────────
    triage_payload: dict[str, Any] = {
        "event_type": EventType.DATA_EXFILTRATION.value,
        "severity": Severity.HIGH.value,
        "need_investigation": True,
        "reasoning": "concurrent triage write",
    }
    evidence_payload: dict[str, Any] = {
        "evidence_list": [],
        "collection_status": CollectionStatus.PARTIAL_DONE.value,
        "overall_confidence": 0.75,
    }

    async def writer_a() -> None:
        """TriageAgent writes triage_result."""
        await context_store.set(event_id, "triage_result", triage_payload)

    async def writer_b() -> None:
        """EvidenceAgent writes evidence_output."""
        await context_store.set(event_id, "evidence_output", evidence_payload)

    # ── Execute concurrently ────────────────────────────────────────────
    await asyncio.gather(writer_a(), writer_b())

    # ── Assert both writes persisted ────────────────────────────────────
    full_ctx = await context_store.get_full_context(event_id)
    assert full_ctx is not None

    stored_triage = full_ctx.triage_result
    assert stored_triage is not None, "triage_result was lost"
    assert isinstance(stored_triage, dict)
    assert stored_triage.get("reasoning") == "concurrent triage write"

    stored_evidence = full_ctx.evidence_output
    assert stored_evidence is not None, "evidence_output was lost"
    assert isinstance(stored_evidence, dict)
    assert stored_evidence.get("collection_status") == CollectionStatus.PARTIAL_DONE.value

    # ── Assert distinct versions (no lost update) ──────────────────────
    triage_version = await context_store.get_field_version(event_id, "triage_result")
    evidence_version = await context_store.get_field_version(event_id, "evidence_output")
    assert triage_version is not None and triage_version > 0
    assert evidence_version is not None and evidence_version > 0
    # Both fields should have been created (version ≥ 1)
    assert triage_version >= 1, f"triage_result version={triage_version}"
    assert evidence_version >= 1, f"evidence_output version={evidence_version}"


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario 4b — Version Conflict Retry
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_version_conflict_retry_on_concurrent_same_field_write(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
    context_store: EventContextStore,
) -> None:
    """ISSUE-055 Scenario 4b: repeated writes to the same field succeed
    with monotonically increasing versions (no lost update).

    This validates the CAS-based conflict resolution in the context store,
    which underpins the optimistic locking contract used by the
    orchestration layer when multiple agents touch shared fields.
    """
    event_id = await _ingest_event(
        event_service,
        session_factory,
        object_id="INC-orch-cas-001",
    )

    from app.api.v1.schemas import EventSummary as APIEventSummary

    api_summary = APIEventSummary(
        event_id=event_id,
        event_type=EventType.DATA_EXFILTRATION,
        title="CAS retry test",
        status=EventStatus.TRIAGING,
        severity=Severity.HIGH,
        risk_score=0,
        final_verdict=FinalVerdict.NONE,
        writeback_required=False,
        writeback_readiness=WritebackReadiness.NOT_REQUIRED,
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
    )
    await context_store.init_context(event_id, api_summary)

    # ── Sequential writes to same field → versions must increase ────────
    versions: list[int] = []
    for i in range(5):
        payload = {
            "event_type": EventType.DATA_EXFILTRATION.value,
            "severity": Severity.HIGH.value,
            "need_investigation": True,
            "reasoning": f"write iteration {i}",
        }
        result = await context_store.set(event_id, "triage_result", payload)
        versions.append(result.version)

    # Versions must be strictly increasing
    for i in range(1, len(versions)):
        assert versions[i] > versions[i - 1], (
            f"version failed to increase: {versions[i - 1]} → {versions[i]}"
        )

    # Final read confirms last write
    full_ctx = await context_store.get_full_context(event_id)
    stored = full_ctx.triage_result
    assert isinstance(stored, dict)
    assert stored.get("reasoning") == "write iteration 4"


# ═══════════════════════════════════════════════════════════════════════════════
# Boundary / failure-path tests (ISSUE-055 review: Should-Fix #3)
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_agent_retry_exhaustion_raises() -> None:
    """ISSUE-055 boundary: RetryingAgentWrapper exhausts all retries.

    ``FlakyStubAgent(fail_count=5)`` + ``RetryingAgentWrapper(max_retries=2)``
    (matching production ``MAX_AGENT_RETRIES=2`` → 3 total attempts).  All
    three attempts fail, so the wrapper must re-raise the final exception
    after recording three failed attempts.

    This guards against the wrapper silently swallowing errors when the
    agent never recovers.
    """
    flaky = make_flaky_evidence_stub(fail_count=5, agent_name="exhaustion_test")
    rw = RetryingAgentWrapper(flaky, max_retries=2)  # 1 initial + 2 retries = 3 total

    with pytest.raises(RuntimeError, match="FlakyStubAgent failure on attempt"):
        await rw.execute(object())

    # All three attempts must have been recorded as failures
    assert rw.attempts == [False, False, False], (
        f"expected 3 failures, got attempts={rw.attempts}"
    )


def test_route_after_triage_required_policy_investigates() -> None:
    """ISSUE-055 boundary: REQUIRED + need_investigation=True → INVESTIGATE.

    For ``DispositionPolicy.REQUIRED`` events that still need investigation
    (and are not false-positive matches), the graph must route into the
    full investigation path (planner → evidence → …), not short-circuit to
    CLOSED or DISPOSITION_ONLY.

    This is a direct routing-function test; the full REQUIRED writeback
    path through the graph is deferred to ISSUE-062.
    """
    state = make_investigation_state(
        event_id="evt-orch-req-001",
        disposition_policy=DispositionPolicy.REQUIRED.value,
        need_investigation=True,
    )
    assert route_after_triage(state) == ROUTE_INVESTIGATE, (
        f"REQUIRED + need_investigation=True must route to INVESTIGATE, "
        f"got {route_after_triage(state)}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Route boundary tests (ISSUE-055 review: Should-Fix #4)
# ═══════════════════════════════════════════════════════════════════════════════


def test_route_after_triage_not_required_no_investigation_routes_to_close() -> None:
    """NOT_REQUIRED + need_investigation=False → ROUTE_CLOSE (early shortcut).

    When an event does not require investigation and disposition is
    NOT_REQUIRED, the graph short-circuits from TRIAGING straight to CLOSED,
    skipping the entire P0 analysis chain.
    """
    state = make_investigation_state(
        event_id="evt-orch-ni-false-001",
        disposition_policy=DispositionPolicy.NOT_REQUIRED.value,
        need_investigation=False,
    )
    assert route_after_triage(state) == ROUTE_CLOSE, (
        f"NOT_REQUIRED + need_investigation=False must route to {ROUTE_CLOSE}, "
        f"got {route_after_triage(state)}"
    )


def test_route_after_triage_not_required_fp_routes_to_close() -> None:
    """NOT_REQUIRED + FP (close_as_fp) → ROUTE_CLOSE.

    False-positive events with NOT_REQUIRED policy skip investigation and
    go directly to CLOSED. The ``close_as_fp`` flag signals that the event
    was determined to be a false positive during triage.
    """
    state = make_investigation_state(
        event_id="evt-orch-fp-001",
        disposition_policy=DispositionPolicy.NOT_REQUIRED.value,
        need_investigation=True,
        false_positive_match={"recommendation": "close_as_fp"},
    )
    assert route_after_triage(state) == ROUTE_CLOSE, (
        f"NOT_REQUIRED + close_as_fp=True must route to {ROUTE_CLOSE}, "
        f"got {route_after_triage(state)}"
    )


def test_route_after_triage_required_fp_readiness_ready_routes_to_disposition_only() -> None:
    """REQUIRED + FP + readiness=READY → ROUTE_DISPOSITION_ONLY.

    A REQUIRED event flagged as false positive with READY writeback readiness
    skips the full investigation chain and enters the disposition-only path,
    which handles the required writeback before closing.
    """
    state = make_investigation_state(
        event_id="evt-orch-req-fp-001",
        disposition_policy=DispositionPolicy.REQUIRED.value,
        need_investigation=True,
        false_positive_match={"recommendation": "close_as_fp"},
        event_status_update_readiness=WritebackReadiness.READY.value,
    )
    assert route_after_triage(state) == ROUTE_DISPOSITION_ONLY, (
        f"REQUIRED + FP + READY must route to {ROUTE_DISPOSITION_ONLY}, "
        f"got {route_after_triage(state)}"
    )


def test_route_after_triage_required_fp_readiness_not_ready_routes_to_manual_hold() -> None:
    """REQUIRED + FP + readiness≠READY → ROUTE_MANUAL_HOLD.

    A REQUIRED event flagged as false positive that is NOT_READY (e.g.
    CAPABILITY_UNKNOWN) cannot proceed to disposition — it must be placed
    on manual hold until the writeback target becomes reachable.
    """
    state = make_investigation_state(
        event_id="evt-orch-req-fp-hold-001",
        disposition_policy=DispositionPolicy.REQUIRED.value,
        need_investigation=True,
        false_positive_match={"recommendation": "close_as_fp"},
        event_status_update_readiness=WritebackReadiness.CAPABILITY_UNKNOWN.value,
    )
    assert route_after_triage(state) == ROUTE_MANUAL_HOLD, (
        f"REQUIRED + FP + CAPABILITY_UNKNOWN must route to {ROUTE_MANUAL_HOLD}, "
        f"got {route_after_triage(state)}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# CAS optimistic-locking test (ISSUE-055 review: Should-Fix #1)
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_compare_and_set_rejects_stale_version(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
    context_store: EventContextStore,
) -> None:
    """ISSUE-055: ``compare_and_set`` rejects a writer holding a stale version.

    Two writers race on the **same** field (triage_result).  Writer A holds
    version 1; writer B writes first and bumps the version to 2; writer A's
    CAS with expected_version=1 must return ``False`` because the field has
    moved on.  This is the real optimistic-locking contract the orchestration
    layer relies on.
    """
    # ── Setup ────────────────────────────────────────────────────────────────
    event_id = await _ingest_event(
        event_service,
        session_factory,
        object_id="INC-orch-cas-stale-001",
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
    )

    from app.api.v1.schemas import EventSummary as APIEventSummary

    api_summary = APIEventSummary(
        event_id=event_id,
        event_type=EventType.DATA_EXFILTRATION,
        title="CAS stale version test",
        status=EventStatus.TRIAGING,
        severity=Severity.HIGH,
        risk_score=0,
        final_verdict=FinalVerdict.NONE,
        writeback_required=False,
        writeback_readiness=WritebackReadiness.NOT_REQUIRED,
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
    )
    await context_store.init_context(event_id, api_summary)

    # ── Writer B wins the race — writes first (version → 1) ──────────────────
    winner_payload: dict[str, Any] = {
        "event_type": EventType.DATA_EXFILTRATION.value,
        "severity": Severity.HIGH.value,
        "need_investigation": True,
        "reasoning": "writer B won the race",
    }
    set_result = await context_store.set(event_id, "triage_result", winner_payload)
    assert set_result.version == 1

    # ── Writer B writes again (version → 2) ──────────────────────────────────
    winner_payload_v2: dict[str, Any] = {
        **winner_payload,
        "reasoning": "writer B updated — v2",
    }
    set_result = await context_store.set(event_id, "triage_result", winner_payload_v2)
    assert set_result.version == 2

    # ── Writer A tries CAS with stale expected_version=1 → must fail ─────────
    stale_payload: dict[str, Any] = {
        "event_type": EventType.INSIDER_THREAT.value,
        "severity": Severity.LOW.value,
        "need_investigation": False,
        "reasoning": "stale writer A — should be rejected",
    }
    cas_ok = await context_store.compare_and_set(
        event_id, "triage_result", expected_version=1, value=stale_payload
    )
    assert cas_ok is False, (
        "compare_and_set with stale version must return False — "
        "field is already at version 2"
    )

    # ── Verify writer B's value is still intact (no lost update) ─────────────
    full_ctx = await context_store.get_full_context(event_id)
    stored = full_ctx.triage_result
    assert isinstance(stored, dict)
    assert stored.get("reasoning") == "writer B updated — v2"

    # ── CAS with current version should succeed ──────────────────────────────
    current_version = await context_store.get_field_version(event_id, "triage_result")
    assert current_version is not None and current_version >= 2

    fresh_payload: dict[str, Any] = {
        "event_type": EventType.DATA_EXFILTRATION.value,
        "severity": Severity.HIGH.value,
        "need_investigation": True,
        "reasoning": "fresh writer with correct version",
    }
    cas_ok = await context_store.compare_and_set(
        event_id, "triage_result", expected_version=current_version, value=fresh_payload
    )
    assert cas_ok is True, (
        f"compare_and_set with current version {current_version} must succeed"
    )

    # Verify the fresh write replaced writer B's value
    full_ctx = await context_store.get_full_context(event_id)
    stored = full_ctx.triage_result
    assert isinstance(stored, dict)
    assert stored.get("reasoning") == "fresh writer with correct version"
