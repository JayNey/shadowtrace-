"""ISSUE-099 ingest → triage → evidence source enrichment integration tests."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agents.evidence_agent import EvidenceAgent
from app.agents.triage_agent import TriageAgent
from app.core.llm.mock_client import MockLLMClient
from app.data_generators.scenarios import build_scenario
from app.ingestion.source_ingester import SourceIngester
from app.mock_xdr.state import MockXDRState
from app.models.agent_io import EvidenceAgentInput
from app.models.enums import EventStatus, EventType, Severity, SourceObjectKind
from app.orchestration.triage_input_builder import build_triage_agent_input
from app.services.agent_trace_service import TraceProjection
from app.services.event_service import EventService
from app.services.state_machine_service import StateMachineService
from tests.integration.conftest import RecordingToolExecutor
from tests.system.helpers import ALL_SOURCE_KINDS, event_id_for_incident

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("clean_state")]

MALICIOUS_PROCESS_HOST = "DEV-WKS-012"
MALICIOUS_PROCESS_ACCOUNT = "dev-user-012"
MALICIOUS_PROCESS_PROC = "ransomware_stage.exe"


async def _ingest_malicious_process(
    *,
    mock_xdr_state: MockXDRState,
    source_adapter: object,
    source_ingester: SourceIngester,
    session_factory: async_sessionmaker[AsyncSession],
) -> str:
    scenario = build_scenario("malicious_process", seed=42)
    mock_xdr_state.load_scenario(scenario)
    summary = await source_ingester.poll(source_adapter, ALL_SOURCE_KINDS, batch_size=20)
    assert summary.rejected == 0, summary.errors
    incident = scenario.incidents[0]
    return await event_id_for_incident(
        session_factory,
        connector_id=incident.reference.connector_id,
        source_object_id=incident.reference.source_object_id,
    )


@pytest.mark.asyncio
async def test_malicious_process_ingest_populates_triage_entities(
    mock_xdr_state: MockXDRState,
    source_adapter: object,
    source_ingester: SourceIngester,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    working_memory: object,
    agent_trace_service: object,
    mock_llm_client: MockLLMClient,
) -> None:
    event_id = await _ingest_malicious_process(
        mock_xdr_state=mock_xdr_state,
        source_adapter=source_adapter,
        source_ingester=source_ingester,
        session_factory=session_factory,
    )
    event = await event_service.get_event(event_id)
    assert event is not None
    event_hostnames = {h.hostname for h in event.entities.hosts if h.hostname}
    assert MALICIOUS_PROCESS_HOST in event_hostnames

    triage_input = await build_triage_agent_input(event_id, event_service=event_service)
    triage = TriageAgent(
        llm_client=mock_llm_client,
        working_memory=working_memory.for_writer("TriageAgent"),
        trace_service=agent_trace_service,
    )
    result = await triage.execute(triage_input)

    triage_hostnames = {h.hostname for h in result.entities.hosts if h.hostname}
    assert MALICIOUS_PROCESS_HOST in triage_hostnames
    assert MALICIOUS_PROCESS_ACCOUNT in {a.username for a in result.entities.accounts}
    assert MALICIOUS_PROCESS_PROC in {p.name for p in result.entities.processes}
    assert "ransomware-like" not in triage_hostnames
    assert result.entity_provenance_summary
    assert result.degraded is False
    assert "text_extraction_empty" in result.degradation_reasons


@pytest.mark.asyncio
async def test_malicious_process_evidence_uses_source_hostname(
    mock_xdr_state: MockXDRState,
    source_adapter: object,
    source_ingester: SourceIngester,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    working_memory: object,
    e2e_tool_executor: object,
    agent_trace_service: object,
    state_machine_service: StateMachineService,
    mock_llm_client: MockLLMClient,
) -> None:
    event_id = await _ingest_malicious_process(
        mock_xdr_state=mock_xdr_state,
        source_adapter=source_adapter,
        source_ingester=source_ingester,
        session_factory=session_factory,
    )
    triage_input = await build_triage_agent_input(event_id, event_service=event_service)
    triage = TriageAgent(
        llm_client=mock_llm_client,
        working_memory=working_memory.for_writer("TriageAgent"),
        trace_service=agent_trace_service,
    )
    triage_result = await triage.execute(triage_input)

    await state_machine_service.transition(
        event_id,
        EventStatus.TRIAGING,
        operator="test",
        reason="issue-099 evidence enrichment test",
    )
    await state_machine_service.transition(
        event_id,
        EventStatus.COLLECTING_EVIDENCE,
        operator="test",
        reason="issue-099 evidence enrichment test",
    )

    recorder = RecordingToolExecutor(e2e_tool_executor)
    evidence = EvidenceAgent(
        llm_client=mock_llm_client,
        tool_executor=recorder,
        working_memory=working_memory.for_writer("EvidenceAgent"),
        trace_service=agent_trace_service,
        event_service=event_service,
        session_factory=session_factory,
    )
    await evidence.execute(
        EvidenceAgentInput(event_id=event_id, triage_result=triage_result),
    )

    edr_calls = [params for name, params in recorder.calls if name == "query_edr_process"]
    assert edr_calls, f"expected query_edr_process calls, got {recorder.calls!r}"
    assert any(params.get("host_id") == MALICIOUS_PROCESS_HOST for params in edr_calls)


@pytest.mark.asyncio
async def test_triage_trace_includes_entity_provenance_summary(
    mock_xdr_state: MockXDRState,
    source_adapter: object,
    source_ingester: SourceIngester,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    working_memory: object,
    agent_trace_service: object,
    mock_llm_client: MockLLMClient,
) -> None:
    from sqlalchemy import select

    from app.db import models as orm

    event_id = await _ingest_malicious_process(
        mock_xdr_state=mock_xdr_state,
        source_adapter=source_adapter,
        source_ingester=source_ingester,
        session_factory=session_factory,
    )
    triage_input = await build_triage_agent_input(event_id, event_service=event_service)
    triage = TriageAgent(
        llm_client=mock_llm_client,
        working_memory=working_memory.for_writer("TriageAgent"),
        trace_service=agent_trace_service,
    )
    await triage.execute(triage_input)

    async with session_factory() as session:
        row = await session.scalar(
            select(orm.AgentTrace)
            .where(
                orm.AgentTrace.event_id == event_id,
                orm.AgentTrace.agent_name == "triage_agent",
            )
            .order_by(orm.AgentTrace.started_at.desc())
            .limit(1)
        )
    assert row is not None
    basis = TraceProjection.decision_basis(row.output_data)
    assert basis.get("entity_provenance_summary")
    assert basis.get("degradation_reasons")


@pytest.mark.asyncio
async def test_entities_empty_if_investigate_before_asset_link(
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Document poll ordering: incident-only ingest has no hostname until asset/log link."""
    from datetime import UTC, datetime

    from app.models.source import SourceReference
    from app.services.event_service import IngestableSource

    sfx = "099-timing"
    incident_ref = SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-1",
        connector_id=f"conn-{sfx}",
        source_object_id=f"INC-{sfx}",
        ingested_at=datetime.now(UTC),
    )
    inc = await event_service.ingest_source_object(
        IngestableSource(
            reference=incident_ref,
            title="Malicious process spawned — ransomware-like behavior",
            event_type=EventType.MALICIOUS_PROCESS,
            severity=Severity.HIGH,
            normalized={"event_type": "malicious_process", "risk_score": 76},
            source_type="mock_xdr",
        )
    )
    event = await event_service.get_event(inc.event_id)
    assert event is not None
    assert not event.entities.hosts


@pytest.mark.asyncio
async def test_supporting_log_enriches_event_without_link_or_snapshot(
    mock_xdr_state: MockXDRState,
    source_adapter: object,
    source_ingester: SourceIngester,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """#655: supporting objects fold into entities via the parent back-reference only.

    The log's structured host/account/process fields must enrich the parent event's
    entities, yet supporting objects must never enter the incident/alert snapshot set
    nor gain a synthetic ``SourceEventLink`` (both are hard pipeline invariants).
    """
    from sqlalchemy import select

    from app.db import models as orm

    event_id = await _ingest_malicious_process(
        mock_xdr_state=mock_xdr_state,
        source_adapter=source_adapter,
        source_ingester=source_ingester,
        session_factory=session_factory,
    )
    event = await event_service.get_event(event_id)
    assert event is not None
    assert MALICIOUS_PROCESS_HOST in {h.hostname for h in event.entities.hosts if h.hostname}

    async with session_factory() as session:
        snapshots = await session.scalar(
            select(orm.SecurityEvent.source_reference_snapshots).where(
                orm.SecurityEvent.event_id == event_id
            )
        )
        linked_kinds = (
            await session.scalars(
                select(orm.SourceObject.source_kind)
                .join(
                    orm.SourceEventLink,
                    orm.SourceEventLink.source_record_id == orm.SourceObject.source_record_id,
                )
                .where(orm.SourceEventLink.event_id == event_id)
            )
        ).all()

    assert {ref["source_kind"] for ref in snapshots or []} == {
        SourceObjectKind.INCIDENT.value,
        SourceObjectKind.ALERT.value,
    }
    assert SourceObjectKind.LOG.value not in linked_kinds
    assert SourceObjectKind.ASSET.value not in linked_kinds
