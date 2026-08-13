"""AnalysisOnlyPipeline triage input wiring (ISSUE-325)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from app.models.agent_io import TriageAgentInput, TriageResult
from app.models.entities import EntitySet, HostEntity
from app.models.enums import EventType, Severity, SourceObjectKind
from app.models.security_event import SecurityEvent
from app.models.source import SourceReference
from app.services.analysis_only_pipeline import AnalysisOnlyPipeline


@pytest.mark.asyncio
async def test_run_triage_passes_structured_prompt_context() -> None:
    captured: list[TriageAgentInput] = []

    class _Triage:
        async def execute(self, triage_input: TriageAgentInput) -> TriageResult:
            captured.append(triage_input)
            return TriageResult(
                event_type=EventType.OTHER,
                severity=Severity.LOW,
                need_investigation=True,
                decision_summary="ok",
            )

    ref = SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-1",
        connector_id="conn-test",
        source_object_id="INC-325",
        ingested_at=datetime.now(UTC),
    )
    event = SecurityEvent(
        event_id="evt-325-ao",
        event_type=EventType.OTHER,
        title="Correlation: elevated session and volume signals on analytics segment",
        description="",
        creation_source_ref=ref,
        raw_alert_snapshot={
            "normalized": {
                "account": "svc-analytics-47",
                "hostname": "WKS-DATA-031",
                "secondary_host": "SRV-DB-STG-02",
                "src_ip": "198.51.100.44",
            }
        },
        entities=EntitySet(hosts=[HostEntity(entity_id="h1", hostname="WKS-DATA-031")]),
    )

    class _FakeEventService:
        async def get_event(self, event_id: str) -> SecurityEvent:
            del event_id
            return event

    pipeline = AnalysisOnlyPipeline(
        triage_agent=_Triage(),
        evidence_agent=MagicMock(),
        rag_agent=MagicMock(),
        risk_agent=MagicMock(),
        report_agent=MagicMock(),
        event_service=_FakeEventService(),
    )
    result, alert_text = await pipeline._run_triage("evt-325-ao", event)

    assert result.decision_summary == "ok"
    assert "Correlation:" in alert_text
    assert len(captured) == 1
    ctx = captured[0].structured_prompt_context
    assert ctx is not None
    assert ctx.normalized_fields["src_ip"] == "198.51.100.44"
    assert ctx.normalized_fields["secondary_host"] == "SRV-DB-STG-02"
    assert captured[0].hint_entities.hosts[0].hostname == "WKS-DATA-031"
