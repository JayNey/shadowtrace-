"""Unit tests for shared triage input builder (ISSUE-566 / ISSUE-325)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.models.context import EventContext
from app.models.entities import EntitySet, HostEntity
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    SourceObjectKind,
    WritebackReadiness,
)
from app.models.security_event import EventSummary, SecurityEvent
from app.models.source import SourceReference
from app.orchestration.triage_input_builder import (
    _normalized_hint_fields,
    build_raw_summary_from_context,
    build_triage_agent_input,
)


def _event_summary(*, event_id: str, title: str) -> EventSummary:
    return EventSummary(
        event_id=event_id,
        event_type=EventType.INSIDER_THREAT,
        title=title,
        status=EventStatus.NEW,
        severity=Severity.LOW,
        risk_score=0,
        final_verdict=FinalVerdict.NONE,
        writeback_required=False,
        writeback_readiness=WritebackReadiness.NOT_REQUIRED,
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
    )


def test_build_raw_summary_from_context() -> None:
    context = EventContext(event=_event_summary(event_id="evt-test-001", title="Suspicious login"))
    summary = build_raw_summary_from_context(context)
    assert "Suspicious login" in summary
    assert "insider_threat" in summary
    assert "low" in summary


@pytest.mark.asyncio
async def test_build_triage_agent_input_uses_context_when_no_event_service() -> None:
    context = EventContext(
        event=_event_summary(event_id="evt-test-003", title="Context-only title"),
    )
    triage_input = await build_triage_agent_input(
        "evt-test-003",
        event_context=context,
        event_service=None,
    )
    assert triage_input.event_id == "evt-test-003"
    assert "Context-only title" in triage_input.raw_event_summary
    assert "insider_threat" in triage_input.raw_event_summary


@pytest.mark.asyncio
async def test_build_triage_agent_input_prefers_event_service_description() -> None:
    class _FakeEvent:
        title = "HTTP investigate test"
        description = "Low risk fixture"
        entities = None

    class _FakeEventService:
        async def get_event(self, event_id: str) -> _FakeEvent:
            return _FakeEvent()

    context = EventContext(event=_event_summary(event_id="evt-test-002", title="Context title"))
    triage_input = await build_triage_agent_input(
        "evt-test-002",
        event_context=context,
        event_service=_FakeEventService(),
    )
    assert triage_input.event_id == "evt-test-002"
    assert "HTTP investigate test" in triage_input.raw_event_summary
    assert "Low risk fixture" in triage_input.raw_event_summary


def test_normalized_hint_fields_reads_domain_and_fqdn() -> None:
    fields = _normalized_hint_fields(
        {
            "fqdn": "storage-sync-cdn.example",
            "secondary_host": "SRV-DB-STG-02",
            "src_ip": "198.51.100.44",
        }
    )
    assert fields["domain"] == "storage-sync-cdn.example"
    assert fields["secondary_host"] == "SRV-DB-STG-02"
    assert fields["src_ip"] == "198.51.100.44"


@pytest.mark.asyncio
async def test_build_triage_agent_input_includes_structured_context_from_event() -> None:
    ref = SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-1",
        connector_id="conn-test",
        source_object_id="INC-325",
        ingested_at=datetime.now(UTC),
    )
    event = SecurityEvent(
        event_id="evt-325",
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
                "domain": "storage-sync-cdn.example",
            }
        },
        entities=EntitySet(
            hosts=[HostEntity(entity_id="h1", hostname="WKS-DATA-031")],
        ),
    )

    class _FakeEventService:
        async def get_event(self, event_id: str) -> SecurityEvent:
            return event

    triage_input = await build_triage_agent_input(
        "evt-325",
        event_service=_FakeEventService(),
    )
    assert triage_input.structured_prompt_context is not None
    ctx = triage_input.structured_prompt_context
    assert ctx.normalized_fields["src_ip"] == "198.51.100.44"
    assert ctx.normalized_fields["secondary_host"] == "SRV-DB-STG-02"
    assert ctx.normalized_fields["domain"] == "storage-sync-cdn.example"
    assert triage_input.hint_entities.hosts[0].hostname == "WKS-DATA-031"
