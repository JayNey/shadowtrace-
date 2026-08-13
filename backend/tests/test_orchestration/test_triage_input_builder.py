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


class _FakeSourceRow:
    def __init__(
        self,
        normalized: dict[str, object],
        raw_payload: dict[str, object] | None = None,
    ) -> None:
        self.normalized = normalized
        self.raw_payload = raw_payload or {}


class _FakeSession:
    def __init__(
        self,
        *,
        by_id: dict[str, _FakeSourceRow] | None = None,
        scalar_rows: list[_FakeSourceRow] | None = None,
    ) -> None:
        self._by_id = by_id or {}
        self._scalar_rows = list(scalar_rows or [])

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *args: object) -> bool:
        return False

    async def get(self, model: object, pk: str) -> _FakeSourceRow | None:
        del model
        return self._by_id.get(pk)

    async def scalar(self, stmt: object) -> _FakeSourceRow | None:
        del stmt
        if not self._scalar_rows:
            return None
        return self._scalar_rows.pop(0)


class _FakeSessionFactory:
    def __init__(
        self,
        *,
        by_id: dict[str, _FakeSourceRow] | None = None,
        scalar_rows: list[_FakeSourceRow] | None = None,
    ) -> None:
        self._by_id = by_id or {}
        self._scalar_rows = list(scalar_rows or [])

    def __call__(self) -> _FakeSession:
        return _FakeSession(by_id=self._by_id, scalar_rows=list(self._scalar_rows))


@pytest.mark.asyncio
async def test_build_triage_agent_input_reads_source_object_when_snapshot_is_baseline() -> None:
    ref = SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-1",
        connector_id="conn-test",
        source_object_id="INC-325",
        ingested_at=datetime.now(UTC),
    )
    event = SecurityEvent(
        event_id="evt-325-ingest",
        event_type=EventType.OTHER,
        title="Correlation: elevated session and volume signals on analytics segment",
        description="",
        creation_source_ref=ref,
        current_primary_source_record_id="src-rec-325",
        raw_alert_snapshot={"normalized": {"risk_score": 72, "scenario": "adversarial"}},
        entities=EntitySet(hosts=[HostEntity(entity_id="h1", hostname="WKS-DATA-031")]),
    )
    source_row = _FakeSourceRow(
        {
            "account": "svc-analytics-47",
            "hostname": "WKS-DATA-031",
            "secondary_host": "SRV-DB-STG-02",
            "src_ip": "198.51.100.44",
        }
    )

    class _FakeEventService:
        _session_factory = _FakeSessionFactory(by_id={"src-rec-325": source_row})

        async def get_event(self, event_id: str) -> SecurityEvent:
            del event_id
            return event

    triage_input = await build_triage_agent_input(
        "evt-325-ingest",
        event_service=_FakeEventService(),
    )
    assert triage_input.structured_prompt_context is not None
    fields = triage_input.structured_prompt_context.normalized_fields
    assert fields["hostname"] == "WKS-DATA-031"
    assert fields["secondary_host"] == "SRV-DB-STG-02"
    assert fields["src_ip"] == "198.51.100.44"
    assert fields["account"] == "svc-analytics-47"
    assert "risk_score" not in fields


@pytest.mark.asyncio
async def test_build_triage_agent_input_loads_related_alerts_capped_at_five() -> None:
    incident_ref = SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-1",
        connector_id="conn-test",
        source_object_id="INC-325",
        ingested_at=datetime.now(UTC),
    )
    alert_refs = [
        SourceReference(
            source_kind=SourceObjectKind.ALERT,
            source_product="mock_xdr",
            source_tenant_id="tenant-1",
            connector_id="conn-test",
            source_object_id=f"ALT-{index}",
            ingested_at=datetime.now(UTC),
        )
        for index in range(6)
    ]
    event = SecurityEvent(
        event_id="evt-325-alerts",
        event_type=EventType.OTHER,
        title="blurry",
        description="",
        creation_source_ref=incident_ref,
        source_reference_snapshots=alert_refs,
        raw_alert_snapshot={"normalized": {"risk_score": 10}},
    )
    scalar_rows = [
        _FakeSourceRow({"title": f"alert-{index}", "gpt_tag": f"tag-{index}"})
        for index in range(6)
    ]

    class _FakeEventService:
        _session_factory = _FakeSessionFactory(scalar_rows=scalar_rows)

        async def get_event(self, event_id: str) -> SecurityEvent:
            del event_id
            return event

    triage_input = await build_triage_agent_input(
        "evt-325-alerts",
        event_service=_FakeEventService(),
    )
    assert triage_input.structured_prompt_context is not None
    assert len(triage_input.structured_prompt_context.related_alerts) == 5
    assert triage_input.structured_prompt_context.related_alerts[0].title == "alert-0"
