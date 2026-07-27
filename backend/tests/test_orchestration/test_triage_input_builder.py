"""Unit tests for shared triage input builder (ISSUE-566)."""

from __future__ import annotations

import pytest

from app.models.context import EventContext
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    WritebackReadiness,
)
from app.models.security_event import EventSummary
from app.orchestration.triage_input_builder import (
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
