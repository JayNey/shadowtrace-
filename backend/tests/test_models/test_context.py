"""EventContext model/schema field alignment (ISSUE-002, ISSUE-265)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

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


def _canonical_event_context_field_names() -> set[str]:
    """Use the deterministic serialization contract as the canonical field source."""
    schema = EventContext.model_json_schema(mode="serialization")
    return set(schema["properties"].keys())


def test_event_context_model_fields_match_serialization_schema() -> None:
    expected = _canonical_event_context_field_names()
    actual = set(EventContext.model_fields.keys())
    assert actual == expected, {
        "missing": expected - actual,
        "unexpected": actual - expected,
    }


def _summary(event_id: str = "evt-1") -> EventSummary:
    return EventSummary(
        event_id=event_id,
        event_type=EventType.INSIDER_THREAT,
        title="t",
        status=EventStatus.NEW,
        severity=Severity.LOW,
        risk_score=0,
        final_verdict=FinalVerdict.NONE,
        writeback_required=False,
        writeback_readiness=WritebackReadiness.NOT_REQUIRED,
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
    )


def test_event_context_event_field_is_event_summary_typed() -> None:
    """ISSUE-094 §2: ``event`` is EventSummary, never the full SecurityEvent."""
    annotation = EventContext.model_fields["event"].annotation
    assert annotation == (EventSummary | None)


def test_event_context_accepts_event_summary() -> None:
    ctx = EventContext(event=_summary())
    assert isinstance(ctx.event, EventSummary)
    assert ctx.event.event_id == "evt-1"


def test_event_context_none_event_ok() -> None:
    ctx = EventContext()
    assert ctx.event is None


def test_event_context_rejects_security_event_shaped_payload() -> None:
    """A raw SecurityEvent-shaped dict (missing writeback_* fields) must fail."""
    with pytest.raises(ValidationError):
        EventContext(
            event={
                "event_id": "evt-1",
                "event_type": "insider_threat",
                "title": "t",
                "creation_source_ref": {
                    "source_kind": "incident",
                    "source_product": "mock_xdr",
                    "source_tenant_id": "t1",
                    "connector_id": "conn-1",
                    "source_object_id": "INC-1",
                },
            }
        )
