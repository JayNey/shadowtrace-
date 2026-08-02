"""ISSUE-158: ingestion-scoped fixtures must stay free of StateMachineService."""

from __future__ import annotations

from app.ingestion.source_ingester import SourceIngester
from app.services.event_service import EventService


def test_ingestion_event_service_has_no_state_machine(
    ingestion_event_service: EventService,
) -> None:
    """Ingestion fixture owner; must not pick up integration state machine wiring."""
    assert ingestion_event_service._state_machine is None


def test_ingestion_source_ingester_uses_ingestion_event_service(
    ingestion_source_ingester: SourceIngester,
    ingestion_event_service: EventService,
) -> None:
    assert ingestion_source_ingester._events is ingestion_event_service
    assert ingestion_event_service._state_machine is None
