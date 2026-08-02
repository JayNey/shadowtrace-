"""ISSUE-158: global integration fixtures must match production wiring."""

from __future__ import annotations

from app.ingestion.source_ingester import SourceIngester
from app.services.event_service import EventService


def test_global_event_service_includes_state_machine(
    event_service: EventService,
) -> None:
    """Integration fixture owner; must not be shadowed by ingestion plugins."""
    assert event_service._state_machine is not None


def test_global_source_ingester_uses_integration_event_service(
    source_ingester: SourceIngester,
    event_service: EventService,
) -> None:
    """Integration ``source_ingester`` must share the state-machine-backed EventService."""
    assert source_ingester._events is event_service
    assert event_service._state_machine is not None
