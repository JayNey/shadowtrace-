"""Unit tests for analysis_only_complete snapshot overlay (ISSUE-103)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.db import models as orm
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
)
from app.services.event_service import EventService


@pytest.mark.asyncio
async def test_get_event_overlays_analysis_only_complete_from_context_store() -> None:
    """Stale security_event snapshot merges analysis_only_complete from context store."""
    event_id = "evt-overlay-103"
    now = datetime.now(UTC)
    row = orm.SecurityEvent(
        event_id=event_id,
        event_type=EventType.MALICIOUS_PROCESS.value,
        title="overlay test",
        description="",
        status=EventStatus.REPORTING.value,
        severity=Severity.HIGH.value,
        final_verdict=FinalVerdict.NONE.value,
        entities={},
        creation_source_ref={
            "source_kind": "incident",
            "source_product": "mock_xdr",
            "source_tenant_id": "tenant-1",
            "connector_id": "conn-1",
            "source_object_id": "inc-1",
            "ingested_at": now.isoformat(),
        },
        source_reference_snapshots=[],
        disposition_policy=DispositionPolicy.REQUIRED.value,
        source_type="mock_xdr",
        occurred_at=now,
        row_version=1,
        event_context_snapshot={"risk_assessment": {"risk_score": 72}},
    )

    session = AsyncMock()

    async def _get(_model: type, pk: str) -> orm.SecurityEvent | None:
        assert pk == event_id
        return row

    session.get = AsyncMock(side_effect=_get)
    session_cm = MagicMock()
    session_cm.__aenter__ = AsyncMock(return_value=session)
    session_cm.__aexit__ = AsyncMock(return_value=False)

    session_factory = MagicMock(return_value=session_cm)
    store = AsyncMock()
    store.get = AsyncMock(return_value=True)
    degraded_flags = AsyncMock()

    service = EventService(session_factory, store, degraded_flags=degraded_flags)
    event = await service.get_event(event_id)

    assert event is not None
    assert event.event_context_snapshot is not None
    assert event.event_context_snapshot.get("analysis_only_complete") is True
    store.get.assert_awaited_once_with(event_id, "analysis_only_complete")
