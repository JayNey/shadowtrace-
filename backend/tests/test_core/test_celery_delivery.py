"""Unit tests for Celery delivery helpers (ISSUE-117 / #622 Phase B)."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from app.core.celery_delivery import (
    celery_task_owner_id,
    normalize_public_task_state,
    should_skip_redelivered_investigation,
)
from app.models.enums import EventStatus, EventType, Severity, SourceObjectKind
from app.models.enums import DispositionPolicy
from app.models.security_event import SecurityEvent
from app.models.source import SourceReference
from datetime import UTC, datetime


def test_celery_task_owner_id_requires_non_empty_task_id() -> None:
    with pytest.raises(ValueError, match="task_id is required"):
        celery_task_owner_id("")


def test_normalize_public_task_state_defaults_pending() -> None:
    assert normalize_public_task_state("") == "PENDING"
    assert normalize_public_task_state("pending") == "PENDING"


@pytest.mark.asyncio
async def test_should_skip_redelivered_investigation_for_closed_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed = SecurityEvent(
        event_id="evt-closed",
        event_type=EventType.OTHER,
        title="closed",
        status=EventStatus.CLOSED,
        severity=Severity.LOW,
        creation_source_ref=SourceReference(
            source_kind=SourceObjectKind.INCIDENT,
            source_product="manual",
            source_tenant_id="tenant-test",
            connector_id="conn-test",
            source_object_id="manual-1",
            ingested_at=datetime.now(UTC),
        ),
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
    )

    class _EventService:
        async def get_event(self, _event_id: str) -> SecurityEvent:
            return closed

    monkeypatch.setattr(
        "app.api.v1.deps.get_event_service",
        AsyncMock(return_value=_EventService()),
    )
    assert await should_skip_redelivered_investigation("evt-closed") is True


@pytest.mark.asyncio
async def test_should_not_skip_redelivered_investigation_for_new_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    new_event = SecurityEvent(
        event_id="evt-new",
        event_type=EventType.OTHER,
        title="new",
        status=EventStatus.NEW,
        severity=Severity.LOW,
        creation_source_ref=SourceReference(
            source_kind=SourceObjectKind.INCIDENT,
            source_product="manual",
            source_tenant_id="tenant-test",
            connector_id="conn-test",
            source_object_id="manual-1",
            ingested_at=datetime.now(UTC),
        ),
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
    )

    class _EventService:
        async def get_event(self, _event_id: str) -> SecurityEvent:
            return new_event

    monkeypatch.setattr(
        "app.api.v1.deps.get_event_service",
        AsyncMock(return_value=_EventService()),
    )
    assert await should_skip_redelivered_investigation("evt-new") is False
