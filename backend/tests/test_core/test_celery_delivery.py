"""Unit tests for Celery delivery helpers (ISSUE-117 / #622 Phase B)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from app.core.celery_delivery import (
    REDELIVERY_TERMINAL_EVENT_STATUSES,
    celery_task_owner_id,
    normalize_public_task_state,
    should_skip_redelivered_investigation,
)
from app.core.errors import DependencyUnavailableError
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    Severity,
    SourceObjectKind,
)
from app.models.security_event import SecurityEvent
from app.models.source import SourceReference


def _sample_event(*, event_id: str, status: EventStatus) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        event_type=EventType.OTHER,
        title="redelivery-test",
        status=status,
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


def test_celery_task_owner_id_requires_non_empty_task_id() -> None:
    with pytest.raises(ValueError, match="task_id is required"):
        celery_task_owner_id("")


def test_normalize_public_task_state_defaults_pending() -> None:
    assert normalize_public_task_state("") == "PENDING"
    assert normalize_public_task_state("pending") == "PENDING"


@pytest.mark.parametrize(
    "status",
    sorted(REDELIVERY_TERMINAL_EVENT_STATUSES, key=lambda item: item.value),
)
@pytest.mark.asyncio
async def test_should_skip_redelivered_investigation_for_terminal_states(
    monkeypatch: pytest.MonkeyPatch,
    status: EventStatus,
) -> None:
    event = _sample_event(event_id=f"evt-{status.value}", status=status)

    class _EventService:
        async def get_event(self, _event_id: str) -> SecurityEvent:
            return event

    monkeypatch.setattr(
        "app.api.v1.deps.get_event_service",
        AsyncMock(return_value=_EventService()),
    )
    assert await should_skip_redelivered_investigation(event.event_id) is True


@pytest.mark.asyncio
async def test_should_not_skip_redelivered_investigation_for_new_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = _sample_event(event_id="evt-new", status=EventStatus.NEW)

    class _EventService:
        async def get_event(self, _event_id: str) -> SecurityEvent:
            return event

    monkeypatch.setattr(
        "app.api.v1.deps.get_event_service",
        AsyncMock(return_value=_EventService()),
    )
    assert await should_skip_redelivered_investigation("evt-new") is False


@pytest.mark.asyncio
async def test_should_skip_redelivered_investigation_when_lookup_degraded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fail_service() -> None:
        raise DependencyUnavailableError(
            message="postgres unavailable",
            error_code="dependency_unavailable",
            details={"dependency": "postgres"},
        )

    monkeypatch.setattr("app.api.v1.deps.get_event_service", _fail_service)
    assert await should_skip_redelivered_investigation("evt-degraded") is True
