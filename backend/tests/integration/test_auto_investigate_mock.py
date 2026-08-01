"""Auto-investigate integration tests with Mock ingest (ISSUE-108 / #612)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytest_plugins = ["tests.test_ingestion.conftest"]

from app.core.config import Settings
from app.db import models as orm
from app.models.enums import EventStatus, EventType, InvestigationIntentStatus, Severity, SourceObjectKind
from app.models.source import SourceReference
from app.services.auto_investigate_policy import AutoInvestigatePolicyService
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService
from app.services.event_service import EventService, IngestableSource
from app.services.investigation_intent_service import InvestigationIntentService


def _incident_source(*, object_id: str) -> IngestableSource:
    ref = SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-mock",
        source_object_id=object_id,
        source_updated_at=datetime.now(UTC),
    )
    return IngestableSource(
        reference=ref,
        title="Suspicious process incident",
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.HIGH,
        normalized={"risk_score": 76, "event_type": "malicious_process"},
    )


@pytest.mark.asyncio
async def test_disabled_auto_investigate_creates_no_intent(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client,
) -> None:
    store = EventContextStore(redis_client, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    settings = Settings(AUTO_INVESTIGATE_ENABLED=False, SOURCE_MODE="mock_xdr")
    intent_service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        degraded_flags=degraded,
        settings=settings,
    )
    events = EventService(
        session_factory,
        store,
        degraded_flags=degraded,
        investigation_intent=intent_service,
    )
    result = await events.ingest_source_object(_incident_source(object_id=f"inc-auto-off-{uuid4().hex[:8]}"))
    async with session_factory() as session:
        rows = (
            await session.scalars(
                select(orm.InvestigationIntent).where(
                    orm.InvestigationIntent.event_id == result.event_id
                )
            )
        ).all()
    assert rows == []


@pytest.mark.asyncio
async def test_enabled_incident_ingest_creates_pending_intent(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client,
) -> None:
    store = EventContextStore(redis_client, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    intent_service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        degraded_flags=degraded,
        settings=settings,
    )
    events = EventService(
        session_factory,
        store,
        degraded_flags=degraded,
        investigation_intent=intent_service,
    )
    result = await events.ingest_source_object(_incident_source(object_id=f"inc-auto-on-{uuid4().hex[:8]}"))
    assert result.created is True
    async with session_factory() as session:
        row = await session.scalar(
            select(orm.InvestigationIntent).where(
                orm.InvestigationIntent.event_id == result.event_id
            )
        )
    assert row is not None
    assert row.status == InvestigationIntentStatus.PENDING.value


@pytest.mark.asyncio
async def test_duplicate_ingest_does_not_create_second_intent(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client,
) -> None:
    store = EventContextStore(redis_client, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    intent_service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        degraded_flags=degraded,
        settings=settings,
    )
    events = EventService(
        session_factory,
        store,
        degraded_flags=degraded,
        investigation_intent=intent_service,
    )
    source = _incident_source(object_id=f"inc-auto-dup-{uuid4().hex[:8]}")
    first = await events.ingest_source_object(source)
    second = await events.ingest_source_object(source)
    assert second.idempotent is True
    async with session_factory() as session:
        rows = (
            await session.scalars(
                select(orm.InvestigationIntent).where(
                    orm.InvestigationIntent.event_id == first.event_id
                )
            )
        ).all()
    assert len(rows) == 1


def _alert_source(*, object_id: str) -> IngestableSource:
    ref = SourceReference(
        source_kind=SourceObjectKind.ALERT,
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-mock",
        source_object_id=object_id,
        source_updated_at=datetime.now(UTC),
    )
    return IngestableSource(
        reference=ref,
        title="Suspicious alert",
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.HIGH,
        normalized={"risk_score": 76, "event_type": "malicious_process"},
    )


@pytest.mark.asyncio
async def test_provisional_alert_materializes_intent_after_window(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client,
) -> None:
    from datetime import timedelta

    store = EventContextStore(redis_client, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_PROVISIONAL_WINDOW_S=60,
    )
    intent_service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        degraded_flags=degraded,
        settings=settings,
    )
    events = EventService(
        session_factory,
        store,
        degraded_flags=degraded,
        investigation_intent=intent_service,
    )
    result = await events.ingest_source_object(
        _alert_source(object_id=f"al-prov-{uuid4().hex[:8]}")
    )
    async with session_factory() as session:
        before = await session.scalar(
            select(orm.InvestigationIntent).where(
                orm.InvestigationIntent.event_id == result.event_id
            )
        )
        assert before is None
        event = await session.get(orm.SecurityEvent, result.event_id)
        assert event is not None
        event.created_at = datetime.now(UTC) - timedelta(minutes=10)
        await session.commit()
    materialized = await intent_service.reconcile_stale(limit=5)
    assert materialized >= 1
    async with session_factory() as session:
        row = await session.scalar(
            select(orm.InvestigationIntent).where(
                orm.InvestigationIntent.event_id == result.event_id
            )
        )
    assert row is not None
    assert row.status == InvestigationIntentStatus.PENDING.value
