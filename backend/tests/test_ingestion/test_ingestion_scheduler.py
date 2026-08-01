"""Ingestion scheduler tests (ISSUE-107 / #611)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.source.base import SourcePage
from app.core.config import Settings, get_settings
from app.db import models as orm
from app.ingestion.ingestion_scheduler import (
    IngestionScheduler,
    ingestion_poll_advisory_lock_key,
)
from app.models.enums import EventStatus, SourceObjectKind
from app.services.event_service import EventService
from tests.test_ingestion.test_source_ingester import FakePagedAdapter, _incident, _suffix


def _scheduler_settings(**overrides: object) -> Settings:
    defaults: dict[str, object] = {
        "database_url": "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
        "redis_url": "redis://localhost:6379/0",
        "source_mode": "mock_xdr",
        "ingestion_scheduler_enabled": True,
        "simulation_enabled": True,
    }
    defaults.update(overrides)
    return Settings(**defaults)


def _multi_kind_pages(
    *,
    incident_items: list,
    server_time: datetime,
    connector_id: str | None = None,
) -> dict[object, SourcePage | Exception]:
    pages: dict[object, SourcePage | Exception] = {}
    for kind in (
        SourceObjectKind.INCIDENT,
        SourceObjectKind.ALERT,
        SourceObjectKind.ASSET,
        SourceObjectKind.LOG,
    ):
        items = incident_items if kind == SourceObjectKind.INCIDENT else []
        page = SourcePage(
            items=items,
            object_kind=kind,
            has_more=False,
            server_time=server_time,
        )
        pages[(kind.value, None, None)] = page
        pages[(kind.value, None)] = page
        if connector_id is not None:
            pages[(kind.value, connector_id, None)] = page
    return pages


def _scheduler(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
    settings: Settings,
) -> IngestionScheduler:
    return IngestionScheduler(
        session_factory=session_factory,
        event_service=event_service,
        settings=settings,
    )


@pytest.mark.asyncio
async def test_run_once_skips_when_scheduler_disabled(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
) -> None:
    scheduler = _scheduler(
        session_factory=session_factory,
        event_service=event_service,
        settings=_scheduler_settings(ingestion_scheduler_enabled=False),
    )
    result = await scheduler.run_once()
    assert result.status == "skipped"
    assert result.reason == "scheduler_disabled"


@pytest.mark.asyncio
@pytest.mark.parametrize("source_mode", ["file", "live", "live_crowdstrike"])
async def test_run_once_skips_non_mock_source_modes(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
    source_mode: str,
) -> None:
    scheduler = _scheduler(
        session_factory=session_factory,
        event_service=event_service,
        settings=_scheduler_settings(source_mode=source_mode),
    )
    result = await scheduler.run_once()
    assert result.status == "skipped"
    assert result.reason == f"source_mode_{source_mode}"


@pytest.mark.asyncio
async def test_run_once_accepts_new_incident(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
) -> None:
    suffix = _suffix()
    connector_id = f"conn-sched-{suffix}"
    base = datetime(2026, 7, 20, 10, 0, tzinfo=UTC)
    incident = _incident(f"INC-SCHED-{suffix}", connector_id, updated_at=base)
    adapter = FakePagedAdapter(
        f"adapter-sched-{suffix}",
        _multi_kind_pages(incident_items=[incident], server_time=base, connector_id=connector_id),
    )
    settings = _scheduler_settings()
    scheduler = _scheduler(
        session_factory=session_factory,
        event_service=event_service,
        settings=settings,
    )

    with patch.object(scheduler, "_build_mock_adapter", return_value=adapter):
        result = await scheduler.run_once()

    assert result.status == "completed"
    assert result.summary is not None
    assert result.summary.accepted == 1
    assert result.summary.duplicate == 0

    async with session_factory() as session:
        count = await session.scalar(
            select(func.count()).select_from(orm.SecurityEvent).where(
                orm.SecurityEvent.status == EventStatus.NEW.value
            )
        )
        assert count is not None and count >= 1


@pytest.mark.asyncio
async def test_run_once_second_poll_accepted_zero_without_new_data(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
) -> None:
    suffix = _suffix()
    connector_id = f"conn-sched2-{suffix}"
    base = datetime(2026, 7, 20, 11, 0, tzinfo=UTC)
    incident = _incident(f"INC-SCHED2-{suffix}", connector_id, updated_at=base)
    adapter = FakePagedAdapter(
        f"adapter-sched2-{suffix}",
        _multi_kind_pages(incident_items=[incident], server_time=base, connector_id=connector_id),
    )
    settings = _scheduler_settings()
    scheduler = _scheduler(
        session_factory=session_factory,
        event_service=event_service,
        settings=settings,
    )

    with patch.object(scheduler, "_build_mock_adapter", return_value=adapter):
        first = await scheduler.run_once()
        second = await scheduler.run_once()

    assert first.summary is not None and first.summary.accepted == 1
    assert second.summary is not None
    assert second.summary.accepted == 0


@pytest.mark.asyncio
async def test_run_once_replay_same_incident_counts_duplicate(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
) -> None:
    suffix = _suffix()
    connector_id = f"conn-dup-{suffix}"
    base = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
    incident = _incident(f"INC-DUP-{suffix}", connector_id, updated_at=base)
    pages = _multi_kind_pages(
        incident_items=[incident],
        server_time=base,
        connector_id=connector_id,
    )
    adapter = FakePagedAdapter(f"adapter-dup-{suffix}", pages)
    settings = _scheduler_settings()
    scheduler = _scheduler(
        session_factory=session_factory,
        event_service=event_service,
        settings=settings,
    )

    with patch.object(scheduler, "_build_mock_adapter", return_value=adapter):
        await scheduler.run_once()
        replay = FakePagedAdapter(f"adapter-dup-{suffix}", pages)
        with patch.object(scheduler, "_build_mock_adapter", return_value=replay):
            result = await scheduler.run_once()

    assert result.summary is not None
    assert result.summary.accepted == 0
    assert result.summary.duplicate == 1


@pytest.mark.asyncio
async def test_run_once_skips_when_advisory_lock_held(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
) -> None:
    settings = _scheduler_settings()
    scheduler = _scheduler(
        session_factory=session_factory,
        event_service=event_service,
        settings=settings,
    )
    lock_key = ingestion_poll_advisory_lock_key()
    async with session_factory() as session:
        locked = await session.scalar(
            text("SELECT pg_try_advisory_lock(:key)").bindparams(key=lock_key)
        )
        assert locked is True
        try:
            result = await scheduler.run_once()
        finally:
            await session.execute(
                text("SELECT pg_advisory_unlock(:key)").bindparams(key=lock_key)
            )

    assert result.status == "skipped"
    assert result.reason == "lock_not_acquired"


@pytest.mark.asyncio
async def test_run_once_releases_lock_after_poll_failure(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
) -> None:
    from app.adapters.mock_xdr import MockXDRSourceAdapter
    from app.ingestion.source_ingester import SourceIngester

    adapter = MockXDRSourceAdapter(
        base_url="http://mock-xdr",
        read_token="mock-read-token",
        write_token="mock-write-token",
    )
    settings = _scheduler_settings()
    scheduler = _scheduler(
        session_factory=session_factory,
        event_service=event_service,
        settings=settings,
    )
    lock_key = ingestion_poll_advisory_lock_key()

    with patch.object(scheduler, "_build_mock_adapter", return_value=adapter):
        with patch.object(SourceIngester, "poll", side_effect=RuntimeError("poll failed")):
            result = await scheduler.run_once()

    assert result.status == "error"
    assert result.reason == "RuntimeError"

    async with session_factory() as session:
        acquired = await session.scalar(
            text("SELECT pg_try_advisory_lock(:key)").bindparams(key=lock_key)
        )
        assert acquired is True
        await session.execute(
            text("SELECT pg_advisory_unlock(:key)").bindparams(key=lock_key)
        )


@pytest.mark.asyncio
async def test_run_once_records_redis_stats(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
    redis_client,
) -> None:
    suffix = _suffix()
    connector_id = f"conn-stats-{suffix}"
    base = datetime(2026, 7, 20, 13, 0, tzinfo=UTC)
    incident = _incident(f"INC-STATS-{suffix}", connector_id, updated_at=base)
    adapter = FakePagedAdapter(
        f"adapter-stats-{suffix}",
        _multi_kind_pages(incident_items=[incident], server_time=base, connector_id=connector_id),
    )
    settings = _scheduler_settings()
    scheduler = IngestionScheduler(
        session_factory=session_factory,
        event_service=event_service,
        settings=settings,
        redis_client=redis_client,
    )

    with patch.object(scheduler, "_build_mock_adapter", return_value=adapter):
        await scheduler.run_once()

    raw = redis_client.get_client()
    accepted = await raw.get("shadowtrace:ingestion:stats:accepted")
    assert accepted is not None
    assert int(accepted) >= 1


def test_poll_sources_task_registered() -> None:
    from app.core.celery_app import celery_app
    from app.tasks.ingestion_tasks import POLL_SOURCES_TASK

    assert celery_app.tasks[POLL_SOURCES_TASK].name == POLL_SOURCES_TASK


def test_beat_schedule_empty_when_scheduler_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INGESTION_SCHEDULER_ENABLED", "false")
    get_settings.cache_clear()
    from importlib import reload

    import app.core.celery_app as celery_module

    reload(celery_module)
    assert celery_module.celery_app.conf.beat_schedule == {}
    get_settings.cache_clear()


def test_beat_schedule_present_when_scheduler_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INGESTION_SCHEDULER_ENABLED", "true")
    monkeypatch.setenv("INGESTION_POLL_INTERVAL_S", "45")
    get_settings.cache_clear()
    from importlib import reload

    import app.core.celery_app as celery_module

    reload(celery_module)
    schedule = celery_module.celery_app.conf.beat_schedule
    assert "shadowtrace-poll-sources" in schedule
    assert schedule["shadowtrace-poll-sources"]["task"] == "shadowtrace.poll_sources"
    assert schedule["shadowtrace-poll-sources"]["schedule"] == 45.0
    get_settings.cache_clear()
