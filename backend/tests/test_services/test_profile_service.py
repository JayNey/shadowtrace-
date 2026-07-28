"""Database-level ProfileService tests for MemoryAgent consolidation (ISSUE-080)."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.agent_io import ProfileUpdate
from app.services.profile_service import ProfileService, profile_id_for

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


def _alembic_config() -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return config


@pytest.fixture(scope="module")
def migrated() -> None:
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(
    migrated: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def clean_profiles(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        await session.execute(text("DELETE FROM entity_profile"))
        await session.commit()


@pytest.mark.asyncio
async def test_profile_service_upsert_increments_event_count(
    session_factory: async_sessionmaker[AsyncSession],
    clean_profiles: None,
) -> None:
    service = ProfileService(session_factory)
    first = ProfileUpdate(
        entity_type="account",
        entity_value="zhangsan",
        event_id="evt-profile-0001",
        risk_score=42,
        behavior_tags=["phase:initial_access"],
    )
    second = ProfileUpdate(
        entity_type="account",
        entity_value="zhangsan",
        event_id="evt-profile-0002",
        risk_score=88,
        behavior_tags=["phase:exfiltration"],
    )

    created = await service.upsert(first)
    replayed = await service.upsert(first)
    updated = await service.upsert(second)
    loaded = await service.get("account", "ZHANGSAN")

    assert created.profile_id == profile_id_for("account", "zhangsan")
    assert replayed.event_count == 1
    assert replayed.risk_history == [42]
    assert updated.event_count == 2
    assert updated.last_event_id == "evt-profile-0002"
    assert updated.risk_history == [42, 88]
    assert updated.behavior_tags == [
        "phase:exfiltration",
        "phase:initial_access",
    ]
    assert loaded is not None
    assert loaded.event_count == 2


@pytest.mark.asyncio
async def test_profile_service_keeps_only_ten_latest_risk_scores(
    session_factory: async_sessionmaker[AsyncSession],
    clean_profiles: None,
) -> None:
    service = ProfileService(session_factory)

    for index in range(12):
        await service.upsert(
            ProfileUpdate(
                entity_type="host",
                entity_value="PC-FIN-023",
                event_id=f"evt-profile-{index:04d}",
                risk_score=index,
                behavior_tags=[f"risk:{index}"],
            )
        )

    loaded = await service.get("host", "PC-FIN-023")

    assert loaded is not None
    assert loaded.event_count == 12
    assert loaded.risk_history == list(range(2, 12))
    assert len(loaded.behavior_tags) == 12
