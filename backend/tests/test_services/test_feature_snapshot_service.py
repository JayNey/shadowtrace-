"""Persistence tests for FeatureSnapshot and DetectionFeatureBaseline (ISSUE-120 Phase A/B)."""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.errors import ValidationError
from app.db import models as orm
from app.models.behavior_observation import (
    BehaviorEntityRef,
    BehaviorObservation,
    BehaviorObservationProvenance,
    BehaviorObservationSourceRef,
)
from app.models.detection_scope import DetectionScopeIdentity, UpstreamConnectorMember
from app.models.feature_snapshot import (
    DetectionBaselineStatus,
    DetectionFeatureBaselineQuery,
    FeatureSnapshotQuery,
    FeatureSnapshotStatus,
    FeatureWindowKind,
)
from app.services.detection_baseline_service import DetectionBaselineService
from app.services.detection_scope_service import DetectionScopeService
from app.services.feature_snapshot_service import FeatureSnapshotService

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
def migrated_database() -> None:
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(
    migrated_database: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def clean_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.DetectionFeatureBaseline))
            await session.execute(delete(orm.FeatureSnapshot))
            await session.execute(delete(orm.BehaviorObservation))
            await session.execute(delete(orm.DetectionScopeRevision))
    yield
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.DetectionFeatureBaseline))
            await session.execute(delete(orm.FeatureSnapshot))
            await session.execute(delete(orm.BehaviorObservation))
            await session.execute(delete(orm.DetectionScopeRevision))


def _snapshot_service(
    session_factory: async_sessionmaker[AsyncSession],
) -> FeatureSnapshotService:
    return FeatureSnapshotService(session_factory)


def _baseline_service(
    session_factory: async_sessionmaker[AsyncSession],
) -> DetectionBaselineService:
    return DetectionBaselineService(session_factory)


def _scope_service(session_factory: async_sessionmaker[AsyncSession]) -> DetectionScopeService:
    return DetectionScopeService(session_factory)


async def _seed_scope(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    suffix: str,
    tenant_id: str,
) -> str:
    service = _scope_service(session_factory)
    identity = DetectionScopeIdentity(
        source_tenant_id=tenant_id,
        source_product="mock_xdr",
        integration_instance_id=f"inst-{suffix}",
    )
    revision = await service.register_revision(
        identity=identity,
        connector_set_version=1,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id=f"conn-{suffix}", source_product="mock_xdr"),
        ],
    )
    activated = await service.activate_revision(revision.scope_revision_id)
    return activated.detection_scope_id


async def _insert_observation(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    suffix: str,
    tenant_id: str,
    scope_id: str,
    observed_at: datetime,
    entity_id: str = "10.0.0.10",
) -> BehaviorObservation:
    observation = BehaviorObservation(
        observation_id=f"obs-{suffix}",
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        source_ref=BehaviorObservationSourceRef(
            source_product="mock_xdr",
            connector_id=f"conn-{suffix[:6]}",
            source_kind="log",
            source_object_id=f"log-{suffix}",
            source_object_type="edr",
            source_revision=1,
        ),
        observed_at=observed_at,
        ingested_at=observed_at,
        entity_refs=[BehaviorEntityRef(entity_type="ip", entity_id=entity_id, role="src")],
        action="create_process",
        category="process_create",
        detection_score=55.0,
        content_hash="c" * 64,
        observation_hash="d" * 64,
        idempotency_key=f"idem-{suffix}",
        provenance=BehaviorObservationProvenance(source_record_id=f"src-{suffix}"),
    )
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.BehaviorObservation(
                    observation_id=observation.observation_id,
                    source_tenant_id=observation.source_tenant_id,
                    detection_scope_id=observation.detection_scope_id,
                    source_product=observation.source_ref.source_product,
                    connector_id=observation.source_ref.connector_id,
                    source_kind=observation.source_ref.source_kind,
                    source_object_id=observation.source_ref.source_object_id,
                    source_object_type=observation.source_ref.source_object_type,
                    source_revision=observation.source_ref.source_revision,
                    source_ref=observation.source_ref.model_dump(mode="json"),
                    observed_at=observation.observed_at,
                    ingested_at=observation.ingested_at,
                    entity_refs=[item.model_dump(mode="json") for item in observation.entity_refs],
                    action=observation.action,
                    category=observation.category,
                    normalized_attributes=observation.normalized_attributes,
                    detection_score=observation.detection_score,
                    schema_version=observation.schema_version,
                    projection_schema_version=observation.projection_schema_version,
                    content_hash=observation.content_hash,
                    observation_hash=observation.observation_hash,
                    idempotency_key=observation.idempotency_key,
                    provenance=observation.provenance.model_dump(mode="json"),
                )
            )
    return observation


@pytest.mark.asyncio
async def test_materialize_ready_snapshot(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    for index, minutes in enumerate((60, 45, 30)):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=minutes),
        )
    service = _snapshot_service(session_factory)
    snapshot = await service.materialize(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )
    assert snapshot.status is FeatureSnapshotStatus.READY
    assert snapshot.features["observation_count"] == 3
    assert snapshot.cache_key == snapshot.content_hash


@pytest.mark.asyncio
async def test_materialize_is_idempotent(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    for index, minutes in enumerate((60, 45, 30)):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=minutes),
        )
    service = _snapshot_service(session_factory)
    first = await service.materialize_or_recompute(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )
    second = await service.materialize_or_recompute(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )
    assert first.snapshot_id == second.snapshot_id


@pytest.mark.asyncio
async def test_late_data_bumps_revision(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 10, 0, tzinfo=UTC)
    for index, minutes in enumerate((60, 45, 30)):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=minutes),
        )
    service = _snapshot_service(session_factory)
    first = await service.materialize_or_recompute(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )
    await _insert_observation(
        session_factory,
        suffix=f"{suffix}-late",
        tenant_id=tenant_id,
        scope_id=scope_id,
        observed_at=datetime(2026, 8, 1, 15, 5, 0, tzinfo=UTC),
    )
    second = await service.materialize_or_recompute(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )
    assert second.revision == first.revision + 1
    assert second.supersedes_snapshot_id == first.snapshot_id
    assert second.features["observation_count"] == 4


@pytest.mark.asyncio
async def test_tenant_isolation(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_a = f"tenant-a-{suffix}"
    tenant_b = f"tenant-b-{suffix}"
    scope_a = await _seed_scope(session_factory, suffix=f"a-{suffix}", tenant_id=tenant_a)
    scope_b = await _seed_scope(session_factory, suffix=f"b-{suffix}", tenant_id=tenant_b)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    for tenant, scope, label in (
        (tenant_a, scope_a, "a"),
        (tenant_b, scope_b, "b"),
    ):
        for index, minutes in enumerate((60, 45, 30)):
            await _insert_observation(
                session_factory,
                suffix=f"{label}-{suffix}-{index}",
                tenant_id=tenant,
                scope_id=scope,
                observed_at=cutoff - timedelta(minutes=minutes),
            )
    service = _snapshot_service(session_factory)
    await service.materialize(
        source_tenant_id=tenant_a,
        detection_scope_id=scope_a,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )
    result = await service.query_snapshots(FeatureSnapshotQuery(source_tenant_id=tenant_a))
    assert result.total == 1
    assert all(item.source_tenant_id == tenant_a for item in result.items)


@pytest.mark.asyncio
async def test_baseline_materialization_with_seasonality(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    snapshot_service = _snapshot_service(session_factory)
    baseline_service = _baseline_service(session_factory)
    cutoffs = [
        datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC),
        datetime(2026, 8, 2, 15, 30, 0, tzinfo=UTC),
        datetime(2026, 8, 3, 15, 30, 0, tzinfo=UTC),
    ]
    for day_index, cutoff in enumerate(cutoffs):
        for obs_index, minutes in enumerate((60, 45, 30)):
            await _insert_observation(
                session_factory,
                suffix=f"{suffix}-d{day_index}-o{obs_index}",
                tenant_id=tenant_id,
                scope_id=scope_id,
                observed_at=cutoff - timedelta(minutes=minutes),
            )
        await snapshot_service.materialize(
            source_tenant_id=tenant_id,
            detection_scope_id=scope_id,
            entity_type="ip",
            entity_id="10.0.0.10",
            window_kind=FeatureWindowKind.ONE_HOUR,
            cutoff_at=cutoff,
        )
    baseline = await baseline_service.materialize_baseline(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoffs[-1],
    )
    assert baseline.peer_group_id is not None
    assert baseline.seasonality_profile is not None
    assert baseline.seasonality_profile.sample_snapshot_count >= 2
    assert baseline.cache_key == baseline.content_hash


@pytest.mark.asyncio
async def test_thirty_day_window_materialization(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC)
    for index in range(20):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=datetime(2026, 8, 1, 10, 0, tzinfo=UTC) + timedelta(days=index),
        )
    snapshot = await _snapshot_service(session_factory).materialize(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.THIRTY_DAYS,
        cutoff_at=cutoff,
    )
    assert snapshot.window_kind is FeatureWindowKind.THIRTY_DAYS
    assert snapshot.status is FeatureSnapshotStatus.READY


@pytest.mark.asyncio
async def test_idempotency_replay_rejects_hash_drift(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    for index, minutes in enumerate((60, 45, 30)):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=minutes),
        )
    service = _snapshot_service(session_factory)
    snapshot = await service.materialize(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )
    tampered = snapshot.model_copy(update={"content_hash": "f" * 64, "cache_key": "f" * 64})
    async with session_factory() as session:
        with pytest.raises(ValidationError, match="different content hash"):
            await service.persist_in_session(session, tampered)


@pytest.mark.asyncio
async def test_materialize_handles_late_data_via_recompute(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 10, 0, tzinfo=UTC)
    for index, minutes in enumerate((60, 45, 30)):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=minutes),
        )
    service = _snapshot_service(session_factory)
    first = await service.materialize(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )
    await _insert_observation(
        session_factory,
        suffix=f"{suffix}-late",
        tenant_id=tenant_id,
        scope_id=scope_id,
        observed_at=datetime(2026, 8, 1, 15, 5, 0, tzinfo=UTC),
    )
    second = await service.materialize(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )
    assert second.revision == first.revision + 1
    assert second.features["observation_count"] == 4


@pytest.mark.asyncio
async def test_materialize_twenty_four_hour_window_ready(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 2, 12, 0, 0, tzinfo=UTC)
    for index, hour in enumerate((2, 6, 10, 14, 18)):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=datetime(2026, 8, 1, hour, 0, tzinfo=UTC),
        )
    snapshot = await _snapshot_service(session_factory).materialize(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.TWENTY_FOUR_HOURS,
        cutoff_at=cutoff,
    )
    assert snapshot.window_kind is FeatureWindowKind.TWENTY_FOUR_HOURS
    assert snapshot.status is FeatureSnapshotStatus.READY


@pytest.mark.asyncio
async def test_seven_day_window_materialization(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 8, 12, 0, 0, tzinfo=UTC)
    for index in range(10):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=datetime(2026, 8, 1, 10, 0, tzinfo=UTC) + timedelta(days=index * 6 // 9),
        )
    snapshot = await _snapshot_service(session_factory).materialize(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.SEVEN_DAYS,
        cutoff_at=cutoff,
    )
    assert snapshot.window_kind is FeatureWindowKind.SEVEN_DAYS
    assert snapshot.status is FeatureSnapshotStatus.READY


@pytest.mark.asyncio
async def test_baseline_insufficient_history_when_few_snapshots(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    snapshot_service = _snapshot_service(session_factory)
    baseline_service = _baseline_service(session_factory)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    for index, minutes in enumerate((60, 45, 30)):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=minutes),
        )
    await snapshot_service.materialize(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )
    baseline = await baseline_service.materialize_baseline(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )
    assert baseline.status is DetectionBaselineStatus.INSUFFICIENT_HISTORY
    assert baseline.stats == {}


@pytest.mark.asyncio
async def test_baseline_insufficient_to_ready_bumps_revision_not_duplicate_slot(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    snapshot_service = _snapshot_service(session_factory)
    baseline_service = _baseline_service(session_factory)
    baseline_cutoff = datetime(2026, 8, 3, 15, 30, 0, tzinfo=UTC)
    day_one_cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    for index, minutes in enumerate((60, 45, 30)):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-d1-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=day_one_cutoff - timedelta(minutes=minutes),
        )
    await snapshot_service.materialize(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=day_one_cutoff,
    )
    first = await baseline_service.materialize_baseline(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=baseline_cutoff,
    )
    assert first.status is DetectionBaselineStatus.INSUFFICIENT_HISTORY
    assert first.revision == 1

    day_two_cutoff = datetime(2026, 8, 2, 15, 30, 0, tzinfo=UTC)
    for index, minutes in enumerate((60, 45, 30)):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-d2-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=day_two_cutoff - timedelta(minutes=minutes),
        )
    await snapshot_service.materialize(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=day_two_cutoff,
    )

    second = await baseline_service.materialize_baseline(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=baseline_cutoff,
    )
    assert second.revision == 2
    assert second.supersedes_baseline_id == first.baseline_id
    assert second.status is DetectionBaselineStatus.READY

    result = await baseline_service.query_baselines(
        DetectionFeatureBaselineQuery(source_tenant_id=tenant_id)
    )
    baseline_cutoff_rows = [item for item in result.items if item.cutoff_at == baseline_cutoff]
    assert len(baseline_cutoff_rows) == 2
    assert {item.revision for item in baseline_cutoff_rows} == {1, 2}


@pytest.mark.asyncio
async def test_get_snapshot_rejects_cross_tenant(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    for index, minutes in enumerate((60, 45, 30)):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=minutes),
        )
    service = _snapshot_service(session_factory)
    snapshot = await service.materialize(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )
    assert (
        await service.get_snapshot(
            source_tenant_id=tenant_id,
            snapshot_id=snapshot.snapshot_id,
        )
        is not None
    )
    assert (
        await service.get_snapshot(
            source_tenant_id="other-tenant",
            snapshot_id=snapshot.snapshot_id,
        )
        is None
    )


@pytest.mark.asyncio
async def test_concurrent_recompute_only_one_extra_revision(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 10, 0, tzinfo=UTC)
    for index, minutes in enumerate((60, 45, 30)):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=minutes),
        )
    service = _snapshot_service(session_factory)
    first = await service.materialize_or_recompute(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )
    await _insert_observation(
        session_factory,
        suffix=f"{suffix}-late",
        tenant_id=tenant_id,
        scope_id=scope_id,
        observed_at=datetime(2026, 8, 1, 15, 5, 0, tzinfo=UTC),
    )

    async def _recompute() -> None:
        await service.materialize_or_recompute(
            source_tenant_id=tenant_id,
            detection_scope_id=scope_id,
            entity_type="ip",
            entity_id="10.0.0.10",
            window_kind=FeatureWindowKind.ONE_HOUR,
            cutoff_at=cutoff,
        )

    await asyncio.gather(_recompute(), _recompute())

    async with session_factory() as session:
        rows = list(
            await session.scalars(
                select(orm.FeatureSnapshot).where(
                    orm.FeatureSnapshot.source_tenant_id == tenant_id,
                    orm.FeatureSnapshot.cutoff_at == cutoff,
                )
            )
        )
    revisions = sorted(int(row.revision) for row in rows)
    assert revisions == [1, 2]
    assert revisions[-1] == first.revision + 1
