"""FeatureSnapshot persistence and recompute (ISSUE-120 Phase A/B / #625)."""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta

from sqlalchemy import and_, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ValidationError
from app.db import models as orm
from app.models.feature_snapshot import (
    FeatureSnapshot,
    FeatureSnapshotListResult,
    FeatureSnapshotQuery,
    FeatureWindowKind,
)
from app.services.feature_snapshot_resolver import (
    FeatureSnapshotResolver,
    build_feature_snapshot,
    compute_window_bounds,
    effective_observation_upper_bound,
    ensure_utc,
    row_to_feature_snapshot,
)

logger = logging.getLogger(__name__)

DEFAULT_ALLOWED_LATENESS = timedelta(minutes=15)


def _materialization_advisory_lock_key(
    *,
    source_tenant_id: str,
    detection_scope_id: str,
    entity_type: str,
    entity_id: str,
    window_kind: FeatureWindowKind,
    window_end: datetime,
    cutoff_at: datetime,
) -> int:
    material = "|".join(
        [
            source_tenant_id,
            detection_scope_id,
            entity_type,
            entity_id,
            window_kind.value,
            ensure_utc(window_end).isoformat(),
            ensure_utc(cutoff_at).isoformat(),
        ]
    ).encode()
    return int.from_bytes(hashlib.sha256(material).digest()[:8], byteorder="big", signed=True)


class FeatureSnapshotService:
    """Materialize and persist event-time feature snapshots from behavior observations."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self._resolver = FeatureSnapshotResolver()

    async def persist_in_session(
        self,
        session: AsyncSession,
        snapshot: FeatureSnapshot,
    ) -> FeatureSnapshot:
        existing = await session.scalar(
            select(orm.FeatureSnapshot).where(
                orm.FeatureSnapshot.idempotency_key == snapshot.idempotency_key
            )
        )
        if existing is not None:
            if existing.content_hash != snapshot.content_hash:
                raise ValidationError(
                    "feature snapshot idempotency replay with different content hash",
                    details={"idempotency_key": snapshot.idempotency_key},
                )
            return row_to_feature_snapshot(existing)

        row = orm.FeatureSnapshot(
            snapshot_id=snapshot.snapshot_id,
            source_tenant_id=snapshot.source_tenant_id,
            detection_scope_id=snapshot.detection_scope_id,
            entity_type=snapshot.entity_type,
            entity_id=snapshot.entity_id,
            feature_contract_version=snapshot.feature_contract_version,
            window_kind=snapshot.window_kind.value,
            window_start=snapshot.window_start,
            window_end=snapshot.window_end,
            cutoff_at=snapshot.cutoff_at,
            allowed_lateness_seconds=snapshot.allowed_lateness_seconds,
            source_watermark=snapshot.source_watermark,
            status=snapshot.status.value,
            features=snapshot.features,
            provenance=snapshot.provenance.model_dump(mode="json"),
            revision=snapshot.revision,
            supersedes_snapshot_id=snapshot.supersedes_snapshot_id,
            content_hash=snapshot.content_hash,
            cache_key=snapshot.cache_key,
            idempotency_key=snapshot.idempotency_key,
            schema_version=snapshot.schema_version,
        )
        try:
            async with session.begin_nested():
                session.add(row)
                await session.flush()
        except IntegrityError:
            existing = await session.scalar(
                select(orm.FeatureSnapshot).where(
                    orm.FeatureSnapshot.idempotency_key == snapshot.idempotency_key
                )
            )
            if existing is None:
                raise
            if existing.content_hash != snapshot.content_hash:
                raise ValidationError(
                    "feature snapshot idempotency replay with different content hash",
                    details={"idempotency_key": snapshot.idempotency_key},
                ) from None
            return row_to_feature_snapshot(existing)
        return row_to_feature_snapshot(row)

    async def materialize(
        self,
        *,
        source_tenant_id: str,
        detection_scope_id: str,
        entity_type: str,
        entity_id: str,
        window_kind: FeatureWindowKind,
        cutoff_at: datetime,
        allowed_lateness: timedelta = DEFAULT_ALLOWED_LATENESS,
    ) -> FeatureSnapshot:
        """Materialize snapshot with idempotent recompute semantics (late-data safe)."""
        return await self.materialize_or_recompute(
            source_tenant_id=source_tenant_id,
            detection_scope_id=detection_scope_id,
            entity_type=entity_type,
            entity_id=entity_id,
            window_kind=window_kind,
            cutoff_at=cutoff_at,
            allowed_lateness=allowed_lateness,
        )

    async def _latest_revision_for_key(
        self,
        session: AsyncSession,
        *,
        source_tenant_id: str,
        detection_scope_id: str,
        entity_type: str,
        entity_id: str,
        window_kind: FeatureWindowKind,
        window_end: datetime,
        cutoff_at: datetime,
    ) -> orm.FeatureSnapshot | None:
        return await session.scalar(
            select(orm.FeatureSnapshot)
            .where(
                and_(
                    orm.FeatureSnapshot.source_tenant_id == source_tenant_id,
                    orm.FeatureSnapshot.detection_scope_id == detection_scope_id,
                    orm.FeatureSnapshot.entity_type == entity_type,
                    orm.FeatureSnapshot.entity_id == entity_id,
                    orm.FeatureSnapshot.window_kind == window_kind.value,
                    orm.FeatureSnapshot.window_end == ensure_utc(window_end),
                    orm.FeatureSnapshot.cutoff_at == ensure_utc(cutoff_at),
                )
            )
            .order_by(orm.FeatureSnapshot.revision.desc())
            .limit(1)
        )

    async def materialize_or_recompute(
        self,
        *,
        source_tenant_id: str,
        detection_scope_id: str,
        entity_type: str,
        entity_id: str,
        window_kind: FeatureWindowKind,
        cutoff_at: datetime,
        allowed_lateness: timedelta = DEFAULT_ALLOWED_LATENESS,
    ) -> FeatureSnapshot:
        """Idempotent materialization; late data within allowed lateness bumps revision."""
        window_start, window_end = compute_window_bounds(
            cutoff_at=cutoff_at,
            window_kind=window_kind,
        )
        upper = effective_observation_upper_bound(
            window_end=window_end,
            cutoff_at=cutoff_at,
            allowed_lateness=allowed_lateness,
        )
        async with self._session_factory() as session:
            async with session.begin():
                await session.execute(
                    text("SELECT pg_advisory_xact_lock(:lock_key)"),
                    {
                        "lock_key": _materialization_advisory_lock_key(
                            source_tenant_id=source_tenant_id,
                            detection_scope_id=detection_scope_id,
                            entity_type=entity_type,
                            entity_id=entity_id,
                            window_kind=window_kind,
                            window_end=window_end,
                            cutoff_at=cutoff_at,
                        ),
                    },
                )
                prior = await self._latest_revision_for_key(
                    session,
                    source_tenant_id=source_tenant_id,
                    detection_scope_id=detection_scope_id,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    window_kind=window_kind,
                    window_end=window_end,
                    cutoff_at=cutoff_at,
                )
                observations = await self._resolver.load_observations_for_window(
                    session,
                    source_tenant_id=source_tenant_id,
                    detection_scope_id=detection_scope_id,
                    window_start=window_start,
                    upper_bound=upper,
                )
                revision = 1
                supersedes: str | None = None
                if prior is not None:
                    candidate = build_feature_snapshot(
                        source_tenant_id=source_tenant_id,
                        detection_scope_id=detection_scope_id,
                        entity_type=entity_type,
                        entity_id=entity_id,
                        window_kind=window_kind,
                        cutoff_at=cutoff_at,
                        observations=observations,
                        revision=int(prior.revision),
                        allowed_lateness=allowed_lateness,
                    )
                    if candidate.content_hash == prior.content_hash:
                        return row_to_feature_snapshot(prior)
                    revision = int(prior.revision) + 1
                    supersedes = prior.snapshot_id

                snapshot = build_feature_snapshot(
                    source_tenant_id=source_tenant_id,
                    detection_scope_id=detection_scope_id,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    window_kind=window_kind,
                    cutoff_at=cutoff_at,
                    observations=observations,
                    revision=revision,
                    supersedes_snapshot_id=supersedes,
                    allowed_lateness=allowed_lateness,
                )
                return await self.persist_in_session(session, snapshot)

    async def get_snapshot(
        self,
        *,
        source_tenant_id: str,
        snapshot_id: str,
    ) -> FeatureSnapshot | None:
        async with self._session_factory() as session:
            row = await session.get(orm.FeatureSnapshot, snapshot_id)
            if row is None or row.source_tenant_id != source_tenant_id:
                return None
            return row_to_feature_snapshot(row)

    async def query_snapshots(self, query: FeatureSnapshotQuery) -> FeatureSnapshotListResult:
        filters = [orm.FeatureSnapshot.source_tenant_id == query.source_tenant_id]
        if query.detection_scope_id is not None:
            filters.append(orm.FeatureSnapshot.detection_scope_id == query.detection_scope_id)
        if query.entity_type is not None:
            filters.append(orm.FeatureSnapshot.entity_type == query.entity_type)
        if query.entity_id is not None:
            filters.append(orm.FeatureSnapshot.entity_id == query.entity_id)
        if query.window_kind is not None:
            filters.append(orm.FeatureSnapshot.window_kind == query.window_kind.value)

        async with self._session_factory() as session:
            total = await session.scalar(
                select(func.count()).select_from(orm.FeatureSnapshot).where(and_(*filters))
            )
            offset = (query.page - 1) * query.page_size
            rows = list(
                await session.scalars(
                    select(orm.FeatureSnapshot)
                    .where(and_(*filters))
                    .order_by(
                        orm.FeatureSnapshot.cutoff_at.desc(),
                        orm.FeatureSnapshot.revision.desc(),
                    )
                    .offset(offset)
                    .limit(query.page_size)
                )
            )
        return FeatureSnapshotListResult(
            total=int(total or 0),
            page=query.page,
            page_size=query.page_size,
            items=[row_to_feature_snapshot(row) for row in rows],
        )

    async def get_by_cache_key(
        self,
        *,
        source_tenant_id: str,
        cache_key: str,
    ) -> FeatureSnapshot | None:
        async with self._session_factory() as session:
            row = await session.scalar(
                select(orm.FeatureSnapshot)
                .where(
                    and_(
                        orm.FeatureSnapshot.source_tenant_id == source_tenant_id,
                        orm.FeatureSnapshot.cache_key == cache_key,
                    )
                )
                .limit(1)
            )
            return row_to_feature_snapshot(row) if row is not None else None
