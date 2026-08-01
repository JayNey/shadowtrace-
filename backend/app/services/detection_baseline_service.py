"""DetectionFeatureBaseline persistence (ISSUE-120 Phase A/B / #625)."""

from __future__ import annotations

import logging
from datetime import datetime

from sqlalchemy import and_, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ValidationError
from app.db import models as orm
from app.models.feature_snapshot import (
    DetectionFeatureBaseline,
    DetectionFeatureBaselineListResult,
    DetectionFeatureBaselineQuery,
    FeatureWindowKind,
)
from app.services.feature_snapshot_resolver import (
    build_detection_feature_baseline,
    ensure_utc,
    row_to_detection_baseline,
    row_to_feature_snapshot,
)

logger = logging.getLogger(__name__)


class DetectionBaselineService:
    """Build rolling baselines from historical snapshots — cutoff-safe, no leakage."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def persist_in_session(
        self,
        session: AsyncSession,
        baseline: DetectionFeatureBaseline,
    ) -> DetectionFeatureBaseline:
        existing = await session.scalar(
            select(orm.DetectionFeatureBaseline).where(
                orm.DetectionFeatureBaseline.idempotency_key == baseline.idempotency_key
            )
        )
        if existing is not None:
            if existing.content_hash != baseline.content_hash:
                raise ValidationError(
                    "detection baseline idempotency replay with different content hash",
                    details={"idempotency_key": baseline.idempotency_key},
                )
            return row_to_detection_baseline(existing)

        row = orm.DetectionFeatureBaseline(
            baseline_id=baseline.baseline_id,
            source_tenant_id=baseline.source_tenant_id,
            detection_scope_id=baseline.detection_scope_id,
            entity_type=baseline.entity_type,
            entity_id=baseline.entity_id,
            peer_group_id=baseline.peer_group_id,
            feature_contract_version=baseline.feature_contract_version,
            window_kind=baseline.window_kind.value,
            cutoff_at=baseline.cutoff_at,
            status=baseline.status.value,
            stats=baseline.stats,
            seasonality_profile=(
                baseline.seasonality_profile.model_dump(mode="json")
                if baseline.seasonality_profile is not None
                else None
            ),
            snapshot_revision_refs=baseline.snapshot_revision_refs,
            revision=baseline.revision,
            supersedes_baseline_id=baseline.supersedes_baseline_id,
            content_hash=baseline.content_hash,
            cache_key=baseline.cache_key,
            idempotency_key=baseline.idempotency_key,
            schema_version=baseline.schema_version,
        )
        try:
            async with session.begin_nested():
                session.add(row)
                await session.flush()
        except IntegrityError:
            existing = await session.scalar(
                select(orm.DetectionFeatureBaseline).where(
                    orm.DetectionFeatureBaseline.idempotency_key == baseline.idempotency_key
                )
            )
            if existing is None:
                raise
            if existing.content_hash != baseline.content_hash:
                raise ValidationError(
                    "detection baseline idempotency replay with different content hash",
                    details={"idempotency_key": baseline.idempotency_key},
                ) from None
            return row_to_detection_baseline(existing)
        return row_to_detection_baseline(row)

    async def _load_snapshots_for_baseline(
        self,
        session: AsyncSession,
        *,
        source_tenant_id: str,
        detection_scope_id: str,
        entity_type: str,
        entity_id: str,
        window_kind: FeatureWindowKind,
        cutoff_at: datetime,
    ) -> list:
        rows = list(
            await session.scalars(
                select(orm.FeatureSnapshot)
                .where(
                    and_(
                        orm.FeatureSnapshot.source_tenant_id == source_tenant_id,
                        orm.FeatureSnapshot.detection_scope_id == detection_scope_id,
                        orm.FeatureSnapshot.entity_type == entity_type,
                        orm.FeatureSnapshot.entity_id == entity_id,
                        orm.FeatureSnapshot.window_kind == window_kind.value,
                        orm.FeatureSnapshot.cutoff_at <= ensure_utc(cutoff_at),
                    )
                )
                .order_by(orm.FeatureSnapshot.cutoff_at.asc(), orm.FeatureSnapshot.revision.asc())
            )
        )
        return [row_to_feature_snapshot(row) for row in rows]

    async def _latest_baseline_revision(
        self,
        session: AsyncSession,
        *,
        source_tenant_id: str,
        detection_scope_id: str,
        entity_type: str,
        entity_id: str,
        window_kind: FeatureWindowKind,
        cutoff_at: datetime,
    ) -> orm.DetectionFeatureBaseline | None:
        return await session.scalar(
            select(orm.DetectionFeatureBaseline)
            .where(
                and_(
                    orm.DetectionFeatureBaseline.source_tenant_id == source_tenant_id,
                    orm.DetectionFeatureBaseline.detection_scope_id == detection_scope_id,
                    orm.DetectionFeatureBaseline.entity_type == entity_type,
                    orm.DetectionFeatureBaseline.entity_id == entity_id,
                    orm.DetectionFeatureBaseline.window_kind == window_kind.value,
                    orm.DetectionFeatureBaseline.cutoff_at == ensure_utc(cutoff_at),
                )
            )
            .order_by(orm.DetectionFeatureBaseline.revision.desc())
            .limit(1)
        )

    async def materialize_baseline(
        self,
        *,
        source_tenant_id: str,
        detection_scope_id: str,
        entity_type: str,
        entity_id: str,
        window_kind: FeatureWindowKind,
        cutoff_at: datetime,
    ) -> DetectionFeatureBaseline:
        async with self._session_factory() as session:
            async with session.begin():
                snapshots = await self._load_snapshots_for_baseline(
                    session,
                    source_tenant_id=source_tenant_id,
                    detection_scope_id=detection_scope_id,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    window_kind=window_kind,
                    cutoff_at=cutoff_at,
                )
                prior = await self._latest_baseline_revision(
                    session,
                    source_tenant_id=source_tenant_id,
                    detection_scope_id=detection_scope_id,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    window_kind=window_kind,
                    cutoff_at=cutoff_at,
                )
                revision = 1
                supersedes: str | None = None
                if prior is not None:
                    candidate = build_detection_feature_baseline(
                        source_tenant_id=source_tenant_id,
                        detection_scope_id=detection_scope_id,
                        entity_type=entity_type,
                        entity_id=entity_id,
                        window_kind=window_kind,
                        cutoff_at=cutoff_at,
                        snapshots=snapshots,
                        revision=int(prior.revision),
                    )
                    if candidate.content_hash == prior.content_hash:
                        return row_to_detection_baseline(prior)
                    revision = int(prior.revision) + 1
                    supersedes = prior.baseline_id

                baseline = build_detection_feature_baseline(
                    source_tenant_id=source_tenant_id,
                    detection_scope_id=detection_scope_id,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    window_kind=window_kind,
                    cutoff_at=cutoff_at,
                    snapshots=snapshots,
                    revision=revision,
                    supersedes_baseline_id=supersedes,
                )
                return await self.persist_in_session(session, baseline)

    async def get_baseline(
        self,
        *,
        source_tenant_id: str,
        baseline_id: str,
    ) -> DetectionFeatureBaseline | None:
        async with self._session_factory() as session:
            row = await session.get(orm.DetectionFeatureBaseline, baseline_id)
            if row is None or row.source_tenant_id != source_tenant_id:
                return None
            return row_to_detection_baseline(row)

    async def query_baselines(
        self,
        query: DetectionFeatureBaselineQuery,
    ) -> DetectionFeatureBaselineListResult:
        filters = [orm.DetectionFeatureBaseline.source_tenant_id == query.source_tenant_id]
        if query.detection_scope_id is not None:
            filters.append(
                orm.DetectionFeatureBaseline.detection_scope_id == query.detection_scope_id
            )
        if query.entity_type is not None:
            filters.append(orm.DetectionFeatureBaseline.entity_type == query.entity_type)
        if query.entity_id is not None:
            filters.append(orm.DetectionFeatureBaseline.entity_id == query.entity_id)
        if query.peer_group_id is not None:
            filters.append(orm.DetectionFeatureBaseline.peer_group_id == query.peer_group_id)
        if query.window_kind is not None:
            filters.append(orm.DetectionFeatureBaseline.window_kind == query.window_kind.value)

        async with self._session_factory() as session:
            total = await session.scalar(
                select(func.count()).select_from(orm.DetectionFeatureBaseline).where(and_(*filters))
            )
            offset = (query.page - 1) * query.page_size
            rows = list(
                await session.scalars(
                    select(orm.DetectionFeatureBaseline)
                    .where(and_(*filters))
                    .order_by(
                        orm.DetectionFeatureBaseline.cutoff_at.desc(),
                        orm.DetectionFeatureBaseline.revision.desc(),
                    )
                    .offset(offset)
                    .limit(query.page_size)
                )
            )
        return DetectionFeatureBaselineListResult(
            total=int(total or 0),
            page=query.page,
            page_size=query.page_size,
            items=[row_to_detection_baseline(row) for row in rows],
        )
