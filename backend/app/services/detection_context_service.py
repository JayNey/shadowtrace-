"""Detection context snapshot persistence (ISSUE-127 / #633)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import and_, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ValidationError
from app.db.orm.detection_context_snapshot import DetectionContextSnapshotORM
from app.models.detection_context_snapshot import (
    DetectionContextSnapshot,
    DetectionContextSnapshotListResult,
    DetectionContextSnapshotQuery,
)

logger = logging.getLogger(__name__)


def row_to_detection_context_snapshot(row: DetectionContextSnapshotORM) -> DetectionContextSnapshot:
    body = DetectionContextSnapshot.model_validate(row.body)
    if body.snapshot_id != row.snapshot_id:
        raise ValidationError(
            "detection context snapshot body id mismatch",
            details={"snapshot_id": row.snapshot_id, "body_snapshot_id": body.snapshot_id},
        )
    return body.model_copy(
        update={
            "created_at": row.created_at,
        }
    )


class DetectionContextService:
    """Append-only detection context snapshot store — single writer via projector."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def persist_in_session(
        self,
        session: AsyncSession,
        snapshot: DetectionContextSnapshot,
    ) -> DetectionContextSnapshot:
        existing = await session.scalar(
            select(DetectionContextSnapshotORM).where(
                DetectionContextSnapshotORM.idempotency_key == snapshot.idempotency_key
            )
        )
        if existing is not None:
            stored = row_to_detection_context_snapshot(existing)
            if stored.content_hash != snapshot.content_hash:
                raise ValidationError(
                    "detection context snapshot idempotency replay with different content hash",
                    details={"idempotency_key": snapshot.idempotency_key},
                )
            return stored

        created_at = snapshot.created_at or datetime.now(UTC)
        payload = snapshot.model_copy(update={"created_at": created_at})
        row = DetectionContextSnapshotORM(
            snapshot_id=payload.snapshot_id,
            tenant_id=payload.tenant_id,
            event_id=payload.event_id,
            event_revision=payload.event_revision,
            promotion_id=payload.promotion_id,
            promotion_link_revision=payload.promotion_link_revision,
            promotion_key=payload.promotion_key,
            revision=payload.revision,
            supersedes_snapshot_id=payload.supersedes_snapshot_id,
            content_hash=payload.content_hash,
            idempotency_key=payload.idempotency_key,
            schema_version=payload.schema_version,
            body=payload.model_dump(mode="json"),
            created_at=created_at,
        )
        try:
            async with session.begin_nested():
                session.add(row)
                await session.flush()
        except IntegrityError:
            existing = await session.scalar(
                select(DetectionContextSnapshotORM).where(
                    DetectionContextSnapshotORM.idempotency_key == snapshot.idempotency_key
                )
            )
            if existing is None:
                raise
            stored = row_to_detection_context_snapshot(existing)
            if stored.content_hash != snapshot.content_hash:
                raise ValidationError(
                    "detection context snapshot idempotency replay with different content hash",
                    details={"idempotency_key": snapshot.idempotency_key},
                ) from None
            return stored
        return payload

    async def get_snapshot(
        self,
        snapshot_id: str,
        *,
        tenant_id: str | None = None,
    ) -> DetectionContextSnapshot | None:
        async with self._session_factory() as session:
            row = await session.get(DetectionContextSnapshotORM, snapshot_id)
            if row is None:
                return None
            if tenant_id is not None and row.tenant_id != tenant_id:
                return None
            return row_to_detection_context_snapshot(row)

    async def query_snapshots(
        self,
        query: DetectionContextSnapshotQuery,
    ) -> DetectionContextSnapshotListResult:
        filters = [DetectionContextSnapshotORM.tenant_id == query.tenant_id]
        if query.event_id is not None:
            filters.append(DetectionContextSnapshotORM.event_id == query.event_id)
        if query.promotion_id is not None:
            filters.append(DetectionContextSnapshotORM.promotion_id == query.promotion_id)
        if query.revision is not None:
            filters.append(DetectionContextSnapshotORM.revision == query.revision)

        async with self._session_factory() as session:
            if query.latest_only and query.event_id is not None and query.revision is None:
                row = await session.scalar(
                    select(DetectionContextSnapshotORM)
                    .where(and_(*filters))
                    .order_by(DetectionContextSnapshotORM.revision.desc())
                    .limit(1)
                )
                items = [row_to_detection_context_snapshot(row)] if row is not None else []
                return DetectionContextSnapshotListResult(total=len(items), items=items)

            total = await session.scalar(
                select(func.count())
                .select_from(DetectionContextSnapshotORM)
                .where(and_(*filters))
            )
            rows = list(
                await session.scalars(
                    select(DetectionContextSnapshotORM)
                    .where(and_(*filters))
                    .order_by(
                        DetectionContextSnapshotORM.revision.desc(),
                        DetectionContextSnapshotORM.created_at.desc(),
                    )
                )
            )
        return DetectionContextSnapshotListResult(
            total=int(total or 0),
            items=[row_to_detection_context_snapshot(row) for row in rows],
        )

    async def next_revision(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        event_id: str,
    ) -> tuple[int, str | None]:
        row = await session.scalar(
            select(DetectionContextSnapshotORM)
            .where(
                DetectionContextSnapshotORM.tenant_id == tenant_id,
                DetectionContextSnapshotORM.event_id == event_id,
            )
            .order_by(DetectionContextSnapshotORM.revision.desc())
            .limit(1)
        )
        if row is None:
            return 1, None
        return int(row.revision) + 1, row.snapshot_id


__all__ = [
    "DetectionContextService",
    "row_to_detection_context_snapshot",
]
