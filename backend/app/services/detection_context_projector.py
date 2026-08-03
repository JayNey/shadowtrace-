"""Trusted detection context projector (ISSUE-127 / #633)."""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ResourceNotFoundError, ValidationError
from app.db import models as orm
from app.db.orm.detection_context_snapshot import DetectionContextSnapshotORM
from app.db.orm.detection_promotion import DetectionPromotionORM
from app.models.detection_context_snapshot import (
    DetectionContextSnapshot,
    DetectionContextSnapshotRef,
)
from app.models.detection_promotion import DetectionPromotionStatus
from app.models.detection_rule import DetectionRuleDefinition
from app.models.feature_snapshot import FeatureSnapshot
from app.services.context_service import append_context_journal_in_session
from app.services.detection_context_resolver import (
    DetectionContextResolver,
    build_detection_context_snapshot,
)
from app.services.detection_context_service import DetectionContextService
from app.services.detection_governance_service import DetectionGovernanceService
from app.services.detection_rule_runtime import row_to_candidate_detection
from app.services.detection_rule_service import (
    DetectionRuleService,
    row_to_detection_rule_package,
)
from app.services.feature_snapshot_resolver import row_to_feature_snapshot

logger = logging.getLogger(__name__)

WRITER_ID = "DetectionContextProjector"


def _promotion_record_from_row(row: DetectionPromotionORM):
    from app.services.detection_promotion_service import _row_to_record

    return _row_to_record(row)


class DetectionContextProjector:
    """Single writer: completed promotion → immutable DetectionContextSnapshot."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        snapshot_service: DetectionContextService | None = None,
        governance: DetectionGovernanceService | None = None,
        rule_service: DetectionRuleService | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._snapshots = snapshot_service or DetectionContextService(session_factory)
        self._governance = governance or DetectionGovernanceService(session_factory)
        self._rules = rule_service or DetectionRuleService(session_factory)

    async def project_from_promotion(
        self,
        promotion_id: str,
        *,
        tenant_id: str,
    ) -> DetectionContextSnapshot | None:
        async with self._session_factory() as session:
            async with session.begin():
                return await self._project_in_session(
                    session,
                    promotion_id=promotion_id,
                    tenant_id=tenant_id,
                )

    async def _project_in_session(
        self,
        session: AsyncSession,
        *,
        promotion_id: str,
        tenant_id: str,
    ) -> DetectionContextSnapshot | None:
        row = await session.get(DetectionPromotionORM, promotion_id)
        if row is None:
            raise ResourceNotFoundError(
                "detection promotion not found",
                details={"promotion_id": promotion_id},
            )
        promotion = _promotion_record_from_row(row)
        if promotion.tenant_id != tenant_id:
            raise ValidationError(
                "detection context projection blocked: tenant mismatch",
                details={"promotion_id": promotion_id, "tenant_id": tenant_id},
            )
        if promotion.status is not DetectionPromotionStatus.COMPLETED:
            logger.info(
                "skip detection context projection: promotion not completed "
                "promotion_id=%s status=%s",
                promotion_id,
                promotion.status.value,
            )
            return None
        if promotion.event_id is None:
            logger.info(
                "skip detection context projection: promotion not event-linked promotion_id=%s",
                promotion_id,
            )
            return None

        decision = await self._governance.get_decision(
            promotion.decision_id,
            tenant_id=tenant_id,
        )
        active = await self._governance.resolve_active_approval(
            tenant_id=tenant_id,
            binding_hash=decision.binding_hash,
        )
        if active is None or active.decision_id != promotion.decision_id:
            raise ValidationError(
                "detection context projection blocked: governance approval not active",
                details={
                    "decision_id": promotion.decision_id,
                    "reason": "governance_approval_not_active",
                },
            )

        candidate_row = await session.scalar(
            select(orm.CandidateDetection).where(
                orm.CandidateDetection.candidate_detection_id == promotion.candidate_detection_id,
                orm.CandidateDetection.source_tenant_id == tenant_id,
            )
        )
        if candidate_row is None:
            raise ValidationError(
                "detection context projection blocked: candidate not found",
                details={"candidate_detection_id": promotion.candidate_detection_id},
            )
        candidate = row_to_candidate_detection(candidate_row)
        if candidate.content_hash != promotion.candidate_content_hash:
            raise ValidationError(
                "detection context projection blocked: candidate hash mismatch",
                details={
                    "candidate_detection_id": promotion.candidate_detection_id,
                    "reason": "candidate_content_hash_mismatch",
                },
            )
        refs = decision.candidate_binding.candidate_refs
        if refs.package_content_hash != promotion.package_content_hash:
            raise ValidationError(
                "detection context projection blocked: package hash mismatch",
                details={"promotion_id": promotion_id},
            )

        event_row = await session.get(
            orm.SecurityEvent,
            promotion.event_id,
            with_for_update=True,
        )
        if event_row is None:
            raise ValidationError(
                "detection context projection blocked: event not found",
                details={"event_id": promotion.event_id},
            )
        current_revision = int(event_row.row_version or 1)
        ingest = promotion.ingest_result
        if ingest is not None and ingest.event_revision is not None:
            if ingest.event_revision > current_revision:
                raise ValidationError(
                    "detection context projection blocked: stale event revision",
                    details={
                        "event_id": promotion.event_id,
                        "ingest_event_revision": ingest.event_revision,
                        "current_event_revision": current_revision,
                    },
                )
            event_revision = ingest.event_revision
        else:
            event_revision = current_revision

        package_row = await session.scalar(
            select(orm.DetectionRulePackage).where(
                orm.DetectionRulePackage.package_id == promotion.package_id,
                orm.DetectionRulePackage.source_tenant_id == tenant_id,
            )
        )
        rule: DetectionRuleDefinition | None = None
        if package_row is not None:
            package = row_to_detection_rule_package(package_row)
            for item in package.rules:
                if (
                    item.rule_id == candidate.rule_id
                    and item.rule_version == candidate.rule_version
                ):
                    rule = item
                    break

        feature_snapshots, projection_errors = await self._load_feature_snapshots(
            session,
            tenant_id=tenant_id,
            snapshot_ids=list(candidate.provenance.snapshot_ids or []),
        )

        revision, supersedes = await self._snapshots.next_revision(
            session,
            tenant_id=tenant_id,
            event_id=promotion.event_id,
        )
        snapshot = build_detection_context_snapshot(
            promotion=promotion,
            candidate=candidate,
            decision=decision,
            event_revision=event_revision,
            rule=rule,
            feature_snapshots=feature_snapshots,
            revision=revision,
            supersedes_snapshot_id=supersedes,
            projection_errors=projection_errors,
        )

        existing = await session.scalar(
            select(DetectionContextSnapshotORM).where(
                DetectionContextSnapshotORM.idempotency_key == snapshot.idempotency_key
            )
        )
        if existing is not None:
            stored = DetectionContextSnapshot.model_validate(existing.body)
            await self._write_context_ref(session, promotion.event_id, stored)
            return stored.model_copy(update={"created_at": existing.created_at})

        persisted = await self._snapshots.persist_in_session(session, snapshot)
        await self._write_context_ref(session, promotion.event_id, persisted)
        return persisted

    async def _load_feature_snapshots(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        snapshot_ids: list[str],
    ) -> tuple[list[FeatureSnapshot], list[str]]:
        if not snapshot_ids:
            return [], []
        rows = list(
            await session.scalars(
                select(orm.FeatureSnapshot).where(
                    orm.FeatureSnapshot.snapshot_id.in_(snapshot_ids),
                    orm.FeatureSnapshot.source_tenant_id == tenant_id,
                )
            )
        )
        by_id = {row.snapshot_id: row_to_feature_snapshot(row) for row in rows}
        missing = [sid for sid in snapshot_ids if sid not in by_id]
        errors = [
            f"missing_feature_snapshot:{snapshot_id}" for snapshot_id in missing
        ]
        snapshots = [by_id[sid] for sid in snapshot_ids if sid in by_id]
        return snapshots, errors

    async def _write_context_ref(
        self,
        session: AsyncSession,
        event_id: str,
        snapshot: DetectionContextSnapshot,
    ) -> None:
        ref = DetectionContextResolver.snapshot_to_context_ref(snapshot)
        await append_context_journal_in_session(
            session,
            event_id,
            "detection_context_snapshot",
            ref.model_dump(mode="json"),
        )

    async def get_latest_ref_for_event(
        self,
        *,
        tenant_id: str,
        event_id: str,
    ) -> DetectionContextSnapshotRef | None:
        from app.models.detection_context_snapshot import DetectionContextSnapshotQuery

        result = await self._snapshots.query_snapshots(
            DetectionContextSnapshotQuery(
                tenant_id=tenant_id,
                event_id=event_id,
                latest_only=True,
            )
        )
        if not result.items:
            return None
        return DetectionContextResolver.snapshot_to_context_ref(result.items[0])


__all__ = ["DetectionContextProjector", "WRITER_ID"]
