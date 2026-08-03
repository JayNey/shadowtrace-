"""Policy release persistence — staged JSON import and CAS activation (ISSUE-129 / #635)."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import and_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.errors import ResourceNotFoundError, ValidationError
from app.db import models as orm
from app.models.attack_control_mapping import AttackControlMapping, MappingApprovalState
from app.models.knowledge_release import (
    KnowledgeImportStatus,
    KnowledgeRelease,
    KnowledgeReleaseLifecycleState,
    KnowledgeReleaseProvenance,
)
from app.models.policy_release import (
    POLICY_CORPUS_ID,
    POLICY_RELEASE_SCHEMA_VERSION,
    POLICY_SOURCE_ID,
    PolicyControl,
    PolicyControlRef,
)
from app.services.knowledge_release_resolver import (
    build_knowledge_release,
    corpus_advisory_lock_key,
)
from app.services.knowledge_release_service import KnowledgeReleaseService
from app.services.policy_release_resolver import (
    build_policy_idempotency_key,
    build_policy_release_id,
    compute_policy_control_hash,
    validate_policy_bundle,
)

logger = logging.getLogger(__name__)


def _row_to_release(row: orm.KnowledgeReleaseORM) -> KnowledgeRelease:
    return KnowledgeRelease(
        release_id=row.release_id,
        corpus_id=row.corpus_id,
        source_id=row.source_id,
        release_version=row.release_version,
        content_hash=row.content_hash,
        provenance=KnowledgeReleaseProvenance.model_validate(row.provenance),
        schema_version=row.schema_version,
        import_status=KnowledgeImportStatus(row.import_status),
        lifecycle_state=KnowledgeReleaseLifecycleState(row.lifecycle_state),
        revision=int(row.revision),
        supersedes_release_id=row.supersedes_release_id,
        object_count=int(row.object_count),
        relationship_count=int(row.relationship_count),
        vector_ready=bool(row.vector_ready),
        embedding_release_id=row.embedding_release_id,
        idempotency_key=row.idempotency_key,
        activated_at=row.activated_at,
        retired_at=row.retired_at,
        created_at=row.created_at,
        failure_reason=row.failure_reason,
    )


class PolicyReleaseService:
    """Offline policy/control bundle registry with staged import and atomic activation."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        settings: Settings | None = None,
        knowledge_release_service: KnowledgeReleaseService | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._settings = settings
        self._knowledge_release_service = knowledge_release_service or KnowledgeReleaseService(
            session_factory,
            settings=settings,
        )

    async def get_release(self, release_id: str) -> KnowledgeRelease | None:
        release = await self._knowledge_release_service.get_release(release_id)
        if release is None or release.corpus_id != POLICY_CORPUS_ID:
            return None
        return release

    async def get_active_release(self) -> KnowledgeRelease | None:
        return await self._knowledge_release_service.get_active_release(POLICY_CORPUS_ID)

    async def stage_policy_bundle(
        self,
        bundle: dict[str, Any],
        *,
        release_version: str,
        provenance: KnowledgeReleaseProvenance,
        supersedes_release_id: str | None = None,
        revision: int = 1,
    ) -> KnowledgeRelease:
        validation = validate_policy_bundle(bundle)
        if not validation.ok:
            raise ValidationError(
                "invalid policy bundle",
                details={"errors": list(validation.errors)},
            )

        idempotency_key = build_policy_idempotency_key(
            content_hash=validation.content_hash,
            release_version=release_version,
        )
        async with self._session_factory() as session:
            async with session.begin():
                existing = await session.scalar(
                    select(orm.KnowledgeReleaseORM)
                    .where(orm.KnowledgeReleaseORM.idempotency_key == idempotency_key)
                    .limit(1)
                )
                if existing is not None:
                    await session.refresh(existing)
                    return _row_to_release(existing)

                release = build_knowledge_release(
                    corpus_id=POLICY_CORPUS_ID,
                    source_id=POLICY_SOURCE_ID,
                    release_version=release_version,
                    content_hash=validation.content_hash,
                    provenance=provenance,
                    object_count=validation.object_count,
                    relationship_count=validation.mapping_count,
                    revision=revision,
                    supersedes_release_id=supersedes_release_id,
                    lifecycle_state=KnowledgeReleaseLifecycleState.STAGED,
                    import_status=KnowledgeImportStatus.VALIDATED,
                    vector_ready=False,
                    release_id=build_policy_release_id(
                        validation.content_hash,
                        release_version,
                    ),
                    idempotency_key=idempotency_key,
                )
                row = orm.KnowledgeReleaseORM(
                    release_id=release.release_id,
                    corpus_id=release.corpus_id,
                    source_id=release.source_id,
                    release_version=release.release_version,
                    content_hash=release.content_hash,
                    provenance=release.provenance.model_dump(mode="json"),
                    schema_version=POLICY_RELEASE_SCHEMA_VERSION,
                    import_status=KnowledgeImportStatus.VALIDATED.value,
                    lifecycle_state=KnowledgeReleaseLifecycleState.STAGED.value,
                    revision=release.revision,
                    supersedes_release_id=supersedes_release_id,
                    object_count=release.object_count,
                    relationship_count=validation.mapping_count,
                    vector_ready=False,
                    embedding_release_id=None,
                    idempotency_key=release.idempotency_key,
                )
                session.add(row)
                await session.flush()
                for control in validation.controls:
                    object_hash = compute_policy_control_hash(control)
                    session.add(
                        orm.PolicyReleaseObjectORM(
                            object_row_id=f"pctl-{uuid.uuid4().hex[:16]}",
                            release_id=release.release_id,
                            control_id=control.control_id,
                            framework_id=control.framework_id,
                            object_hash=object_hash,
                            payload=control.model_dump(mode="json"),
                        )
                    )
                for mapping in validation.mappings:
                    session.add(
                        orm.AttackControlMappingORM(
                            mapping_row_id=f"acmap-{uuid.uuid4().hex[:16]}",
                            release_id=release.release_id,
                            mapping_id=mapping.mapping_id,
                            technique_id=mapping.technique_id,
                            control_id=mapping.control_id,
                            framework_id=mapping.framework_id,
                            approval_state=mapping.approval_state.value,
                            mapping_version=mapping.mapping_version,
                            provenance=mapping.provenance,
                        )
                    )
                try:
                    await session.flush()
                except IntegrityError:
                    async with self._session_factory() as replay_session:
                        existing_after = await replay_session.scalar(
                            select(orm.KnowledgeReleaseORM)
                            .where(orm.KnowledgeReleaseORM.idempotency_key == idempotency_key)
                            .limit(1)
                        )
                        if existing_after is not None:
                            return _row_to_release(existing_after)
                    raise
                await session.refresh(row)
                return _row_to_release(row)

    async def activate_release(self, release_id: str) -> KnowledgeRelease:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(
                    orm.KnowledgeReleaseORM,
                    release_id,
                    with_for_update=True,
                )
                if row is None or row.corpus_id != POLICY_CORPUS_ID:
                    raise ResourceNotFoundError(
                        "policy release not found",
                        details={"release_id": release_id},
                    )
                if row.lifecycle_state == KnowledgeReleaseLifecycleState.FAILED.value:
                    raise ValidationError(
                        "cannot activate a failed policy release",
                        details={"release_id": release_id},
                    )
                if row.lifecycle_state == KnowledgeReleaseLifecycleState.RETIRED.value:
                    raise ValidationError(
                        "cannot activate a retired policy release",
                        details={"release_id": release_id},
                    )
                if row.import_status != KnowledgeImportStatus.VALIDATED.value:
                    raise ValidationError(
                        "policy release import is not validated",
                        details={"release_id": release_id},
                    )
                if row.lifecycle_state == KnowledgeReleaseLifecycleState.ACTIVE.value:
                    await session.refresh(row)
                    return _row_to_release(row)

                await session.execute(
                    text("SELECT pg_advisory_xact_lock(:lock_key)"),
                    {"lock_key": corpus_advisory_lock_key(row.corpus_id)},
                )
                active_rows = await session.scalars(
                    select(orm.KnowledgeReleaseORM)
                    .where(
                        and_(
                            orm.KnowledgeReleaseORM.corpus_id == POLICY_CORPUS_ID,
                            orm.KnowledgeReleaseORM.lifecycle_state
                            == KnowledgeReleaseLifecycleState.ACTIVE.value,
                            orm.KnowledgeReleaseORM.release_id != release_id,
                        )
                    )
                    .with_for_update()
                )
                for active in active_rows:
                    active.lifecycle_state = KnowledgeReleaseLifecycleState.RETIRED.value
                    active.retired_at = now

                row.lifecycle_state = KnowledgeReleaseLifecycleState.ACTIVE.value
                row.activated_at = now
                row.retired_at = None
                await session.flush()
                await session.refresh(row)
                return _row_to_release(row)

    async def resolve_control_ref(
        self,
        ref: PolicyControlRef,
        *,
        allow_retired: bool = True,
    ) -> tuple[PolicyControl, KnowledgeRelease]:
        if ref.corpus_id != POLICY_CORPUS_ID:
            raise ValidationError(
                "policy ref corpus mismatch",
                details={"expected": POLICY_CORPUS_ID, "actual": ref.corpus_id},
            )
        release = await self.get_release(ref.release_id)
        if release is None:
            raise ValidationError(
                "policy release not found",
                details={"release_id": ref.release_id, "reason": "release_missing"},
            )
        if ref.bundle_content_hash != release.content_hash:
            raise ValidationError(
                "policy bundle hash mismatch",
                details={"release_id": ref.release_id, "reason": "bundle_hash_mismatch"},
            )
        if ref.release_version != release.release_version:
            raise ValidationError(
                "policy release version mismatch",
                details={"release_id": ref.release_id, "reason": "release_version_mismatch"},
            )
        if release.lifecycle_state is KnowledgeReleaseLifecycleState.FAILED:
            raise ValidationError(
                "policy release failed",
                details={"release_id": ref.release_id, "reason": "release_failed"},
            )
        if not allow_retired and release.lifecycle_state is KnowledgeReleaseLifecycleState.RETIRED:
            raise ValidationError(
                "policy release retired",
                details={"release_id": ref.release_id, "reason": "release_retired"},
            )

        async with self._session_factory() as session:
            obj = await session.scalar(
                select(orm.PolicyReleaseObjectORM).where(
                    and_(
                        orm.PolicyReleaseObjectORM.release_id == ref.release_id,
                        orm.PolicyReleaseObjectORM.control_id == ref.control_id,
                    )
                )
            )
        if obj is None:
            raise ValidationError(
                "policy control not found in release",
                details={
                    "release_id": ref.release_id,
                    "control_id": ref.control_id,
                    "reason": "control_missing",
                },
            )
        if ref.content_hash != obj.object_hash:
            raise ValidationError(
                "policy control content hash mismatch",
                details={"control_id": ref.control_id, "reason": "content_hash_mismatch"},
            )
        control = PolicyControl.model_validate(obj.payload)
        if ref.framework_id != control.framework_id:
            raise ValidationError(
                "policy control framework mismatch",
                details={
                    "control_id": ref.control_id,
                    "reason": "framework_id_mismatch",
                },
            )
        if ref.text_locator != control.text_locator:
            raise ValidationError(
                "policy control text locator mismatch",
                details={
                    "control_id": ref.control_id,
                    "reason": "text_locator_mismatch",
                },
            )
        return control, release

    async def list_approved_mappings(
        self,
        release_id: str,
        *,
        technique_id: str | None = None,
    ) -> list[AttackControlMapping]:
        async with self._session_factory() as session:
            query = select(orm.AttackControlMappingORM).where(
                and_(
                    orm.AttackControlMappingORM.release_id == release_id,
                    orm.AttackControlMappingORM.approval_state
                    == MappingApprovalState.APPROVED.value,
                )
            )
            if technique_id is not None:
                query = query.where(
                    orm.AttackControlMappingORM.technique_id == technique_id
                )
            rows = await session.scalars(query)
            return [
                AttackControlMapping(
                    mapping_id=row.mapping_id,
                    release_id=row.release_id,
                    technique_id=row.technique_id,
                    control_id=row.control_id,
                    framework_id=row.framework_id,
                    approval_state=MappingApprovalState(row.approval_state),
                    mapping_version=row.mapping_version,
                    provenance=row.provenance,
                )
                for row in rows
            ]


__all__ = ["PolicyReleaseService"]
