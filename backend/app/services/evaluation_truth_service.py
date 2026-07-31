"""EvaluationCaseTruth persistence — canonical ground truth (ISSUE-113 Phase A).

Append-only revisions with tenant-scoped read paths. Agent/runtime outputs are
never written here; corrections create new rows rather than updating in place.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import orjson
from pydantic import BaseModel
from sqlalchemy import and_, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ResourceNotFoundError, ValidationError
from app.core.sanitization import redact_sensitive_text
from app.db import models as orm
from app.models.evaluation_truth import (
    EVALUATION_TRUTH_SCHEMA_VERSION,
    EvaluationCaseTruth,
    EvaluationDatasetManifest,
    EvaluationTruthListResult,
    EvaluationTruthQuery,
    LabelProvenance,
    OperationalTruthMapping,
    SliceExpectation,
    SliceType,
    ThreatSliceExpectation,
    TruthObservationRef,
)

logger = logging.getLogger(__name__)

_HASH_EXCLUDE = frozenset(
    {
        "truth_id",
        "truth_hash",
        "idempotency_key",
        "created_at",
    }
)


def _canonical_bytes(value: Any) -> bytes:
    return orjson.dumps(value, option=orjson.OPT_SORT_KEYS)


def compute_truth_hash(payload: dict[str, Any]) -> str:
    canonical = {k: v for k, v in payload.items() if k not in _HASH_EXCLUDE}
    return hashlib.sha256(_canonical_bytes(canonical)).hexdigest()


def compute_content_hash(payload: dict[str, Any]) -> str:
    """Hash adjudicated case content (observations + expectation + provenance)."""
    content_keys = (
        "tenant_id",
        "source_tenant_id",
        "source_product",
        "connector_id",
        "dataset_id",
        "dataset_version",
        "case_id",
        "case_version",
        "observation_refs",
        "slice_expectation",
        "label_provenance",
        "operational_mapping",
        "retention_policy",
        "schema_version",
    )
    canonical = {key: payload[key] for key in content_keys if key in payload}
    return hashlib.sha256(_canonical_bytes(canonical)).hexdigest()


def build_idempotency_key(
    *,
    tenant_id: str,
    dataset_id: str,
    case_id: str,
    revision: int,
) -> str:
    return f"{tenant_id}:{dataset_id}:{case_id}:rev{revision}"


def _sanitize_provenance(provenance: LabelProvenance) -> LabelProvenance:
    return provenance.model_copy(
        update={
            "adjudicator": redact_sensitive_text(provenance.adjudicator)[:128],
            "revision_notes": redact_sensitive_text(provenance.revision_notes)[:512],
        }
    )


def _to_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return dict(value)
    return {}


def _parse_slice_expectation(raw: Any) -> SliceExpectation:
    if isinstance(raw, BaseModel):
        return raw  # type: ignore[return-value]
    if not isinstance(raw, dict):
        raise ValidationError("slice_expectation must be an object")
    slice_type = raw.get("slice_type")
    if slice_type == SliceType.THREAT.value:
        return ThreatSliceExpectation.model_validate(raw)
    if slice_type == SliceType.BENIGN.value:
        from app.models.evaluation_truth import BenignSliceExpectation

        return BenignSliceExpectation.model_validate(raw)
    if slice_type == SliceType.UNEVALUABLE.value:
        from app.models.evaluation_truth import UnevaluableSliceExpectation

        return UnevaluableSliceExpectation.model_validate(raw)
    raise ValidationError(f"unsupported slice_type: {slice_type!r}")


def compute_dataset_manifest_hash(content_hashes: list[str]) -> str:
    """Hash sorted per-case content hashes into a dataset-level manifest hash."""
    return hashlib.sha256(_canonical_bytes(sorted(content_hashes))).hexdigest()


def build_evaluation_case_truth(
    *,
    tenant_id: str,
    dataset_id: str,
    dataset_version: str,
    case_id: str,
    slice_expectation: SliceExpectation,
    label_provenance: LabelProvenance,
    observation_refs: list[TruthObservationRef] | None = None,
    source_tenant_id: str | None = None,
    source_product: str | None = None,
    connector_id: str | None = None,
    case_version: int = 1,
    operational_mapping: OperationalTruthMapping | None = None,
    revision: int = 1,
    supersedes_truth_id: str | None = None,
    correction_reason: str | None = None,
    retention_policy: str = "evaluation_standard",
) -> EvaluationCaseTruth:
    provenance = _sanitize_provenance(label_provenance)
    refs = observation_refs or []
    payload = {
        "tenant_id": tenant_id.strip(),
        "source_tenant_id": source_tenant_id,
        "source_product": source_product,
        "connector_id": connector_id,
        "dataset_id": dataset_id.strip(),
        "dataset_version": dataset_version.strip(),
        "case_id": case_id.strip(),
        "case_version": max(1, case_version),
        "observation_refs": [item.model_dump(mode="json") for item in refs[:100]],
        "slice_expectation": _to_mapping(slice_expectation),
        "label_provenance": provenance.model_dump(mode="json"),
        "operational_mapping": (
            operational_mapping.model_dump(mode="json") if operational_mapping else None
        ),
        "retention_policy": retention_policy,
        "schema_version": EVALUATION_TRUTH_SCHEMA_VERSION,
        "revision": max(1, revision),
        "supersedes_truth_id": supersedes_truth_id,
        "correction_reason": (
            redact_sensitive_text(correction_reason)[:512] if correction_reason else None
        ),
    }
    content_hash = compute_content_hash(payload)
    truth_id = f"truth-{uuid.uuid4().hex[:12]}"
    idempotency_key = build_idempotency_key(
        tenant_id=payload["tenant_id"],
        dataset_id=payload["dataset_id"],
        case_id=payload["case_id"],
        revision=payload["revision"],
    )
    payload.update(
        {
            "truth_id": truth_id,
            "content_hash": content_hash,
            "idempotency_key": idempotency_key,
            "created_at": datetime.now(UTC),
        }
    )
    truth_hash = compute_truth_hash(payload)
    return EvaluationCaseTruth(
        truth_id=truth_id,
        tenant_id=payload["tenant_id"],
        source_tenant_id=payload["source_tenant_id"],
        source_product=payload["source_product"],
        connector_id=payload["connector_id"],
        dataset_id=payload["dataset_id"],
        dataset_version=payload["dataset_version"],
        case_id=payload["case_id"],
        case_version=payload["case_version"],
        content_hash=content_hash,
        observation_refs=refs,
        slice_expectation=_parse_slice_expectation(payload["slice_expectation"]),
        label_provenance=provenance,
        operational_mapping=operational_mapping,
        revision=payload["revision"],
        supersedes_truth_id=payload["supersedes_truth_id"],
        correction_reason=payload["correction_reason"],
        retention_policy=payload["retention_policy"],
        schema_version=payload["schema_version"],
        truth_hash=truth_hash,
        idempotency_key=idempotency_key,
        created_at=payload["created_at"],
    )


def _orm_from_truth(truth: EvaluationCaseTruth) -> orm.EvaluationCaseTruth:
    return orm.EvaluationCaseTruth(
        truth_id=truth.truth_id,
        tenant_id=truth.tenant_id,
        source_tenant_id=truth.source_tenant_id,
        source_product=truth.source_product,
        connector_id=truth.connector_id,
        dataset_id=truth.dataset_id,
        dataset_version=truth.dataset_version,
        case_id=truth.case_id,
        case_version=truth.case_version,
        content_hash=truth.content_hash,
        observation_refs=[item.model_dump(mode="json") for item in truth.observation_refs],
        slice_expectation=_to_mapping(truth.slice_expectation),
        label_provenance=truth.label_provenance.model_dump(mode="json"),
        operational_mapping=(
            truth.operational_mapping.model_dump(mode="json")
            if truth.operational_mapping is not None
            else None
        ),
        revision=truth.revision,
        supersedes_truth_id=truth.supersedes_truth_id,
        correction_reason=truth.correction_reason,
        retention_policy=truth.retention_policy,
        schema_version=truth.schema_version,
        truth_hash=truth.truth_hash,
        idempotency_key=truth.idempotency_key,
        created_at=truth.created_at or datetime.now(UTC),
    )


def _truth_from_orm(row: orm.EvaluationCaseTruth) -> EvaluationCaseTruth:
    mapping = row.operational_mapping if isinstance(row.operational_mapping, dict) else None
    return EvaluationCaseTruth(
        truth_id=row.truth_id,
        tenant_id=row.tenant_id,
        source_tenant_id=row.source_tenant_id,
        source_product=row.source_product,
        connector_id=row.connector_id,
        dataset_id=row.dataset_id,
        dataset_version=row.dataset_version,
        case_id=row.case_id,
        case_version=row.case_version,
        content_hash=row.content_hash,
        observation_refs=[
            TruthObservationRef.model_validate(item)
            for item in (row.observation_refs or [])
            if isinstance(item, dict)
        ],
        slice_expectation=_parse_slice_expectation(row.slice_expectation),
        label_provenance=LabelProvenance.model_validate(row.label_provenance),
        operational_mapping=(
            OperationalTruthMapping.model_validate(mapping) if mapping else None
        ),
        revision=row.revision,
        supersedes_truth_id=row.supersedes_truth_id,
        correction_reason=row.correction_reason,
        retention_policy=row.retention_policy,
        schema_version=row.schema_version,
        truth_hash=row.truth_hash,
        idempotency_key=row.idempotency_key,
        created_at=row.created_at,
    )


class EvaluationTruthService:
    """Append-only canonical truth store with tenant-scoped reads."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def persist_in_session(
        self,
        session: AsyncSession,
        truth: EvaluationCaseTruth,
    ) -> EvaluationCaseTruth:
        existing = await session.scalar(
            select(orm.EvaluationCaseTruth).where(
                orm.EvaluationCaseTruth.idempotency_key == truth.idempotency_key
            )
        )
        if existing is not None:
            if existing.truth_hash != truth.truth_hash:
                logger.warning(
                    "EvaluationCaseTruth idempotency replay hash mismatch key=%s",
                    truth.idempotency_key,
                )
                raise ValidationError(
                    "truth idempotency key replay with different content hash"
                )
            return _truth_from_orm(existing)

        if truth.supersedes_truth_id:
            prior = await session.scalar(
                select(orm.EvaluationCaseTruth).where(
                    orm.EvaluationCaseTruth.truth_id == truth.supersedes_truth_id,
                    orm.EvaluationCaseTruth.tenant_id == truth.tenant_id,
                )
            )
            if prior is None:
                raise ValidationError(
                    f"supersedes_truth_id not found for tenant: {truth.supersedes_truth_id}"
                )
            if prior.revision >= truth.revision:
                raise ValidationError("revision must increase when superseding prior truth")

        row = _orm_from_truth(truth)
        try:
            async with session.begin_nested():
                session.add(row)
                await session.flush()
        except IntegrityError:
            existing = await session.scalar(
                select(orm.EvaluationCaseTruth).where(
                    orm.EvaluationCaseTruth.idempotency_key == truth.idempotency_key
                )
            )
            if existing is None:
                raise
            if existing.truth_hash != truth.truth_hash:
                raise ValidationError(
                    "truth idempotency key replay with different content hash"
                ) from None
            return _truth_from_orm(existing)
        return _truth_from_orm(row)

    async def persist(
        self,
        truth: EvaluationCaseTruth,
        *,
        session: AsyncSession | None = None,
    ) -> EvaluationCaseTruth:
        if session is not None:
            return await self.persist_in_session(session, truth)
        async with self._session_factory() as owned_session:
            async with owned_session.begin():
                return await self.persist_in_session(owned_session, truth)

    async def append_correction(
        self,
        *,
        tenant_id: str,
        supersedes_truth_id: str,
        slice_expectation: SliceExpectation,
        label_provenance: LabelProvenance,
        correction_reason: str,
        observation_refs: list[TruthObservationRef] | None = None,
        operational_mapping: OperationalTruthMapping | None = None,
        session: AsyncSession | None = None,
    ) -> EvaluationCaseTruth:
        if not correction_reason.strip():
            raise ValidationError("correction_reason is required for truth revision")

        async def _run(sess: AsyncSession) -> EvaluationCaseTruth:
            prior = await sess.scalar(
                select(orm.EvaluationCaseTruth).where(
                    orm.EvaluationCaseTruth.truth_id == supersedes_truth_id,
                    orm.EvaluationCaseTruth.tenant_id == tenant_id,
                )
            )
            if prior is None:
                raise ResourceNotFoundError(f"truth not found: {supersedes_truth_id}")
            prior_truth = _truth_from_orm(prior)
            corrected = build_evaluation_case_truth(
                tenant_id=prior_truth.tenant_id,
                source_tenant_id=prior_truth.source_tenant_id,
                source_product=prior_truth.source_product,
                connector_id=prior_truth.connector_id,
                dataset_id=prior_truth.dataset_id,
                dataset_version=prior_truth.dataset_version,
                case_id=prior_truth.case_id,
                case_version=prior_truth.case_version,
                observation_refs=observation_refs or prior_truth.observation_refs,
                slice_expectation=slice_expectation,
                label_provenance=label_provenance,
                operational_mapping=operational_mapping or prior_truth.operational_mapping,
                revision=prior_truth.revision + 1,
                supersedes_truth_id=prior_truth.truth_id,
                correction_reason=correction_reason,
                retention_policy=prior_truth.retention_policy,
            )
            return await self.persist_in_session(sess, corrected)

        if session is not None:
            return await _run(session)
        async with self._session_factory() as owned_session:
            async with owned_session.begin():
                return await _run(owned_session)

    async def get_truth(
        self,
        truth_id: str,
        *,
        tenant_id: str,
        session: AsyncSession | None = None,
    ) -> EvaluationCaseTruth | None:
        stmt = select(orm.EvaluationCaseTruth).where(
            orm.EvaluationCaseTruth.truth_id == truth_id,
            orm.EvaluationCaseTruth.tenant_id == tenant_id,
        )

        async def _run(sess: AsyncSession) -> EvaluationCaseTruth | None:
            row = await sess.scalar(stmt)
            return _truth_from_orm(row) if row is not None else None

        if session is not None:
            return await _run(session)
        async with self._session_factory() as owned_session:
            return await _run(owned_session)

    async def get_latest_truth(
        self,
        *,
        tenant_id: str,
        dataset_id: str,
        case_id: str,
        session: AsyncSession | None = None,
    ) -> EvaluationCaseTruth | None:
        stmt = (
            select(orm.EvaluationCaseTruth)
            .where(
                orm.EvaluationCaseTruth.tenant_id == tenant_id,
                orm.EvaluationCaseTruth.dataset_id == dataset_id,
                orm.EvaluationCaseTruth.case_id == case_id,
            )
            .order_by(orm.EvaluationCaseTruth.revision.desc())
            .limit(1)
        )

        async def _run(sess: AsyncSession) -> EvaluationCaseTruth | None:
            row = await sess.scalar(stmt)
            return _truth_from_orm(row) if row is not None else None

        if session is not None:
            return await _run(session)
        async with self._session_factory() as owned_session:
            return await _run(owned_session)

    async def query_truths(
        self,
        query: EvaluationTruthQuery,
        *,
        session: AsyncSession | None = None,
    ) -> EvaluationTruthListResult:
        filters = [orm.EvaluationCaseTruth.tenant_id == query.tenant_id]
        if query.dataset_id is not None:
            filters.append(orm.EvaluationCaseTruth.dataset_id == query.dataset_id)
        if query.dataset_version is not None:
            filters.append(orm.EvaluationCaseTruth.dataset_version == query.dataset_version)
        if query.case_id is not None:
            filters.append(orm.EvaluationCaseTruth.case_id == query.case_id)
        if query.slice_type is not None:
            filters.append(
                orm.EvaluationCaseTruth.slice_expectation["slice_type"].astext
                == query.slice_type.value
            )

        offset = (query.page - 1) * query.page_size

        async def _run(sess: AsyncSession) -> EvaluationTruthListResult:
            if query.latest_revision_only:
                latest_subq = (
                    select(
                        orm.EvaluationCaseTruth.case_id,
                        func.max(orm.EvaluationCaseTruth.revision).label("max_revision"),
                    )
                    .where(*filters)
                    .group_by(orm.EvaluationCaseTruth.case_id)
                    .subquery()
                )
                base_stmt = (
                    select(orm.EvaluationCaseTruth)
                    .join(
                        latest_subq,
                        and_(
                            orm.EvaluationCaseTruth.case_id == latest_subq.c.case_id,
                            orm.EvaluationCaseTruth.revision == latest_subq.c.max_revision,
                        ),
                    )
                    .where(*filters)
                )
                total = await sess.scalar(
                    select(func.count()).select_from(base_stmt.subquery())
                )
                rows = await sess.scalars(
                    base_stmt.order_by(
                        orm.EvaluationCaseTruth.dataset_id.asc(),
                        orm.EvaluationCaseTruth.case_id.asc(),
                    )
                    .offset(offset)
                    .limit(query.page_size)
                )
            else:
                total = await sess.scalar(
                    select(func.count()).select_from(orm.EvaluationCaseTruth).where(*filters)
                )
                rows = await sess.scalars(
                    select(orm.EvaluationCaseTruth)
                    .where(*filters)
                    .order_by(
                        orm.EvaluationCaseTruth.dataset_id.asc(),
                        orm.EvaluationCaseTruth.case_id.asc(),
                        orm.EvaluationCaseTruth.revision.asc(),
                    )
                    .offset(offset)
                    .limit(query.page_size)
                )
            items = [_truth_from_orm(row) for row in rows]
            return EvaluationTruthListResult(
                total=int(total or 0),
                page=query.page,
                page_size=query.page_size,
                items=items,
            )

        if session is not None:
            return await _run(session)
        async with self._session_factory() as owned_session:
            return await _run(owned_session)

    async def get_dataset_manifest(
        self,
        *,
        tenant_id: str,
        dataset_id: str,
        dataset_version: str,
        session: AsyncSession | None = None,
    ) -> EvaluationDatasetManifest:
        """Build dataset content hash from latest revision per case."""

        async def _run(sess: AsyncSession) -> EvaluationDatasetManifest:
            subq = (
                select(
                    orm.EvaluationCaseTruth.case_id,
                    func.max(orm.EvaluationCaseTruth.revision).label("max_revision"),
                )
                .where(
                    orm.EvaluationCaseTruth.tenant_id == tenant_id,
                    orm.EvaluationCaseTruth.dataset_id == dataset_id,
                    orm.EvaluationCaseTruth.dataset_version == dataset_version,
                )
                .group_by(orm.EvaluationCaseTruth.case_id)
                .subquery()
            )
            rows = await sess.scalars(
                select(orm.EvaluationCaseTruth)
                .join(
                    subq,
                    (orm.EvaluationCaseTruth.case_id == subq.c.case_id)
                    & (orm.EvaluationCaseTruth.revision == subq.c.max_revision),
                )
                .where(
                    orm.EvaluationCaseTruth.tenant_id == tenant_id,
                    orm.EvaluationCaseTruth.dataset_id == dataset_id,
                    orm.EvaluationCaseTruth.dataset_version == dataset_version,
                )
                .order_by(orm.EvaluationCaseTruth.case_id.asc())
            )
            content_hashes = sorted(row.content_hash for row in rows)
            dataset_hash = compute_dataset_manifest_hash(content_hashes)
            return EvaluationDatasetManifest(
                tenant_id=tenant_id,
                dataset_id=dataset_id,
                dataset_version=dataset_version,
                content_hash=dataset_hash,
                case_count=len(content_hashes),
                schema_version=EVALUATION_TRUTH_SCHEMA_VERSION,
            )

        if session is not None:
            return await _run(session)
        async with self._session_factory() as owned_session:
            return await _run(owned_session)


__all__ = [
    "EvaluationTruthService",
    "build_evaluation_case_truth",
    "build_idempotency_key",
    "compute_content_hash",
    "compute_dataset_manifest_hash",
    "compute_truth_hash",
]
