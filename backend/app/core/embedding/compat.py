"""Vector compatibility and pre-filter validation (ISSUE-140)."""

from __future__ import annotations

import hashlib
import math
import re

from app.core.embedding.base import EmbeddingCompatibilityError, EmbeddingPrefilterError
from app.models.embedding import (
    EmbeddingRelease,
    VectorNormalization,
    VectorQueryContext,
    VectorQueryFilter,
)

_PREFILTER_SQL_FRAGMENT = re.compile(
    r"tenant_id\s*=\s*:tenant_id[\s\S]*corpus_id\s*=\s*:corpus_id[\s\S]*"
    r"release_id\s*=\s*:release_id[\s\S]*embedding_release_id\s*=\s*:embedding_release_id",
    re.IGNORECASE,
)


def compute_content_hash(content: str) -> str:
    """SHA-256 hex digest of normalized UTF-8 content."""
    normalized = content.strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def validate_vector_dimension(
    vector: list[float],
    *,
    expected_dimension: int,
    context: str,
) -> None:
    if len(vector) != expected_dimension:
        raise EmbeddingCompatibilityError(
            message=f"{context}: vector dimension mismatch",
            error_code="embedding_dimension_mismatch",
            details={"expected": expected_dimension, "actual": len(vector)},
        )


def validate_vector_normalization(
    vector: list[float],
    *,
    expected: VectorNormalization,
    context: str,
    tolerance: float = 1e-3,
) -> None:
    """Fail closed when stored/query vectors violate the active release normalization."""
    if expected != VectorNormalization.UNIT_L2:
        return
    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0.0 or abs(norm - 1.0) > tolerance:
        raise EmbeddingCompatibilityError(
            message=f"{context}: vector normalization mismatch (expected unit_l2)",
            error_code="embedding_compatibility_error",
            details={"expected": expected.value, "l2_norm": norm},
        )


def validate_release_compatibility(
    *,
    query_release: EmbeddingRelease,
    stored_release: EmbeddingRelease,
) -> None:
    """Fail closed when query and stored vectors are not from compatible releases."""
    mismatches: list[str] = []
    if query_release.provider_mode != stored_release.provider_mode:
        mismatches.append("provider_mode")
    if query_release.model_id != stored_release.model_id:
        mismatches.append("model_id")
    if query_release.release_id != stored_release.release_id:
        mismatches.append("release_id")
    if query_release.dimension != stored_release.dimension:
        mismatches.append("dimension")
    if query_release.normalization != stored_release.normalization:
        mismatches.append("normalization")
    if query_release.distance_metric != stored_release.distance_metric:
        mismatches.append("distance_metric")
    if query_release.content_schema_version != stored_release.content_schema_version:
        mismatches.append("content_schema_version")
    if query_release.preprocess_schema_version != stored_release.preprocess_schema_version:
        mismatches.append("preprocess_schema_version")
    if query_release.config_hash != stored_release.config_hash:
        mismatches.append("config_hash")
    if mismatches:
        raise EmbeddingCompatibilityError(
            message="query vector release incompatible with stored vector release",
            error_code="embedding_release_mismatch",
            details={"fields": mismatches},
        )


def validate_vector_query_context(ctx: VectorQueryContext) -> None:
    """Ensure filter scope matches the active release and vector dimension."""
    validate_vector_prefilter(ctx.filter)
    if ctx.filter.embedding_release_id != ctx.active_release.release_id:
        raise EmbeddingCompatibilityError(
            message="filter embedding_release_id does not match active release",
            error_code="embedding_release_mismatch",
            details={
                "filter_release": ctx.filter.embedding_release_id,
                "active_release": ctx.active_release.release_id,
            },
        )
    if ctx.query_vector:
        validate_vector_dimension(
            ctx.query_vector,
            expected_dimension=ctx.active_release.dimension,
            context="query_vector",
        )
        validate_vector_normalization(
            ctx.query_vector,
            expected=ctx.active_release.normalization,
            context="query_vector",
        )


def validate_vector_prefilter(filter_: VectorQueryFilter) -> None:
    """Require tenant/corpus/release scope before any vector candidate fetch."""
    missing = [
        name
        for name, value in (
            ("tenant_id", filter_.tenant_id.strip()),
            ("corpus_id", filter_.corpus_id.strip()),
            ("release_id", filter_.release_id.strip()),
            ("embedding_release_id", filter_.embedding_release_id.strip()),
        )
        if not value
    ]
    if missing:
        raise EmbeddingPrefilterError(
            message="vector pre-filter required before candidate fetch",
            error_code="embedding_prefilter_required",
            details={"missing": missing},
        )


def build_prefiltered_vector_sql(*, include_vector_order: bool = True) -> str:
    """SQL template for future ``knowledge_vector`` store (#634).

    Not wired to KnowledgeStore yet.
    """
    order_clause = (
        "\n            ORDER BY embedding <=> :query_vector\n            LIMIT :top_k"
        if include_vector_order
        else ""
    )
    return (
        """
            SELECT chunk_id, tenant_id, corpus_id, release_id, embedding_release_id,
                   content, metadata,
                   1.0 - (embedding <=> :query_vector) AS score
            FROM knowledge_vector
            WHERE tenant_id = :tenant_id
              AND corpus_id = :corpus_id
              AND release_id = :release_id
              AND embedding_release_id = :embedding_release_id
        """
        + order_clause
    )


def assert_prefilter_in_sql(sql: str) -> None:
    """Backend-specific proof that pre-filter predicates precede vector ordering."""
    if not _PREFILTER_SQL_FRAGMENT.search(sql):
        raise EmbeddingPrefilterError(
            message="vector SQL missing mandatory tenant/release pre-filter",
            error_code="embedding_prefilter_required",
            details={"sql_excerpt": sql.strip()[:240]},
        )
