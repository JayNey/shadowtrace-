"""Embedding compatibility and pre-filter tests (ISSUE-140)."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.core.embedding.base import EmbeddingCompatibilityError, EmbeddingPrefilterError
from app.core.embedding.compat import (
    assert_prefilter_in_sql,
    build_prefiltered_vector_sql,
    compute_content_hash,
    validate_release_compatibility,
    validate_vector_dimension,
    validate_vector_prefilter,
    validate_vector_query_context,
)
from app.core.embedding.release import build_embedding_release
from app.models.embedding import VectorQueryContext, VectorQueryFilter


def _release(release_id: str = "mock-v1") -> object:
    return build_embedding_release(
        Settings(embedding_mode="mock", embedding_release_id=release_id),
    )


def test_validate_vector_dimension_fail_closed() -> None:
    with pytest.raises(EmbeddingCompatibilityError, match="dimension mismatch"):
        validate_vector_dimension([0.1, 0.2], expected_dimension=1024, context="test")


def test_validate_release_compatibility_detects_mismatch() -> None:
    query = _release("mock-v1")
    stored = _release("mock-v2")
    with pytest.raises(EmbeddingCompatibilityError, match="incompatible"):
        validate_release_compatibility(query_release=query, stored_release=stored)


def test_validate_release_compatibility_detects_model_id_mismatch() -> None:
    query = build_embedding_release(Settings(embedding_mode="mock", embedding_model_id="model-a"))
    stored = build_embedding_release(Settings(embedding_mode="mock", embedding_model_id="model-b"))
    with pytest.raises(EmbeddingCompatibilityError, match="incompatible"):
        validate_release_compatibility(query_release=query, stored_release=stored)


def test_validate_vector_prefilter_requires_scope() -> None:
    with pytest.raises(EmbeddingPrefilterError, match="pre-filter required"):
        validate_vector_prefilter(
            VectorQueryFilter.model_construct(
                tenant_id="",
                corpus_id="attack_kb",
                release_id="rel-1",
                embedding_release_id="mock-v1",
            )
        )


def test_prefiltered_sql_contains_mandatory_filters() -> None:
    sql = build_prefiltered_vector_sql()
    assert_prefilter_in_sql(sql)
    assert "ORDER BY embedding <=>" in sql


def test_prefiltered_sql_without_vector_order_still_scoped() -> None:
    sql = build_prefiltered_vector_sql(include_vector_order=False)
    assert_prefilter_in_sql(sql)
    assert "ORDER BY" not in sql


def test_assert_prefilter_in_sql_rejects_unscoped_sql() -> None:
    with pytest.raises(EmbeddingPrefilterError, match="missing mandatory tenant"):
        assert_prefilter_in_sql(
            """
            SELECT chunk_id FROM knowledge_vector
            WHERE kb_name = :kb_name
            ORDER BY embedding <=> :query_vector
            """
        )


def test_vector_query_context_rejects_release_mismatch() -> None:
    release = _release("mock-v1")
    ctx = VectorQueryContext(
        filter=VectorQueryFilter(
            tenant_id="tenant-a",
            corpus_id="attack_kb",
            release_id="rel-1",
            embedding_release_id="other-release",
        ),
        active_release=release,
    )
    with pytest.raises(EmbeddingCompatibilityError, match="does not match active release"):
        validate_vector_query_context(ctx)


def test_compute_content_hash_stable() -> None:
    assert compute_content_hash(" hello ") == compute_content_hash("hello")
