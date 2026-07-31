"""Embedding service layer (ISSUE-041, ISSUE-140)."""

from app.core.embedding.base import (
    EmbeddingCompatibilityError,
    EmbeddingError,
    EmbeddingPrefilterError,
    EmbeddingUnavailableError,
)
from app.core.embedding.compat import (
    assert_prefilter_in_sql,
    build_prefiltered_vector_sql,
    compute_content_hash,
    validate_release_compatibility,
    validate_vector_dimension,
    validate_vector_prefilter,
    validate_vector_query_context,
)
from app.core.embedding.factory import (
    close_embedding_client,
    get_embedding_client,
    reset_embedding_client,
)
from app.core.embedding.mock_embedder import DEFAULT_EMBEDDING_DIM, EMBEDDING_DIM, MockEmbedder
from app.core.embedding.release import build_embedding_release, compute_config_hash
from app.core.embedding.service import EmbeddingService

__all__ = [
    "DEFAULT_EMBEDDING_DIM",
    "EMBEDDING_DIM",
    "EmbeddingCompatibilityError",
    "EmbeddingError",
    "EmbeddingPrefilterError",
    "EmbeddingService",
    "EmbeddingUnavailableError",
    "MockEmbedder",
    "assert_prefilter_in_sql",
    "build_embedding_release",
    "build_prefiltered_vector_sql",
    "close_embedding_client",
    "compute_config_hash",
    "compute_content_hash",
    "get_embedding_client",
    "reset_embedding_client",
    "validate_release_compatibility",
    "validate_vector_dimension",
    "validate_vector_prefilter",
    "validate_vector_query_context",
]
