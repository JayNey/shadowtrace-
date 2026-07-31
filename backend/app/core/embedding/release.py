"""EmbeddingRelease construction from settings (ISSUE-140)."""

from __future__ import annotations

import hashlib

from app.core.config import Settings
from app.core.embedding.base import EmbeddingCompatibilityError
from app.models.embedding import (
    EmbeddingProviderMode,
    EmbeddingRelease,
    VectorDistanceMetric,
    VectorNormalization,
)

_SUPPORTED_MODES = frozenset({"mock", "local", "remote"})
_SUPPORTED_METRICS = frozenset(m.value for m in VectorDistanceMetric)
_SUPPORTED_NORMALIZATION = frozenset(n.value for n in VectorNormalization)


def _normalize_mode(raw: str) -> EmbeddingProviderMode:
    mode = raw.strip().lower()
    if mode not in _SUPPORTED_MODES:
        raise EmbeddingCompatibilityError(
            message=f"unsupported embedding_mode: {raw!r}",
            error_code="embedding_mode_conflict",
            details={"embedding_mode": raw, "supported": sorted(_SUPPORTED_MODES)},
        )
    return EmbeddingProviderMode(mode)


def _normalize_metric(raw: str) -> VectorDistanceMetric:
    metric = raw.strip().lower()
    if metric not in _SUPPORTED_METRICS:
        raise EmbeddingCompatibilityError(
            message=f"unsupported embedding distance metric: {raw!r}",
            error_code="embedding_metric_mismatch",
            details={"distance_metric": raw, "supported": sorted(_SUPPORTED_METRICS)},
        )
    return VectorDistanceMetric(metric)


def _normalize_normalization(raw: str) -> VectorNormalization:
    norm = raw.strip().lower()
    if norm not in _SUPPORTED_NORMALIZATION:
        raise EmbeddingCompatibilityError(
            message=f"unsupported embedding normalization: {raw!r}",
            error_code="embedding_compatibility_error",
            details={"normalization": raw, "supported": sorted(_SUPPORTED_NORMALIZATION)},
        )
    return VectorNormalization(norm)


def compute_config_hash(settings: Settings) -> str:
    """Deterministic sanitized fingerprint of embedding config (no secrets)."""
    payload = "|".join(
        [
            settings.embedding_mode.strip().lower(),
            settings.embedding_model_id.strip(),
            settings.embedding_release_id.strip(),
            str(settings.embedding_dimension),
            settings.embedding_distance_metric.strip().lower(),
            settings.embedding_normalization.strip().lower(),
            settings.embedding_content_schema_version.strip(),
            settings.embedding_preprocess_schema_version.strip(),
            settings.embedding_api_base_url.rstrip("/"),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def build_embedding_release(settings: Settings) -> EmbeddingRelease:
    """Build the active release descriptor from runtime settings."""
    mode = _normalize_mode(settings.embedding_mode)
    metric = _normalize_metric(settings.embedding_distance_metric)
    normalization = _normalize_normalization(settings.embedding_normalization)
    if mode == EmbeddingProviderMode.MOCK and normalization != VectorNormalization.UNIT_L2:
        raise EmbeddingCompatibilityError(
            message="mock embedding release requires unit_l2 normalization",
            error_code="embedding_compatibility_error",
            details={"normalization": normalization.value},
        )
    if metric != VectorDistanceMetric.COSINE:
        raise EmbeddingCompatibilityError(
            message="P0 vector store uses pgvector cosine; only cosine metric is supported",
            error_code="embedding_metric_mismatch",
            details={"distance_metric": metric.value},
        )
    config_hash = settings.embedding_config_hash.strip() or compute_config_hash(settings)
    return EmbeddingRelease(
        provider_mode=mode,
        model_id=settings.embedding_model_id.strip(),
        release_id=settings.embedding_release_id.strip(),
        dimension=settings.embedding_dimension,
        normalization=normalization,
        distance_metric=metric,
        content_schema_version=settings.embedding_content_schema_version.strip(),
        preprocess_schema_version=settings.embedding_preprocess_schema_version.strip(),
        config_hash=config_hash,
    )
