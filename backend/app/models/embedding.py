"""Embedding / vector contract models (ISSUE-140).

Typed release metadata and vector record identity for mock + production providers.
Downstream import (#634) and filtered retrieval (#636) consume these contracts.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EmbeddingProviderMode(StrEnum):
    MOCK = "mock"
    LOCAL = "local"
    REMOTE = "remote"


class VectorDistanceMetric(StrEnum):
    COSINE = "cosine"
    L2 = "l2"
    INNER_PRODUCT = "inner_product"


class VectorNormalization(StrEnum):
    UNIT_L2 = "unit_l2"
    NONE = "none"


class EmbeddingRelease(BaseModel):
    """Immutable embedding release descriptor (config-injected, not hardcoded SDK versions)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider_mode: EmbeddingProviderMode
    model_id: str = Field(..., min_length=1, description="Provider model identifier from config")
    release_id: str = Field(..., min_length=1, description="Logical release id from config")
    dimension: int = Field(..., ge=1, le=8192)
    normalization: VectorNormalization
    distance_metric: VectorDistanceMetric
    content_schema_version: str = Field(..., min_length=1)
    preprocess_schema_version: str = Field(..., min_length=1)
    config_hash: str = Field(
        default="",
        description="Sanitized artifact/config fingerprint (never secrets)",
    )

    @field_validator("model_id", "release_id", "content_schema_version", "preprocess_schema_version")
    @classmethod
    def _strip_non_empty(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("must be non-empty")
        return stripped


class VectorRecordIdentity(BaseModel):
    """Vector row binding: tenant/corpus/object/release/content revision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(..., min_length=1)
    corpus_id: str = Field(..., min_length=1)
    object_id: str = Field(..., min_length=1)
    release_id: str = Field(..., min_length=1)
    embedding_release_id: str = Field(..., min_length=1)
    content_hash: str = Field(..., min_length=1, description="SHA-256 hex of normalized content")
    vector_revision: int = Field(default=1, ge=1, description="Monotonic revision on content/release change")

    @property
    def idempotency_key(self) -> str:
        """Unique upsert key including revision for content/release changes (#634)."""
        return (
            f"{self.tenant_id}:{self.corpus_id}:{self.object_id}:"
            f"{self.release_id}:{self.embedding_release_id}:"
            f"{self.content_hash}:r{self.vector_revision}"
        )


class VectorQueryFilter(BaseModel):
    """Mandatory tenant/release scope applied before vector candidate fetch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(..., min_length=1)
    corpus_id: str = Field(..., min_length=1)
    release_id: str = Field(..., min_length=1)
    embedding_release_id: str = Field(..., min_length=1)

    @field_validator("tenant_id", "corpus_id", "release_id", "embedding_release_id")
    @classmethod
    def _strip_non_empty(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("must be non-empty")
        return stripped


class VectorQueryContext(BaseModel):
    """Query-side vector context bound to an active embedding release."""

    model_config = ConfigDict(extra="forbid")

    filter: VectorQueryFilter
    active_release: EmbeddingRelease
    query_vector: list[float] = Field(default_factory=list, description="Populated after embed step")

    def with_query_vector(self, vector: list[float]) -> VectorQueryContext:
        return self.model_copy(update={"query_vector": vector})


class EmbeddingProviderHealth(BaseModel):
    """Sanitized embedding provider readiness for /health and diagnostics."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., description="ok | degraded | error")
    mode: EmbeddingProviderMode
    release_id: str
    model_id: str
    dimension: int
    distance_metric: VectorDistanceMetric
    normalization: VectorNormalization
    config_hash: str = ""
    error_code: str | None = None
    latency_ms: float | None = None


class VectorImportUpsert(BaseModel):
    """Idempotent bulk import row contract (#634 consumes)."""

    model_config = ConfigDict(extra="forbid")

    identity: VectorRecordIdentity
    content: str = Field(..., min_length=1)
    metadata: dict[str, str] = Field(default_factory=dict)
