"""ATT&CK STIX knowledge release contract (ISSUE-128 / #634, ISSUE-130 / #636)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

KNOWLEDGE_RELEASE_SCHEMA_VERSION = "1.0"
ATTACK_CORPUS_ID = "attack_enterprise"
ATTACK_KB_NAME = "attack_kb"
ATTACK_SOURCE_ID = "mitre_attack_stix"


class KnowledgeReleaseLifecycleState(StrEnum):
    """Release lifecycle — activation/retirement are server-owned transitions."""

    DRAFT = "draft"
    STAGED = "staged"
    ACTIVE = "active"
    RETIRED = "retired"
    FAILED = "failed"


class KnowledgeImportStatus(StrEnum):
    """Staged import validation outcome."""

    PENDING = "pending"
    VALIDATED = "validated"
    FAILED = "failed"


class KnowledgeReleaseProvenance(BaseModel):
    """Offline import provenance — no runtime network dependency."""

    model_config = ConfigDict(extra="forbid")

    source_path: str = Field(..., min_length=1, description="Local bundle path or fixture id")
    imported_by: str = Field(default="system", min_length=1)
    import_kind: str = Field(default="stix_bundle", min_length=1)


class KnowledgeRelease(BaseModel):
    """Immutable ATT&CK STIX release descriptor with lifecycle metadata."""

    model_config = ConfigDict(extra="forbid")

    release_id: str = Field(..., min_length=1, max_length=128)
    corpus_id: str = Field(..., min_length=1, max_length=64)
    source_id: str = Field(..., min_length=1, max_length=64)
    release_version: str = Field(..., min_length=1, max_length=64)
    content_hash: str = Field(..., min_length=64, max_length=64)
    provenance: KnowledgeReleaseProvenance
    schema_version: str = Field(default=KNOWLEDGE_RELEASE_SCHEMA_VERSION, min_length=1)
    import_status: KnowledgeImportStatus = KnowledgeImportStatus.PENDING
    lifecycle_state: KnowledgeReleaseLifecycleState = KnowledgeReleaseLifecycleState.DRAFT
    revision: int = Field(default=1, ge=1)
    supersedes_release_id: str | None = Field(default=None, max_length=128)
    object_count: int = Field(default=0, ge=0)
    relationship_count: int = Field(default=0, ge=0)
    vector_ready: bool = Field(
        default=False,
        description="True only when vectors were imported under a compatible EmbeddingRelease",
    )
    embedding_release_id: str | None = Field(default=None, max_length=128)
    idempotency_key: str = Field(..., min_length=1, max_length=256)
    activated_at: datetime | None = None
    retired_at: datetime | None = None
    created_at: datetime | None = None
    failure_reason: str | None = None


KNOWLEDGE_QUERY_PLAN_SCHEMA_VERSION = "1.0"
DEFAULT_KNOWLEDGE_TOP_K = 5
DEFAULT_KNOWLEDGE_MAX_CANDIDATES = 50


class KnowledgeFilterKind(StrEnum):
    """Typed metadata filters applied before candidate fetch (#636).

    Phase A supports ``source_id`` and ``content_type`` only. ``time_*`` values are
    schema-reserved and rejected by the server validator until a later phase.
    """

    SOURCE_ID = "source_id"
    CONTENT_TYPE = "content_type"
    TIME_AFTER = "time_after"
    TIME_BEFORE = "time_before"


class KnowledgeTypedFilter(BaseModel):
    """One storage-layer metadata predicate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: KnowledgeFilterKind
    value: str = Field(..., min_length=1)

    @field_validator("value")
    @classmethod
    def _strip_value(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("filter value must be non-empty")
        return stripped


class KnowledgeQueryBudget(BaseModel):
    """Retrieval budget — server-owned; agent hints may only narrow."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    top_k: int = Field(default=DEFAULT_KNOWLEDGE_TOP_K, ge=1, le=100)
    max_candidates: int = Field(default=DEFAULT_KNOWLEDGE_MAX_CANDIDATES, ge=1, le=500)


class KnowledgeQueryPlanHints(BaseModel):
    """Agent-provided retrieval hints — validator may only narrow scope."""

    model_config = ConfigDict(extra="forbid")

    corpus_ids: list[str] = Field(default_factory=list)
    source_ids: list[str] = Field(default_factory=list)
    content_types: list[str] = Field(default_factory=list)
    top_k: int | None = Field(default=None, ge=1, le=100)
    filters: list[KnowledgeTypedFilter] = Field(default_factory=list)


class KnowledgeQueryPlan(BaseModel):
    """Request-scoped knowledge retrieval plan with release pinning and filters."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(
        default=KNOWLEDGE_QUERY_PLAN_SCHEMA_VERSION,
        min_length=1,
    )
    tenant_id: str = Field(default="", min_length=0)
    principal: str = Field(default="", min_length=0)
    corpus_id: str = Field(..., min_length=1)
    kb_name: str = Field(..., min_length=1)
    allowed_corpora: tuple[str, ...] = Field(default_factory=tuple)
    active_release_id: str = Field(..., min_length=1)
    embedding_release_id: str = Field(..., min_length=1)
    typed_filters: tuple[KnowledgeTypedFilter, ...] = Field(default_factory=tuple)
    budget: KnowledgeQueryBudget = Field(default_factory=KnowledgeQueryBudget)
    trace_id: str = Field(..., min_length=1)
    plan_hash: str = Field(default="", min_length=0, max_length=64)
    pinned_at: datetime
    rejected_reasons: tuple[str, ...] = Field(default_factory=tuple)
    degraded_reasons: tuple[str, ...] = Field(default_factory=tuple)


class KnowledgeQueryPlanValidationOutcome(BaseModel):
    """Validator output — accepted plan or fail-closed rejection."""

    model_config = ConfigDict(extra="forbid")

    accepted: bool
    plan: KnowledgeQueryPlan | None = None
    rejected_reasons: list[str] = Field(default_factory=list)
    degraded_reasons: list[str] = Field(default_factory=list)
    sanitized_plan_hash: str = ""


__all__ = [
    "ATTACK_CORPUS_ID",
    "ATTACK_KB_NAME",
    "ATTACK_SOURCE_ID",
    "DEFAULT_KNOWLEDGE_MAX_CANDIDATES",
    "DEFAULT_KNOWLEDGE_TOP_K",
    "KNOWLEDGE_QUERY_PLAN_SCHEMA_VERSION",
    "KNOWLEDGE_RELEASE_SCHEMA_VERSION",
    "KnowledgeFilterKind",
    "KnowledgeImportStatus",
    "KnowledgeQueryBudget",
    "KnowledgeQueryPlan",
    "KnowledgeQueryPlanHints",
    "KnowledgeQueryPlanValidationOutcome",
    "KnowledgeTypedFilter",
    "KnowledgeRelease",
    "KnowledgeReleaseLifecycleState",
    "KnowledgeReleaseProvenance",
]
