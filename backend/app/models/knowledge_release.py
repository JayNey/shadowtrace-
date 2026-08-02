"""ATT&CK STIX knowledge release contract (ISSUE-128 / #634 Phase A)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


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


class KnowledgeQueryPlan(BaseModel):
    """Request-scoped knowledge + embedding release pinning for retrieval."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    corpus_id: str = Field(..., min_length=1)
    kb_name: str = Field(..., min_length=1)
    active_release_id: str = Field(..., min_length=1)
    embedding_release_id: str = Field(..., min_length=1)
    trace_id: str = Field(..., min_length=1)
    pinned_at: datetime


__all__ = [
    "ATTACK_CORPUS_ID",
    "ATTACK_KB_NAME",
    "ATTACK_SOURCE_ID",
    "KNOWLEDGE_RELEASE_SCHEMA_VERSION",
    "KnowledgeImportStatus",
    "KnowledgeQueryPlan",
    "KnowledgeRelease",
    "KnowledgeReleaseLifecycleState",
    "KnowledgeReleaseProvenance",
]
