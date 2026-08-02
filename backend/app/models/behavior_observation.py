"""BehaviorObservation contract — ISSUE-119 / #624 Phase 0.

Durable, tenant-scoped semantic projection of persisted source objects for the
detection pipeline. Observations reference source evidence by identity and hash;
raw payloads are never duplicated here.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

BEHAVIOR_OBSERVATION_SCHEMA_VERSION = "1.0"
BEHAVIOR_OBSERVATION_PROJECTION_SCHEMA_VERSION = "1.0"


class BehaviorObservationProjectionStatus(StrEnum):
    """Retry lifecycle for semantic projection failures."""

    PENDING_RETRY = "pending_retry"
    DEAD_LETTER = "dead_letter"
    RESOLVED = "resolved"


class BehaviorEntityRef(BaseModel):
    """Normalized entity reference extracted from source semantics."""

    model_config = ConfigDict(extra="forbid")

    entity_type: str = Field(..., min_length=1, max_length=64)
    entity_id: str = Field(..., min_length=1, max_length=256)
    role: str | None = Field(default=None, max_length=64)


class BehaviorObservationSourceRef(BaseModel):
    """Pointer to the upstream source object revision that produced the observation."""

    model_config = ConfigDict(extra="forbid")

    source_product: str = Field(..., min_length=1, max_length=64)
    connector_id: str = Field(..., min_length=1, max_length=128)
    source_kind: str = Field(..., min_length=1, max_length=32)
    source_object_id: str = Field(..., min_length=1, max_length=256)
    source_object_type: str | None = Field(default=None, max_length=128)
    source_revision: int = Field(..., ge=1)


class BehaviorObservationProvenance(BaseModel):
    """Rebuild metadata — references durable source store, never raw payload copies."""

    model_config = ConfigDict(extra="forbid")

    source_record_id: str = Field(..., min_length=1, max_length=128)
    raw_payload_hash: str | None = Field(default=None, max_length=128)
    source_concurrency_token: str | None = Field(default=None, max_length=256)
    projection_engine: str = Field(default="behavior_observation_v1", min_length=1, max_length=64)
    scope_binding_unverified: bool = Field(
        default=False,
        description="True when scope id came from metadata fallback while an ACTIVE scope exists",
    )


class BehaviorObservation(BaseModel):
    """Immutable semantic observation derived from one source object revision."""

    model_config = ConfigDict(extra="forbid")

    observation_id: str = Field(..., min_length=1, max_length=128)
    source_tenant_id: str = Field(..., min_length=1, max_length=128)
    detection_scope_id: str = Field(..., min_length=1, max_length=128)
    source_ref: BehaviorObservationSourceRef
    observed_at: datetime
    ingested_at: datetime
    entity_refs: list[BehaviorEntityRef] = Field(default_factory=list)
    action: str | None = Field(default=None, max_length=128)
    category: str | None = Field(default=None, max_length=128)
    normalized_attributes: dict[str, Any] = Field(default_factory=dict)
    detection_score: float | None = Field(default=None, ge=0.0, le=100.0)
    schema_version: str = Field(default=BEHAVIOR_OBSERVATION_SCHEMA_VERSION, min_length=1)
    projection_schema_version: str = Field(
        default=BEHAVIOR_OBSERVATION_PROJECTION_SCHEMA_VERSION,
        min_length=1,
    )
    content_hash: str = Field(..., min_length=64, max_length=64)
    observation_hash: str = Field(..., min_length=64, max_length=64)
    idempotency_key: str = Field(..., min_length=1, max_length=512)
    provenance: BehaviorObservationProvenance
    supersedes_observation_id: str | None = Field(default=None, max_length=128)
    created_at: datetime | None = None


class BehaviorObservationQuery(BaseModel):
    """Tenant-scoped read path for behavior observations."""

    model_config = ConfigDict(extra="forbid")

    source_tenant_id: str = Field(..., min_length=1, max_length=128)
    detection_scope_id: str | None = Field(default=None, max_length=128)
    connector_id: str | None = Field(default=None, max_length=128)
    source_kind: str | None = Field(default=None, max_length=32)
    source_object_id: str | None = Field(default=None, max_length=256)
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)


class BehaviorObservationListResult(BaseModel):
    """Paginated observation query result."""

    model_config = ConfigDict(extra="forbid")

    total: int = Field(..., ge=0)
    page: int = Field(..., ge=1)
    page_size: int = Field(..., ge=1)
    items: list[BehaviorObservation] = Field(default_factory=list)


class BehaviorObservationProjectionFailureRecord(BaseModel):
    """Read-only projection failure row for ops visibility (ISSUE-156)."""

    model_config = ConfigDict(extra="forbid")

    failure_id: str = Field(..., min_length=1, max_length=128)
    source_record_id: str = Field(..., min_length=1, max_length=128)
    source_tenant_id: str = Field(..., min_length=1, max_length=128)
    attempt: int = Field(..., ge=1)
    status: BehaviorObservationProjectionStatus
    error_category: str = Field(..., min_length=1, max_length=64)
    detail: dict[str, Any] = Field(default_factory=dict)
    next_retry_at: datetime | None = None
    resolved_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class BehaviorObservationProjectionFailureQuery(BaseModel):
    """Tenant-scoped read path for projection failure backlog."""

    model_config = ConfigDict(extra="forbid")

    source_tenant_id: str = Field(..., min_length=1, max_length=128)
    status: BehaviorObservationProjectionStatus | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)


class BehaviorObservationProjectionFailureListResult(BaseModel):
    """Paginated projection failure query result."""

    model_config = ConfigDict(extra="forbid")

    total: int = Field(..., ge=0)
    page: int = Field(..., ge=1)
    page_size: int = Field(..., ge=1)
    items: list[BehaviorObservationProjectionFailureRecord] = Field(default_factory=list)
