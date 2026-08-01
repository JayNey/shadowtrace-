"""Canonical Detection Scope contract — Phase 0 (ISSUE-120 / #625).

Server-owned scope identity for detection/feature pipelines. Scope is derived from
``source_tenant_id``, upstream integration instance, versioned upstream connector
set, and optional environment/region. Derived detection connectors (#629) must
reference an established ``detection_scope_id`` and are excluded from the upstream
connector set that defines scope identity.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

DETECTION_SCOPE_SCHEMA_VERSION = "1.0"


class ConnectorScopeRole(StrEnum):
    """Connector participation in detection scope identity."""

    UPSTREAM_SOURCE = "upstream_source"
    DERIVED_DETECTION = "derived_detection"


class DetectionScopeLifecycleState(StrEnum):
    """Revision lifecycle — activation/retirement are server-owned transitions."""

    DRAFT = "draft"
    ACTIVE = "active"
    RETIRED = "retired"


class UpstreamConnectorMember(BaseModel):
    """One upstream source connector in a versioned scope connector set."""

    model_config = ConfigDict(extra="forbid")

    connector_id: str = Field(..., min_length=1, max_length=128)
    source_product: str = Field(..., min_length=1, max_length=64)
    role: ConnectorScopeRole = Field(default=ConnectorScopeRole.UPSTREAM_SOURCE)

    @field_validator("role")
    @classmethod
    def _must_be_upstream(cls, value: ConnectorScopeRole) -> ConnectorScopeRole:
        if value is not ConnectorScopeRole.UPSTREAM_SOURCE:
            raise ValueError("upstream connector set members must have role=upstream_source")
        return value


class DetectionScopeConnectorSet(BaseModel):
    """Versioned, canonical upstream connector membership for one scope revision."""

    model_config = ConfigDict(extra="forbid")

    connector_set_version: int = Field(..., ge=1)
    upstream_connectors: list[UpstreamConnectorMember] = Field(min_length=1)


class DetectionScopeIdentity(BaseModel):
    """Stable upstream integration boundary — independent of connector membership edits."""

    model_config = ConfigDict(extra="forbid")

    source_tenant_id: str = Field(..., min_length=1, max_length=128)
    source_product: str = Field(..., min_length=1, max_length=64)
    integration_instance_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Server-owned upstream integration instance identifier.",
    )
    environment: str | None = Field(default=None, max_length=64)
    region: str | None = Field(default=None, max_length=64)


class DerivedDetectionConnectorBinding(BaseModel):
    """Derived detection connector that references but does not define scope identity."""

    model_config = ConfigDict(extra="forbid")

    connector_id: str = Field(..., min_length=1, max_length=128)
    detection_scope_id: str = Field(..., min_length=1, max_length=128)
    role: ConnectorScopeRole = Field(default=ConnectorScopeRole.DERIVED_DETECTION)

    @field_validator("role")
    @classmethod
    def _must_be_derived(cls, value: ConnectorScopeRole) -> ConnectorScopeRole:
        if value is not ConnectorScopeRole.DERIVED_DETECTION:
            raise ValueError("derived connector binding must have role=derived_detection")
        return value


class DetectionScopeRevision(BaseModel):
    """Immutable, append-only scope revision with traceable lifecycle."""

    model_config = ConfigDict(extra="forbid")

    scope_revision_id: str = Field(..., min_length=1, max_length=128)
    detection_scope_id: str = Field(..., min_length=1, max_length=128)
    identity: DetectionScopeIdentity
    connector_set: DetectionScopeConnectorSet
    lifecycle_state: DetectionScopeLifecycleState = DetectionScopeLifecycleState.DRAFT
    revision: int = Field(default=1, ge=1)
    supersedes_scope_revision_id: str | None = Field(default=None, max_length=128)
    content_hash: str = Field(..., min_length=64, max_length=64)
    identity_hash: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description=(
            "SHA-256 of upstream integration identity only (tenant/product/instance/env/region). "
            "Distinct from detection_scope_id, which also includes connector_set_version."
        ),
    )
    idempotency_key: str = Field(..., min_length=1, max_length=256)
    schema_version: str = Field(default=DETECTION_SCOPE_SCHEMA_VERSION, min_length=1)
    activated_at: datetime | None = None
    retired_at: datetime | None = None
    created_at: datetime | None = None


class DetectionScopeQuery(BaseModel):
    """Read path for canonical scope revisions (tenant-scoped)."""

    model_config = ConfigDict(extra="forbid")

    source_tenant_id: str = Field(..., min_length=1, max_length=128)
    source_product: str | None = Field(default=None, max_length=64)
    integration_instance_id: str | None = Field(default=None, max_length=128)
    detection_scope_id: str | None = Field(default=None, max_length=128)
    lifecycle_state: DetectionScopeLifecycleState | None = None
    latest_revision_only: bool = True
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)


class DetectionScopeListResult(BaseModel):
    """Paginated scope revision query result."""

    model_config = ConfigDict(extra="forbid")

    total: int = Field(..., ge=0)
    page: int = Field(..., ge=1)
    page_size: int = Field(..., ge=1)
    items: list[DetectionScopeRevision] = Field(default_factory=list)
