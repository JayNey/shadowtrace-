"""Shadow run contracts for ReAct mock query pivot (ISSUE-135 / #641 Phase A)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

SHADOW_RUN_SCHEMA_VERSION = "1.0"
SHADOW_QUERY_ARTIFACT_SCHEMA_VERSION = "1.0"
DEFAULT_SHADOW_RETENTION_POLICY = "shadow_pivot_v1"


class ShadowRunStatus(StrEnum):
    """Lifecycle for an isolated shadow query pivot run."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"


class ShadowQueryArtifactKind(StrEnum):
    """Typed artifact emitted by shadow retrieval/query steps."""

    RETRIEVAL_HIT = "retrieval_hit"
    TOOL_PROJECTION = "tool_projection"
    PIVOT_SUMMARY = "pivot_summary"


class ShadowRunProvenance(BaseModel):
    """Server-owned run provenance — no client trust."""

    model_config = ConfigDict(extra="forbid")

    trigger: str = Field(..., min_length=1)
    principal: str = Field(..., min_length=1)
    policy_version: str = Field(default=DEFAULT_SHADOW_RETENTION_POLICY, min_length=1)
    schema_version: str = Field(default=SHADOW_RUN_SCHEMA_VERSION, min_length=1)


class ShadowQueryArtifact(BaseModel):
    """One typed, sanitized shadow artifact (never raw CoT)."""

    model_config = ConfigDict(extra="forbid")

    artifact_id: str = Field(..., min_length=1)
    shadow_run_id: str = Field(..., min_length=1)
    kind: ShadowQueryArtifactKind
    content_hash: str = Field(..., min_length=64, max_length=64)
    payload: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)
    retention_expires_at: datetime | None = None
    created_at: datetime | None = None


class ShadowRun(BaseModel):
    """Isolated shadow namespace run bound to one production event correlation id."""

    model_config = ConfigDict(extra="forbid")

    shadow_run_id: str = Field(..., min_length=1)
    event_id: str = Field(..., min_length=1)
    tenant_id: str = Field(..., min_length=1)
    namespace_key: str = Field(..., min_length=1)
    status: ShadowRunStatus = ShadowRunStatus.RUNNING
    max_steps: int = Field(default=5, ge=1, le=50)
    step_count: int = Field(default=0, ge=0)
    max_tool_calls: int = Field(default=5, ge=0, le=100)
    tool_call_count: int = Field(default=0, ge=0)
    provenance: ShadowRunProvenance
    result_summary: dict[str, Any] = Field(default_factory=dict)
    rejected_reasons: list[str] = Field(default_factory=list)
    retention_expires_at: datetime
    created_at: datetime | None = None
    completed_at: datetime | None = None


class ShadowQueryPivotRequest(BaseModel):
    """Trusted entry request for a shadow-only query pivot."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(..., min_length=1)
    tenant_id: str = Field(..., min_length=1)
    principal: str = Field(..., min_length=1)
    trace_id: str = Field(..., min_length=1)
    goal: str = Field(..., min_length=1)
    evidence_gaps: list[str] = Field(default_factory=list)
    observation: str = ""
    allowed_query_tools: list[str] = Field(default_factory=list)


class ShadowQueryPivotResult(BaseModel):
    """Outcome of one shadow pivot — production stores remain untouched."""

    model_config = ConfigDict(extra="forbid")

    shadow_run_id: str
    status: ShadowRunStatus
    react_stop_reason: str | None = None
    artifacts: list[ShadowQueryArtifact] = Field(default_factory=list)
    decision_record_ids: list[str] = Field(default_factory=list)
    rejected_reasons: list[str] = Field(default_factory=list)
    degraded: bool = False


__all__ = [
    "DEFAULT_SHADOW_RETENTION_POLICY",
    "SHADOW_QUERY_ARTIFACT_SCHEMA_VERSION",
    "SHADOW_RUN_SCHEMA_VERSION",
    "ShadowQueryArtifact",
    "ShadowQueryArtifactKind",
    "ShadowQueryPivotRequest",
    "ShadowQueryPivotResult",
    "ShadowRun",
    "ShadowRunProvenance",
    "ShadowRunStatus",
]
