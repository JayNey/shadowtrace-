"""ToolCallGrant contracts — bound principal, scope, and safe projection (ISSUE-134 / #640)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

TOOL_CALL_GRANT_SCHEMA_VERSION = "1.0"
DEFAULT_TOOL_CALL_GRANT_POLICY_VERSION = "tool-grant-v1"

EVIDENCE_COMPATIBILITY_POLICY_VERSION = "evidence-compat-v1"
EVIDENCE_COMPATIBILITY_QUERY_TOOLS: frozenset[str] = frozenset(
    {
        "query_account_login",
        "query_edr_process",
        "query_file_access",
        "query_network_flow",
        "query_dns",
        "query_asset_info",
        "query_vuln_info",
        "query_threat_intel",
        "query_history_cases",
    }
)


class ToolCallMode(StrEnum):
    """Execution namespace for tool-call grants."""

    PRODUCTION = "production"
    SHADOW = "shadow"
    COMPATIBILITY = "compatibility"


class ToolCallAttemptStatus(StrEnum):
    """Lifecycle of one grant-bound tool attempt."""

    RESERVED = "reserved"
    DENIED = "denied"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"


class BoundExecutionPrincipal(BaseModel):
    """Server-issued trusted execution identity; never derived from LLM params."""

    model_config = ConfigDict(extra="forbid")

    principal_id: str = Field(min_length=8, max_length=128)
    agent_name: str = Field(min_length=1, max_length=128)
    actor_type: str = Field(min_length=1, max_length=64)


class ToolCallGrantScope(BaseModel):
    """Minimal typed scope bound to a grant."""

    model_config = ConfigDict(extra="forbid")

    allowed_tools: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_entities: list[str] = Field(default_factory=list)
    connector_ids: list[str] = Field(default_factory=list)

    @field_validator("allowed_tools", "allowed_domains", "allowed_entities", "connector_ids")
    @classmethod
    def _normalize_scope_lists(cls, value: list[str]) -> list[str]:
        seen: set[str] = set()
        normalized: list[str] = []
        for item in value:
            token = str(item).strip()
            if not token or token in seen:
                continue
            seen.add(token)
            normalized.append(token)
        return normalized


class ToolCallGrant(BaseModel):
    """Authoritative server-side grant contract (opaque token validated separately)."""

    model_config = ConfigDict(extra="forbid")

    grant_id: str
    mode: ToolCallMode
    namespace_key: str
    shadow_run_id: str | None = None
    event_id: str
    plan_step_id: str | None = None
    task_id: str | None = None
    tenant_id: str
    scope: ToolCallGrantScope
    execution_principal: BoundExecutionPrincipal
    max_calls: int = Field(ge=1, le=10_000)
    attempt_count: int = Field(default=0, ge=0)
    valid_from: datetime
    expires_at: datetime
    policy_version: str
    schema_version: str = TOOL_CALL_GRANT_SCHEMA_VERSION
    revoked_at: datetime | None = None
    created_at: datetime

    @model_validator(mode="after")
    def _shadow_mode_requires_run_id(self) -> ToolCallGrant:
        if self.mode is ToolCallMode.SHADOW and not (self.shadow_run_id or "").strip():
            raise ValueError("shadow_run_id is required when mode=shadow")
        if self.mode is not ToolCallMode.SHADOW and self.shadow_run_id:
            raise ValueError("shadow_run_id must be null unless mode=shadow")
        if self.expires_at <= self.valid_from:
            raise ValueError("expires_at must be after valid_from")
        return self


class ToolCallGrantCreateRequest(BaseModel):
    """Trusted caller input to mint a new grant."""

    model_config = ConfigDict(extra="forbid")

    mode: ToolCallMode = ToolCallMode.PRODUCTION
    shadow_run_id: str | None = None
    event_id: str
    plan_step_id: str | None = None
    task_id: str | None = None
    tenant_id: str
    scope: ToolCallGrantScope
    execution_principal: BoundExecutionPrincipal
    max_calls: int = Field(default=32, ge=1, le=10_000)
    valid_for_seconds: int = Field(default=900, ge=1, le=86_400)
    policy_version: str = DEFAULT_TOOL_CALL_GRANT_POLICY_VERSION
    idempotency_key: str = Field(min_length=8, max_length=256)


class ToolCallAttemptRecord(BaseModel):
    """One auditable attempt row bound to a grant."""

    model_config = ConfigDict(extra="forbid")

    attempt_id: str
    grant_id: str
    mode: ToolCallMode
    namespace_key: str
    shadow_run_id: str | None = None
    event_id: str
    tool_name: str
    attempt_seq: int = Field(ge=1)
    status: ToolCallAttemptStatus
    denial_reason: str | None = None
    params_hash: str
    result_status: str | None = None
    projection_hash: str | None = None
    created_at: datetime


class SafeToolProjection(BaseModel):
    """Typed, sanitized tool output safe for LLM consumption."""

    model_config = ConfigDict(extra="forbid")

    tool_name: str
    status: str
    data: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)
    trust_level: str = "untrusted"
    taint_flags: list[str] = Field(default_factory=list)
    projection_hash: str


class ToolCallGrantIssueResult(BaseModel):
    """Opaque grant token returned once at issuance."""

    model_config = ConfigDict(extra="forbid")

    grant: ToolCallGrant
    grant_token: str


__all__ = [
    "DEFAULT_TOOL_CALL_GRANT_POLICY_VERSION",
    "EVIDENCE_COMPATIBILITY_POLICY_VERSION",
    "EVIDENCE_COMPATIBILITY_QUERY_TOOLS",
    "TOOL_CALL_GRANT_SCHEMA_VERSION",
    "BoundExecutionPrincipal",
    "SafeToolProjection",
    "ToolCallAttemptRecord",
    "ToolCallAttemptStatus",
    "ToolCallGrant",
    "ToolCallGrantCreateRequest",
    "ToolCallGrantIssueResult",
    "ToolCallGrantScope",
    "ToolCallMode",
]
