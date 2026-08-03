"""Request-scoped policy retrieval plan with release + profile pinning (ISSUE-129 / #635)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.knowledge_release import KnowledgeQueryPlan

POLICY_QUERY_PLAN_SCHEMA_VERSION = "1.0"


class PolicyQueryPlan(BaseModel):
    """Immutable per-request policy corpus + organization profile pin."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default=POLICY_QUERY_PLAN_SCHEMA_VERSION, min_length=1)
    tenant_id: str = Field(..., min_length=1, max_length=128)
    principal: str = Field(..., min_length=1, max_length=128)
    knowledge_plan: KnowledgeQueryPlan
    profile_id: str | None = Field(default=None, max_length=128)
    profile_revision: int | None = Field(default=None, ge=1)
    plan_hash: str = Field(default="", min_length=0, max_length=64)
    pinned_at: datetime


__all__ = [
    "POLICY_QUERY_PLAN_SCHEMA_VERSION",
    "PolicyQueryPlan",
]
