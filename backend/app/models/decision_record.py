"""Durable DecisionRecord contract (ISSUE-131 Phase B).

Sanitized, idempotent decision artifacts referenced from decision_trace entries.
Never stores raw chain-of-thought, prompts, or unredacted tool payloads.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class DecisionStage(StrEnum):
    """Decision lifecycle stage (bounded vocabulary)."""

    REACT_THINK = "react_think"
    REACT_REFLECT = "react_reflect"
    PLANNER = "planner"
    RISK = "risk"
    RESPONSE = "response"
    TRIAGE = "triage"
    EVIDENCE = "evidence"
    VERIFY = "verify"
    OTHER = "other"


class DecisionRecordCandidate(BaseModel):
    """Candidate considered during a decision (type/name/id only)."""

    model_config = ConfigDict(extra="forbid")

    candidate_type: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    candidate_id: str = ""


class DecisionRecord(BaseModel):
    """Sanitized durable decision artifact."""

    model_config = ConfigDict(extra="forbid")

    record_id: str = Field(..., min_length=1)
    event_id: str = Field(..., min_length=1)
    stage: DecisionStage
    actor: str = Field(..., min_length=1)
    input_refs: list[dict[str, str]] = Field(default_factory=list)
    candidates: list[DecisionRecordCandidate] = Field(default_factory=list)
    selected: dict[str, Any] = Field(default_factory=dict)
    reason_codes: list[str] = Field(default_factory=list)
    decision_summary: str = Field(default="", max_length=512)
    rule_version: str | None = None
    model_version: str | None = None
    prompt_policy_version: str | None = None
    kb_version: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    uncertainty_codes: list[str] = Field(default_factory=list)
    guardrail_flags: list[str] = Field(default_factory=list)
    degraded: bool = False
    trace_ref: str | None = None
    schema_version: str = Field(default="1.0", min_length=1)
    record_hash: str = Field(default="", min_length=0)
    idempotency_key: str = Field(..., min_length=1)
    revision: int = Field(default=1, ge=1)
    parent_record_id: str | None = None
    supersedes_record_id: str | None = None
    retention_policy: str = Field(default="standard", min_length=1)
    unresolved_refs: list[str] = Field(default_factory=list)
    owner: str = Field(default="", max_length=128)
    created_at: datetime | None = None

    @field_validator("decision_summary")
    @classmethod
    def _bound_summary(cls, value: str) -> str:
        return value[:512]


__all__ = [
    "DecisionRecord",
    "DecisionRecordCandidate",
    "DecisionStage",
]
