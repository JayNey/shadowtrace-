"""AgentTask / AgentArtifact coordination ledger contracts (ISSUE-133 / #639 Phase A)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

AGENT_TASK_SCHEMA_VERSION = "1.0"
AGENT_ARTIFACT_SCHEMA_VERSION = "1.0"
CONTENT_PROJECTION_SCHEMA_VERSION = "1.0"
DEFAULT_TASK_LEASE_SECONDS = 300

# Allowlisted EventContext fields agents may reference in typed goals/projections.
ALLOWLISTED_EVENT_CONTEXT_FIELDS: frozenset[str] = frozenset(
    {
        "evidence_output",
        "graph_output",
        "rag_output",
        "risk_assessment",
        "triage_result",
        "source_snapshot",
        "detection_context_snapshot",
        "storyline",
        "false_positive_match",
        "fp_adjudication",
    }
)

MAX_GOAL_PARAMETERS_BYTES = 8_192
MAX_PROJECTION_BYTES = 256_000
MAX_ARTIFACT_PAYLOAD_BYTES = 512_000


class AgentTaskStatus(StrEnum):
    """Task lifecycle — at-least-once delivery with exactly-once terminal transitions."""

    QUEUED = "queued"
    CLAIMED = "claimed"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    DEAD = "dead"
    MANUAL = "manual"


TERMINAL_AGENT_TASK_STATUSES: frozenset[AgentTaskStatus] = frozenset(
    {
        AgentTaskStatus.COMPLETED,
        AgentTaskStatus.FAILED,
        AgentTaskStatus.CANCELLED,
        AgentTaskStatus.EXPIRED,
        AgentTaskStatus.DEAD,
        AgentTaskStatus.MANUAL,
    }
)


class AgentTaskType(StrEnum):
    """Phase A task types — single coordinator, no DAG engine."""

    EVIDENCE_COLLECT = "evidence_collect"
    RISK_SCORE = "risk_score"
    REPORT_GENERATE = "report_generate"


class SideEffectStatus(StrEnum):
    NONE = "none"
    UNKNOWN = "unknown"


class AgentTaskContextRef(BaseModel):
    """Allowlisted pointer to EventContext field or prior artifact."""

    model_config = ConfigDict(extra="forbid")

    ref_kind: Literal["event_context_field", "artifact"]
    ref_id: str = Field(min_length=1, max_length=128)
    schema_version: str = Field(default="1.0", min_length=1, max_length=16)

    @model_validator(mode="after")
    def _validate_ref(self) -> AgentTaskContextRef:
        if self.ref_kind == "event_context_field" and self.ref_id not in ALLOWLISTED_EVENT_CONTEXT_FIELDS:
            raise ValueError(f"event_context_field ref not allowlisted: {self.ref_id}")
        return self


class AgentTaskGoal(BaseModel):
    """Versioned typed task input — not free-text instructions."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default=AGENT_TASK_SCHEMA_VERSION, min_length=1, max_length=16)
    task_type: AgentTaskType
    context_refs: list[AgentTaskContextRef] = Field(default_factory=list, max_length=16)
    parameters: dict[str, Any] = Field(default_factory=dict)
    tool_call_grant_id: str | None = Field(default=None, max_length=128)


class AgentTaskClaim(BaseModel):
    """Lease-bound worker claim with fencing token."""

    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(min_length=1, max_length=128)
    fencing_token: str = Field(min_length=16, max_length=256)
    lease_expires_at: datetime
    attempt: int = Field(ge=1)
    worker_principal: str = Field(min_length=1, max_length=128)
    revision: int = Field(ge=1)


class ContentProjection(BaseModel):
    """Schema-validated bounded view — no raw DB dump or CoT."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default=CONTENT_PROJECTION_SCHEMA_VERSION, min_length=1, max_length=16)
    projection_kind: str = Field(min_length=1, max_length=64)
    fields: dict[str, Any] = Field(default_factory=dict)
    source_refs: list[AgentTaskContextRef] = Field(default_factory=list, max_length=16)
    byte_size: int = Field(default=0, ge=0)


class AgentArtifact(BaseModel):
    """Immutable producer output bound to task revision/attempt."""

    model_config = ConfigDict(extra="forbid")

    artifact_id: str = Field(min_length=1, max_length=128)
    task_id: str = Field(min_length=1, max_length=128)
    event_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    logical_artifact_key: str = Field(min_length=1, max_length=128)
    producer_revision: int = Field(ge=1)
    producer_attempt: int = Field(ge=1)
    schema_version: str = Field(default=AGENT_ARTIFACT_SCHEMA_VERSION, min_length=1, max_length=16)
    content_hash: str = Field(min_length=64, max_length=64)
    payload: dict[str, Any] = Field(default_factory=dict)
    source_refs: list[AgentTaskContextRef] = Field(default_factory=list, max_length=16)
    decision_record_refs: list[str] = Field(default_factory=list, max_length=32)
    created_at: datetime

    @field_validator("decision_record_refs")
    @classmethod
    def _normalize_decision_refs(cls, value: list[str]) -> list[str]:
        seen: set[str] = set()
        normalized: list[str] = []
        for item in value:
            token = str(item).strip()
            if not token or token in seen:
                continue
            seen.add(token)
            normalized.append(token[:128])
        return normalized


class AgentTask(BaseModel):
    """Durable coordination ledger row."""

    model_config = ConfigDict(extra="forbid")

    task_id: str
    event_id: str
    tenant_id: str
    task_type: AgentTaskType
    goal: AgentTaskGoal
    status: AgentTaskStatus
    revision: int = Field(default=1, ge=1)
    attempt: int = Field(default=0, ge=0)
    claim_owner: str | None = None
    fencing_token: str | None = None
    lease_expires_at: datetime | None = None
    side_effect_status: SideEffectStatus = SideEffectStatus.NONE
    idempotency_key: str
    schema_version: str = AGENT_TASK_SCHEMA_VERSION
    last_error: str | None = None
    created_at: datetime
    updated_at: datetime


class AgentTaskAttemptRecord(BaseModel):
    """Auditable attempt history for redelivery tracing."""

    model_config = ConfigDict(extra="forbid")

    attempt_id: str
    task_id: str
    attempt_seq: int = Field(ge=1)
    worker_principal: str
    status: AgentTaskStatus
    fencing_token_hash: str
    started_at: datetime
    finished_at: datetime | None = None
    error_summary: str | None = None


class AgentTaskEnqueueRequest(BaseModel):
    """Trusted enqueue input."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    goal: AgentTaskGoal
    idempotency_key: str = Field(min_length=8, max_length=256)


class AgentTaskClaimRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(min_length=1, max_length=128)
    worker_principal: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    lease_seconds: int = Field(default=DEFAULT_TASK_LEASE_SECONDS, ge=1, le=3600)


class AgentArtifactPersistRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    logical_artifact_key: str = Field(min_length=1, max_length=128)
    payload: dict[str, Any] = Field(default_factory=dict)
    source_refs: list[AgentTaskContextRef] = Field(default_factory=list, max_length=16)
    decision_record_refs: list[str] = Field(default_factory=list, max_length=32)
    schema_version: str = Field(default=AGENT_ARTIFACT_SCHEMA_VERSION, min_length=1, max_length=16)


def validate_agent_task_transition(
    current: AgentTaskStatus,
    target: AgentTaskStatus,
    *,
    allow_retry: bool = False,
) -> None:
    """Fail closed on illegal transitions."""
    if current is target:
        return
    allowed: dict[AgentTaskStatus, set[AgentTaskStatus]] = {
        AgentTaskStatus.QUEUED: {AgentTaskStatus.CLAIMED, AgentTaskStatus.CANCELLED, AgentTaskStatus.EXPIRED},
        AgentTaskStatus.CLAIMED: {
            AgentTaskStatus.RUNNING,
            AgentTaskStatus.QUEUED,
            AgentTaskStatus.CANCELLED,
            AgentTaskStatus.EXPIRED,
        },
        AgentTaskStatus.RUNNING: {
            AgentTaskStatus.COMPLETED,
            AgentTaskStatus.FAILED,
            AgentTaskStatus.CANCELLED,
            AgentTaskStatus.MANUAL,
            AgentTaskStatus.DEAD,
        },
        AgentTaskStatus.FAILED: {AgentTaskStatus.QUEUED} if allow_retry else set(),
        AgentTaskStatus.EXPIRED: {AgentTaskStatus.QUEUED} if allow_retry else set(),
    }
    if target in allowed.get(current, set()):
        return
    if current in TERMINAL_AGENT_TASK_STATUSES:
        raise ValueError(f"terminal task cannot transition from {current.value} to {target.value}")
    raise ValueError(f"illegal task transition {current.value} -> {target.value}")


__all__ = [
    "AGENT_ARTIFACT_SCHEMA_VERSION",
    "AGENT_TASK_SCHEMA_VERSION",
    "ALLOWLISTED_EVENT_CONTEXT_FIELDS",
    "CONTENT_PROJECTION_SCHEMA_VERSION",
    "DEFAULT_TASK_LEASE_SECONDS",
    "MAX_ARTIFACT_PAYLOAD_BYTES",
    "MAX_GOAL_PARAMETERS_BYTES",
    "MAX_PROJECTION_BYTES",
    "TERMINAL_AGENT_TASK_STATUSES",
    "AgentArtifact",
    "AgentArtifactPersistRequest",
    "AgentTask",
    "AgentTaskAttemptRecord",
    "AgentTaskClaim",
    "AgentTaskClaimRequest",
    "AgentTaskContextRef",
    "AgentTaskEnqueueRequest",
    "AgentTaskGoal",
    "AgentTaskStatus",
    "AgentTaskType",
    "ContentProjection",
    "SideEffectStatus",
    "validate_agent_task_transition",
]
