"""Immutable detection context snapshot contracts (ISSUE-127 / #633).

Trusted projector output from completed promotion sagas (#629). Single writer;
append-only revisions; consumers read by snapshot revision without re-joining
candidate/governance/evaluation facts.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

DETECTION_CONTEXT_SNAPSHOT_SCHEMA_VERSION = "1.0"


class DetectionContextEvidenceRefKind(StrEnum):
    """Ordered evidence anchor kinds pinned into a snapshot."""

    BEHAVIOR_OBSERVATION = "behavior_observation"
    FEATURE_SNAPSHOT = "feature_snapshot"
    SOURCE_RECORD = "source_record"
    PROMOTION = "promotion"


class DetectionContextEvidenceRef(BaseModel):
    """One ordered evidence anchor — investigation namespace refs only."""

    model_config = ConfigDict(extra="forbid")

    ref_kind: DetectionContextEvidenceRefKind
    ref_id: str = Field(..., min_length=1, max_length=128)
    ordinal: int = Field(..., ge=0)


class DetectionContextAttackRef(BaseModel):
    """ATT&CK technique pin — structured ids only, no narrative text."""

    model_config = ConfigDict(extra="forbid")

    technique_id: str = Field(..., min_length=1, max_length=32)
    technique_name: str | None = Field(default=None, max_length=128)
    source: Literal["rule", "evaluation", "unknown"] = "unknown"


class DetectionContextReleaseRefs(BaseModel):
    """Pinned release identities for candidate/rule/model/feature/scope."""

    model_config = ConfigDict(extra="forbid")

    candidate_detection_id: str = Field(..., min_length=1, max_length=128)
    candidate_content_hash: str = Field(..., min_length=64, max_length=64)
    package_id: str = Field(..., min_length=1, max_length=128)
    package_version: int = Field(..., ge=1)
    package_content_hash: str = Field(..., min_length=64, max_length=64)
    rule_id: str = Field(..., min_length=1, max_length=128)
    rule_version: int = Field(..., ge=1)
    feature_contract_version: str = Field(..., min_length=1, max_length=32)
    detection_scope_id: str = Field(..., min_length=1, max_length=128)
    scope_revision_id: str | None = Field(default=None, max_length=128)
    model_release_id: str | None = Field(default=None, max_length=128)
    model_release_hash: str | None = Field(default=None, max_length=64)


class DetectionContextGovernanceRefs(BaseModel):
    """Governance decision pins frozen at promotion time."""

    model_config = ConfigDict(extra="forbid")

    decision_id: str = Field(..., min_length=1, max_length=128)
    binding_hash: str = Field(..., min_length=64, max_length=64)
    decision_hash: str = Field(..., min_length=64, max_length=64)
    candidate_set_hash: str = Field(..., min_length=64, max_length=64)


class DetectionContextEvaluationRefs(BaseModel):
    """Evaluation artifact pins from governance binding."""

    model_config = ConfigDict(extra="forbid")

    evaluation_id: str = Field(..., min_length=1, max_length=128)
    artifact_hash: str = Field(..., min_length=64, max_length=64)
    dataset_id: str = Field(..., min_length=1, max_length=128)
    dataset_version: str = Field(..., min_length=1, max_length=64)
    dataset_content_hash: str = Field(..., min_length=64, max_length=64)
    code_sha: str = Field(..., min_length=7, max_length=64)


class DetectionContextScoreSummary(BaseModel):
    """Typed detection scores — no free-text model output."""

    model_config = ConfigDict(extra="forbid")

    matched_value: float = Field(..., ge=0)
    detection_score: float | None = Field(default=None, ge=0.0, le=100.0)
    severity: str = Field(..., min_length=1, max_length=32)
    operator: str = Field(..., min_length=1, max_length=32)


class DetectionContextCoverageSummary(BaseModel):
    """Coverage/status rollup for pinned feature snapshots."""

    model_config = ConfigDict(extra="forbid")

    feature_snapshot_count: int = Field(default=0, ge=0)
    ready_snapshot_count: int = Field(default=0, ge=0)
    insufficient_history_count: int = Field(default=0, ge=0)
    insufficient_coverage_count: int = Field(default=0, ge=0)


class DetectionContextSnapshot(BaseModel):
    """Immutable detection context revision for one promoted event."""

    model_config = ConfigDict(extra="forbid")

    snapshot_id: str = Field(..., min_length=1, max_length=128)
    schema_version: str = Field(
        default=DETECTION_CONTEXT_SNAPSHOT_SCHEMA_VERSION,
        min_length=1,
    )
    tenant_id: str = Field(..., min_length=1, max_length=128)
    event_id: str = Field(..., min_length=1, max_length=128)
    event_revision: int = Field(..., ge=1)
    promotion_id: str = Field(..., min_length=1, max_length=128)
    promotion_link_revision: int = Field(..., ge=1)
    promotion_key: str = Field(..., min_length=1, max_length=512)
    release_refs: DetectionContextReleaseRefs
    governance_refs: DetectionContextGovernanceRefs
    evaluation_refs: DetectionContextEvaluationRefs
    evidence_refs: list[DetectionContextEvidenceRef] = Field(default_factory=list)
    attack_refs: list[DetectionContextAttackRef] = Field(default_factory=list)
    scores: DetectionContextScoreSummary
    coverage: DetectionContextCoverageSummary = Field(
        default_factory=DetectionContextCoverageSummary
    )
    projection_errors: list[str] = Field(default_factory=list, max_length=16)
    revision: int = Field(default=1, ge=1)
    supersedes_snapshot_id: str | None = Field(default=None, max_length=128)
    content_hash: str = Field(..., min_length=64, max_length=64)
    idempotency_key: str = Field(..., min_length=1, max_length=512)
    created_at: datetime | None = None


class DetectionContextSnapshotRef(BaseModel):
    """Compact ref written to EventContext for read-only consumers."""

    model_config = ConfigDict(extra="forbid")

    snapshot_id: str = Field(..., min_length=1, max_length=128)
    revision: int = Field(..., ge=1)
    content_hash: str = Field(..., min_length=64, max_length=64)
    promotion_id: str = Field(..., min_length=1, max_length=128)
    promotion_link_revision: int = Field(..., ge=1)
    event_revision: int = Field(..., ge=1)
    created_at: datetime | None = None


class DetectionContextSnapshotQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(..., min_length=1, max_length=128)
    event_id: str | None = Field(default=None, max_length=128)
    promotion_id: str | None = Field(default=None, max_length=128)
    revision: int | None = Field(default=None, ge=1)
    latest_only: bool = True


class DetectionContextSnapshotListResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total: int = Field(..., ge=0)
    items: list[DetectionContextSnapshot] = Field(default_factory=list)


__all__ = [
    "DETECTION_CONTEXT_SNAPSHOT_SCHEMA_VERSION",
    "DetectionContextAttackRef",
    "DetectionContextCoverageSummary",
    "DetectionContextEvaluationRefs",
    "DetectionContextEvidenceRef",
    "DetectionContextEvidenceRefKind",
    "DetectionContextGovernanceRefs",
    "DetectionContextReleaseRefs",
    "DetectionContextScoreSummary",
    "DetectionContextSnapshot",
    "DetectionContextSnapshotListResult",
    "DetectionContextSnapshotQuery",
    "DetectionContextSnapshotRef",
]
