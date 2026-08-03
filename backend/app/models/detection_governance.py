"""Detection governance decision contract (ISSUE-125 / #630 Phase A).

Pre-promotion governance consumes immutable ``DetectionEvaluationArtifact`` (#631)
and emits versioned ``DetectionGovernanceDecision`` records. Approval is decoupled
from production promotion (#629) and must never be inferred from evaluation pass.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.models.detection_evaluation import DetectionCandidateRefs

DETECTION_GOVERNANCE_SCHEMA_VERSION = "1.0"


class DetectionGovernanceDecisionKind(StrEnum):
    """Governance outcome — not package runtime state or promotion status."""

    APPROVE = "approve"
    REJECT = "reject"
    EXPIRE = "expire"
    REVOKE = "revoke"


class DetectionGovernanceReasonCode(StrEnum):
    """Machine-readable eligibility and audit reason codes."""

    ARTIFACT_HASH_MISMATCH = "artifact_hash_mismatch"
    ARTIFACT_INCOMPLETE = "artifact_incomplete"
    ARTIFACT_STATUS_FAILED = "artifact_status_failed"
    GATE_FAIL_CLOSED = "gate_fail_closed"
    GATE_NOT_PASS = "gate_not_pass"
    QUALITY_METRIC_FAIL_CLOSED = "quality_metric_fail_closed"
    QUALITY_METRIC_INSUFFICIENT_SAMPLE = "quality_metric_insufficient_sample"
    TENANT_ISOLATION_FAILED = "tenant_isolation_failed"
    REQUIRED_SCORER_ERRORS = "required_scorer_errors"
    RUNTIME_ERROR_BUDGET_EXCEEDED = "runtime_error_budget_exceeded"
    THRESHOLD_MANIFEST_MISMATCH = "threshold_manifest_mismatch"
    CANDIDATE_BINDING_MISMATCH = "candidate_binding_mismatch"
    REVIEWER_REQUIRED = "reviewer_required"
    POLICY_VERSION_MISMATCH = "policy_version_mismatch"
    DECISION_REVOKED = "decision_revoked"
    DECISION_EXPIRED = "decision_expired"
    DECISION_SUPERSEDED = "decision_superseded"
    MANUAL_REJECT = "manual_reject"
    MANUAL_REVOKE = "manual_revoke"


class DetectionGovernanceCandidateBinding(BaseModel):
    """Pinned candidate identity bound into a governance decision."""

    model_config = ConfigDict(extra="forbid")

    candidate_set_hash: str = Field(..., min_length=64, max_length=64)
    candidate_refs: DetectionCandidateRefs
    feature_contract_version: str = Field(..., min_length=1, max_length=32)
    detection_scope_id: str = Field(..., min_length=1, max_length=128)
    scope_revision_id: str | None = Field(default=None, max_length=128)
    model_release_id: str | None = Field(default=None, max_length=128)
    model_release_hash: str | None = Field(default=None, max_length=64)


class DetectionGovernanceThresholdBinding(BaseModel):
    """Threshold manifest identity frozen at decision time."""

    model_config = ConfigDict(extra="forbid")

    manifest_version: str = Field(..., min_length=1, max_length=64)
    manifest_path: str | None = Field(default=None, max_length=512)


class DetectionGovernanceEvaluationBinding(BaseModel):
    """Evaluation artifact identity frozen at decision time."""

    model_config = ConfigDict(extra="forbid")

    evaluation_id: str = Field(..., min_length=1, max_length=128)
    dataset_id: str = Field(..., min_length=1, max_length=128)
    dataset_version: str = Field(..., min_length=1, max_length=64)
    dataset_content_hash: str = Field(..., min_length=64, max_length=64)
    artifact_hash: str = Field(..., min_length=64, max_length=64)
    code_sha: str = Field(..., min_length=7, max_length=64)


class DetectionGovernanceEligibilityAssessment(BaseModel):
    """Fail-closed eligibility outcome for pre-promotion approval."""

    model_config = ConfigDict(extra="forbid")

    eligible: bool
    reason_codes: list[DetectionGovernanceReasonCode] = Field(default_factory=list)
    messages: list[str] = Field(default_factory=list)


class DetectionGovernanceDecision(BaseModel):
    """Immutable governance record consumable by #629 promotion gate (Phase B+)."""

    model_config = ConfigDict(extra="forbid")

    decision_id: str = Field(..., min_length=1, max_length=128)
    schema_version: str = Field(
        default=DETECTION_GOVERNANCE_SCHEMA_VERSION,
        min_length=1,
    )
    tenant_id: str = Field(..., min_length=1, max_length=128)
    decision: DetectionGovernanceDecisionKind
    candidate_binding: DetectionGovernanceCandidateBinding
    evaluation_binding: DetectionGovernanceEvaluationBinding
    threshold_binding: DetectionGovernanceThresholdBinding
    binding_hash: str = Field(..., min_length=64, max_length=64)
    decision_hash: str = Field(default="", min_length=0, max_length=64)
    policy_version: str = Field(..., min_length=1, max_length=64)
    reviewer_subject: str = Field(..., min_length=1, max_length=256)
    reviewer_roles: list[str] = Field(default_factory=list)
    reason_codes: list[DetectionGovernanceReasonCode] = Field(default_factory=list)
    reason_note: str = Field(default="", max_length=1024)
    decided_at: datetime
    expires_at: datetime | None = None
    supersedes_decision_id: str | None = Field(default=None, max_length=128)


class DetectionGovernanceDecisionRequest(BaseModel):
    """Service/API input to record a governance decision (approve/reject only)."""

    model_config = ConfigDict(extra="forbid")

    decision: DetectionGovernanceDecisionKind
    reason_note: str = Field(default="", max_length=1024)
    expires_at: datetime | None = None


class DetectionGovernanceRevokeRequest(BaseModel):
    """Input to revoke a prior approval."""

    model_config = ConfigDict(extra="forbid")

    reason_note: str = Field(..., min_length=1, max_length=1024)


class DetectionGovernancePromotionGateResult(BaseModel):
    """Promotion eligibility snapshot for #629 (read-only in Phase A)."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    decision_id: str | None = None
    reason_codes: list[DetectionGovernanceReasonCode] = Field(default_factory=list)
    messages: list[str] = Field(default_factory=list)


__all__ = [
    "DETECTION_GOVERNANCE_SCHEMA_VERSION",
    "DetectionGovernanceCandidateBinding",
    "DetectionGovernanceDecision",
    "DetectionGovernanceDecisionKind",
    "DetectionGovernanceDecisionRequest",
    "DetectionGovernanceEligibilityAssessment",
    "DetectionGovernanceEvaluationBinding",
    "DetectionGovernancePromotionGateResult",
    "DetectionGovernanceReasonCode",
    "DetectionGovernanceRevokeRequest",
    "DetectionGovernanceThresholdBinding",
]
