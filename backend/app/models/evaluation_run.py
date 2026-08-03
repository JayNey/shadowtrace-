"""Evaluation run artifact contract (ISSUE-105 / #608).

Machine-readable, reproducible evaluation results consumed by CI and (later)
frontend artifact viewers. Does **not** define truth semantics — those live in
``EvaluationCaseTruth`` (#618 Phase A).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.evaluation_truth import SliceType

if TYPE_CHECKING:
    from app.models.evaluation_quality import EvaluationQualityReport

EVALUATION_RUN_SCHEMA_VERSION = "1.0"


class ScorerOutcome(StrEnum):
    """Typed scorer result; unevaluable/error never count as pass."""

    PASS = "pass"
    FAIL = "fail"
    UNEVALUABLE = "unevaluable"
    ERROR = "error"
    SKIPPED = "skipped"  # reserved: explicit scorer opt-out (#642+)


class EvaluationRunStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    UNEVALUABLE = "unevaluable"


class GateVerdict(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    FAIL_CLOSED = "fail_closed"


class EvaluationReleaseRefs(BaseModel):
    """Pinned release identifiers for reproducibility."""

    model_config = ConfigDict(extra="forbid")

    model_release_id: str | None = None
    prompt_release_id: str | None = None
    rule_release_id: str | None = None
    kb_release_id: str | None = None
    config_profile: str = Field(default="mock_p0", min_length=1)


class EvaluationRunConfig(BaseModel):
    """Frozen runner configuration bound into the artifact."""

    model_config = ConfigDict(extra="forbid")

    seed: int = Field(..., ge=0)
    replay_mode: str = Field(default="mock_deterministic", min_length=1)
    replay_fidelity: str = Field(
        default="slice_adapter_stub",
        min_length=1,
        description=(
            "Replay fidelity label. Threat/benign echo expectations; security/knowledge "
            "use slice_adapter_stub until investigate replay (#631) is wired."
        ),
    )
    release_refs: EvaluationReleaseRefs = Field(default_factory=EvaluationReleaseRefs)
    scorer_ids: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


class SecurityCaseObservation(BaseModel):
    """Structured security replay observation for #642 security slice scorers."""

    model_config = ConfigDict(extra="forbid")

    expectation_kind: str = Field(..., min_length=1, max_length=64)
    cross_tenant_denied: bool | None = None
    grant_forgery_rejected: bool | None = None
    grant_budget_race_rejected: bool | None = None
    side_effect_blocked: bool | None = None
    prompt_injection_contained: bool | None = None
    production_store_mutated: bool | None = None
    dependency_degraded: bool | None = None


class KnowledgeCaseObservation(BaseModel):
    """Structured knowledge replay observation for #642 knowledge slice scorers."""

    model_config = ConfigDict(extra="forbid")

    expectation_kind: str = Field(..., min_length=1, max_length=64)
    release_id: str | None = Field(default=None, max_length=128)
    plan_hash: str | None = Field(default=None, min_length=64, max_length=64)
    tenant_filter_applied: bool | None = None
    citation_chunk_ids: list[str] = Field(default_factory=list)
    degraded: bool | None = None
    chunk_count: int | None = Field(default=None, ge=0)
    empty_results: bool | None = None
    dependency_degraded: bool | None = None


class CaseObservation(BaseModel):
    """Deterministic mock-replay observation for one evaluation case."""

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(..., min_length=1)
    slice_type: SliceType
    observed_case_label: str | None = None
    observed_final_verdict: str | None = None
    observed_risk_score: int | None = Field(default=None, ge=0, le=100)
    observed_attack_techniques: list[str] = Field(default_factory=list)
    observed_incident_group_id: str | None = Field(default=None, max_length=128)
    observation_available: bool = True
    replay_notes: str = Field(default="", max_length=512)
    security: SecurityCaseObservation | None = None
    knowledge: KnowledgeCaseObservation | None = None


class EvaluationScorerResult(BaseModel):
    """One scorer outcome for a single case."""

    model_config = ConfigDict(extra="forbid")

    scorer_id: str = Field(..., min_length=1)
    outcome: ScorerOutcome
    reason_code: str = Field(default="", max_length=128)
    message: str = Field(default="", max_length=512)
    details: dict[str, Any] = Field(default_factory=dict)


class EvaluationCaseResult(BaseModel):
    """Aggregated per-case evaluation output."""

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(..., min_length=1)
    truth_id: str = Field(..., min_length=1)
    truth_revision: int = Field(..., ge=1)
    truth_content_hash: str = Field(..., min_length=64, max_length=64)
    slice_type: SliceType
    observation: CaseObservation
    scorer_results: list[EvaluationScorerResult] = Field(default_factory=list)
    case_status: EvaluationRunStatus
    unevaluable_reason: str | None = None
    critical: bool = Field(
        default=False,
        description="When true, gate may fail closed regardless of aggregate pass_rate (#642).",
    )


class EvaluationAggregateMetrics(BaseModel):
    """Dataset-level rollups with explicit denominators."""

    model_config = ConfigDict(extra="forbid")

    case_count: int = Field(..., ge=0)
    pass_count: int = Field(..., ge=0)
    fail_count: int = Field(..., ge=0)
    unevaluable_count: int = Field(..., ge=0)
    error_count: int = Field(..., ge=0)
    pass_rate: float = Field(..., ge=0.0, le=1.0)
    required_scorer_error_count: int = Field(default=0, ge=0)


class EvaluationGateDiff(BaseModel):
    """Machine-readable threshold comparison delta."""

    model_config = ConfigDict(extra="forbid")

    field: str = Field(..., min_length=1)
    expected: Any = None
    actual: Any = None
    reason: str = Field(..., min_length=1)


class EvaluationGateResult(BaseModel):
    """Threshold/baseline gate outcome."""

    model_config = ConfigDict(extra="forbid")

    verdict: GateVerdict
    manifest_version: str = Field(default="", max_length=64)
    manifest_path: str | None = None
    diffs: list[EvaluationGateDiff] = Field(default_factory=list)
    quarantine_active: bool = Field(
        default=False,
        description=(
            "True when an active (non-expired) quarantine overrides threshold "
            "failures; consumers must read diffs alongside verdict."
        ),
    )


class EvaluationThresholdRule(BaseModel):
    """One fail-closed threshold rule."""

    model_config = ConfigDict(extra="forbid")

    metric: str = Field(..., min_length=1)
    op: str = Field(..., pattern="^(gte|lte|eq)$")
    value: float


class EvaluationQuarantinePolicy(BaseModel):
    """Flaky-test quarantine metadata for CI gate management."""

    model_config = ConfigDict(extra="forbid")

    owner: str = Field(..., min_length=1, max_length=128)
    expires_at: datetime | None = None
    reason: str = Field(default="", max_length=512)


class EvaluationThresholdManifest(BaseModel):
    """Versioned gate manifest for a dataset evaluation profile."""

    model_config = ConfigDict(extra="forbid")

    manifest_version: str = Field(..., min_length=1)
    dataset_id: str = Field(..., min_length=1)
    dataset_version: str | None = None
    required_scorers: list[str] = Field(default_factory=list)
    thresholds: list[EvaluationThresholdRule] = Field(default_factory=list)
    min_pass_rate: float = Field(default=1.0, ge=0.0, le=1.0)
    max_error_count: int = Field(default=0, ge=0)
    max_unevaluable_count: int | None = Field(
        default=None,
        ge=0,
        description="When set, fail closed when unevaluable_count exceeds this ceiling.",
    )
    required_gate: bool = Field(default=False)
    require_critical_pass: bool = Field(
        default=True,
        description="Fail closed when any critical case does not complete successfully.",
    )
    max_unexpected_dependency_degraded: int | None = Field(
        default=None,
        ge=0,
        description=(
            "When set, fail closed when unexpected dependency_degraded observations "
            "exceed this count (cases where dependency degraded but not expected)."
        ),
    )
    quarantine: EvaluationQuarantinePolicy | None = None


class EvaluationRunArtifact(BaseModel):
    """Complete evaluation run artifact (persisted as JSON, not a fact DB)."""

    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(..., min_length=1)
    schema_version: str = Field(default=EVALUATION_RUN_SCHEMA_VERSION, min_length=1)
    tenant_id: str = Field(..., min_length=1)
    dataset_id: str = Field(..., min_length=1)
    dataset_version: str = Field(..., min_length=1)
    dataset_content_hash: str = Field(..., min_length=64, max_length=64)
    code_sha: str = Field(..., min_length=7, max_length=64)
    config: EvaluationRunConfig
    started_at: datetime
    completed_at: datetime
    status: EvaluationRunStatus
    case_results: list[EvaluationCaseResult] = Field(default_factory=list)
    aggregates: EvaluationAggregateMetrics
    gate: EvaluationGateResult | None = None
    quality_report: EvaluationQualityReport | None = None
    errors: list[str] = Field(default_factory=list)
    artifact_hash: str = Field(default="", min_length=0, max_length=64)


__all__ = [
    "EVALUATION_RUN_SCHEMA_VERSION",
    "CaseObservation",
    "EvaluationAggregateMetrics",
    "EvaluationCaseResult",
    "EvaluationGateDiff",
    "EvaluationGateResult",
    "EvaluationReleaseRefs",
    "EvaluationRunArtifact",
    "EvaluationRunConfig",
    "EvaluationRunStatus",
    "EvaluationScorerResult",
    "EvaluationQuarantinePolicy",
    "EvaluationThresholdManifest",
    "EvaluationThresholdRule",
    "GateVerdict",
    "KnowledgeCaseObservation",
    "ScorerOutcome",
    "SecurityCaseObservation",
]


def _rebuild_with_quality_report() -> None:
    from app.models.evaluation_quality import EvaluationQualityReport

    EvaluationRunArtifact.model_rebuild(
        _types_namespace={"EvaluationQualityReport": EvaluationQualityReport}
    )


_rebuild_with_quality_report()
