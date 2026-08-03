"""Post-promotion detection comparison artifact (ISSUE-126 / #631 Phase B).

Compares completed promotion outcomes (#629) and trusted context snapshots (#633)
against an immutable pre-promotion ``DetectionEvaluationArtifact``. Emits advisory
recommendations only — does not modify models/rules or overwrite Phase A artifacts.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.models.detection_context_snapshot import DetectionContextEvaluationRefs
from app.models.evaluation_run import EvaluationRunStatus
from app.models.evaluation_truth import SliceType

DETECTION_PRODUCTION_COMPARISON_SCHEMA_VERSION = "1.0"


class DetectionProductionRecommendationKind(StrEnum):
    """Advisory recommendation — not an approval or automatic rollback."""

    CONTINUE = "continue"
    MONITOR = "monitor"
    ROLLBACK_RECOMMENDED = "rollback_recommended"
    INSUFFICIENT_DATA = "insufficient_data"


class DetectionProductionOutcomeStatus(StrEnum):
    """Shadow vs production alignment for one evaluation case."""

    ALIGNED = "aligned"
    DRIFT = "drift"
    MISSING_PROMOTION = "missing_promotion"
    UNEXPECTED_PROMOTION = "unexpected_promotion"
    SNAPSHOT_MISSING = "snapshot_missing"
    NOT_APPLICABLE = "not_applicable"


class DetectionProductionCaseBinding(BaseModel):
    """Fixture/manifest expectation for one promoted evaluation case."""

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(..., min_length=1)
    expect_promotion: bool = True
    expected_production_severity: str | None = Field(default=None, max_length=32)
    min_coverage_ready_ratio: float | None = Field(default=None, ge=0.0, le=1.0)


class DetectionProductionBindingManifest(BaseModel):
    """Pinned case bindings for production comparison datasets."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default="1.0", min_length=1)
    shadow_dataset_id: str = Field(..., min_length=1)
    shadow_dataset_version: str = Field(..., min_length=1)
    bindings: list[DetectionProductionCaseBinding] = Field(default_factory=list)
    content_hash: str = Field(default="", min_length=0, max_length=64)


class DetectionProductionComparisonConfig(BaseModel):
    """Frozen comparison configuration bound into the artifact."""

    model_config = ConfigDict(extra="forbid")

    phase_a_artifact_hash: str = Field(..., min_length=64, max_length=64)
    phase_a_evaluation_id: str = Field(..., min_length=1, max_length=128)
    binding_manifest_hash: str = Field(..., min_length=64, max_length=64)
    comparison_fidelity: str = Field(
        default="production_post_promotion_v1",
        min_length=1,
        description="Production signals from #629 promotions + #633 context snapshots.",
    )
    seed: int = Field(
        default=0,
        ge=0,
        description="Reserved comparison run seed for provenance (not used in diff logic).",
    )


class DetectionProductionCaseComparison(BaseModel):
    """Per-case shadow vs production outcome comparison."""

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(..., min_length=1)
    slice_type: SliceType
    shadow_case_status: EvaluationRunStatus
    shadow_candidate_count: int = Field(default=0, ge=0)
    outcome_status: DetectionProductionOutcomeStatus
    promotion_id: str | None = Field(default=None, max_length=128)
    event_id: str | None = Field(default=None, max_length=128)
    candidate_detection_id: str | None = Field(default=None, max_length=128)
    production_severity: str | None = Field(default=None, max_length=32)
    coverage_ready_count: int | None = Field(default=None, ge=0)
    coverage_total_count: int | None = Field(default=None, ge=0)
    drift_reasons: list[str] = Field(default_factory=list, max_length=16)


class DetectionProductionCoverageDrift(BaseModel):
    """Dataset-level production coverage drift rollup."""

    model_config = ConfigDict(extra="forbid")

    compared_case_count: int = Field(default=0, ge=0)
    production_ready_snapshot_total: int = Field(default=0, ge=0)
    production_feature_snapshot_total: int = Field(default=0, ge=0)
    production_insufficient_coverage_total: int = Field(default=0, ge=0)
    drift_detected: bool = False
    drift_reasons: list[str] = Field(default_factory=list, max_length=16)


class DetectionProductionComparisonArtifact(BaseModel):
    """Immutable post-promotion comparison artifact (separate from Phase A)."""

    model_config = ConfigDict(extra="forbid")

    comparison_id: str = Field(..., min_length=1)
    schema_version: str = Field(
        default=DETECTION_PRODUCTION_COMPARISON_SCHEMA_VERSION,
        min_length=1,
    )
    tenant_id: str = Field(..., min_length=1)
    code_sha: str = Field(..., min_length=7, max_length=64)
    phase_a_refs: DetectionContextEvaluationRefs
    config: DetectionProductionComparisonConfig
    started_at: datetime
    completed_at: datetime
    status: EvaluationRunStatus
    case_comparisons: list[DetectionProductionCaseComparison] = Field(default_factory=list)
    coverage_drift: DetectionProductionCoverageDrift = Field(
        default_factory=DetectionProductionCoverageDrift
    )
    recommendation: DetectionProductionRecommendationKind
    recommendation_reasons: list[str] = Field(default_factory=list, max_length=16)
    errors: list[str] = Field(default_factory=list)
    artifact_hash: str = Field(default="", min_length=0, max_length=64)
    advisory_note: str = Field(
        default=(
            "Advisory recommendation only; does not modify models/rules, "
            "governance state, or the Phase A evaluation artifact."
        ),
        max_length=512,
    )


__all__ = [
    "DETECTION_PRODUCTION_COMPARISON_SCHEMA_VERSION",
    "DetectionProductionBindingManifest",
    "DetectionProductionCaseBinding",
    "DetectionProductionCaseComparison",
    "DetectionProductionComparisonArtifact",
    "DetectionProductionComparisonConfig",
    "DetectionProductionCoverageDrift",
    "DetectionProductionOutcomeStatus",
    "DetectionProductionRecommendationKind",
]
