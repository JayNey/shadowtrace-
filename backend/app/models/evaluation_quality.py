"""Offline evaluation quality report contract (ISSUE-113 Phase B).

Dataset-level metrics with explicit denominators, fail-closed semantics, and
confidence intervals. Consumed by the #608 evaluation runner artifact.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.models.evaluation_run import EvaluationReleaseRefs

EVALUATION_QUALITY_SCHEMA_VERSION = "1.0"


class QualityMetricStatus(StrEnum):
    """Whether a metric value is safe to interpret."""

    COMPUTED = "computed"
    FAIL_CLOSED = "fail_closed"
    INSUFFICIENT_SAMPLE = "insufficient_sample"


class MetricDenominator(BaseModel):
    """Explicit numerator/denominator with missing-truth and error accounting."""

    model_config = ConfigDict(extra="forbid")

    numerator: int = Field(..., ge=0)
    denominator: int = Field(..., ge=0)
    missing_truth_count: int = Field(default=0, ge=0)
    error_count: int = Field(default=0, ge=0)


class ConfidenceInterval(BaseModel):
    """Wilson score interval for a proportion metric."""

    model_config = ConfigDict(extra="forbid")

    lower: float = Field(..., ge=0.0, le=1.0)
    upper: float = Field(..., ge=0.0, le=1.0)
    level: float = Field(default=0.95, ge=0.0, le=1.0)
    method: str = Field(default="wilson", min_length=1, max_length=32)


class QualityMetricValue(BaseModel):
    """One typed offline quality metric."""

    model_config = ConfigDict(extra="forbid")

    metric_id: str = Field(..., min_length=1, max_length=64)
    value: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Null when status is fail_closed or insufficient_sample.",
    )
    status: QualityMetricStatus
    denominator: MetricDenominator
    confidence_interval: ConfidenceInterval | None = None
    reason: str = Field(default="", max_length=256)


class GroupingScorerSummary(BaseModel):
    """Rollup for optional severity/ATT&CK/incident grouping scorers."""

    model_config = ConfigDict(extra="forbid")

    scorer_id: str = Field(..., min_length=1, max_length=64)
    evaluated_count: int = Field(..., ge=0)
    pass_count: int = Field(default=0, ge=0)
    fail_count: int = Field(default=0, ge=0)
    not_applicable_count: int = Field(default=0, ge=0)
    error_count: int = Field(default=0, ge=0)


class EvaluationQualityReport(BaseModel):
    """Machine-readable offline quality report bound to one evaluation run."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default=EVALUATION_QUALITY_SCHEMA_VERSION, min_length=1)
    dataset_id: str = Field(..., min_length=1, max_length=128)
    dataset_version: str = Field(..., min_length=1, max_length=64)
    dataset_content_hash: str = Field(..., min_length=64, max_length=64)
    code_sha: str = Field(..., min_length=7, max_length=64)
    release_refs: EvaluationReleaseRefs = Field(default_factory=EvaluationReleaseRefs)
    sample_counts: dict[str, int] = Field(default_factory=dict)
    metrics: list[QualityMetricValue] = Field(default_factory=list)
    grouping_scorer_summaries: list[GroupingScorerSummary] = Field(default_factory=list)


__all__ = [
    "EVALUATION_QUALITY_SCHEMA_VERSION",
    "ConfidenceInterval",
    "EvaluationQualityReport",
    "GroupingScorerSummary",
    "MetricDenominator",
    "QualityMetricStatus",
    "QualityMetricValue",
]
