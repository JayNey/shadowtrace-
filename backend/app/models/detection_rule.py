"""Detection-as-Code rule runtime contracts — ISSUE-121 / #626.

Executable rule packages are versioned, tenant/scope-safe, and deterministic.
Runtime lifecycle (draft/validated/shadow_active/disabled) is separate from
governance approval (#630) and production promotion (#629).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

DETECTION_RULE_SCHEMA_VERSION = "1.0"
CANDIDATE_DETECTION_SCHEMA_VERSION = "1.0"
DEFAULT_MAX_OBSERVATION_SCAN = 1000

PHASE_A_OPERATORS = frozenset({"event_match", "event_count", "value_count"})


class DetectionRuleRuntimeState(StrEnum):
    """Executable package state — not governance approval or production promotion."""

    DRAFT = "draft"
    VALIDATED = "validated"
    SHADOW_ACTIVE = "shadow_active"
    DISABLED = "disabled"


class RuleOperatorKind(StrEnum):
    """Phase A operators supported by the minimal runtime."""

    EVENT_MATCH = "event_match"
    EVENT_COUNT = "event_count"
    VALUE_COUNT = "value_count"


class MissingDataPolicy(StrEnum):
    """Behavior when required fields or snapshot signal is absent."""

    SKIP = "skip"
    FAIL = "fail"
    TREAT_AS_ZERO = "treat_as_zero"


class DetectionRulePackageProvenance(BaseModel):
    """Authoring and review trace — not a substitute for #630 governance."""

    model_config = ConfigDict(extra="forbid")

    author: str = Field(..., min_length=1, max_length=128)
    review_artifact_ref: str | None = Field(default=None, max_length=256)
    test_artifact_ref: str | None = Field(default=None, max_length=256)
    compiled_at: datetime | None = None


class DetectionRuleDefinition(BaseModel):
    """Single compiled rule within a package."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(..., min_length=1, max_length=128)
    rule_version: int = Field(..., ge=1)
    operator: RuleOperatorKind
    feature_contract_version: str = Field(..., min_length=1, max_length=32)
    detection_scope_id: str = Field(..., min_length=1, max_length=128)
    window_kind: str = Field(..., min_length=1, max_length=16)
    group_key_fields: list[str] = Field(..., min_length=1, max_length=8)
    threshold: float = Field(..., ge=0)
    severity: str = Field(..., min_length=1, max_length=32)
    required_fields: list[str] = Field(default_factory=list, max_length=16)
    missing_data_policy: MissingDataPolicy = MissingDataPolicy.SKIP
    match_criteria: dict[str, Any] = Field(default_factory=dict)
    value_field: str | None = Field(default=None, max_length=128)
    max_observation_scan: int = Field(default=DEFAULT_MAX_OBSERVATION_SCAN, ge=1, le=10_000)

    @field_validator("group_key_fields")
    @classmethod
    def _validate_group_key_fields(cls, value: list[str]) -> list[str]:
        allowed = {"entity_type", "entity_id", "category", "action"}
        for field_name in value:
            if field_name not in allowed:
                raise ValueError(f"unsupported group key field: {field_name}")
        return value


class DetectionRulePackage(BaseModel):
    """Versioned, compilable rule bundle."""

    model_config = ConfigDict(extra="forbid")

    package_id: str = Field(..., min_length=1, max_length=128)
    source_tenant_id: str = Field(..., min_length=1, max_length=128)
    package_version: int = Field(..., ge=1)
    runtime_state: DetectionRuleRuntimeState
    rules: list[DetectionRuleDefinition] = Field(..., min_length=1, max_length=64)
    provenance: DetectionRulePackageProvenance
    content_hash: str = Field(..., min_length=64, max_length=64)
    idempotency_key: str = Field(..., min_length=1, max_length=512)
    schema_version: str = Field(default=DETECTION_RULE_SCHEMA_VERSION, min_length=1)
    supersedes_package_id: str | None = Field(default=None, max_length=128)
    created_at: datetime | None = None


class CandidateDetectionProvenance(BaseModel):
    """Evidence anchors for shadow candidate output."""

    model_config = ConfigDict(extra="forbid")

    observation_ids: list[str] = Field(default_factory=list, max_length=256)
    snapshot_ids: list[str] = Field(default_factory=list, max_length=64)
    window_start: datetime | None = None
    window_end: datetime | None = None


class CandidateDetection(BaseModel):
    """Shadow-only detection candidate — never creates Event/SourceAlert."""

    model_config = ConfigDict(extra="forbid")

    candidate_detection_id: str = Field(..., min_length=1, max_length=128)
    source_tenant_id: str = Field(..., min_length=1, max_length=128)
    detection_scope_id: str = Field(..., min_length=1, max_length=128)
    package_id: str = Field(..., min_length=1, max_length=128)
    package_version: int = Field(..., ge=1)
    rule_id: str = Field(..., min_length=1, max_length=128)
    rule_version: int = Field(..., ge=1)
    operator: RuleOperatorKind
    group_key: dict[str, str] = Field(default_factory=dict)
    cutoff_at: datetime
    window_kind: str = Field(..., min_length=1, max_length=16)
    matched_value: float = Field(..., ge=0)
    severity: str = Field(..., min_length=1, max_length=32)
    shadow_only: Literal[True] = True
    provenance: CandidateDetectionProvenance
    content_hash: str = Field(..., min_length=64, max_length=64)
    idempotency_key: str = Field(..., min_length=1, max_length=512)
    schema_version: str = Field(default=CANDIDATE_DETECTION_SCHEMA_VERSION, min_length=1)
    created_at: datetime | None = None


class DetectionRuleRuntimeError(BaseModel):
    """Typed runtime failure — never silently treated as benign."""

    model_config = ConfigDict(extra="forbid")

    error_id: str = Field(..., min_length=1, max_length=128)
    source_tenant_id: str = Field(..., min_length=1, max_length=128)
    package_id: str = Field(..., min_length=1, max_length=128)
    rule_id: str | None = Field(default=None, max_length=128)
    error_category: str = Field(..., min_length=1, max_length=64)
    error_message: str = Field(..., min_length=1, max_length=512)
    detail: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None


class DetectionRulePackageQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_tenant_id: str = Field(..., min_length=1, max_length=128)
    runtime_state: DetectionRuleRuntimeState | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)


class DetectionRulePackageListResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total: int = Field(..., ge=0)
    page: int = Field(..., ge=1)
    page_size: int = Field(..., ge=1)
    items: list[DetectionRulePackage] = Field(default_factory=list)


class CandidateDetectionQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_tenant_id: str = Field(..., min_length=1, max_length=128)
    detection_scope_id: str | None = Field(default=None, max_length=128)
    package_id: str | None = Field(default=None, max_length=128)
    rule_id: str | None = Field(default=None, max_length=128)
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)


class CandidateDetectionListResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total: int = Field(..., ge=0)
    page: int = Field(..., ge=1)
    page_size: int = Field(..., ge=1)
    items: list[CandidateDetection] = Field(default_factory=list)


class DetectionRuleRuntimeResult(BaseModel):
    """Execution outcome for one shadow run."""

    model_config = ConfigDict(extra="forbid")

    candidates: list[CandidateDetection] = Field(default_factory=list)
    errors: list[DetectionRuleRuntimeError] = Field(default_factory=list)
    rules_evaluated: int = Field(default=0, ge=0)
    observations_scanned: int = Field(default=0, ge=0)
