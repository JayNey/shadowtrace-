"""Canonical evaluation truth contract (ISSUE-113 Phase A).

``EvaluationCaseTruth`` is the single source of adjudicated ground truth for
offline/shadow evaluation. It is **not** agent output, runtime severity, or
response outcome — those are operational observations compared against truth.

Other issues (#608 runner, #642 slice scorers) consume this contract; they must
not create parallel truth tables or schemas.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import CaseLabel, FinalVerdict

EVALUATION_TRUTH_SCHEMA_VERSION = "1.0"
SLICE_EXPECTATION_SCHEMA_VERSION = "1.0"
SLICE_EXPECTATION_SCHEMA_VERSION_1_1 = "1.1"


class SliceType(StrEnum):
    """Evaluation slices; extend via reviewed schema revision only (#618 / #642)."""

    THREAT = "threat"
    BENIGN = "benign"
    UNEVALUABLE = "unevaluable"
    SECURITY = "security"
    KNOWLEDGE = "knowledge"
    AGENTIC = "agentic"
    COORDINATION = "coordination"


class SecurityExpectationKind(StrEnum):
    """Typed security slice expectations (Phase A deterministic cases)."""

    CROSS_TENANT_DENIED = "cross_tenant_denied"
    GRANT_FORGERY_REJECTED = "grant_forgery_rejected"  # Issue alias: approval forgery
    GRANT_BUDGET_RACE = "grant_budget_race"
    SIDE_EFFECT_BLOCKED = "side_effect_blocked"
    SIDE_EFFECT_UNKNOWN = "side_effect_unknown"
    PROMPT_INJECTION_CONTAINED = "prompt_injection_contained"
    PRODUCTION_ISOLATION = "production_isolation"


class KnowledgeExpectationKind(StrEnum):
    """Typed knowledge slice expectations (Phase A deterministic cases)."""

    RELEASE_PINNED_RETRIEVAL = "release_pinned_retrieval"
    CITATION_CORRECTNESS = "citation_correctness"
    TENANT_FILTER = "tenant_filter"
    DEGRADED_NO_RELEASE = "degraded_no_release"


class AgenticExpectationKind(StrEnum):
    """Typed ReAct shadow pivot expectations (#642 Phase B / #641)."""

    SHADOW_ISOLATION = "shadow_isolation"
    BOUNDED_PIVOT_SUCCESS = "bounded_pivot_success"
    EVIDENCE_FIDELITY = "evidence_fidelity"
    NO_RAW_COT = "no_raw_cot"
    SHADOW_CROSS_TENANT_DENIED = "shadow_cross_tenant_denied"
    SHADOW_BUDGET_RACE = "shadow_budget_race"
    SHADOW_DEGRADED_FAIL_CLOSED = "shadow_degraded_fail_closed"
    SHADOW_UNSUPPORTED_TOOL_DENIED = "shadow_unsupported_tool_denied"


class CoordinationExpectationKind(StrEnum):
    """Typed task/artifact coordination expectations (#642 Phase C / #639)."""

    STALE_FENCING_DENIED = "stale_fencing_denied"
    ARTIFACT_IDEMPOTENT_REPLAY = "artifact_idempotent_replay"
    ATTEMPT_HISTORY_AUDITABLE = "attempt_history_auditable"
    CROSS_TENANT_TASK_DENIED = "cross_tenant_task_denied"
    PROMPT_INJECTION_PROJECTION_DENIED = "prompt_injection_projection_denied"
    FORGED_GRANT_DENIED = "forged_grant_denied"
    CRASH_RETRY_NO_DUPLICATE_TERMINAL = "crash_retry_no_duplicate_terminal"
    SIDE_EFFECT_UNKNOWN_MANUAL = "side_effect_unknown_manual"


class TruthObservationRef(BaseModel):
    """Immutable observation anchor (source object, scenario pack, etc.)."""

    model_config = ConfigDict(extra="forbid")

    ref_type: str = Field(..., min_length=1, max_length=64)
    ref_id: str = Field(..., min_length=1, max_length=128)
    source_product: str | None = Field(default=None, max_length=64)
    connector_id: str | None = Field(default=None, max_length=64)


class LabelProvenance(BaseModel):
    """Who adjudicated the label and when — append-only across revisions."""

    model_config = ConfigDict(extra="forbid")

    adjudicator: str = Field(..., min_length=1, max_length=128)
    adjudicated_at: datetime
    source_kind: str = Field(..., min_length=1, max_length=64)
    revision_notes: str = Field(default="", max_length=512)

    @field_validator("revision_notes")
    @classmethod
    def _bound_notes(cls, value: str) -> str:
        return value[:512]


class OperationalTruthMapping(BaseModel):
    """Maps semantic truth to operational anchors for shadow replay.

    ``event_id`` / ``detection_id`` / ``disposition_id`` reference runtime
    Event/Detection/Disposition state. They are evaluation anchors, **not**
    ground truth. Never copy agent severity, verdict, or response outcome here.
    """

    model_config = ConfigDict(extra="forbid")

    mapping_version: str = Field(default="1.0", min_length=1)
    event_id: str | None = Field(default=None, max_length=128)
    detection_id: str | None = Field(default=None, max_length=128)
    disposition_id: str | None = Field(default=None, max_length=128)
    notes: str = Field(default="", max_length=256)

    @field_validator("notes")
    @classmethod
    def _bound_notes(cls, value: str) -> str:
        return value[:256]


class ThreatSliceExpectation(BaseModel):
    """Expectation for confirmed-threat cases."""

    model_config = ConfigDict(extra="forbid")

    slice_type: Literal["threat"] = "threat"
    schema_version: str = Field(default=SLICE_EXPECTATION_SCHEMA_VERSION, min_length=1)
    expected_case_label: CaseLabel = CaseLabel.TRUE_POSITIVE
    expected_final_verdict: FinalVerdict = FinalVerdict.CONFIRMED_THREAT
    expected_risk_score: int | None = Field(default=None, ge=0, le=100)
    expected_attack_techniques: list[str] = Field(default_factory=list)
    expected_incident_group_id: str | None = Field(default=None, max_length=128)


class BenignSliceExpectation(BaseModel):
    """Expectation for confirmed-benign / false-positive cases."""

    model_config = ConfigDict(extra="forbid")

    slice_type: Literal["benign"] = "benign"
    schema_version: str = Field(default=SLICE_EXPECTATION_SCHEMA_VERSION, min_length=1)
    expected_case_label: CaseLabel = CaseLabel.FALSE_POSITIVE
    expected_final_verdict: FinalVerdict = FinalVerdict.FALSE_POSITIVE
    expected_risk_score: int | None = Field(default=None, ge=0, le=100)
    expected_attack_techniques: list[str] = Field(default_factory=list)
    expected_incident_group_id: str | None = Field(default=None, max_length=128)


class UnevaluableSliceExpectation(BaseModel):
    """Explicit unevaluable slice — unknown truth must not default to benign."""

    model_config = ConfigDict(extra="forbid")

    slice_type: Literal["unevaluable"] = "unevaluable"
    schema_version: str = Field(default=SLICE_EXPECTATION_SCHEMA_VERSION, min_length=1)
    reason_code: str = Field(..., min_length=1, max_length=64)
    detail: str = Field(default="", max_length=512)

    @field_validator("detail")
    @classmethod
    def _bound_detail(cls, value: str) -> str:
        return value[:512]


class SecuritySliceExpectation(BaseModel):
    """Security gate expectations — cross-tenant, grant, side-effect, isolation."""

    model_config = ConfigDict(extra="forbid")

    slice_type: Literal["security"] = "security"
    schema_version: str = Field(default=SLICE_EXPECTATION_SCHEMA_VERSION_1_1, min_length=1)
    expectation_kind: SecurityExpectationKind
    critical: bool = Field(default=True)
    expected_cross_tenant_denied: bool | None = None
    expected_grant_forgery_rejected: bool | None = None
    expected_grant_budget_race_rejected: bool | None = None
    expected_side_effect_blocked: bool | None = None
    expected_side_effect_unknown_contained: bool | None = None
    expected_prompt_injection_contained: bool | None = None
    expected_production_store_mutated: bool = False
    replay_variant: str = Field(default="pass", min_length=1, max_length=32)


class KnowledgeSliceExpectation(BaseModel):
    """Knowledge retrieval expectations — release pinning, citation, filters."""

    model_config = ConfigDict(extra="forbid")

    slice_type: Literal["knowledge"] = "knowledge"
    schema_version: str = Field(default=SLICE_EXPECTATION_SCHEMA_VERSION_1_1, min_length=1)
    expectation_kind: KnowledgeExpectationKind
    critical: bool = Field(default=False)
    expected_release_id: str | None = Field(default=None, max_length=128)
    expected_plan_hash: str | None = Field(default=None, min_length=64, max_length=64)
    expected_citation_chunk_ids: list[str] = Field(default_factory=list)
    expected_tenant_filter_applied: bool | None = None
    expected_degraded: bool = False
    expected_empty_results: bool = False
    replay_variant: str = Field(default="pass", min_length=1, max_length=32)


class AgenticSliceExpectation(BaseModel):
    """ReAct shadow pivot expectations — isolation, bounded pivot, evidence fidelity."""

    model_config = ConfigDict(extra="forbid")

    slice_type: Literal["agentic"] = "agentic"
    schema_version: str = Field(default=SLICE_EXPECTATION_SCHEMA_VERSION_1_1, min_length=1)
    expectation_kind: AgenticExpectationKind
    critical: bool = Field(default=True)
    expected_production_store_mutated: bool = False
    expected_shadow_namespace_used: bool | None = None
    expected_pivot_completed: bool | None = None
    expected_typed_artifact_produced: bool | None = None
    expected_step_count_within_bounds: bool | None = None
    expected_evidence_refs_valid: bool | None = None
    expected_raw_cot_persisted: bool | None = None
    expected_cross_tenant_denied: bool | None = None
    expected_budget_race_rejected: bool | None = None
    expected_degraded_fail_closed: bool | None = None
    expected_unsupported_tool_denied: bool | None = None
    replay_variant: str = Field(default="pass", min_length=1, max_length=32)


class CoordinationSliceExpectation(BaseModel):
    """Task/artifact coordination expectations — fencing, replay, crash recovery."""

    model_config = ConfigDict(extra="forbid")

    slice_type: Literal["coordination"] = "coordination"
    schema_version: str = Field(default=SLICE_EXPECTATION_SCHEMA_VERSION_1_1, min_length=1)
    expectation_kind: CoordinationExpectationKind
    critical: bool = Field(default=True)
    expected_stale_fencing_denied: bool | None = None
    expected_duplicate_logical_artifact: bool | None = None
    expected_content_hash_match: bool | None = None
    expected_attempt_recorded: bool | None = None
    expected_cross_tenant_denied: bool | None = None
    expected_projection_rejected: bool | None = None
    expected_forged_grant_rejected: bool | None = None
    expected_terminal_transition_idempotent: bool | None = None
    expected_manual_resolution_required: bool | None = None
    expected_blind_retry_blocked: bool | None = None
    replay_variant: str = Field(default="pass", min_length=1, max_length=32)


SliceExpectation = Annotated[
    ThreatSliceExpectation
    | BenignSliceExpectation
    | UnevaluableSliceExpectation
    | SecuritySliceExpectation
    | KnowledgeSliceExpectation
    | AgenticSliceExpectation
    | CoordinationSliceExpectation,
    Field(discriminator="slice_type"),
]


class EvaluationCaseTruth(BaseModel):
    """Immutable revision of adjudicated case truth for offline evaluation."""

    model_config = ConfigDict(extra="forbid")

    truth_id: str = Field(..., min_length=1)
    tenant_id: str = Field(..., min_length=1)
    source_tenant_id: str | None = Field(default=None, max_length=64)
    source_product: str | None = Field(default=None, max_length=64)
    connector_id: str | None = Field(default=None, max_length=64)
    dataset_id: str = Field(..., min_length=1, max_length=128)
    dataset_version: str = Field(..., min_length=1, max_length=64)
    case_id: str = Field(..., min_length=1, max_length=128)
    case_version: int = Field(default=1, ge=1)
    content_hash: str = Field(..., min_length=64, max_length=64)
    observation_refs: list[TruthObservationRef] = Field(default_factory=list)
    slice_expectation: SliceExpectation
    label_provenance: LabelProvenance
    operational_mapping: OperationalTruthMapping | None = None
    revision: int = Field(default=1, ge=1)
    supersedes_truth_id: str | None = Field(default=None, max_length=128)
    correction_reason: str | None = Field(default=None, max_length=512)
    retention_policy: str = Field(default="evaluation_standard", min_length=1)
    schema_version: str = Field(default=EVALUATION_TRUTH_SCHEMA_VERSION, min_length=1)
    truth_hash: str = Field(default="", min_length=0, max_length=64)
    idempotency_key: str = Field(..., min_length=1)
    created_at: datetime | None = None

    @field_validator("correction_reason")
    @classmethod
    def _bound_correction(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value[:512]


class EvaluationTruthQuery(BaseModel):
    """Read-only query contract for canonical truth (tenant-scoped)."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(..., min_length=1)
    dataset_id: str | None = Field(default=None, max_length=128)
    dataset_version: str | None = Field(default=None, max_length=64)
    case_id: str | None = Field(default=None, max_length=128)
    slice_type: SliceType | None = None
    latest_revision_only: bool = Field(
        default=True,
        description=(
            "When true (default), return only the highest revision per case_id. "
            "Set false to include superseded historical revisions."
        ),
    )
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)


class EvaluationTruthListResult(BaseModel):
    """Paginated read-only truth query result."""

    model_config = ConfigDict(extra="forbid")

    total: int = Field(..., ge=0)
    page: int = Field(..., ge=1)
    page_size: int = Field(..., ge=1)
    items: list[EvaluationCaseTruth] = Field(default_factory=list)


class EvaluationDatasetManifest(BaseModel):
    """Dataset-level hash and revision metadata for reproducible evaluation runs."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(..., min_length=1)
    dataset_id: str = Field(..., min_length=1)
    dataset_version: str = Field(..., min_length=1)
    content_hash: str = Field(..., min_length=64, max_length=64)
    case_count: int = Field(..., ge=0)
    schema_version: str = Field(default=EVALUATION_TRUTH_SCHEMA_VERSION, min_length=1)


__all__ = [
    "AgenticExpectationKind",
    "AgenticSliceExpectation",
    "BenignSliceExpectation",
    "CoordinationExpectationKind",
    "CoordinationSliceExpectation",
    "EVALUATION_TRUTH_SCHEMA_VERSION",
    "EvaluationCaseTruth",
    "EvaluationDatasetManifest",
    "EvaluationTruthListResult",
    "EvaluationTruthQuery",
    "KnowledgeExpectationKind",
    "KnowledgeSliceExpectation",
    "LabelProvenance",
    "OperationalTruthMapping",
    "SLICE_EXPECTATION_SCHEMA_VERSION",
    "SLICE_EXPECTATION_SCHEMA_VERSION_1_1",
    "SecurityExpectationKind",
    "SecuritySliceExpectation",
    "SliceExpectation",
    "SliceType",
    "ThreatSliceExpectation",
    "TruthObservationRef",
    "UnevaluableSliceExpectation",
]
