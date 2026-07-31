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


class SliceType(StrEnum):
    """First-round evaluation slices; extend via reviewed schema revision only."""

    THREAT = "threat"
    BENIGN = "benign"
    UNEVALUABLE = "unevaluable"


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


class BenignSliceExpectation(BaseModel):
    """Expectation for confirmed-benign / false-positive cases."""

    model_config = ConfigDict(extra="forbid")

    slice_type: Literal["benign"] = "benign"
    schema_version: str = Field(default=SLICE_EXPECTATION_SCHEMA_VERSION, min_length=1)
    expected_case_label: CaseLabel = CaseLabel.FALSE_POSITIVE
    expected_final_verdict: FinalVerdict = FinalVerdict.FALSE_POSITIVE


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


SliceExpectation = Annotated[
    ThreatSliceExpectation | BenignSliceExpectation | UnevaluableSliceExpectation,
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
    "BenignSliceExpectation",
    "EVALUATION_TRUTH_SCHEMA_VERSION",
    "EvaluationCaseTruth",
    "EvaluationDatasetManifest",
    "EvaluationTruthListResult",
    "EvaluationTruthQuery",
    "LabelProvenance",
    "OperationalTruthMapping",
    "SLICE_EXPECTATION_SCHEMA_VERSION",
    "SliceExpectation",
    "SliceType",
    "ThreatSliceExpectation",
    "TruthObservationRef",
    "UnevaluableSliceExpectation",
]
