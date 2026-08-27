"""Post-evidence false-positive adjudication models (ISSUE-114)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ChangeWindowBaseline(BaseModel):
    """One authorized maintenance / change window from org baseline data."""

    model_config = ConfigDict(extra="forbid")

    window_id: str
    authorized_accounts: list[str] = Field(default_factory=list)
    authorized_actions: list[str] = Field(default_factory=list)
    authorized_asset_groups: list[str] = Field(default_factory=list)
    valid_from: str
    valid_until: str
    description: str = ""


class OrgChangeWindowBaseline(BaseModel):
    """Tenant-scoped change-window baseline loaded from structured data."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    tenant_id: str
    change_windows: list[ChangeWindowBaseline] = Field(default_factory=list)


class FpAdjudicationResult(BaseModel):
    """Typed post-evidence FP decision output (ISSUE-114 Phase B)."""

    model_config = ConfigDict(extra="forbid")

    recommendation: str = Field(
        ...,
        description="close_as_fp | investigate | no_fp_signal",
    )
    phase: str = Field(default="post_evidence")
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    matched_conditions: list[str] = Field(default_factory=list)
    missing_conditions: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    matched_window_id: str | None = None
    max_score: float | None = Field(
        default=None,
        description="Confidence score for close_as_fp recommendations (0.0–1.0).",
    )
    qualification_level: int = Field(
        default=0,
        ge=0,
        le=4,
        description="Evidence qualification 0–4. close_as_fp only at level 4.",
    )
    arbitration: str | None = Field(
        default=None,
        description="no_contradiction | malicious_overrides_allowance",
    )
    adjudicated_at: str | None = None
    source: str = "PostEvidenceFpAdjudicator"


__all__ = [
    "ChangeWindowBaseline",
    "FpAdjudicationResult",
    "OrgChangeWindowBaseline",
]
