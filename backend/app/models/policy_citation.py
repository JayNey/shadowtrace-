"""Typed policy citations with applicability boundaries (ISSUE-129 / #635 Phase A)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ApplicabilityStatus(StrEnum):
    """Server-evaluated control applicability — never a legal compliance verdict."""

    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    NOT_EVALUATED = "not_evaluated"


class ApplicabilityReasonCode(StrEnum):
    """Machine-readable applicability boundary codes."""

    PROFILE_MISSING = "profile_missing"
    PROFILE_INCOMPLETE = "profile_incomplete"
    FRAMEWORK_NOT_ALLOWED = "framework_not_allowed"
    JURISDICTION_MISMATCH = "jurisdiction_mismatch"
    INDUSTRY_MISMATCH = "industry_mismatch"
    MAPPING_NOT_APPROVED = "mapping_not_approved"
    CONTROL_NOT_IN_RELEASE = "control_not_in_release"
    PROFILE_REVISION_STALE = "profile_revision_stale"


class PolicyCitation(BaseModel):
    """Evidence citation with exact locator and applicability boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    framework_id: str = Field(..., min_length=1, max_length=64)
    release_id: str = Field(..., min_length=1, max_length=128)
    control_id: str = Field(..., min_length=1, max_length=128)
    text_locator: str = Field(..., min_length=1, max_length=128)
    applicability_status: ApplicabilityStatus
    applicability_reason: ApplicabilityReasonCode | None = None
    mapping_provenance: str | None = Field(default=None, max_length=256)
    mapping_version: str | None = Field(default=None, max_length=32)
    technique_id: str | None = Field(default=None, max_length=32)
    profile_id: str | None = Field(default=None, max_length=128)
    profile_revision: int | None = Field(default=None, ge=1)


class PolicyApplicabilityHints(BaseModel):
    """Untrusted agent/query hints — server profile always wins."""

    model_config = ConfigDict(extra="forbid")

    framework_ids: list[str] = Field(default_factory=list)
    jurisdiction_codes: list[str] = Field(default_factory=list)
    industry_codes: list[str] = Field(default_factory=list)


__all__ = [
    "ApplicabilityReasonCode",
    "ApplicabilityStatus",
    "PolicyApplicabilityHints",
    "PolicyCitation",
]
