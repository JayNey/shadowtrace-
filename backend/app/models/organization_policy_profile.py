"""Server-owned organization policy profile (ISSUE-129 / #635 Phase A)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

ORGANIZATION_POLICY_PROFILE_SCHEMA_VERSION = "1.0"


class OrganizationPolicyProfile(BaseModel):
    """Tenant applicability profile — resolved by server auth, not agent hints."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(
        default=ORGANIZATION_POLICY_PROFILE_SCHEMA_VERSION,
        min_length=1,
    )
    profile_id: str = Field(..., pattern=r"^opp-[0-9a-fA-F]{8}$")
    tenant_id: str = Field(..., min_length=1, max_length=128)
    revision: int = Field(default=1, ge=1)
    owner_principal: str = Field(..., min_length=1, max_length=128)
    framework_allowlist: tuple[str, ...] = Field(default_factory=tuple)
    jurisdiction_codes: tuple[str, ...] = Field(default_factory=tuple)
    industry_codes: tuple[str, ...] = Field(default_factory=tuple)
    effective_at: datetime
    approved_by: str | None = Field(default=None, max_length=128)
    audit_note: str | None = Field(default=None, max_length=512)
    created_at: datetime
    updated_at: datetime


class OrganizationPolicyProfileUpsertRequest(BaseModel):
    """Trusted profile write input."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(..., min_length=1, max_length=128)
    owner_principal: str = Field(..., min_length=1, max_length=128)
    framework_allowlist: tuple[str, ...] = Field(default_factory=tuple)
    jurisdiction_codes: tuple[str, ...] = Field(default_factory=tuple)
    industry_codes: tuple[str, ...] = Field(default_factory=tuple)
    approved_by: str | None = Field(default=None, max_length=128)
    audit_note: str | None = Field(default=None, max_length=512)


__all__ = [
    "ORGANIZATION_POLICY_PROFILE_SCHEMA_VERSION",
    "OrganizationPolicyProfile",
    "OrganizationPolicyProfileUpsertRequest",
]
