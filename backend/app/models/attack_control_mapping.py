"""ATT&CK↔control mapping approval lifecycle (ISSUE-129 / #635 Phase A)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class MappingApprovalState(StrEnum):
    """Curated mappings only — model suggestions stay candidate until approved."""

    CANDIDATE = "candidate"
    APPROVED = "approved"


class AttackControlMapping(BaseModel):
    """Immutable mapping row bound to one policy release."""

    model_config = ConfigDict(extra="forbid")

    mapping_id: str = Field(..., min_length=1, max_length=128)
    release_id: str = Field(..., min_length=1, max_length=128)
    technique_id: str = Field(..., min_length=1, max_length=32)
    control_id: str = Field(..., pattern=r"^ctrl-[0-9a-fA-F]{8}$")
    framework_id: str = Field(..., min_length=1, max_length=64)
    approval_state: MappingApprovalState
    mapping_version: str = Field(..., min_length=1, max_length=32)
    provenance: str = Field(..., min_length=1, max_length=256)


__all__ = [
    "AttackControlMapping",
    "MappingApprovalState",
]
