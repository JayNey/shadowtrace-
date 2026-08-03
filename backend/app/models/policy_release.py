"""Policy/Control corpus release contracts (ISSUE-129 / #635 Phase A)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.models.attack_control_mapping import MappingApprovalState
from app.models.knowledge_release import KnowledgeReleaseLifecycleState

POLICY_CORPUS_ID = "policy_control"
POLICY_KB_NAME = "policy_kb"
POLICY_SOURCE_ID = "shadowtrace_policy_controls"
POLICY_RELEASE_SCHEMA_VERSION = "1.0"
POLICY_CONTROL_REF_SCHEMA_VERSION = "1.0"


class PolicyControl(BaseModel):
    """One immutable control object within a policy release bundle."""

    model_config = ConfigDict(extra="forbid")

    control_id: str = Field(..., pattern=r"^ctrl-[0-9a-fA-F]{8}$")
    framework_id: str = Field(..., min_length=1, max_length=64)
    control_family: str = Field(..., min_length=1, max_length=64)
    title: str = Field(..., min_length=1, max_length=256)
    requirement_text: str = Field(..., min_length=1, max_length=4096)
    text_locator: str = Field(..., min_length=1, max_length=128)
    jurisdiction_codes: tuple[str, ...] = Field(default_factory=tuple)
    industry_codes: tuple[str, ...] = Field(default_factory=tuple)


class PolicyControlRef(BaseModel):
    """Immutable control version/hash reference — not a bare control_id string."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default=POLICY_CONTROL_REF_SCHEMA_VERSION, min_length=1)
    control_id: str = Field(..., pattern=r"^ctrl-[0-9a-fA-F]{8}$")
    framework_id: str = Field(..., min_length=1, max_length=64)
    release_id: str = Field(..., min_length=1, max_length=128)
    release_version: str = Field(..., min_length=1, max_length=64)
    content_hash: str = Field(..., min_length=64, max_length=64)
    bundle_content_hash: str = Field(..., min_length=64, max_length=64)
    text_locator: str = Field(..., min_length=1, max_length=128)
    revision: int = Field(default=1, ge=1)
    corpus_id: str = Field(default=POLICY_CORPUS_ID, min_length=1)
    lifecycle_state: KnowledgeReleaseLifecycleState | None = Field(
        default=None,
        description="Release lifecycle at pin time (audit only)",
    )


class PolicyMappingBundleEntry(BaseModel):
    """ATT&CK↔control mapping row embedded in an offline import bundle."""

    model_config = ConfigDict(extra="forbid")

    mapping_id: str = Field(..., min_length=1, max_length=128)
    technique_id: str = Field(..., min_length=1, max_length=32)
    control_id: str = Field(..., pattern=r"^ctrl-[0-9a-fA-F]{8}$")
    framework_id: str = Field(..., min_length=1, max_length=64)
    approval_state: MappingApprovalState
    mapping_version: str = Field(..., min_length=1, max_length=32)
    provenance: str = Field(..., min_length=1, max_length=256)


__all__ = [
    "POLICY_CONTROL_REF_SCHEMA_VERSION",
    "POLICY_CORPUS_ID",
    "POLICY_KB_NAME",
    "POLICY_RELEASE_SCHEMA_VERSION",
    "POLICY_SOURCE_ID",
    "PolicyControl",
    "PolicyControlRef",
    "PolicyMappingBundleEntry",
]
