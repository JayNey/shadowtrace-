"""Playbook release contract and immutable refs (ISSUE-139 / #645 Phase A)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import ActionLevel
from app.models.knowledge_release import KnowledgeReleaseLifecycleState

PLAYBOOK_CORPUS_ID = "playbook_soar"
PLAYBOOK_KB_NAME = "playbook_kb"
PLAYBOOK_SOURCE_ID = "shadowtrace_playbooks"
PLAYBOOK_RELEASE_SCHEMA_VERSION = "1.0"
PLAYBOOK_REF_SCHEMA_VERSION = "1.0"
MAX_ACTION_TEMPLATE_SNAPSHOT_BYTES = 2048


class PlaybookActionTemplateSnapshot(BaseModel):
    """Bounded typed action template pinned at plan materialization time."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    step_order: int = Field(..., ge=1)
    tool_name: str = Field(..., min_length=1)
    action_level: ActionLevel
    action_name: str = Field(..., min_length=1)
    required_capabilities: tuple[str, ...] = Field(default_factory=tuple)
    template_hash: str = Field(..., min_length=64, max_length=64)


class PlaybookRef(BaseModel):
    """Immutable playbook version/hash reference — not a bare playbook_id string."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default=PLAYBOOK_REF_SCHEMA_VERSION, min_length=1)
    playbook_id: str = Field(..., pattern=r"^pb-[0-9a-fA-F]{8}$")
    release_id: str = Field(..., min_length=1, max_length=128)
    release_version: str = Field(..., min_length=1, max_length=64)
    content_hash: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="SHA-256 of canonical playbook object JSON",
    )
    bundle_content_hash: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="SHA-256 of canonical release bundle JSON",
    )
    revision: int = Field(default=1, ge=1)
    corpus_id: str = Field(default=PLAYBOOK_CORPUS_ID, min_length=1)
    lifecycle_state: KnowledgeReleaseLifecycleState | None = Field(
        default=None,
        description="Release lifecycle at pin time (audit only)",
    )


class ResolvedPlaybook(BaseModel):
    """Playbook resolved from an immutable ref with release metadata."""

    model_config = ConfigDict(extra="forbid")

    ref: PlaybookRef
    release_version: str
    release_lifecycle_state: KnowledgeReleaseLifecycleState
    playbook_name: str
    step_count: int = Field(ge=0)


__all__ = [
    "MAX_ACTION_TEMPLATE_SNAPSHOT_BYTES",
    "PLAYBOOK_CORPUS_ID",
    "PLAYBOOK_KB_NAME",
    "PLAYBOOK_REF_SCHEMA_VERSION",
    "PLAYBOOK_RELEASE_SCHEMA_VERSION",
    "PLAYBOOK_SOURCE_ID",
    "PlaybookActionTemplateSnapshot",
    "PlaybookRef",
    "ResolvedPlaybook",
]
