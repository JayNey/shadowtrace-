"""Evidence models (intro §4.3.5 / ISSUE-002 field spec)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import EvidenceSource
from app.models.source import SourceReference


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    event_id: str
    source: EvidenceSource
    evidence_type: str
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    timestamp: datetime | None = None
    related_entities: list[str] = Field(default_factory=list)
    source_ref: SourceReference | None = None
    raw_data: dict[str, Any] = Field(default_factory=dict)
    mitre_technique: str | None = None
    is_conflicting: bool = False


class EvidenceSafeProjection(BaseModel):
    """Versioned API/working-memory safe view — never exposes domain raw_data (ISSUE-269)."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default="1.0", min_length=1, max_length=16)
    evidence_id: str
    event_id: str
    source: EvidenceSource
    evidence_type: str
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    timestamp: datetime | None = None
    related_entities: list[str] = Field(default_factory=list)
    source_ref: SourceReference | None = None
    mitre_technique: str | None = None
    is_conflicting: bool = False
    observation_fields: dict[str, str] = Field(default_factory=dict)


class EvidenceConflict(BaseModel):
    """A detected contradiction between two or more pieces of evidence."""

    model_config = ConfigDict(extra="forbid")

    conflict_id: str
    event_id: str
    description: str
    evidence_ids: list[str] = Field(default_factory=list)
    sources: list[EvidenceSource] = Field(default_factory=list)
    detail: dict[str, Any] = Field(default_factory=dict)


class EvidenceGap(BaseModel):
    """A required evidence source that could not be collected."""

    model_config = ConfigDict(extra="forbid")

    event_id: str
    missing_source: EvidenceSource
    reason: str
    detail: dict[str, Any] = Field(default_factory=dict)


SKIP_GAP_REASONS: frozenset[str] = frozenset(
    {"source_skipped", "invalid_entity", "triage_degraded"}
)


def skipped_entity_description(tool_name: str) -> str:
    """Default EvidenceAgent skip text when a required entity is missing or invalid."""
    return f"required entity missing or invalid for {tool_name}"
