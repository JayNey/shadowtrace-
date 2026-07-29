"""Domain models for governed long-term memory candidates (ISSUE-081)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

MemoryCandidateType = Literal["fp_rule", "history_case", "profile"]
MemoryReviewStatus = Literal["pending", "promoted", "demoted"]


class MemoryCandidate(BaseModel):
    """A durable candidate that must be reviewed before entering long-term memory."""

    model_config = ConfigDict(extra="forbid")

    kb_name: str = Field(min_length=1, max_length=100)
    candidate_type: MemoryCandidateType
    payload: dict[str, Any]
    confidence: float = Field(ge=0.0, le=1.0)


class MemoryReview(BaseModel):
    """Stable service/API representation of a memory review row."""

    model_config = ConfigDict(extra="forbid", from_attributes=True)

    review_id: str
    kb_name: str
    candidate_type: MemoryCandidateType
    payload: dict[str, Any]
    status: MemoryReviewStatus
    confidence: float
    created_at: datetime
    decided_at: datetime | None = None
    operator: str | None = None
