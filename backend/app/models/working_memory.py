"""Working-memory access models (ISSUE-014 / intro §4.11)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ScratchpadEntry(BaseModel):
    """One append-only scratchpad note (FIFO-capped at 200)."""

    model_config = ConfigDict(extra="forbid")

    agent_name: str
    timestamp: datetime
    note: str


class MemoryAccessLog(BaseModel):
    """Audit trail for WorkingMemory read/write attempts."""

    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    agent_name: str
    op: Literal["read", "write"]
    key: str
    allowed: bool = Field(description="False when ownership/guardrail blocked the op")
