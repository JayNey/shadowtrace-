"""LLM provider health and audit contracts (ISSUE-106 / #609)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class LLMProviderMode(StrEnum):
    MOCK = "mock"
    OPENAI_COMPATIBLE = "openai_compatible"
    CUSTOM = "custom"


class LLMProbeStatus(BaseModel):
    """Sanitized result of the most recent optional provider probe."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., description="ok | error | skipped")
    probe_method: str | None = None
    error_class: str | None = None
    error_code: str | None = None
    latency_ms: float | None = None


class LLMCallLogAggregate(BaseModel):
    """Rolling summary from durable ``llm_call_log`` rows (no prompt text)."""

    model_config = ConfigDict(extra="forbid")

    window_minutes: int = Field(..., ge=1)
    total_calls: int = Field(default=0, ge=0)
    success_calls: int = Field(default=0, ge=0)
    success_rate: float | None = None
    last_status: str | None = None
    last_error_class: str | None = None


class LLMProviderHealth(BaseModel):
    """Sanitized LLM readiness for /health and smoke tooling."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., description="ok | degraded | error")
    mode: str
    base_url_redacted: str = ""
    primary_model: str
    probe_enabled: bool = False
    last_probe_status: LLMProbeStatus
    audit: LLMCallLogAggregate | None = None


__all__ = [
    "LLMCallLogAggregate",
    "LLMProbeStatus",
    "LLMProviderHealth",
    "LLMProviderMode",
]
