"""Retrieval call context (ISSUE-138).

Every RetrievalPipeline invocation receives explicit tenant/principal/event/trace
identifiers. Nil UUIDs and empty strings are rejected.
"""

from __future__ import annotations

from dataclasses import dataclass

from opentelemetry import trace

from app.core.config import Settings, get_settings
from app.models.agent_io import RAGAgentInput

_NIL_UUID = "00000000-0000-0000-0000-000000000000"


def _validate_identifier(name: str, value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{name} must be non-empty")
    if normalized.lower() == _NIL_UUID:
        raise ValueError(f"{name} must not be the nil UUID")
    return normalized


def current_trace_id() -> str | None:
    """Return the active OTel trace id when telemetry is enabled."""
    span = trace.get_current_span()
    ctx = span.get_span_context()
    if ctx is not None and ctx.is_valid and ctx.trace_id != 0:
        return format(ctx.trace_id, "032x")
    return None


@dataclass(frozen=True, slots=True)
class RetrievalContext:
    tenant_id: str
    principal: str
    event_id: str
    trace_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _validate_identifier("tenant_id", self.tenant_id))
        object.__setattr__(self, "principal", _validate_identifier("principal", self.principal))
        object.__setattr__(self, "event_id", _validate_identifier("event_id", self.event_id))
        object.__setattr__(self, "trace_id", _validate_identifier("trace_id", self.trace_id))

    @classmethod
    def from_rag_input(
        cls,
        input: RAGAgentInput,
        *,
        settings: Settings | None = None,
    ) -> RetrievalContext:
        cfg = settings or get_settings()
        raw_tenant = (input.tenant_id or "").strip()
        if not raw_tenant:
            if cfg.app_env.strip().lower() == "production":
                raise ValueError("tenant_id is required in production")
            raw_tenant = cfg.retrieval_default_tenant_id.strip()
        principal = (input.principal or "investigation:rag_agent").strip()
        trace_id = (input.trace_id or current_trace_id() or f"evt:{input.event_id}").strip()
        return cls(
            tenant_id=raw_tenant,
            principal=principal,
            event_id=input.event_id,
            trace_id=trace_id,
        )


__all__ = ["RetrievalContext", "current_trace_id"]
