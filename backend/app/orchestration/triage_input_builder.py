"""Shared TriageAgentInput construction for graph nodes and SuperAgent (ISSUE-566)."""

from __future__ import annotations

import logging
from typing import Any, Protocol

from app.models.agent_io import TriageAgentInput
from app.models.context import EventContext
from app.models.entities import EntitySet

logger = logging.getLogger(__name__)


class _EventServiceLike(Protocol):
    async def get_event(self, event_id: str) -> Any: ...


def build_raw_summary_from_context(event_context: EventContext | None) -> str:
    """Build a textual summary of the event for TriageAgent input."""
    if event_context is not None and event_context.event is not None:
        event = event_context.event
        parts = [
            f"title={event.title}",
            f"type={event.event_type.value}",
            f"severity={event.severity.value}",
        ]
        return " | ".join(parts)
    return ""


async def build_triage_agent_input(
    event_id: str,
    *,
    event_context: EventContext | None = None,
    event_service: _EventServiceLike | None = None,
) -> TriageAgentInput:
    """Build triage input aligned with ``AnalysisOnlyPipeline._run_triage``."""
    raw_summary = build_raw_summary_from_context(event_context)
    hint_entities = EntitySet()

    if event_service is not None:
        try:
            event = await event_service.get_event(event_id)
        except Exception:
            logger.debug(
                "triage input: event lookup failed for event=%s",
                event_id,
                exc_info=True,
            )
            event = None
        if event is not None:
            fallback_title = (
                event_context.event.title
                if event_context is not None and event_context.event is not None
                else event_id
            )
            if isinstance(event, dict):
                title = str(event.get("title") or fallback_title)
                description = str(event.get("description") or "")
                raw_summary = f"{title}. {description}".strip(". ")
            else:
                title = str(getattr(event, "title", "") or fallback_title)
                description = str(getattr(event, "description", "") or "").strip()
                raw_summary = f"{title}. {description}".strip(". ")
                entities = getattr(event, "entities", None)
                if entities is not None:
                    hint_entities = entities

    return TriageAgentInput(
        event_id=event_id,
        raw_event_summary=raw_summary,
        hint_entities=hint_entities,
    )


__all__ = ["build_raw_summary_from_context", "build_triage_agent_input"]
