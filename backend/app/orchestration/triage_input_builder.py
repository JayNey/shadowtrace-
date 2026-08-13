"""Shared TriageAgentInput construction for graph nodes and SuperAgent (ISSUE-566)."""

from __future__ import annotations

import logging
from typing import Any, Protocol

from sqlalchemy import select

from app.db import models as orm
from app.models.agent_io import (
    TriageAgentInput,
    TriageRelatedAlertHint,
    TriageStructuredPromptContext,
)
from app.models.context import EventContext
from app.models.entities import EntitySet
from app.models.enums import SourceObjectKind
from app.models.security_event import SecurityEvent
from app.models.source import SourceReference

logger = logging.getLogger(__name__)

_NORMALIZED_HINT_KEYS = (
    "hostname",
    "secondary_host",
    "src_ip",
    "dst_ip",
    "domain",
    "account",
)
_MAX_RELATED_ALERTS = 5


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


def _normalized_dict_from_event(event: Any) -> dict[str, Any]:
    raw_snapshot = getattr(event, "raw_alert_snapshot", None)
    if isinstance(raw_snapshot, dict):
        nested = raw_snapshot.get("normalized")
        if isinstance(nested, dict) and nested:
            return dict(nested)
    if isinstance(event, dict):
        nested = event.get("normalized")
        if isinstance(nested, dict) and nested:
            return dict(nested)
        raw = event.get("raw_alert_snapshot")
        if isinstance(raw, dict):
            nested = raw.get("normalized")
            if isinstance(nested, dict) and nested:
                return dict(nested)
    return {}


def _normalized_hint_fields(normalized: dict[str, Any]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for key in _NORMALIZED_HINT_KEYS:
        if key == "domain":
            value = normalized.get("domain") or normalized.get("fqdn")
        else:
            value = normalized.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            fields[key] = text
    return fields


def _related_alert_title(
    normalized: dict[str, Any],
    raw_payload: dict[str, Any],
    ref: SourceReference,
) -> str:
    for candidate in (
        normalized.get("title"),
        normalized.get("alert_type"),
        raw_payload.get("title"),
        raw_payload.get("rule"),
    ):
        if candidate:
            return str(candidate).strip()
    return f"alert:{ref.source_object_id}"


def _related_alert_tag(normalized: dict[str, Any]) -> str:
    for key in ("gpt_tag", "tag", "level"):
        value = normalized.get(key)
        if value:
            return str(value).strip()
    return ""


async def _load_related_alert_hints(
    event_service: _EventServiceLike,
    event: SecurityEvent,
) -> list[TriageRelatedAlertHint]:
    alert_refs = [
        ref
        for ref in event.source_reference_snapshots
        if ref.source_kind is SourceObjectKind.ALERT
    ][: _MAX_RELATED_ALERTS]
    if not alert_refs:
        return []

    session_factory = getattr(event_service, "_session_factory", None)
    if session_factory is None:
        return []

    hints: list[TriageRelatedAlertHint] = []
    try:
        async with session_factory() as session:
            for ref in alert_refs:
                row = await session.scalar(
                    select(orm.SourceObject).where(
                        orm.SourceObject.source_product == ref.source_product,
                        orm.SourceObject.source_tenant_id == ref.source_tenant_id,
                        orm.SourceObject.connector_id == ref.connector_id,
                        orm.SourceObject.source_kind == ref.source_kind.value,
                        orm.SourceObject.source_object_id == ref.source_object_id,
                    )
                )
                if row is None:
                    continue
                normalized = dict(row.normalized or {})
                raw_payload = dict(row.raw_payload or {})
                hints.append(
                    TriageRelatedAlertHint(
                        title=_related_alert_title(normalized, raw_payload, ref),
                        tag=_related_alert_tag(normalized),
                    )
                )
    except Exception:
        logger.debug(
            "triage input: related alert lookup failed for event=%s",
            event.event_id,
            exc_info=True,
        )
        return []

    return hints[:_MAX_RELATED_ALERTS]


async def _load_source_normalized(
    event_service: _EventServiceLike,
    event: SecurityEvent,
) -> dict[str, Any]:
    """Load full ticket normalized fields from SourceObject (not risk-baseline snapshot)."""
    session_factory = getattr(event_service, "_session_factory", None)
    if session_factory is None:
        return {}

    try:
        async with session_factory() as session:
            row = None
            record_id = event.current_primary_source_record_id
            if record_id:
                row = await session.get(orm.SourceObject, record_id)
            if row is None:
                ref = event.creation_source_ref
                row = await session.scalar(
                    select(orm.SourceObject).where(
                        orm.SourceObject.source_product == ref.source_product,
                        orm.SourceObject.source_tenant_id == ref.source_tenant_id,
                        orm.SourceObject.connector_id == ref.connector_id,
                        orm.SourceObject.source_kind == ref.source_kind.value,
                        orm.SourceObject.source_object_id == ref.source_object_id,
                    )
                )
            if row is None:
                return {}
            return dict(row.normalized or {})
    except Exception:
        logger.debug(
            "triage input: source normalized lookup failed for event=%s",
            event.event_id,
            exc_info=True,
        )
        return {}


def _merge_normalized_dicts(*parts: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for part in parts:
        for key, value in part.items():
            if value is None:
                continue
            text = str(value).strip()
            if text:
                merged[key] = value
    return merged


def _build_structured_prompt_context(
    event: Any,
    *,
    related_alerts: list[TriageRelatedAlertHint],
    source_normalized: dict[str, Any] | None = None,
) -> TriageStructuredPromptContext | None:
    merged = _merge_normalized_dicts(
        _normalized_dict_from_event(event),
        source_normalized or {},
    )
    normalized_fields = _normalized_hint_fields(merged)
    if not normalized_fields and not related_alerts:
        return None
    return TriageStructuredPromptContext(
        normalized_fields=normalized_fields,
        related_alerts=related_alerts,
    )


async def build_triage_agent_input(
    event_id: str,
    *,
    event_context: EventContext | None = None,
    event_service: _EventServiceLike | None = None,
) -> TriageAgentInput:
    """Build triage input aligned with ``AnalysisOnlyPipeline._run_triage``."""
    raw_summary = build_raw_summary_from_context(event_context)
    hint_entities = EntitySet()
    structured_prompt_context: TriageStructuredPromptContext | None = None
    loaded_event: Any | None = None

    if event_service is not None:
        try:
            loaded_event = await event_service.get_event(event_id)
        except Exception:
            logger.debug(
                "triage input: event lookup failed for event=%s",
                event_id,
                exc_info=True,
            )
            loaded_event = None
        if loaded_event is not None:
            fallback_title = (
                event_context.event.title
                if event_context is not None and event_context.event is not None
                else event_id
            )
            if isinstance(loaded_event, dict):
                title = str(loaded_event.get("title") or fallback_title)
                description = str(loaded_event.get("description") or "")
                raw_summary = f"{title}. {description}".strip(". ")
            else:
                title = str(getattr(loaded_event, "title", "") or fallback_title)
                description = str(getattr(loaded_event, "description", "") or "").strip()
                raw_summary = f"{title}. {description}".strip(". ")
                entities = getattr(loaded_event, "entities", None)
                if entities is not None:
                    hint_entities = entities

            related_alerts: list[TriageRelatedAlertHint] = []
            source_normalized: dict[str, Any] = {}
            if isinstance(loaded_event, SecurityEvent):
                source_normalized = await _load_source_normalized(event_service, loaded_event)
                related_alerts = await _load_related_alert_hints(event_service, loaded_event)
            structured_prompt_context = _build_structured_prompt_context(
                loaded_event,
                related_alerts=related_alerts,
                source_normalized=source_normalized,
            )

    return TriageAgentInput(
        event_id=event_id,
        raw_event_summary=raw_summary,
        hint_entities=hint_entities,
        structured_prompt_context=structured_prompt_context,
    )


__all__ = [
    "build_raw_summary_from_context",
    "build_triage_agent_input",
    "_normalized_hint_fields",
]
