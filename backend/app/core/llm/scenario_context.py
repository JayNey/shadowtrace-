"""Resolve MockLLM scenario routing keys from investigation context (ISSUE-199)."""

from __future__ import annotations

from typing import Any


def resolve_llm_scenario_id(
    *,
    override: str | None = None,
    source_snapshot: dict[str, Any] | None = None,
    raw_alert_snapshot: dict[str, Any] | None = None,
) -> str | None:
    """Return explicit override or scenario label from event/source context.

    Production DI must not hardcode demo scenario names. When no override is
    configured and no scenario is present on the event, returns ``None`` so
    MockLLM falls back to ``default.json``.
    """
    if override:
        return override
    for blob in (source_snapshot, raw_alert_snapshot):
        resolved = _scenario_from_blob(blob)
        if resolved is not None:
            return resolved
    return None


def _scenario_from_blob(blob: dict[str, Any] | None) -> str | None:
    if not isinstance(blob, dict):
        return None
    direct = blob.get("scenario")
    if isinstance(direct, str):
        trimmed = direct.strip()
        if trimmed:
            return trimmed
    normalized = blob.get("normalized")
    if isinstance(normalized, dict):
        nested = normalized.get("scenario")
        if isinstance(nested, str):
            trimmed = nested.strip()
            if trimmed:
                return trimmed
    raw_alert = blob.get("raw_alert_snapshot")
    if isinstance(raw_alert, dict):
        return _scenario_from_blob(raw_alert)
    return None


__all__ = ["resolve_llm_scenario_id"]
