"""Human classification override helpers (ISSUE-209).

Derived ``classification_source`` lives in ``classification_source`` (ISSUE-211
shared module). This module keeps human PATCH / reinvestigate helpers and
re-exports the derive API for existing call sites.
"""

from __future__ import annotations

from typing import Any

from app.services.classification_source import (
    CLASSIFICATION_OVERRIDE_KEY,
    TRIAGE_RESULT_KEY,
    classification_override_from_snapshot,
    derive_classification_source,
)

__all__ = [
    "CLASSIFICATION_OVERRIDE_KEY",
    "TRIAGE_RESULT_KEY",
    "apply_event_type_to_triage_payload",
    "build_human_classification_override",
    "classification_override_from_snapshot",
    "derive_classification_source",
    "human_override_event_type",
]


def apply_event_type_to_triage_payload(
    triage: Any,
    event_type: str,
) -> tuple[Any, bool]:
    """Copy triage payload with ``event_type`` synced; return ``(payload, changed)``.

    Used so human classification overrides keep ResponseAgent rule selection
    aligned with ``SecurityEvent.event_type`` when reinvestigate is skipped.
    """
    if triage is None:
        return None, False

    if isinstance(triage, dict):
        current = str(triage.get("event_type") or "")
        if current == event_type:
            return triage, False
        updated = dict(triage)
        updated["event_type"] = event_type
        return updated, True

    dump = getattr(triage, "model_dump", None)
    if callable(dump):
        try:
            data = dump(mode="json")
        except TypeError:
            data = dump()
        if not isinstance(data, dict):
            return triage, False
        current = str(data.get("event_type") or "")
        if current == event_type:
            return triage, False
        data["event_type"] = event_type
        return data, True

    return triage, False


def build_human_classification_override(
    *,
    event_type: str,
    reason: str,
    operator: str,
    previous_event_type: str,
    updated_at: str,
    reinvestigate: bool = False,
) -> dict[str, Any]:
    """Build the durable human override payload stored in context / snapshot."""
    return {
        "source": "human",
        "event_type": event_type,
        "previous_event_type": previous_event_type,
        "reason": reason,
        "operator": operator,
        "updated_at": updated_at,
        "reinvestigate": bool(reinvestigate),
    }


def human_override_event_type(
    classification_override: dict[str, Any] | None,
) -> str | None:
    """Return the human-overridden event_type value, or None if not applicable."""
    if not isinstance(classification_override, dict):
        return None
    if str(classification_override.get("source") or "") != "human":
        return None
    raw = classification_override.get("event_type")
    if raw is None:
        return None
    value = str(raw).strip()
    return value or None
