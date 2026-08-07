"""Shared live/XDR writeback side-effect fence (ISSUE-222)."""

from __future__ import annotations

from app.core.config import Settings, get_settings
from app.core.errors import ValidationError
from app.models.enums import ExecutionOwner

WRITEBACK_FENCE_BLOCKED_ERROR_CODE = "writeback_fence_blocked"


def assert_live_side_effects_allowed(
    *,
    settings: Settings | None = None,
    action_id: str | None = None,
) -> None:
    """Block when ALLOW_LIVE_SIDE_EFFECTS is enabled (P0 fail-closed)."""
    resolved = settings or get_settings()
    if resolved.allow_live_side_effects:
        details: dict[str, object] = {"allow_live_side_effects": True}
        if action_id is not None:
            details["action_id"] = action_id
        raise ValidationError(
            "live side effects are disabled in ISSUE-059 P0",
            details=details,
        )


def assert_xdr_writeback_allowed(
    *,
    settings: Settings | None = None,
    action_id: str | None = None,
    execution_owner: ExecutionOwner,
) -> None:
    """Block live disposition writeback unless ALLOW_XDR_WRITEBACK is enabled."""
    if execution_owner is not ExecutionOwner.XDR_MANAGED:
        return
    resolved = settings or get_settings()
    disposition_mode = resolved.disposition_mode.strip().lower()
    if "mock" not in disposition_mode and not resolved.allow_xdr_writeback:
        details: dict[str, object] = {"disposition_mode": resolved.disposition_mode}
        if action_id is not None:
            details["action_id"] = action_id
        raise ValidationError(
            "xdr writeback is not enabled for live disposition mode",
            details=details,
        )


def assert_writeback_side_effects_allowed(
    *,
    settings: Settings | None = None,
    action_id: str | None = None,
    execution_owner: ExecutionOwner,
) -> None:
    """Combined claim/delivery fence: live side effects + XDR writeback."""
    assert_live_side_effects_allowed(settings=settings, action_id=action_id)
    assert_xdr_writeback_allowed(
        settings=settings,
        action_id=action_id,
        execution_owner=execution_owner,
    )


__all__ = [
    "WRITEBACK_FENCE_BLOCKED_ERROR_CODE",
    "assert_live_side_effects_allowed",
    "assert_writeback_side_effects_allowed",
    "assert_xdr_writeback_allowed",
]
