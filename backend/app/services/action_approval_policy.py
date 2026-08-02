"""Versioned Action approval policy source (#613 Phase 0 / ISSUE-109)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.models.enums import ActionLevel
from app.models.workflow import AUTO_APPROVABLE_ACTION_LEVELS, parse_action_level_label

if TYPE_CHECKING:
    from app.core.config import Settings

# Bump when AUTO_APPROVABLE_ACTION_LEVELS or level-rule semantics change.
APPROVAL_POLICY_VERSION = "issue109_v1"
APPROVAL_POLICY_SOURCE = "AUTO_APPROVABLE_ACTION_LEVELS"

_ACTION_LEVEL_RANK: dict[ActionLevel, int] = {
    ActionLevel.L0: 0,
    ActionLevel.L1: 1,
    ActionLevel.L2: 2,
    ActionLevel.L3: 3,
    ActionLevel.L4: 4,
    ActionLevel.L5: 5,
}


def auto_approvable_levels() -> frozenset[ActionLevel]:
    """Levels the system may auto-approve after hard gates pass."""
    return AUTO_APPROVABLE_ACTION_LEVELS


def action_level_rank(level: ActionLevel) -> int:
    return _ACTION_LEVEL_RANK[level]


def resolve_runtime_max_auto_level(settings: Settings) -> ActionLevel | None:
    """Return auto-approve cap when mock auto-response is enabled (#613).

    When ``AUTO_RESPONSE_ENABLED`` is false, returns ``None`` so L0/L1 keep
    the default mock-loop auto-approve behavior without an extra cap.
    """
    if not settings.auto_response_enabled:
        return None
    raw = (settings.auto_response_max_auto_level or "L1").strip()
    return parse_action_level_label(raw) or ActionLevel.L1


__all__ = [
    "APPROVAL_POLICY_SOURCE",
    "APPROVAL_POLICY_VERSION",
    "action_level_rank",
    "auto_approvable_levels",
    "parse_action_level_label",
    "resolve_runtime_max_auto_level",
]
