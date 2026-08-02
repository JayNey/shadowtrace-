"""Versioned Action approval policy source (#613 Phase 0 / ISSUE-109)."""

from __future__ import annotations

from app.models.enums import ActionLevel
from app.models.workflow import AUTO_APPROVABLE_ACTION_LEVELS, parse_action_level_label

# Bump when AUTO_APPROVABLE_ACTION_LEVELS or level-rule semantics change.
APPROVAL_POLICY_VERSION = "issue109_v1"
APPROVAL_POLICY_SOURCE = "AUTO_APPROVABLE_ACTION_LEVELS"


def auto_approvable_levels() -> frozenset[ActionLevel]:
    """Levels the system may auto-approve after hard gates pass."""
    return AUTO_APPROVABLE_ACTION_LEVELS


__all__ = [
    "APPROVAL_POLICY_SOURCE",
    "APPROVAL_POLICY_VERSION",
    "auto_approvable_levels",
    "parse_action_level_label",
]
