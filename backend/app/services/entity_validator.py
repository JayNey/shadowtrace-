"""Backward-compatible re-export of shared entity validation (ISSUE-099 / ISSUE-100)."""

from app.agents.rules.entity_validation import (
    EntityProvenance,
    EntityRejection,
    EntityValidationResult,
    is_plausible_regex_hostname,
    validate_entity_set,
    validate_host_entity,
)

__all__ = [
    "EntityProvenance",
    "EntityRejection",
    "EntityValidationResult",
    "is_plausible_regex_hostname",
    "validate_entity_set",
    "validate_host_entity",
]
