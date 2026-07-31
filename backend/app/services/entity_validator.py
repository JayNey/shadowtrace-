"""Backward-compatible re-export of shared entity validation (ISSUE-099 / ISSUE-100)."""

from app.agents.rules.entity_validation import (
    HOST_CONTEXT_PREFIX,
    HOST_CONTEXTUAL_PATTERN,
    EntityProvenance,
    EntityRejection,
    EntityValidationResult,
    is_plausible_regex_hostname,
    validate_entity_set,
    validate_host_entity,
)

__all__ = [
    "HOST_CONTEXTUAL_PATTERN",
    "HOST_CONTEXT_PREFIX",
    "EntityProvenance",
    "EntityRejection",
    "EntityValidationResult",
    "is_plausible_regex_hostname",
    "validate_entity_set",
    "validate_host_entity",
]
