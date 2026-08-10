"""Disposition delivery error classification (ISSUE-300).

Classifies adapter/worker failures without parsing exception messages.
Used by OutboxWorker and paused reconcile to avoid retrying pre-submit
deterministic rejections as ambiguous transport outcomes.
"""

from __future__ import annotations

from enum import StrEnum

from app.core.errors import (
    GuardrailViolationError,
    ValidationError,
    WritebackConflictError,
    WritebackUnsupportedError,
)

# Explicit adapter/domain rejection codes that must never enter PAUSED/lookup retry.
_DETERMINISTIC_ADAPTER_REJECTION_CODES: frozenset[str] = frozenset(
    {
        "not_found",
        "unauthorized_field",
        "invalid_operation",
        "permission_denied",
        "auth_error",
        "adapter_validation_error",
        "idempotency_key_reuse",
        "disposition_id_reuse",
        "writeback_unsupported",
        "mock_validation_error",
        "invalid_cursor",
        "adapter_not_found",
    }
)

# Low-cardinality metric bucket when an allowlisted code is not recognized.
_DEAD_LETTER_METRIC_FALLBACK_CODE = "adapter_validation_error"


class DispositionDeliveryErrorKind(StrEnum):
    DETERMINISTIC_REJECTION = "deterministic_rejection"
    CONFLICT = "conflict"
    AMBIGUOUS_OUTCOME = "ambiguous_outcome"
    GUARDRAIL = "guardrail"


def is_deterministic_adapter_rejection_code(error_code: str | None) -> bool:
    """True when ``error_code`` denotes a definitive pre-/post-submit adapter rejection."""
    if not error_code:
        return False
    if error_code in _DETERMINISTIC_ADAPTER_REJECTION_CODES:
        return True
    return error_code.startswith("unsupported_")


def bounded_dead_letter_error_code(error_code: str | None) -> str:
    """Map arbitrary adapter codes to a low-cardinality metric label."""
    if error_code and is_deterministic_adapter_rejection_code(error_code):
        if error_code in _DETERMINISTIC_ADAPTER_REJECTION_CODES:
            return error_code
        if error_code.startswith("unsupported_"):
            return "unsupported"
    if error_code == "version_conflict":
        return "version_conflict"
    if error_code == "guardrail_blocked":
        return "guardrail_blocked"
    return _DEAD_LETTER_METRIC_FALLBACK_CODE


def classify_disposition_delivery_error(
    exc: BaseException,
) -> tuple[DispositionDeliveryErrorKind, str | None]:
    """Classify an outbox delivery failure for worker/reconcile handling."""
    if isinstance(exc, GuardrailViolationError):
        return DispositionDeliveryErrorKind.GUARDRAIL, exc.error_code
    if isinstance(exc, WritebackConflictError):
        return DispositionDeliveryErrorKind.CONFLICT, exc.error_code
    if isinstance(exc, WritebackUnsupportedError):
        return DispositionDeliveryErrorKind.DETERMINISTIC_REJECTION, exc.error_code
    if isinstance(exc, ValidationError):
        if is_deterministic_adapter_rejection_code(exc.error_code):
            return DispositionDeliveryErrorKind.DETERMINISTIC_REJECTION, exc.error_code
        return DispositionDeliveryErrorKind.AMBIGUOUS_OUTCOME, exc.error_code
    return DispositionDeliveryErrorKind.AMBIGUOUS_OUTCOME, None


__all__ = [
    "DispositionDeliveryErrorKind",
    "bounded_dead_letter_error_code",
    "classify_disposition_delivery_error",
    "is_deterministic_adapter_rejection_code",
]
