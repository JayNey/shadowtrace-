"""ISSUE-300 disposition delivery error classification unit tests."""

from __future__ import annotations

import pytest

from app.adapters.disposition.error_classification import (
    DispositionDeliveryErrorKind,
    bounded_dead_letter_error_code,
    classify_disposition_delivery_error,
    is_deterministic_adapter_rejection_code,
)
from app.core.errors import (
    GuardrailViolationError,
    ValidationError,
    WritebackConflictError,
    WritebackUnsupportedError,
)


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("not_found", True),
        ("unsupported_intent", True),
        ("unauthorized_field", True),
        ("invalid_operation", True),
        ("permission_denied", True),
        ("auth_error", True),
        ("adapter_validation_error", True),
        ("idempotency_key_reuse", True),
        ("disposition_id_reuse", True),
        ("writeback_unsupported", True),
        ("mock_validation_error", True),
        ("invalid_cursor", True),
        ("adapter_not_found", True),
        ("validation_error", False),
        ("delivery_outcome_unknown", False),
        (None, False),
    ],
)
def test_is_deterministic_adapter_rejection_code(code: str | None, expected: bool) -> None:
    assert is_deterministic_adapter_rejection_code(code) is expected


def test_bounded_dead_letter_error_code_maps_unknown_to_bucket() -> None:
    assert bounded_dead_letter_error_code("not_found") == "not_found"
    assert bounded_dead_letter_error_code("unsupported_foo") == "unsupported"
    assert bounded_dead_letter_error_code("totally_new_code") == "adapter_validation_error"


@pytest.mark.parametrize(
    ("exc", "kind", "code"),
    [
        (
            ValidationError("missing object", error_code="not_found"),
            DispositionDeliveryErrorKind.DETERMINISTIC_REJECTION,
            "not_found",
        ),
        (
            ValidationError("bad input", error_code="validation_error"),
            DispositionDeliveryErrorKind.AMBIGUOUS_OUTCOME,
            "validation_error",
        ),
        (
            WritebackConflictError("stale token", error_code="version_conflict"),
            DispositionDeliveryErrorKind.CONFLICT,
            "version_conflict",
        ),
        (
            WritebackUnsupportedError("unsupported", error_code="writeback_unsupported"),
            DispositionDeliveryErrorKind.DETERMINISTIC_REJECTION,
            "writeback_unsupported",
        ),
        (
            GuardrailViolationError("blocked"),
            DispositionDeliveryErrorKind.GUARDRAIL,
            "guardrail_failed",
        ),
    ],
)
def test_classify_disposition_delivery_error(
    exc: BaseException,
    kind: DispositionDeliveryErrorKind,
    code: str,
) -> None:
    assert classify_disposition_delivery_error(exc) == (kind, code)
