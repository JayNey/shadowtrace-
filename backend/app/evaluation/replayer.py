"""Mock-only deterministic case replayer (ISSUE-105 / #608).

Never reads production Event/Detection/Disposition tables. Produces deterministic
observations derived from canonical truth + seed for scorer consumption.
"""

from __future__ import annotations

import hashlib

from app.models.evaluation_run import CaseObservation
from app.models.evaluation_truth import (
    BenignSliceExpectation,
    EvaluationCaseTruth,
    SliceType,
    ThreatSliceExpectation,
    UnevaluableSliceExpectation,
)


def _derive_case_nonce(case_id: str, seed: int) -> int:
    digest = hashlib.sha256(f"{seed}:{case_id}".encode()).hexdigest()
    return int(digest[:8], 16)


class MockDeterministicReplayer:
    """Deterministic mock replay for evaluation cases."""

    replay_mode = "mock_deterministic"

    def replay(self, truth: EvaluationCaseTruth, *, seed: int) -> CaseObservation:
        slice_type = SliceType(truth.slice_expectation.slice_type)
        _ = _derive_case_nonce(truth.case_id, seed)

        if isinstance(truth.slice_expectation, UnevaluableSliceExpectation):
            return CaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                observation_available=False,
                replay_notes=f"unevaluable:{truth.slice_expectation.reason_code}",
            )

        if isinstance(truth.slice_expectation, ThreatSliceExpectation):
            return CaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                observed_case_label=truth.slice_expectation.expected_case_label.value,
                observed_final_verdict=truth.slice_expectation.expected_final_verdict.value,
                observation_available=True,
                replay_notes="mock_deterministic:threat",
            )

        if isinstance(truth.slice_expectation, BenignSliceExpectation):
            return CaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                observed_case_label=truth.slice_expectation.expected_case_label.value,
                observed_final_verdict=truth.slice_expectation.expected_final_verdict.value,
                observation_available=True,
                replay_notes="mock_deterministic:benign",
            )

        return CaseObservation(
            case_id=truth.case_id,
            slice_type=slice_type,
            observation_available=False,
            replay_notes="unsupported_slice_expectation",
        )


__all__ = ["MockDeterministicReplayer"]
