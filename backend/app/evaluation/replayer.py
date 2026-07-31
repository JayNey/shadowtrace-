"""Mock-only deterministic case replayer (ISSUE-105 / #608).

Never reads production Event/Detection/Disposition tables. Produces deterministic
observations derived from canonical truth + seed for scorer consumption.

Phase-1 stub: copies adjudicated slice expectations into observations so the
runner/scorer/gate plumbing can be validated before mock investigate replay (#631)
is wired. ``seed`` is bound into replay notes for traceability but does not yet
change observation outcomes.
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
    replay_fidelity = "echo_truth_stub"

    def replay(self, truth: EvaluationCaseTruth, *, seed: int) -> CaseObservation:
        slice_type = SliceType(truth.slice_expectation.slice_type)
        nonce = _derive_case_nonce(truth.case_id, seed)

        if isinstance(truth.slice_expectation, UnevaluableSliceExpectation):
            return CaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                observation_available=False,
                replay_notes=f"unevaluable:{truth.slice_expectation.reason_code};seed={seed};n={nonce:x}",
            )

        if isinstance(truth.slice_expectation, ThreatSliceExpectation):
            return CaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                observed_case_label=truth.slice_expectation.expected_case_label.value,
                observed_final_verdict=truth.slice_expectation.expected_final_verdict.value,
                observation_available=True,
                replay_notes=f"mock_deterministic:threat;seed={seed};n={nonce:x}",
            )

        if isinstance(truth.slice_expectation, BenignSliceExpectation):
            return CaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                observed_case_label=truth.slice_expectation.expected_case_label.value,
                observed_final_verdict=truth.slice_expectation.expected_final_verdict.value,
                observation_available=True,
                replay_notes=f"mock_deterministic:benign;seed={seed};n={nonce:x}",
            )

        return CaseObservation(
            case_id=truth.case_id,
            slice_type=slice_type,
            observation_available=False,
            replay_notes=f"unsupported_slice_expectation;seed={seed};n={nonce:x}",
        )


__all__ = ["MockDeterministicReplayer"]
