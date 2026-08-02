"""Detection slice scorers — compare shadow candidates against canonical truth."""

from __future__ import annotations

from app.evaluation.detection.scorers.base import DetectionScorerContext
from app.models.detection_evaluation import DetectionCaseObservation
from app.models.evaluation_run import EvaluationScorerResult, ScorerOutcome
from app.models.evaluation_truth import (
    BenignSliceExpectation,
    EvaluationCaseTruth,
    SliceType,
    ThreatSliceExpectation,
    UnevaluableSliceExpectation,
)


def _pass(scorer_id: str, message: str = "") -> EvaluationScorerResult:
    return EvaluationScorerResult(
        scorer_id=scorer_id,
        outcome=ScorerOutcome.PASS,
        message=message,
    )


def _fail(scorer_id: str, reason_code: str, message: str) -> EvaluationScorerResult:
    return EvaluationScorerResult(
        scorer_id=scorer_id,
        outcome=ScorerOutcome.FAIL,
        reason_code=reason_code,
        message=message,
    )


def _unevaluable(scorer_id: str, reason_code: str, message: str) -> EvaluationScorerResult:
    return EvaluationScorerResult(
        scorer_id=scorer_id,
        outcome=ScorerOutcome.UNEVALUABLE,
        reason_code=reason_code,
        message=message,
    )


def _error(scorer_id: str, reason_code: str, message: str) -> EvaluationScorerResult:
    return EvaluationScorerResult(
        scorer_id=scorer_id,
        outcome=ScorerOutcome.ERROR,
        reason_code=reason_code,
        message=message,
    )


class ThreatDetectionScorer:
    """Threat slice must produce at least one expected shadow candidate."""

    scorer_id = "threat_detection"
    supported_slices = frozenset({SliceType.THREAT})

    def score(
        self,
        truth: EvaluationCaseTruth,
        observation: DetectionCaseObservation,
        ctx: DetectionScorerContext,
    ) -> EvaluationScorerResult:
        if not isinstance(truth.slice_expectation, ThreatSliceExpectation):
            return _error(self.scorer_id, "invalid_expectation", "expected threat slice")
        if observation.runtime_errors:
            return _error(
                self.scorer_id,
                "runtime_error",
                observation.runtime_errors[0].error_message[:256],
            )
        if not observation.observation_available:
            return _unevaluable(self.scorer_id, "missing_replay", "shadow replay unavailable")
        if not observation.candidates:
            return _fail(self.scorer_id, "no_detection", "threat case produced no candidates")
        if ctx.expected_rule_ids:
            fired = {candidate.rule_id for candidate in observation.candidates}
            missing = [rule_id for rule_id in ctx.expected_rule_ids if rule_id not in fired]
            if missing:
                return _fail(
                    self.scorer_id,
                    "missing_expected_rule",
                    f"expected rules not fired: {missing}",
                )
        return _pass(self.scorer_id, "threat detection satisfied")


class BenignDetectionScorer:
    """Benign slice must stay silent — hard negatives must not fire."""

    scorer_id = "benign_detection"
    supported_slices = frozenset({SliceType.BENIGN})

    def score(
        self,
        truth: EvaluationCaseTruth,
        observation: DetectionCaseObservation,
        ctx: DetectionScorerContext,
    ) -> EvaluationScorerResult:
        if not isinstance(truth.slice_expectation, BenignSliceExpectation):
            return _error(self.scorer_id, "invalid_expectation", "expected benign slice")
        if observation.runtime_errors:
            return _error(
                self.scorer_id,
                "runtime_error",
                observation.runtime_errors[0].error_message[:256],
            )
        if not observation.observation_available:
            return _unevaluable(self.scorer_id, "missing_replay", "shadow replay unavailable")
        if observation.candidates:
            return _fail(
                self.scorer_id,
                "false_positive",
                f"benign case produced {len(observation.candidates)} candidate(s)",
            )
        return _pass(self.scorer_id, "benign silence satisfied")


class UnevaluableDetectionScorer:
    """Unevaluable slice must not be forced into benign via silent pass."""

    scorer_id = "unevaluable_coverage"
    supported_slices = frozenset({SliceType.UNEVALUABLE})

    def score(
        self,
        truth: EvaluationCaseTruth,
        observation: DetectionCaseObservation,
        ctx: DetectionScorerContext,
    ) -> EvaluationScorerResult:
        if not isinstance(truth.slice_expectation, UnevaluableSliceExpectation):
            return _error(self.scorer_id, "invalid_expectation", "expected unevaluable slice")
        if observation.candidates:
            return _fail(
                self.scorer_id,
                "forced_detection",
                "unevaluable case must not produce candidates",
            )
        if observation.runtime_errors and observation.observation_available:
            return _fail(
                self.scorer_id,
                "runtime_error_on_unevaluable",
                "unevaluable case surfaced runtime errors instead of coverage",
            )
        return _unevaluable(
            self.scorer_id,
            truth.slice_expectation.reason_code,
            truth.slice_expectation.detail or "explicit unevaluable slice",
        )


__all__ = [
    "BenignDetectionScorer",
    "ThreatDetectionScorer",
    "UnevaluableDetectionScorer",
]
