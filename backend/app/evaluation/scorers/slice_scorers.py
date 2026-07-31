"""Phase A slice scorers — compare mock observations against canonical truth."""

from __future__ import annotations

from app.evaluation.scorers.base import ScorerContext
from app.models.evaluation_run import CaseObservation, EvaluationScorerResult, ScorerOutcome
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


class ThreatSliceScorer:
    scorer_id = "threat_label"
    supported_slices = frozenset({SliceType.THREAT})

    def score(
        self,
        truth: EvaluationCaseTruth,
        observation: CaseObservation,
        ctx: ScorerContext,
    ) -> EvaluationScorerResult:
        if not isinstance(truth.slice_expectation, ThreatSliceExpectation):
            return _error(self.scorer_id, "invalid_expectation", "expected threat slice")
        if not observation.observation_available:
            return _unevaluable(self.scorer_id, "missing_observation", "no mock observation")
        expected_label = truth.slice_expectation.expected_case_label.value
        expected_verdict = truth.slice_expectation.expected_final_verdict.value
        if observation.observed_case_label != expected_label:
            return _fail(
                self.scorer_id,
                "label_mismatch",
                f"observed label {observation.observed_case_label!r} != {expected_label!r}",
            )
        if observation.observed_final_verdict != expected_verdict:
            return _fail(
                self.scorer_id,
                "verdict_mismatch",
                f"observed verdict {observation.observed_final_verdict!r} != {expected_verdict!r}",
            )
        return _pass(self.scorer_id, "threat expectation satisfied")


class BenignSliceScorer:
    scorer_id = "benign_label"
    supported_slices = frozenset({SliceType.BENIGN})

    def score(
        self,
        truth: EvaluationCaseTruth,
        observation: CaseObservation,
        ctx: ScorerContext,
    ) -> EvaluationScorerResult:
        if not isinstance(truth.slice_expectation, BenignSliceExpectation):
            return _error(self.scorer_id, "invalid_expectation", "expected benign slice")
        if not observation.observation_available:
            return _unevaluable(self.scorer_id, "missing_observation", "no mock observation")
        expected_label = truth.slice_expectation.expected_case_label.value
        expected_verdict = truth.slice_expectation.expected_final_verdict.value
        if observation.observed_case_label != expected_label:
            return _fail(
                self.scorer_id,
                "label_mismatch",
                f"observed label {observation.observed_case_label!r} != {expected_label!r}",
            )
        if observation.observed_final_verdict != expected_verdict:
            return _fail(
                self.scorer_id,
                "verdict_mismatch",
                f"observed verdict {observation.observed_final_verdict!r} != {expected_verdict!r}",
            )
        return _pass(self.scorer_id, "benign expectation satisfied")


class UnevaluableSliceScorer:
    scorer_id = "unevaluable_coverage"
    supported_slices = frozenset({SliceType.UNEVALUABLE})

    def score(
        self,
        truth: EvaluationCaseTruth,
        observation: CaseObservation,
        ctx: ScorerContext,
    ) -> EvaluationScorerResult:
        if not isinstance(truth.slice_expectation, UnevaluableSliceExpectation):
            return _error(self.scorer_id, "invalid_expectation", "expected unevaluable slice")
        if observation.observation_available and (
            observation.observed_case_label or observation.observed_final_verdict
        ):
            return _fail(
                self.scorer_id,
                "forced_label",
                "unevaluable case must not produce observed labels",
            )
        return _unevaluable(
            self.scorer_id,
            truth.slice_expectation.reason_code,
            truth.slice_expectation.detail or "explicit unevaluable slice",
        )


__all__ = [
    "BenignSliceScorer",
    "ThreatSliceScorer",
    "UnevaluableSliceScorer",
]
