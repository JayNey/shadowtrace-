"""Optional grouping scorers — severity, ATT&CK, incident (ISSUE-113 Phase B).

Independent typed scorers that do not participate in promotion eligibility.
When truth lacks optional expectation fields the scorer returns PASS with
``not_applicable`` so required label scorers remain authoritative.
"""

from __future__ import annotations

from app.evaluation.scorers.base import ScorerContext
from app.models.evaluation_run import CaseObservation, EvaluationScorerResult, ScorerOutcome
from app.models.evaluation_truth import (
    BenignSliceExpectation,
    EvaluationCaseTruth,
    SliceType,
    ThreatSliceExpectation,
)


def _not_applicable(scorer_id: str, message: str) -> EvaluationScorerResult:
    return EvaluationScorerResult(
        scorer_id=scorer_id,
        outcome=ScorerOutcome.PASS,
        reason_code="not_applicable",
        message=message,
    )


def _fail(scorer_id: str, reason_code: str, message: str) -> EvaluationScorerResult:
    return EvaluationScorerResult(
        scorer_id=scorer_id,
        outcome=ScorerOutcome.FAIL,
        reason_code=reason_code,
        message=message,
    )


def _pass(scorer_id: str, message: str) -> EvaluationScorerResult:
    return EvaluationScorerResult(
        scorer_id=scorer_id,
        outcome=ScorerOutcome.PASS,
        message=message,
    )


def _error(scorer_id: str, reason_code: str, message: str) -> EvaluationScorerResult:
    return EvaluationScorerResult(
        scorer_id=scorer_id,
        outcome=ScorerOutcome.ERROR,
        reason_code=reason_code,
        message=message,
    )


def _evaluable_expectation(
    truth: EvaluationCaseTruth,
) -> ThreatSliceExpectation | BenignSliceExpectation | None:
    if isinstance(truth.slice_expectation, (ThreatSliceExpectation, BenignSliceExpectation)):
        return truth.slice_expectation
    return None


class SeverityAlignmentScorer:
    scorer_id = "severity_alignment"
    supported_slices = frozenset({SliceType.THREAT, SliceType.BENIGN})

    def score(
        self,
        truth: EvaluationCaseTruth,
        observation: CaseObservation,
        ctx: ScorerContext,
    ) -> EvaluationScorerResult:
        expectation = _evaluable_expectation(truth)
        if expectation is None:
            return _not_applicable(self.scorer_id, "unevaluable slice has no severity expectation")
        if expectation.expected_risk_score is None:
            return _not_applicable(self.scorer_id, "no expected_risk_score configured in truth")
        if not observation.observation_available:
            return _error(self.scorer_id, "missing_observation", "observation unavailable")
        if observation.observed_risk_score is None:
            return _fail(
                self.scorer_id,
                "missing_observed_severity",
                "observation missing observed_risk_score",
            )
        if observation.observed_risk_score != expectation.expected_risk_score:
            return _fail(
                self.scorer_id,
                "severity_mismatch",
                (
                    f"observed risk_score {observation.observed_risk_score} "
                    f"!= expected {expectation.expected_risk_score}"
                ),
            )
        return _pass(self.scorer_id, "severity aligned with truth")


class AttackTechniqueCoverageScorer:
    scorer_id = "attack_technique_coverage"
    supported_slices = frozenset({SliceType.THREAT, SliceType.BENIGN})

    def score(
        self,
        truth: EvaluationCaseTruth,
        observation: CaseObservation,
        ctx: ScorerContext,
    ) -> EvaluationScorerResult:
        expectation = _evaluable_expectation(truth)
        if expectation is None:
            return _not_applicable(self.scorer_id, "unevaluable slice has no ATT&CK expectation")
        expected = expectation.expected_attack_techniques
        if not expected:
            return _not_applicable(
                self.scorer_id, "no expected_attack_techniques configured in truth"
            )
        if not observation.observation_available:
            return _error(self.scorer_id, "missing_observation", "observation unavailable")
        observed = set(observation.observed_attack_techniques)
        missing = [technique for technique in expected if technique not in observed]
        if missing:
            return _fail(
                self.scorer_id,
                "technique_missing",
                f"missing expected techniques: {', '.join(missing)}",
            )
        return _pass(self.scorer_id, "expected ATT&CK techniques covered")


class IncidentGroupingConsistencyScorer:
    scorer_id = "incident_grouping_consistency"
    supported_slices = frozenset({SliceType.THREAT, SliceType.BENIGN})

    def score(
        self,
        truth: EvaluationCaseTruth,
        observation: CaseObservation,
        ctx: ScorerContext,
    ) -> EvaluationScorerResult:
        expectation = _evaluable_expectation(truth)
        if expectation is None:
            return _not_applicable(self.scorer_id, "unevaluable slice has no incident grouping")
        if expectation.expected_incident_group_id is None:
            return _not_applicable(
                self.scorer_id, "no expected_incident_group_id configured in truth"
            )
        if not observation.observation_available:
            return _error(self.scorer_id, "missing_observation", "observation unavailable")
        if observation.observed_incident_group_id is None:
            return _fail(
                self.scorer_id,
                "missing_observed_group",
                "observation missing observed_incident_group_id",
            )
        if observation.observed_incident_group_id != expectation.expected_incident_group_id:
            return _fail(
                self.scorer_id,
                "incident_group_mismatch",
                (
                    f"observed group {observation.observed_incident_group_id!r} "
                    f"!= expected {expectation.expected_incident_group_id!r}"
                ),
            )
        return _pass(self.scorer_id, "incident grouping consistent with truth")


__all__ = [
    "AttackTechniqueCoverageScorer",
    "IncidentGroupingConsistencyScorer",
    "SeverityAlignmentScorer",
]
