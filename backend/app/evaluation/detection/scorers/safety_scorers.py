"""Tenant isolation and resource budget scorers (ISSUE-126 / #631 Phase A)."""

from __future__ import annotations

from app.evaluation.detection.scorers.base import DetectionScorerContext
from app.models.detection_evaluation import DetectionCaseObservation
from app.models.evaluation_run import EvaluationScorerResult, ScorerOutcome
from app.models.evaluation_truth import EvaluationCaseTruth, SliceType


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


def _skipped(scorer_id: str, reason_code: str, message: str) -> EvaluationScorerResult:
    return EvaluationScorerResult(
        scorer_id=scorer_id,
        outcome=ScorerOutcome.SKIPPED,
        reason_code=reason_code,
        message=message,
    )


class TenantIsolationScorer:
    """Candidates must remain within the adjudicated source tenant."""

    scorer_id = "tenant_isolation"
    supported_slices = frozenset({SliceType.THREAT, SliceType.BENIGN})

    def score(
        self,
        truth: EvaluationCaseTruth,
        observation: DetectionCaseObservation,
        ctx: DetectionScorerContext,
    ) -> EvaluationScorerResult:
        foreign = [
            candidate
            for candidate in observation.candidates
            if candidate.source_tenant_id != ctx.source_tenant_id
        ]
        if foreign:
            return _fail(
                self.scorer_id,
                "cross_tenant_leak",
                f"found {len(foreign)} candidate(s) outside source tenant",
            )
        return _pass(self.scorer_id, "tenant isolation satisfied")


class ResourceBudgetScorer:
    """Fail closed when shadow runtime exceeds configured scan budget."""

    scorer_id = "resource_budget"
    supported_slices = frozenset({SliceType.THREAT, SliceType.BENIGN})

    def score(
        self,
        truth: EvaluationCaseTruth,
        observation: DetectionCaseObservation,
        ctx: DetectionScorerContext,
    ) -> EvaluationScorerResult:
        if ctx.max_observations_scanned is None:
            return _skipped(self.scorer_id, "not_applicable", "no resource budget configured")
        scanned = observation.resource_metrics.observations_scanned
        if scanned > ctx.max_observations_scanned:
            return _fail(
                self.scorer_id,
                "scan_budget_exceeded",
                f"observations_scanned={scanned} > budget={ctx.max_observations_scanned}",
            )
        return _pass(self.scorer_id, "resource budget satisfied")


__all__ = ["ResourceBudgetScorer", "TenantIsolationScorer"]
