"""Coordination (task/artifact ledger) slice scorers (ISSUE-136 / #642 Phase C)."""

from __future__ import annotations

from app.evaluation.scorers.base import ScorerContext
from app.models.evaluation_run import CaseObservation, EvaluationScorerResult, ScorerOutcome
from app.models.evaluation_truth import (
    CoordinationExpectationKind,
    CoordinationSliceExpectation,
    EvaluationCaseTruth,
    SliceType,
)

_KIND_REQUIRED_FIELDS: dict[CoordinationExpectationKind, tuple[str, ...]] = {
    CoordinationExpectationKind.STALE_FENCING_DENIED: ("expected_stale_fencing_denied",),
    CoordinationExpectationKind.ARTIFACT_IDEMPOTENT_REPLAY: (
        "expected_duplicate_logical_artifact",
        "expected_content_hash_match",
    ),
    CoordinationExpectationKind.ATTEMPT_HISTORY_AUDITABLE: ("expected_attempt_recorded",),
    CoordinationExpectationKind.CROSS_TENANT_TASK_DENIED: ("expected_cross_tenant_denied",),
    CoordinationExpectationKind.PROMPT_INJECTION_PROJECTION_DENIED: (
        "expected_projection_rejected",
    ),
    CoordinationExpectationKind.FORGED_GRANT_DENIED: ("expected_forged_grant_rejected",),
    CoordinationExpectationKind.CRASH_RETRY_NO_DUPLICATE_TERMINAL: (
        "expected_terminal_transition_idempotent",
    ),
    CoordinationExpectationKind.SIDE_EFFECT_UNKNOWN_MANUAL: (
        "expected_manual_resolution_required",
        "expected_blind_retry_blocked",
    ),
}

_OBSERVED_FIELD_BY_EXPECTATION: dict[str, str] = {
    "expected_stale_fencing_denied": "stale_fencing_denied",
    "expected_duplicate_logical_artifact": "duplicate_logical_artifact",
    "expected_content_hash_match": "content_hash_match",
    "expected_attempt_recorded": "attempt_recorded",
    "expected_cross_tenant_denied": "cross_tenant_denied",
    "expected_projection_rejected": "projection_rejected",
    "expected_forged_grant_rejected": "forged_grant_rejected",
    "expected_terminal_transition_idempotent": "terminal_transition_idempotent",
    "expected_manual_resolution_required": "manual_resolution_required",
    "expected_blind_retry_blocked": "blind_retry_blocked",
}


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


def _validate_expectation_config(
    scorer_id: str,
    expectation: CoordinationSliceExpectation,
) -> EvaluationScorerResult | None:
    required = _KIND_REQUIRED_FIELDS.get(expectation.expectation_kind, ())
    for field_name in required:
        value = getattr(expectation, field_name)
        if field_name == "expected_duplicate_logical_artifact" and value is not False:
            return _fail(
                scorer_id,
                "invalid_expectation_config",
                f"{expectation.expectation_kind.value} requires {field_name}=False",
            )
        if value is None:
            return _fail(
                scorer_id,
                "invalid_expectation_config",
                f"{expectation.expectation_kind.value} requires {field_name}",
            )
    return None


class CoordinationSliceScorer:
    """Compare structured coordination observations against canonical expectations."""

    scorer_id = "coordination_ledger"
    supported_slices = frozenset({SliceType.COORDINATION})

    def score(
        self,
        truth: EvaluationCaseTruth,
        observation: CaseObservation,
        ctx: ScorerContext,
    ) -> EvaluationScorerResult:
        del ctx
        if not isinstance(truth.slice_expectation, CoordinationSliceExpectation):
            return _error(self.scorer_id, "invalid_expectation", "expected coordination slice")
        if not observation.observation_available or observation.coordination is None:
            return _unevaluable(
                self.scorer_id,
                "missing_observation",
                "no coordination observation",
            )

        expectation = truth.slice_expectation
        config_error = _validate_expectation_config(self.scorer_id, expectation)
        if config_error is not None:
            return config_error

        observed = observation.coordination
        if observed.dependency_degraded:
            return _fail(
                self.scorer_id,
                "required_dependency_degraded",
                "required coordination dependency degraded",
            )

        if observed.expectation_kind != expectation.expectation_kind.value:
            return _fail(
                self.scorer_id,
                "expectation_kind_mismatch",
                f"observed kind {observed.expectation_kind!r} != "
                f"{expectation.expectation_kind.value!r}",
            )

        for expected_field, observed_field in _OBSERVED_FIELD_BY_EXPECTATION.items():
            expected = getattr(expectation, expected_field)
            if expected is None:
                continue
            actual = getattr(observed, observed_field)
            if actual is None:
                return _fail(
                    self.scorer_id,
                    "missing_observed_field",
                    f"observation missing {observed_field}",
                )
            if actual != expected:
                return _fail(
                    self.scorer_id,
                    f"{observed_field}_mismatch",
                    f"{observed_field}: observed={actual} expected={expected}",
                )

        return _pass(
            self.scorer_id,
            f"coordination expectation satisfied ({expectation.expectation_kind.value})",
        )


__all__ = ["CoordinationSliceScorer"]
