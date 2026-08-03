"""Knowledge slice scorers (ISSUE-136 / #642 Phase A)."""

from __future__ import annotations

from app.evaluation.scorers.base import ScorerContext
from app.models.evaluation_run import CaseObservation, EvaluationScorerResult, ScorerOutcome
from app.models.evaluation_truth import (
    EvaluationCaseTruth,
    KnowledgeExpectationKind,
    KnowledgeSliceExpectation,
    SliceType,
)

_KIND_REQUIRED_FIELDS: dict[KnowledgeExpectationKind, tuple[str, ...]] = {
    KnowledgeExpectationKind.RELEASE_PINNED_RETRIEVAL: ("expected_release_id",),
    KnowledgeExpectationKind.CITATION_CORRECTNESS: ("expected_citation_chunk_ids",),
    KnowledgeExpectationKind.TENANT_FILTER: ("expected_tenant_filter_applied",),
    KnowledgeExpectationKind.DEGRADED_NO_RELEASE: ("expected_degraded",),
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
    expectation: KnowledgeSliceExpectation,
) -> EvaluationScorerResult | None:
    required = _KIND_REQUIRED_FIELDS.get(expectation.expectation_kind, ())
    for field_name in required:
        value = getattr(expectation, field_name)
        if field_name == "expected_citation_chunk_ids":
            if not value:
                return _fail(
                    scorer_id,
                    "invalid_expectation_config",
                    f"{expectation.expectation_kind.value} requires non-empty {field_name}",
                )
            continue
        if field_name == "expected_degraded" and value is not True:
            return _fail(
                scorer_id,
                "invalid_expectation_config",
                f"{expectation.expectation_kind.value} requires {field_name}=True",
            )
        if value is None:
            return _fail(
                scorer_id,
                "invalid_expectation_config",
                f"{expectation.expectation_kind.value} requires {field_name}",
            )
    return None


class KnowledgeSliceScorer:
    """Compare structured knowledge observations against canonical expectations."""

    scorer_id = "knowledge_retrieval"
    supported_slices = frozenset({SliceType.KNOWLEDGE})

    def score(
        self,
        truth: EvaluationCaseTruth,
        observation: CaseObservation,
        ctx: ScorerContext,
    ) -> EvaluationScorerResult:
        del ctx
        if not isinstance(truth.slice_expectation, KnowledgeSliceExpectation):
            return _error(self.scorer_id, "invalid_expectation", "expected knowledge slice")
        if not observation.observation_available or observation.knowledge is None:
            return _unevaluable(self.scorer_id, "missing_observation", "no knowledge observation")

        expectation = truth.slice_expectation
        config_error = _validate_expectation_config(self.scorer_id, expectation)
        if config_error is not None:
            return config_error

        observed = observation.knowledge
        if observed.dependency_degraded and not expectation.expected_degraded:
            return _fail(
                self.scorer_id,
                "required_dependency_degraded",
                "required knowledge dependency degraded without expected degraded outcome",
            )

        if observed.expectation_kind != expectation.expectation_kind.value:
            return _fail(
                self.scorer_id,
                "expectation_kind_mismatch",
                f"observed kind {observed.expectation_kind!r} != "
                f"{expectation.expectation_kind.value!r}",
            )

        if expectation.expected_release_id is not None:
            if observed.release_id != expectation.expected_release_id:
                return _fail(
                    self.scorer_id,
                    "release_mismatch",
                    f"release_id {observed.release_id!r} != {expectation.expected_release_id!r}",
                )

        if expectation.expected_plan_hash is not None:
            if observed.plan_hash != expectation.expected_plan_hash:
                return _fail(
                    self.scorer_id,
                    "plan_hash_mismatch",
                    "plan hash does not match pinned expectation",
                )

        if expectation.expected_tenant_filter_applied is not None:
            if observed.tenant_filter_applied != expectation.expected_tenant_filter_applied:
                return _fail(
                    self.scorer_id,
                    "tenant_filter_mismatch",
                    "tenant filter application mismatch",
                )

        if expectation.expected_citation_chunk_ids:
            observed_ids = set(observed.citation_chunk_ids)
            expected_ids = set(expectation.expected_citation_chunk_ids)
            if observed_ids != expected_ids:
                return _fail(
                    self.scorer_id,
                    "citation_mismatch",
                    f"citation chunks {sorted(observed_ids)} != {sorted(expected_ids)}",
                )

        if observed.degraded is None:
            return _fail(
                self.scorer_id, "missing_observed_field", "observation missing degraded flag"
            )
        if observed.degraded != expectation.expected_degraded:
            return _fail(
                self.scorer_id,
                "degraded_mismatch",
                f"degraded={observed.degraded} expected={expectation.expected_degraded}",
            )

        if observed.empty_results is None:
            return _fail(
                self.scorer_id,
                "missing_observed_field",
                "observation missing empty_results flag",
            )
        if observed.empty_results != expectation.expected_empty_results:
            return _fail(
                self.scorer_id,
                "empty_results_mismatch",
                (
                    f"empty_results={observed.empty_results} "
                    f"expected={expectation.expected_empty_results}"
                ),
            )

        return _pass(
            self.scorer_id,
            f"knowledge expectation satisfied ({expectation.expectation_kind.value})",
        )


__all__ = ["KnowledgeSliceScorer"]
