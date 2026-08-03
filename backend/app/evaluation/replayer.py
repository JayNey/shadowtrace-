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

from app.models.evaluation_run import CaseObservation, KnowledgeCaseObservation, SecurityCaseObservation
from app.models.evaluation_truth import (
    BenignSliceExpectation,
    EvaluationCaseTruth,
    KnowledgeSliceExpectation,
    SecuritySliceExpectation,
    SliceType,
    ThreatSliceExpectation,
    UnevaluableSliceExpectation,
)


def _derive_case_nonce(case_id: str, seed: int) -> int:
    digest = hashlib.sha256(f"{seed}:{case_id}".encode()).hexdigest()
    return int(digest[:8], 16)


def _invert_bool(value: bool | None, *, fail: bool) -> bool | None:
    if value is None:
        return None
    return (not value) if fail else value


def _security_observation(
    expectation: SecuritySliceExpectation,
    *,
    fail: bool,
) -> SecurityCaseObservation:
    return SecurityCaseObservation(
        expectation_kind=expectation.expectation_kind.value,
        cross_tenant_denied=_invert_bool(expectation.expected_cross_tenant_denied, fail=fail),
        grant_forgery_rejected=_invert_bool(
            expectation.expected_grant_forgery_rejected,
            fail=fail,
        ),
        grant_budget_race_rejected=_invert_bool(
            expectation.expected_grant_budget_race_rejected,
            fail=fail,
        ),
        side_effect_blocked=_invert_bool(expectation.expected_side_effect_blocked, fail=fail),
        prompt_injection_contained=_invert_bool(
            expectation.expected_prompt_injection_contained,
            fail=fail,
        ),
        production_store_mutated=_invert_bool(
            expectation.expected_production_store_mutated,
            fail=fail,
        ),
    )


def _knowledge_observation(
    expectation: KnowledgeSliceExpectation,
    *,
    fail: bool,
) -> KnowledgeCaseObservation:
    release_id = expectation.expected_release_id
    plan_hash = expectation.expected_plan_hash
    tenant_filter = expectation.expected_tenant_filter_applied
    citations = list(expectation.expected_citation_chunk_ids)
    degraded = expectation.expected_degraded
    empty_results = expectation.expected_empty_results

    if fail:
        if release_id is not None:
            release_id = f"{release_id}-wrong"
        if plan_hash is not None:
            plan_hash = "0" * 64
        if tenant_filter is not None:
            tenant_filter = not tenant_filter
        if citations:
            citations = [f"{citations[0]}-wrong"]
        degraded = not degraded
        empty_results = not empty_results

    return KnowledgeCaseObservation(
        expectation_kind=expectation.expectation_kind.value,
        release_id=release_id,
        plan_hash=plan_hash,
        tenant_filter_applied=tenant_filter,
        citation_chunk_ids=citations,
        degraded=degraded,
        empty_results=empty_results,
        chunk_count=0 if empty_results else max(len(citations), 1),
    )


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
            expectation = truth.slice_expectation
            return CaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                observed_case_label=expectation.expected_case_label.value,
                observed_final_verdict=expectation.expected_final_verdict.value,
                observed_risk_score=expectation.expected_risk_score,
                observed_attack_techniques=list(expectation.expected_attack_techniques),
                observed_incident_group_id=expectation.expected_incident_group_id,
                observation_available=True,
                replay_notes=f"mock_deterministic:threat;seed={seed};n={nonce:x}",
            )

        if isinstance(truth.slice_expectation, BenignSliceExpectation):
            benign_expectation = truth.slice_expectation
            return CaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                observed_case_label=benign_expectation.expected_case_label.value,
                observed_final_verdict=benign_expectation.expected_final_verdict.value,
                observed_risk_score=benign_expectation.expected_risk_score,
                observed_attack_techniques=list(benign_expectation.expected_attack_techniques),
                observed_incident_group_id=benign_expectation.expected_incident_group_id,
                observation_available=True,
                replay_notes=f"mock_deterministic:benign;seed={seed};n={nonce:x}",
            )

        if isinstance(truth.slice_expectation, SecuritySliceExpectation):
            expectation = truth.slice_expectation
            fail = expectation.replay_variant == "fail"
            return CaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                observation_available=True,
                security=_security_observation(expectation, fail=fail),
                replay_notes=(
                    f"mock_deterministic:security:{expectation.replay_variant};"
                    f"seed={seed};n={nonce:x}"
                ),
            )

        if isinstance(truth.slice_expectation, KnowledgeSliceExpectation):
            expectation = truth.slice_expectation
            fail = expectation.replay_variant == "fail"
            return CaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                observation_available=True,
                knowledge=_knowledge_observation(expectation, fail=fail),
                replay_notes=(
                    f"mock_deterministic:knowledge:{expectation.replay_variant};"
                    f"seed={seed};n={nonce:x}"
                ),
            )

        return CaseObservation(
            case_id=truth.case_id,
            slice_type=slice_type,
            observation_available=False,
            replay_notes=f"unsupported_slice_expectation;seed={seed};n={nonce:x}",
        )


__all__ = ["MockDeterministicReplayer"]
