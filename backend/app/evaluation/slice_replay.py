"""Deterministic slice replay adapters for security/knowledge evaluation (#642 Phase A).

Adapters simulate grant-boundary and retrieval-pipeline decision paths without
touching production stores. Observations are derived from expectation_kind +
seed, not copied field-for-field from truth expectations (unlike echo_truth_stub).
"""

from __future__ import annotations

import hashlib

from app.models.evaluation_run import KnowledgeCaseObservation, SecurityCaseObservation
from app.models.evaluation_truth import (
    KnowledgeExpectationKind,
    KnowledgeSliceExpectation,
    SecurityExpectationKind,
    SecuritySliceExpectation,
)


def derive_plan_hash(*, release_id: str, case_id: str, seed: int) -> str:
    """Canonical pinned-plan hash used by the knowledge release adapter."""
    payload = f"plan:{release_id}:{case_id}:{seed}"
    return hashlib.sha256(payload.encode()).hexdigest()


def _simulate_grant_boundary(
    expectation: SecuritySliceExpectation,
    *,
    fail: bool,
) -> SecurityCaseObservation:
    """Simulate ToolCallGrant / tenant boundary mediation (mock-only)."""
    kind = expectation.expectation_kind
    dependency_degraded = False
    side_effect_unknown_contained: bool | None = None

    if kind is SecurityExpectationKind.CROSS_TENANT_DENIED:
        cross_tenant_denied = True
        grant_forgery_rejected = None
        grant_budget_race_rejected = None
        side_effect_blocked = None
        prompt_injection_contained = None
    elif kind is SecurityExpectationKind.GRANT_FORGERY_REJECTED:
        cross_tenant_denied = None
        grant_forgery_rejected = True
        grant_budget_race_rejected = None
        side_effect_blocked = None
        prompt_injection_contained = None
    elif kind is SecurityExpectationKind.GRANT_BUDGET_RACE:
        cross_tenant_denied = None
        grant_forgery_rejected = None
        grant_budget_race_rejected = True
        side_effect_blocked = None
        prompt_injection_contained = None
    elif kind is SecurityExpectationKind.SIDE_EFFECT_BLOCKED:
        cross_tenant_denied = None
        grant_forgery_rejected = None
        grant_budget_race_rejected = None
        side_effect_blocked = True
        prompt_injection_contained = None
    elif kind is SecurityExpectationKind.SIDE_EFFECT_UNKNOWN:
        cross_tenant_denied = None
        grant_forgery_rejected = None
        grant_budget_race_rejected = None
        side_effect_blocked = None
        side_effect_unknown_contained = True
        prompt_injection_contained = None
    elif kind is SecurityExpectationKind.PROMPT_INJECTION_CONTAINED:
        cross_tenant_denied = None
        grant_forgery_rejected = None
        grant_budget_race_rejected = None
        side_effect_blocked = None
        prompt_injection_contained = True
    else:  # PRODUCTION_ISOLATION
        cross_tenant_denied = None
        grant_forgery_rejected = None
        grant_budget_race_rejected = None
        side_effect_blocked = None
        prompt_injection_contained = None

    production_store_mutated = False

    if fail:
        production_store_mutated = True
        if cross_tenant_denied is not None:
            cross_tenant_denied = False
        if grant_forgery_rejected is not None:
            grant_forgery_rejected = False
        if grant_budget_race_rejected is not None:
            grant_budget_race_rejected = False
        if side_effect_blocked is not None:
            side_effect_blocked = False
        if side_effect_unknown_contained is not None:
            side_effect_unknown_contained = False
        if prompt_injection_contained is not None:
            prompt_injection_contained = False

    return SecurityCaseObservation(
        expectation_kind=kind.value,
        cross_tenant_denied=cross_tenant_denied,
        grant_forgery_rejected=grant_forgery_rejected,
        grant_budget_race_rejected=grant_budget_race_rejected,
        side_effect_blocked=side_effect_blocked,
        side_effect_unknown_contained=side_effect_unknown_contained,
        prompt_injection_contained=prompt_injection_contained,
        production_store_mutated=production_store_mutated,
        dependency_degraded=dependency_degraded,
    )


def _simulate_knowledge_retrieval(
    expectation: KnowledgeSliceExpectation,
    *,
    case_id: str,
    seed: int,
    fail: bool,
) -> KnowledgeCaseObservation:
    """Simulate release-pinned retrieval pipeline paths (mock-only)."""
    kind = expectation.expectation_kind
    dependency_degraded = False
    release_id = expectation.expected_release_id
    plan_hash = expectation.expected_plan_hash
    tenant_filter = expectation.expected_tenant_filter_applied
    citations = list(expectation.expected_citation_chunk_ids)
    degraded = expectation.expected_degraded
    empty_results = expectation.expected_empty_results

    if kind is KnowledgeExpectationKind.DEGRADED_NO_RELEASE:
        dependency_degraded = True
        release_id = None
        plan_hash = None
        degraded = True
        empty_results = True
        citations = []
    elif kind is KnowledgeExpectationKind.RELEASE_PINNED_RETRIEVAL:
        if not release_id:
            dependency_degraded = True
            degraded = True
            empty_results = True
        else:
            plan_hash = derive_plan_hash(release_id=release_id, case_id=case_id, seed=seed)
            degraded = False
            empty_results = False
    elif kind is KnowledgeExpectationKind.TENANT_FILTER:
        tenant_filter = True if tenant_filter is not False else False
        degraded = False
        empty_results = False
    elif kind is KnowledgeExpectationKind.CITATION_CORRECTNESS:
        degraded = False
        empty_results = False

    if fail and kind is not KnowledgeExpectationKind.DEGRADED_NO_RELEASE:
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
        dependency_degraded = False

    return KnowledgeCaseObservation(
        expectation_kind=kind.value,
        release_id=release_id,
        plan_hash=plan_hash,
        tenant_filter_applied=tenant_filter,
        citation_chunk_ids=citations,
        degraded=degraded,
        empty_results=empty_results,
        chunk_count=0 if empty_results else max(len(citations), 1),
        dependency_degraded=dependency_degraded,
    )


def replay_security_slice(
    expectation: SecuritySliceExpectation,
    *,
    fail: bool,
) -> SecurityCaseObservation:
    return _simulate_grant_boundary(expectation, fail=fail)


def replay_knowledge_slice(
    expectation: KnowledgeSliceExpectation,
    *,
    case_id: str,
    seed: int,
    fail: bool,
) -> KnowledgeCaseObservation:
    return _simulate_knowledge_retrieval(
        expectation,
        case_id=case_id,
        seed=seed,
        fail=fail,
    )


__all__ = [
    "derive_plan_hash",
    "replay_knowledge_slice",
    "replay_security_slice",
]
