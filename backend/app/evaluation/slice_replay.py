"""Deterministic slice replay adapters for evaluation slices (#642 Phase A/B/C).

Adapters simulate security grant boundaries, knowledge retrieval, ReAct shadow
pivot paths, and task/artifact coordination without touching production stores.
Observations are derived from expectation_kind (+ seed for knowledge plan_hash),
not copied field-for-field from truth expectations (unlike echo_truth_stub).

Replay fidelity label: ``slice_adapter_stub`` — does not invoke live #641/#639
runtime services; negative paths use ``replay_variant=fail`` in unit tests.
"""

from __future__ import annotations

import hashlib

from app.models.evaluation_run import (
    AgenticCaseObservation,
    CoordinationCaseObservation,
    KnowledgeCaseObservation,
    SecurityCaseObservation,
)
from app.models.evaluation_truth import (
    AgenticExpectationKind,
    AgenticSliceExpectation,
    CoordinationExpectationKind,
    CoordinationSliceExpectation,
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


def _simulate_agentic_shadow(
    expectation: AgenticSliceExpectation,
    *,
    fail: bool,
) -> AgenticCaseObservation:
    """Simulate ReAct shadow pivot decision paths (mock-only)."""
    kind = expectation.expectation_kind
    dependency_degraded = False
    production_store_mutated = expectation.expected_production_store_mutated
    shadow_namespace_used: bool | None = None
    pivot_completed: bool | None = None
    typed_artifact_produced: bool | None = None
    step_count_within_bounds: bool | None = None
    evidence_refs_valid: bool | None = None
    raw_cot_persisted: bool | None = None
    cross_tenant_denied: bool | None = None
    budget_race_rejected: bool | None = None
    degraded_fail_closed: bool | None = None
    unsupported_tool_denied: bool | None = None

    if kind is AgenticExpectationKind.SHADOW_ISOLATION:
        shadow_namespace_used = True
        production_store_mutated = False
    elif kind is AgenticExpectationKind.BOUNDED_PIVOT_SUCCESS:
        shadow_namespace_used = True
        pivot_completed = True
        typed_artifact_produced = True
        step_count_within_bounds = True
    elif kind is AgenticExpectationKind.EVIDENCE_FIDELITY:
        evidence_refs_valid = True
        typed_artifact_produced = True
    elif kind is AgenticExpectationKind.NO_RAW_COT:
        raw_cot_persisted = False
    elif kind is AgenticExpectationKind.SHADOW_CROSS_TENANT_DENIED:
        cross_tenant_denied = True
    elif kind is AgenticExpectationKind.SHADOW_BUDGET_RACE:
        budget_race_rejected = True
    elif kind is AgenticExpectationKind.SHADOW_DEGRADED_FAIL_CLOSED:
        degraded_fail_closed = True
        dependency_degraded = True
    elif kind is AgenticExpectationKind.SHADOW_UNSUPPORTED_TOOL_DENIED:
        unsupported_tool_denied = True

    if fail:
        production_store_mutated = True
        if shadow_namespace_used is not None:
            shadow_namespace_used = False
        if pivot_completed is not None:
            pivot_completed = False
        if typed_artifact_produced is not None:
            typed_artifact_produced = False
        if step_count_within_bounds is not None:
            step_count_within_bounds = False
        if evidence_refs_valid is not None:
            evidence_refs_valid = False
        if raw_cot_persisted is not None:
            raw_cot_persisted = True
        if cross_tenant_denied is not None:
            cross_tenant_denied = False
        if budget_race_rejected is not None:
            budget_race_rejected = False
        if degraded_fail_closed is not None:
            degraded_fail_closed = False
            dependency_degraded = False
        if unsupported_tool_denied is not None:
            unsupported_tool_denied = False

    return AgenticCaseObservation(
        expectation_kind=kind.value,
        production_store_mutated=production_store_mutated,
        shadow_namespace_used=shadow_namespace_used,
        pivot_completed=pivot_completed,
        typed_artifact_produced=typed_artifact_produced,
        step_count_within_bounds=step_count_within_bounds,
        evidence_refs_valid=evidence_refs_valid,
        raw_cot_persisted=raw_cot_persisted,
        cross_tenant_denied=cross_tenant_denied,
        budget_race_rejected=budget_race_rejected,
        degraded_fail_closed=degraded_fail_closed,
        unsupported_tool_denied=unsupported_tool_denied,
        dependency_degraded=dependency_degraded,
    )


def _simulate_coordination_ledger(
    expectation: CoordinationSliceExpectation,
    *,
    fail: bool,
) -> CoordinationCaseObservation:
    """Simulate typed task/artifact coordination paths (mock-only)."""
    kind = expectation.expectation_kind
    dependency_degraded = False
    stale_fencing_denied: bool | None = None
    duplicate_logical_artifact: bool | None = None
    content_hash_match: bool | None = None
    attempt_recorded: bool | None = None
    cross_tenant_denied: bool | None = None
    projection_rejected: bool | None = None
    forged_grant_rejected: bool | None = None
    terminal_transition_idempotent: bool | None = None
    manual_resolution_required: bool | None = None
    blind_retry_blocked: bool | None = None

    if kind is CoordinationExpectationKind.STALE_FENCING_DENIED:
        stale_fencing_denied = True
    elif kind is CoordinationExpectationKind.ARTIFACT_IDEMPOTENT_REPLAY:
        duplicate_logical_artifact = False
        content_hash_match = True
    elif kind is CoordinationExpectationKind.ATTEMPT_HISTORY_AUDITABLE:
        attempt_recorded = True
    elif kind is CoordinationExpectationKind.CROSS_TENANT_TASK_DENIED:
        cross_tenant_denied = True
    elif kind is CoordinationExpectationKind.PROMPT_INJECTION_PROJECTION_DENIED:
        projection_rejected = True
    elif kind is CoordinationExpectationKind.FORGED_GRANT_DENIED:
        forged_grant_rejected = True
    elif kind is CoordinationExpectationKind.CRASH_RETRY_NO_DUPLICATE_TERMINAL:
        terminal_transition_idempotent = True
    elif kind is CoordinationExpectationKind.SIDE_EFFECT_UNKNOWN_MANUAL:
        manual_resolution_required = True
        blind_retry_blocked = True

    if fail:
        if stale_fencing_denied is not None:
            stale_fencing_denied = False
        if duplicate_logical_artifact is not None:
            duplicate_logical_artifact = True
        if content_hash_match is not None:
            content_hash_match = False
        if attempt_recorded is not None:
            attempt_recorded = False
        if cross_tenant_denied is not None:
            cross_tenant_denied = False
        if projection_rejected is not None:
            projection_rejected = False
        if forged_grant_rejected is not None:
            forged_grant_rejected = False
        if terminal_transition_idempotent is not None:
            terminal_transition_idempotent = False
        if manual_resolution_required is not None:
            manual_resolution_required = False
        if blind_retry_blocked is not None:
            blind_retry_blocked = False

    return CoordinationCaseObservation(
        expectation_kind=kind.value,
        stale_fencing_denied=stale_fencing_denied,
        duplicate_logical_artifact=duplicate_logical_artifact,
        content_hash_match=content_hash_match,
        attempt_recorded=attempt_recorded,
        cross_tenant_denied=cross_tenant_denied,
        projection_rejected=projection_rejected,
        forged_grant_rejected=forged_grant_rejected,
        terminal_transition_idempotent=terminal_transition_idempotent,
        manual_resolution_required=manual_resolution_required,
        blind_retry_blocked=blind_retry_blocked,
        dependency_degraded=dependency_degraded,
    )


def replay_agentic_slice(
    expectation: AgenticSliceExpectation,
    *,
    fail: bool,
) -> AgenticCaseObservation:
    return _simulate_agentic_shadow(expectation, fail=fail)


def replay_coordination_slice(
    expectation: CoordinationSliceExpectation,
    *,
    fail: bool,
) -> CoordinationCaseObservation:
    return _simulate_coordination_ledger(expectation, fail=fail)


__all__ = [
    "derive_plan_hash",
    "replay_agentic_slice",
    "replay_coordination_slice",
    "replay_knowledge_slice",
    "replay_security_slice",
]
