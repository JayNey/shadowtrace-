"""KnowledgeQueryPlan validation — ISSUE-130 / #636 Phase A.

Server-owned plan assembly: agent hints may only narrow scope. Unsupported filters,
corpus/release/embedding mismatches, and budget violations fail closed.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.models.knowledge_release import (
    DEFAULT_KNOWLEDGE_MAX_CANDIDATES,
    DEFAULT_KNOWLEDGE_TOP_K,
    KNOWLEDGE_QUERY_PLAN_SCHEMA_VERSION,
    KnowledgeFilterKind,
    KnowledgeQueryBudget,
    KnowledgeQueryPlan,
    KnowledgeQueryPlanHints,
    KnowledgeQueryPlanValidationOutcome,
    KnowledgeTypedFilter,
)
from app.services.knowledge_release_resolver import kb_name_to_corpus

_SUPPORTED_HINT_FILTER_KINDS: frozenset[KnowledgeFilterKind] = frozenset(
    {
        KnowledgeFilterKind.SOURCE_ID,
        KnowledgeFilterKind.CONTENT_TYPE,
    }
)

_DEFAULT_SERVER_BUDGET = KnowledgeQueryBudget(
    top_k=DEFAULT_KNOWLEDGE_TOP_K,
    max_candidates=DEFAULT_KNOWLEDGE_MAX_CANDIDATES,
)


def compute_plan_hash(payload: dict[str, Any]) -> str:
    """Deterministic SHA-256 hex digest of a sanitized plan payload."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _sanitize_hint_list(values: list[str]) -> list[str]:
    clean: list[str] = []
    seen: set[str] = set()
    for raw in values:
        item = raw.strip()
        if not item:
            continue
        if item in seen:
            continue
        seen.add(item)
        clean.append(item)
    return clean


def resolve_allowed_corpora_for_kbs(kb_names: list[str]) -> frozenset[str]:
    """Map requested KB names to server-known corpus ids (#635 policy deferred)."""
    corpora: set[str] = set()
    for kb_name in kb_names:
        corpus_id = kb_name_to_corpus(kb_name)
        if corpus_id is not None:
            corpora.add(corpus_id)
    return frozenset(corpora)


def validate_knowledge_query_plan(
    base_plan: KnowledgeQueryPlan,
    *,
    tenant_id: str,
    principal: str,
    kb_names: list[str],
    active_embedding_release_id: str,
    hints: KnowledgeQueryPlanHints | None = None,
    server_budget: KnowledgeQueryBudget | None = None,
) -> KnowledgeQueryPlanValidationOutcome:
    """Validate and enrich a release-pinned plan before storage candidate fetch."""
    rejected: list[str] = []
    degraded: list[str] = []
    agent_hints = hints or KnowledgeQueryPlanHints()
    budget = server_budget or _DEFAULT_SERVER_BUDGET

    normalized_tenant = tenant_id.strip()
    normalized_principal = principal.strip()
    if not normalized_tenant:
        rejected.append("missing_tenant_id")
    if not normalized_principal:
        rejected.append("missing_principal")

    allowed_corpora = resolve_allowed_corpora_for_kbs(kb_names)
    if base_plan.corpus_id not in allowed_corpora:
        rejected.append("corpus_not_allowed_for_kb")

    hint_corpora = _sanitize_hint_list(agent_hints.corpus_ids)
    if hint_corpora:
        if len(hint_corpora) > 1:
            rejected.append("agent_corpus_hint_expands_scope")
        elif hint_corpora[0] != base_plan.corpus_id:
            rejected.append("agent_corpus_hint_mismatch")
        narrowed_corpora = (base_plan.corpus_id,)
    else:
        narrowed_corpora = (base_plan.corpus_id,)

    if base_plan.embedding_release_id != active_embedding_release_id:
        rejected.append("embedding_release_incompatible")

    unsupported_filters = [
        filt.kind.value
        for filt in agent_hints.filters
        if filt.kind not in _SUPPORTED_HINT_FILTER_KINDS
    ]
    if unsupported_filters:
        rejected.append("unsupported_filter_kind")

    typed_filters: list[KnowledgeTypedFilter] = []
    seen_filters: set[tuple[str, str]] = set()

    def _append_filter(filt: KnowledgeTypedFilter) -> None:
        key = (filt.kind.value, filt.value)
        if key in seen_filters:
            return
        seen_filters.add(key)
        typed_filters.append(filt)

    for filt in base_plan.typed_filters:
        if filt.kind not in _SUPPORTED_HINT_FILTER_KINDS:
            rejected.append("unsupported_filter_kind")
            continue
        _append_filter(filt)

    source_ids = _sanitize_hint_list(agent_hints.source_ids)
    content_types = _sanitize_hint_list(agent_hints.content_types)
    for source_id in source_ids:
        _append_filter(KnowledgeTypedFilter(kind=KnowledgeFilterKind.SOURCE_ID, value=source_id))
    for content_type in content_types:
        _append_filter(
            KnowledgeTypedFilter(kind=KnowledgeFilterKind.CONTENT_TYPE, value=content_type)
        )
    for filt in agent_hints.filters:
        if filt.kind in _SUPPORTED_HINT_FILTER_KINDS:
            _append_filter(filt)

    resolved_top_k = budget.top_k
    if agent_hints.top_k is not None:
        if agent_hints.top_k > budget.top_k:
            rejected.append("budget_top_k_exceeded")
        else:
            resolved_top_k = agent_hints.top_k

    candidate_budget = budget.max_candidates
    if candidate_budget < resolved_top_k:
        rejected.append("budget_max_candidates_below_top_k")

    if rejected:
        return KnowledgeQueryPlanValidationOutcome(
            accepted=False,
            plan=None,
            rejected_reasons=rejected,
            degraded_reasons=degraded,
            sanitized_plan_hash="",
        )

    resolved_budget = KnowledgeQueryBudget(top_k=resolved_top_k, max_candidates=candidate_budget)
    if agent_hints.top_k is not None and agent_hints.top_k < budget.top_k:
        degraded.append("agent_top_k_narrowed")

    enriched = KnowledgeQueryPlan(
        schema_version=KNOWLEDGE_QUERY_PLAN_SCHEMA_VERSION,
        tenant_id=normalized_tenant,
        principal=normalized_principal,
        corpus_id=base_plan.corpus_id,
        kb_name=base_plan.kb_name,
        # Single pinned corpus for this request; not the full multi-kb allow-list.
        allowed_corpora=narrowed_corpora if narrowed_corpora else allowed_corpora,
        active_release_id=base_plan.active_release_id,
        embedding_release_id=base_plan.embedding_release_id,
        typed_filters=tuple(typed_filters),
        budget=resolved_budget,
        trace_id=base_plan.trace_id,
        pinned_at=base_plan.pinned_at,
        rejected_reasons=tuple(),
        degraded_reasons=tuple(degraded),
        plan_hash="",
    )
    hash_payload = enriched.model_dump(
        mode="json",
        exclude={"plan_hash", "rejected_reasons", "degraded_reasons"},
    )
    plan_hash = compute_plan_hash(hash_payload)
    final_plan = enriched.model_copy(update={"plan_hash": plan_hash})

    return KnowledgeQueryPlanValidationOutcome(
        accepted=True,
        plan=final_plan,
        rejected_reasons=[],
        degraded_reasons=degraded,
        sanitized_plan_hash=plan_hash,
    )


__all__ = [
    "compute_plan_hash",
    "resolve_allowed_corpora_for_kbs",
    "validate_knowledge_query_plan",
]
