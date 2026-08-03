"""KnowledgeQueryPlan validator tests (ISSUE-130 / #636 Phase A)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.config import Settings
from app.core.embedding.release import build_embedding_release
from app.models.knowledge_release import (
    ATTACK_CORPUS_ID,
    KnowledgeFilterKind,
    KnowledgeQueryBudget,
    KnowledgeQueryPlan,
    KnowledgeQueryPlanHints,
    KnowledgeTypedFilter,
)
from app.services.knowledge_query_plan_validator import (
    compute_plan_hash,
    resolve_allowed_corpora_for_kbs,
    validate_knowledge_query_plan,
)


def _base_plan(*, embedding_release_id: str = "mock-v1") -> KnowledgeQueryPlan:
    return KnowledgeQueryPlan(
        corpus_id=ATTACK_CORPUS_ID,
        kb_name="attack_kb",
        active_release_id="krel-test",
        embedding_release_id=embedding_release_id,
        trace_id="trace-validator",
        pinned_at=datetime.now(UTC),
    )


def _active_embedding_release_id() -> str:
    return build_embedding_release(Settings(EMBEDDING_MODE="mock")).release_id


def test_validate_accepts_release_pinned_plan_with_tenant_scope() -> None:
    active_emb = _active_embedding_release_id()
    outcome = validate_knowledge_query_plan(
        _base_plan(embedding_release_id=active_emb),
        tenant_id="tenant-a",
        principal="investigation:rag_agent",
        kb_names=["attack_kb"],
        active_embedding_release_id=active_emb,
    )
    assert outcome.accepted is True
    assert outcome.plan is not None
    assert outcome.plan.tenant_id == "tenant-a"
    assert outcome.plan.plan_hash
    assert outcome.sanitized_plan_hash == outcome.plan.plan_hash


def test_validate_rejects_missing_tenant() -> None:
    active_emb = _active_embedding_release_id()
    outcome = validate_knowledge_query_plan(
        _base_plan(embedding_release_id=active_emb),
        tenant_id="",
        principal="investigation:rag_agent",
        kb_names=["attack_kb"],
        active_embedding_release_id=active_emb,
    )
    assert outcome.accepted is False
    assert "missing_tenant_id" in outcome.rejected_reasons


def test_validate_rejects_missing_principal() -> None:
    active_emb = _active_embedding_release_id()
    outcome = validate_knowledge_query_plan(
        _base_plan(embedding_release_id=active_emb),
        tenant_id="tenant-a",
        principal="",
        kb_names=["attack_kb"],
        active_embedding_release_id=active_emb,
    )
    assert outcome.accepted is False
    assert "missing_principal" in outcome.rejected_reasons


def test_validate_rejects_embedding_release_mismatch() -> None:
    active_emb = _active_embedding_release_id()
    outcome = validate_knowledge_query_plan(
        _base_plan(embedding_release_id="other-release"),
        tenant_id="tenant-a",
        principal="investigation:rag_agent",
        kb_names=["attack_kb"],
        active_embedding_release_id=active_emb,
    )
    assert outcome.accepted is False
    assert "embedding_release_incompatible" in outcome.rejected_reasons


def test_validate_rejects_unsupported_filter_kind() -> None:
    active_emb = _active_embedding_release_id()
    hints = KnowledgeQueryPlanHints(
        filters=[
            KnowledgeTypedFilter(kind=KnowledgeFilterKind.TIME_AFTER, value="2026-01-01T00:00:00Z")
        ]
    )
    outcome = validate_knowledge_query_plan(
        _base_plan(embedding_release_id=active_emb),
        tenant_id="tenant-a",
        principal="investigation:rag_agent",
        kb_names=["attack_kb"],
        active_embedding_release_id=active_emb,
        hints=hints,
    )
    assert outcome.accepted is False
    assert "unsupported_filter_kind" in outcome.rejected_reasons


def test_validate_narrows_agent_top_k_without_expanding_scope() -> None:
    active_emb = _active_embedding_release_id()
    hints = KnowledgeQueryPlanHints(top_k=2, source_ids=["mitre_attack_stix"])
    outcome = validate_knowledge_query_plan(
        _base_plan(embedding_release_id=active_emb),
        tenant_id="tenant-a",
        principal="investigation:rag_agent",
        kb_names=["attack_kb"],
        active_embedding_release_id=active_emb,
        hints=hints,
        server_budget=KnowledgeQueryBudget(top_k=5, max_candidates=20),
    )
    assert outcome.accepted is True
    assert outcome.plan is not None
    assert outcome.plan.budget.top_k == 2
    assert len(outcome.plan.typed_filters) == 1
    assert outcome.plan.typed_filters[0].kind == KnowledgeFilterKind.SOURCE_ID


def test_validate_rejects_agent_top_k_budget_expansion() -> None:
    active_emb = _active_embedding_release_id()
    hints = KnowledgeQueryPlanHints(top_k=20)
    outcome = validate_knowledge_query_plan(
        _base_plan(embedding_release_id=active_emb),
        tenant_id="tenant-a",
        principal="investigation:rag_agent",
        kb_names=["attack_kb"],
        active_embedding_release_id=active_emb,
        hints=hints,
        server_budget=KnowledgeQueryBudget(top_k=5, max_candidates=20),
    )
    assert outcome.accepted is False
    assert "budget_top_k_exceeded" in outcome.rejected_reasons


def test_validate_rejects_corpus_not_allowed_for_kb() -> None:
    active_emb = _active_embedding_release_id()
    outcome = validate_knowledge_query_plan(
        _base_plan(embedding_release_id=active_emb),
        tenant_id="tenant-a",
        principal="investigation:rag_agent",
        kb_names=["fp_case_kb"],
        active_embedding_release_id=active_emb,
    )
    assert outcome.accepted is False
    assert "corpus_not_allowed_for_kb" in outcome.rejected_reasons


def test_resolve_allowed_corpora_includes_playbook_kb() -> None:
    corpora = resolve_allowed_corpora_for_kbs(["attack_kb", "playbook_kb"])
    assert corpora == frozenset({"attack_enterprise", "playbook_soar"})


def test_validate_accepts_playbook_release_pinned_plan() -> None:
    from app.models.playbook_release import PLAYBOOK_CORPUS_ID, PLAYBOOK_KB_NAME

    active_emb = _active_embedding_release_id()
    plan = KnowledgeQueryPlan(
        corpus_id=PLAYBOOK_CORPUS_ID,
        kb_name=PLAYBOOK_KB_NAME,
        active_release_id="pbrel-test",
        embedding_release_id=active_emb,
        trace_id="trace-playbook",
        pinned_at=datetime.now(UTC),
    )
    outcome = validate_knowledge_query_plan(
        plan,
        tenant_id="tenant-a",
        principal="investigation:rag_agent",
        kb_names=[PLAYBOOK_KB_NAME],
        active_embedding_release_id=active_emb,
    )
    assert outcome.accepted is True
    assert outcome.plan is not None
    assert outcome.plan.corpus_id == PLAYBOOK_CORPUS_ID
    assert outcome.plan.plan_hash


def test_compute_plan_hash_is_stable() -> None:
    payload = {"corpus_id": ATTACK_CORPUS_ID, "top_k": 5}
    assert compute_plan_hash(payload) == compute_plan_hash(payload)


@pytest.mark.parametrize(
    "hint_corpora,expected_reason",
    [
        (["unknown_corpus"], "agent_corpus_hint_mismatch"),
        (["attack_enterprise", "other_corpus"], "agent_corpus_hint_expands_scope"),
    ],
)
def test_validate_rejects_adversarial_corpus_hints(
    hint_corpora: list[str],
    expected_reason: str,
) -> None:
    active_emb = _active_embedding_release_id()
    hints = KnowledgeQueryPlanHints(corpus_ids=hint_corpora)
    outcome = validate_knowledge_query_plan(
        _base_plan(embedding_release_id=active_emb),
        tenant_id="tenant-a",
        principal="investigation:rag_agent",
        kb_names=["attack_kb"],
        active_embedding_release_id=active_emb,
        hints=hints,
    )
    assert outcome.accepted is False
    assert expected_reason in outcome.rejected_reasons
