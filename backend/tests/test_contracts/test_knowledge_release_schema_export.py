"""Knowledge release contract schema export tests (ISSUE-128 / #634)."""

from __future__ import annotations

from app.models import MODEL_REGISTRY


def test_knowledge_release_contract_models_are_registered() -> None:
    assert "KnowledgeRelease" in MODEL_REGISTRY
    assert "KnowledgeQueryPlan" in MODEL_REGISTRY
