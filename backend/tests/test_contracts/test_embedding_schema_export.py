"""Embedding contract schema export tests (ISSUE-140)."""

from __future__ import annotations

from app.models import MODEL_REGISTRY


def test_embedding_contract_models_are_registered() -> None:
    expected = {
        "EmbeddingRelease",
        "VectorRecordIdentity",
        "VectorQueryFilter",
        "VectorQueryContext",
        "EmbeddingProviderHealth",
        "VectorImportUpsert",
    }
    assert expected <= set(MODEL_REGISTRY.keys())
