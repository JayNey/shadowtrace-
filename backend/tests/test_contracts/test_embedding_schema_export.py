"""Embedding contract schema export tests (ISSUE-140)."""

from __future__ import annotations

import json

from app.models import MODEL_REGISTRY
from app.models.embedding import VectorIndexSchema, VectorRecordIdentity


def test_embedding_contract_models_are_registered() -> None:
    expected = {
        "EmbeddingRelease",
        "VectorRecordIdentity",
        "VectorIndexSchema",
        "VectorQueryFilter",
        "VectorQueryContext",
        "EmbeddingProviderHealth",
        "VectorImportUpsert",
    }
    assert expected <= set(MODEL_REGISTRY.keys())


def test_vector_record_identity_schema_exports_idempotency_key() -> None:
    schema = VectorRecordIdentity.model_json_schema(mode="serialization")
    assert "idempotency_key" in schema.get("properties", {})


def test_vector_record_identity_idempotency_key_in_model_dump() -> None:
    identity = VectorRecordIdentity(
        tenant_id="tenant-a",
        corpus_id="attack_kb",
        object_id="obj-1",
        release_id="rel-1",
        embedding_release_id="mock-v1",
        content_hash="abc123",
        vector_revision=2,
    )
    payload = identity.model_dump(mode="json")
    assert payload["idempotency_key"] == identity.idempotency_key


def test_vector_index_schema_golden_json_roundtrip() -> None:
    index = VectorIndexSchema()
    golden = json.dumps(index.model_dump(mode="json"), sort_keys=True)
    restored = VectorIndexSchema.model_validate_json(golden)
    assert restored == index
    assert "vector_revision" in restored.unique_key_fields
