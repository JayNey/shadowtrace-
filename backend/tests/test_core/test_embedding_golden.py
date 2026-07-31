"""Embedding import/query golden tests (ISSUE-140)."""

from __future__ import annotations

import hashlib

import pytest

from app.core.config import Settings
from app.core.embedding.compat import compute_content_hash, validate_vector_query_context
from app.core.embedding.release import build_embedding_release
from app.core.embedding.service import EmbeddingService
from app.models.embedding import (
    VectorImportUpsert,
    VectorQueryContext,
    VectorQueryFilter,
    VectorRecordIdentity,
)

_GOLDEN_TEXTS = ("hello world", "shadowtrace golden probe")


@pytest.mark.asyncio
async def test_mock_embed_golden_checksum_stable() -> None:
    svc = EmbeddingService(Settings(embedding_mode="mock"))
    vectors = await svc.embed_texts(list(_GOLDEN_TEXTS))
    checksums = tuple(hashlib.sha256(repr(vec).encode()).hexdigest() for vec in vectors)
    await svc.close()

    svc2 = EmbeddingService(Settings(embedding_mode="mock"))
    reruns = await svc2.embed_texts(list(_GOLDEN_TEXTS))
    rerun_checksums = tuple(hashlib.sha256(repr(vec).encode()).hexdigest() for vec in reruns)
    await svc2.close()

    assert rerun_checksums == checksums
    assert len({*checksums}) == len(_GOLDEN_TEXTS)


def test_vector_import_upsert_golden_json_roundtrip() -> None:
    content = "golden import content"
    identity = VectorRecordIdentity(
        tenant_id="tenant-a",
        corpus_id="attack_kb",
        object_id="obj-golden-1",
        release_id="rel-golden",
        embedding_release_id="mock-v1",
        content_hash=compute_content_hash(content),
        vector_revision=1,
    )
    row = VectorImportUpsert(
        identity=identity,
        content=content,
        metadata={"source": "golden"},
    )
    payload = row.model_dump(mode="json")
    assert payload["identity"]["idempotency_key"] == identity.idempotency_key
    input_payload = row.model_dump(mode="python")
    input_payload["identity"].pop("idempotency_key", None)
    restored = VectorImportUpsert.model_validate(input_payload)
    assert restored == row
    assert restored.identity.idempotency_key == identity.idempotency_key


def test_vector_query_context_golden_happy_path() -> None:
    release = build_embedding_release(Settings(embedding_mode="mock"))
    unit_vector = [0.0] * release.dimension
    unit_vector[0] = 1.0
    ctx = VectorQueryContext(
        filter=VectorQueryFilter(
            tenant_id="tenant-a",
            corpus_id="attack_kb",
            release_id="rel-golden",
            embedding_release_id=release.release_id,
        ),
        active_release=release,
        query_vector=unit_vector,
    )
    validate_vector_query_context(ctx)
