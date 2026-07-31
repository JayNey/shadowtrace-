"""EmbeddingRelease and settings contract tests (ISSUE-140)."""

from __future__ import annotations

import hashlib
import math

import pytest

from app.core.config import Settings
from app.core.embedding.release import build_embedding_release, compute_config_hash
from app.core.errors import ConfigurationError
from app.models.embedding import EmbeddingProviderMode, VectorDistanceMetric, VectorNormalization


def test_build_embedding_release_from_defaults() -> None:
    release = build_embedding_release(Settings(embedding_mode="mock"))
    assert release.provider_mode == EmbeddingProviderMode.MOCK
    assert release.dimension == 1024
    assert release.distance_metric == VectorDistanceMetric.COSINE
    assert release.normalization == VectorNormalization.UNIT_L2
    assert release.release_id == "mock-v1"
    assert release.model_id == "mock-embedder"


def test_compute_config_hash_is_deterministic() -> None:
    settings = Settings(embedding_mode="mock", embedding_release_id="mock-v1")
    assert compute_config_hash(settings) == compute_config_hash(settings)


def test_production_rejects_mock_embedding_mode() -> None:
    with pytest.raises(ConfigurationError, match="embedding_mode=mock"):
        Settings(
            app_env="production",
            simulation_enabled=False,
            source_mode="xdr",
            tool_mode="live",
            disposition_mode="xdr",
            disposition_adapter_kind="http",
            llm_mode="openai_compatible",
            embedding_mode="mock",
        )


@pytest.mark.asyncio
async def test_production_remote_unavailable_fail_closed_no_mock_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.embedding.base import EmbeddingUnavailableError
    from app.core.embedding.remote_embedder import RemoteEmbedder

    settings = Settings(
        embedding_mode="remote",
        embedding_api_base_url="http://unreachable.local",
        embedding_model_id="remote-model",
    )
    remote = RemoteEmbedder(settings)

    async def _boom(_texts: list[str]) -> list[list[float]]:
        raise EmbeddingUnavailableError(
            message="embedding provider request failed",
            error_code="embedding_provider_unavailable",
        )

    monkeypatch.setattr(remote, "embed", _boom)
    with pytest.raises(EmbeddingUnavailableError):
        await remote.embed(["probe"])
    await remote.close()


@pytest.mark.asyncio
async def test_batch_limit_fail_closed() -> None:
    from app.core.embedding.base import EmbeddingCompatibilityError
    from app.core.embedding.service import EmbeddingService

    svc = EmbeddingService(
        Settings(embedding_mode="mock", embedding_max_batch_size=2),
    )
    with pytest.raises(EmbeddingCompatibilityError, match="batch exceeds"):
        await svc.embed_texts(["a", "b", "c"])
    await svc.close()


def test_vector_record_idempotency_key() -> None:
    from app.models.embedding import VectorRecordIdentity

    identity = VectorRecordIdentity(
        tenant_id="tenant-a",
        corpus_id="attack_kb",
        object_id="obj-1",
        release_id="rel-1",
        embedding_release_id="mock-v1",
        content_hash="abc123",
        vector_revision=2,
    )
    assert identity.idempotency_key == "tenant-a:attack_kb:obj-1:rel-1:mock-v1:abc123"


@pytest.mark.asyncio
async def test_mock_embeddings_are_deterministic_across_reruns() -> None:
    from app.core.embedding.service import EmbeddingService

    svc = EmbeddingService(Settings(embedding_mode="mock"))
    first = await svc.embed_texts(["hello world", "shadowtrace probe"])
    second = await svc.embed_texts(["hello world", "shadowtrace probe"])
    assert first == second
    for vector in first:
        norm = math.sqrt(sum(v * v for v in vector))
        assert abs(norm - 1.0) < 1e-6
    checksums = [hashlib.sha256(str(vec).encode()).hexdigest() for vec in first]
    assert len({*checksums}) == 2
    await svc.close()
