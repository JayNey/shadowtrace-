"""Health endpoint embedding provider tests (ISSUE-140)."""

from __future__ import annotations

import pytest

from app.api.v1 import health as health_module


@pytest.mark.asyncio
async def test_check_embedding_provider_mock_mode_ok() -> None:
    from app.core.embedding.factory import reset_embedding_client

    reset_embedding_client()
    payload = await health_module.check_embedding_provider()
    assert payload["status"] == "ok"
    assert payload["mode"] == "mock"
    assert payload["release_id"] == "mock-v1"
    assert payload["dimension"] == 1024
    assert payload["store_vector_dimension"] == 1024
    assert payload["index_schema_ok"] is True
    assert "api_key" not in str(payload).lower()
    reset_embedding_client()


@pytest.mark.asyncio
async def test_check_embedding_provider_reports_schema_drift() -> None:
    from app.core.config import Settings
    from app.core.embedding.factory import reset_embedding_client
    from app.core.embedding.service import EmbeddingService

    reset_embedding_client()
    svc = EmbeddingService(Settings(embedding_mode="mock", embedding_dimension=512))
    health = await svc.health_probe()
    await svc.close()
    assert health.index_schema_ok is False
    assert health.status == "degraded"
    assert health.error_code == "embedding_schema_drift"
    assert health.store_vector_dimension == 1024
    reset_embedding_client()
