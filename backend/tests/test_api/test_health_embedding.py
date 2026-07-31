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
    assert "api_key" not in str(payload).lower()
    reset_embedding_client()
