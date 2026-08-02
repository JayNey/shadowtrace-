"""Health endpoint LLM diagnostics tests (ISSUE-106 / #609)."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.config import Settings, get_settings
from app.main import app


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> Iterator[None]:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture(autouse=True)
def _mock_celery_health() -> Iterator[None]:
    default_payload: dict[str, Any] = {
        "task_mode": "background",
        "broker": "ok",
        "worker": {"status": "not_applicable", "workers": 0, "worker_ids": []},
    }
    with patch(
        "app.api.v1.health.build_celery_health",
        new_callable=AsyncMock,
        return_value=default_payload,
    ):
        yield


def _llm_payload(*, status: str = "ok") -> dict[str, Any]:
    return {
        "status": status,
        "mode": "mock",
        "base_url_redacted": "",
        "primary_model": "mock-model",
        "probe_enabled": False,
        "last_probe_status": {"status": "skipped"},
        "audit": {
            "window_minutes": 60,
            "total_calls": 0,
            "success_calls": 0,
            "success_rate": None,
            "last_status": None,
            "last_error_class": None,
        },
    }


@pytest.mark.asyncio
async def test_health_includes_llm_block_without_secrets(client: AsyncClient) -> None:
    settings = Settings(SIMULATION_ENABLED=True)
    app.dependency_overrides[get_settings] = lambda: settings

    with (
        patch("app.api.v1.health.check_postgres", new_callable=AsyncMock, return_value="ok"),
        patch("app.api.v1.health.check_redis", new_callable=AsyncMock, return_value="ok"),
        patch(
            "app.api.v1.health.check_embedding_provider",
            new_callable=AsyncMock,
            return_value={"status": "ok", "mode": "mock"},
        ),
        patch(
            "app.api.v1.health.check_llm_provider",
            new_callable=AsyncMock,
            return_value=_llm_payload(status="ok"),
        ),
    ):
        response = await client.get("/api/v1/health")

    app.dependency_overrides.clear()
    assert response.status_code == 200
    llm = response.json()["llm"]
    assert llm["status"] == "ok"
    assert llm["mode"] == "mock"
    dumped = str(llm).lower()
    for forbidden in ("api_key", "secret", "password", "authorization", "prompt"):
        assert forbidden not in dumped


@pytest.mark.asyncio
async def test_health_llm_degraded_does_not_cause_503_by_default(client: AsyncClient) -> None:
    settings = Settings(SIMULATION_ENABLED=True, LLM_REQUIRED=False)
    app.dependency_overrides[get_settings] = lambda: settings

    with (
        patch("app.api.v1.health.check_postgres", new_callable=AsyncMock, return_value="ok"),
        patch("app.api.v1.health.check_redis", new_callable=AsyncMock, return_value="ok"),
        patch(
            "app.api.v1.health.check_embedding_provider",
            new_callable=AsyncMock,
            return_value={"status": "ok", "mode": "mock"},
        ),
        patch(
            "app.api.v1.health.check_llm_provider",
            new_callable=AsyncMock,
            return_value=_llm_payload(status="degraded"),
        ),
    ):
        response = await client.get("/api/v1/health")

    app.dependency_overrides.clear()
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["llm"]["status"] == "degraded"


@pytest.mark.asyncio
async def test_health_llm_required_degraded_returns_503(client: AsyncClient) -> None:
    settings = Settings(SIMULATION_ENABLED=True, LLM_REQUIRED=True)
    app.dependency_overrides[get_settings] = lambda: settings

    with (
        patch("app.api.v1.health.check_postgres", new_callable=AsyncMock, return_value="ok"),
        patch("app.api.v1.health.check_redis", new_callable=AsyncMock, return_value="ok"),
        patch(
            "app.api.v1.health.check_embedding_provider",
            new_callable=AsyncMock,
            return_value={"status": "ok", "mode": "mock"},
        ),
        patch(
            "app.api.v1.health.check_llm_provider",
            new_callable=AsyncMock,
            return_value=_llm_payload(status="degraded"),
        ),
    ):
        response = await client.get("/api/v1/health")

    app.dependency_overrides.clear()
    assert response.status_code == 503
    assert response.json()["status"] == "degraded"
