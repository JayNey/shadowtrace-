"""Health endpoint Celery semantics tests (ISSUE-117 / #622 Phase A)."""

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


@pytest.mark.asyncio
async def test_health_worker_degraded_returns_200_not_503(client: AsyncClient) -> None:
    settings = Settings(
        DATABASE_URL="postgresql+asyncpg://u:p@localhost:5432/db",
        REDIS_URL="redis://localhost:6379/0",
        TASK_MODE="celery",
        SIMULATION_ENABLED=True,
    )
    app.dependency_overrides[get_settings] = lambda: settings

    celery_payload: dict[str, Any] = {
        "task_mode": "celery",
        "broker": "ok",
        "worker": {"status": "degraded", "workers": 0, "worker_ids": []},
    }

    with (
        patch("app.api.v1.health.check_postgres", new_callable=AsyncMock, return_value="ok"),
        patch("app.api.v1.health.check_redis", new_callable=AsyncMock, return_value="ok"),
        patch(
            "app.api.v1.health.check_embedding_provider",
            new_callable=AsyncMock,
            return_value={"status": "ok", "mode": "mock"},
        ),
        patch(
            "app.api.v1.health.build_celery_health",
            new_callable=AsyncMock,
            return_value=celery_payload,
        ),
    ):
        response = await client.get("/api/v1/health")

    app.dependency_overrides.clear()
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["celery"]["worker"]["status"] == "degraded"


@pytest.mark.asyncio
async def test_health_worker_error_returns_200_with_degraded_overall(
    client: AsyncClient,
) -> None:
    settings = Settings(
        DATABASE_URL="postgresql+asyncpg://u:p@localhost:5432/db",
        REDIS_URL="redis://localhost:6379/0",
        TASK_MODE="celery",
        SIMULATION_ENABLED=True,
    )
    app.dependency_overrides[get_settings] = lambda: settings

    celery_payload: dict[str, Any] = {
        "task_mode": "celery",
        "broker": "ok",
        "worker": {
            "status": "error",
            "workers": 0,
            "worker_ids": [],
            "reason": "TimeoutError",
        },
    }

    with (
        patch("app.api.v1.health.check_postgres", new_callable=AsyncMock, return_value="ok"),
        patch("app.api.v1.health.check_redis", new_callable=AsyncMock, return_value="ok"),
        patch(
            "app.api.v1.health.check_embedding_provider",
            new_callable=AsyncMock,
            return_value={"status": "ok", "mode": "mock"},
        ),
        patch(
            "app.api.v1.health.build_celery_health",
            new_callable=AsyncMock,
            return_value=celery_payload,
        ),
    ):
        response = await client.get("/api/v1/health")

    app.dependency_overrides.clear()
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["celery"]["worker"]["status"] == "error"


@pytest.mark.asyncio
async def test_health_celery_broker_down_still_503_via_hard_deps(client: AsyncClient) -> None:
    settings = Settings(
        TASK_MODE="celery",
        SIMULATION_ENABLED=True,
    )
    app.dependency_overrides[get_settings] = lambda: settings

    with (
        patch("app.api.v1.health.check_postgres", new_callable=AsyncMock, return_value="ok"),
        patch("app.api.v1.health.check_redis", new_callable=AsyncMock, return_value="error"),
        patch(
            "app.api.v1.health.check_embedding_provider",
            new_callable=AsyncMock,
            return_value={"status": "ok", "mode": "mock"},
        ),
        patch(
            "app.api.v1.health.build_celery_health",
            new_callable=AsyncMock,
            return_value={
                "task_mode": "celery",
                "broker": "error",
                "worker": {"status": "error", "workers": 0, "worker_ids": []},
            },
        ),
    ):
        response = await client.get("/api/v1/health")

    app.dependency_overrides.clear()
    assert response.status_code == 503
    assert response.json()["redis"] == "error"
