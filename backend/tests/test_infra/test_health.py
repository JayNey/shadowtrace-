"""Health endpoint tests (ISSUE-001)."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.v1 import health as health_module
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
    """Avoid live broker/worker probes in ISSUE-001 health tests."""
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


def _llm_health_payload(*, status: str = "ok") -> dict[str, Any]:
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
async def test_health_ok_fields_complete(client: AsyncClient) -> None:
    settings = Settings(
        DATABASE_URL="postgresql+asyncpg://u:p@localhost:5432/db",
        REDIS_URL="redis://localhost:6379/0",
        SOURCE_MODE="mock_xdr",
        DISPOSITION_MODE="mock_xdr",
        TOOL_MODE="mock",
        SIMULATION_ENABLED=True,
        APP_VERSION="0.1.0",
    )
    app.dependency_overrides[get_settings] = lambda: settings

    with (
        patch("app.api.v1.health.check_postgres", new_callable=AsyncMock, return_value="ok"),
        patch("app.api.v1.health.check_redis", new_callable=AsyncMock, return_value="ok"),
        patch(
            "app.api.v1.health.check_embedding_provider",
            new_callable=AsyncMock,
            return_value={
                "status": "ok",
                "mode": "mock",
                "release_id": "mock-v1",
                "model_id": "mock-embedder",
                "dimension": 1024,
                "store_vector_dimension": 1024,
                "index_schema_ok": True,
                "distance_metric": "cosine",
                "normalization": "unit_l2",
                "config_hash": "abc",
                "error_code": None,
                "latency_ms": 1.0,
            },
        ),
        patch(
            "app.api.v1.health.check_llm_provider",
            new_callable=AsyncMock,
            return_value=_llm_health_payload(status="ok"),
        ),
        patch(
            "app.api.v1.health._check_loaded_resources",
            new_callable=AsyncMock,
            return_value={"status": "ready", "pipeline_attached": True, "reasons": []},
        ),
        patch(
            "app.api.v1.health._check_playbook_resources",
            new_callable=AsyncMock,
            return_value={
                "status": "ready",
                "mode": "production",
                "active_release_id": "krel-playbook-test01",
                "postgres": "ok",
                "session_pool": "pooled",
                "fixture_fallback_enabled": False,
                "reasons": [],
            },
        ),
    ):
        response = await client.get("/api/v1/health")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    assert body["status"] == "ok"
    assert body["postgres"] == "ok"
    assert body["redis"] == "ok"
    assert body["embedding_provider"]["status"] == "ok"
    assert body["embedding_provider"]["mode"] == "mock"
    assert "api_key" not in str(body["embedding_provider"]).lower()
    assert body["llm"]["status"] == "ok"
    assert body["llm"]["mode"] == "mock"
    assert "api_key" not in str(body["llm"]).lower()
    assert "prompt" not in str(body["llm"]).lower()
    assert body["simulation_enabled"] is True
    assert body["version"] == "0.1.0"
    assert set(body["celery"].keys()) >= {"task_mode", "broker", "worker"}
    assert body["investigation"]["task_mode"] == "background"
    assert body["investigation"]["auto_response_enabled"] is False
    assert body["investigation"]["approval_policy_version"] == "issue109_v1"
    assert body["investigation"]["detection_governance_policy_version"] == "issue125_v1"

    for key in ("source_adapter", "disposition_adapter", "tool_provider"):
        component = body[key]
        assert set(component.keys()) >= {"status", "mode", "capability"}
        assert "credential" not in str(component).lower()
        assert "password" not in str(component).lower()
        assert "api_key" not in str(component).lower()


@pytest.mark.asyncio
async def test_health_investigation_block_matches_contract(client: AsyncClient) -> None:
    from app.api.v1 import schemas as s
    from app.services.action_approval_policy import APPROVAL_POLICY_VERSION

    settings = Settings(
        DATABASE_URL="postgresql+asyncpg://u:p@localhost:5432/db",
        REDIS_URL="redis://localhost:6379/0",
        AUTO_RESPONSE_ENABLED=True,
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        DISPOSITION_MODE="mock_xdr",
        TOOL_MODE="mock",
    )
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
            return_value=_llm_health_payload(status="ok"),
        ),
    ):
        response = await client.get("/api/v1/health")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    investigation = response.json()["investigation"]
    cfg = s.InvestigationHealthConfig.model_validate(investigation)
    assert cfg.auto_response_enabled is True
    assert cfg.auto_investigate_enabled is True
    assert cfg.approval_policy_version == APPROVAL_POLICY_VERSION
    from app.services.detection_governance_policy import DETECTION_GOVERNANCE_POLICY_VERSION

    assert cfg.detection_governance_policy_version == DETECTION_GOVERNANCE_POLICY_VERSION


@pytest.mark.asyncio
async def test_health_degraded_returns_503_when_postgres_down(client: AsyncClient) -> None:
    settings = Settings(SIMULATION_ENABLED=True)
    app.dependency_overrides[get_settings] = lambda: settings

    with (
        patch("app.api.v1.health.check_postgres", new_callable=AsyncMock, return_value="error"),
        patch("app.api.v1.health.check_redis", new_callable=AsyncMock, return_value="ok"),
        patch(
            "app.api.v1.health.check_llm_provider",
            new_callable=AsyncMock,
            return_value=_llm_health_payload(status="ok"),
        ),
    ):
        response = await client.get("/api/v1/health")

    app.dependency_overrides.clear()
    assert response.status_code == 503
    assert response.json()["status"] == "degraded"
    assert response.json()["postgres"] == "error"


@pytest.mark.asyncio
async def test_health_degraded_returns_503_when_redis_down(client: AsyncClient) -> None:
    settings = Settings(SIMULATION_ENABLED=True)
    app.dependency_overrides[get_settings] = lambda: settings

    with (
        patch("app.api.v1.health.check_postgres", new_callable=AsyncMock, return_value="ok"),
        patch("app.api.v1.health.check_redis", new_callable=AsyncMock, return_value="error"),
        patch(
            "app.api.v1.health.check_llm_provider",
            new_callable=AsyncMock,
            return_value=_llm_health_payload(status="ok"),
        ),
    ):
        response = await client.get("/api/v1/health")

    app.dependency_overrides.clear()
    assert response.status_code == 503
    assert response.json()["status"] == "degraded"
    assert response.json()["redis"] == "error"


@pytest.mark.asyncio
async def test_health_degraded_returns_503_when_embedding_degraded(client: AsyncClient) -> None:
    settings = Settings(SIMULATION_ENABLED=True)
    app.dependency_overrides[get_settings] = lambda: settings

    with (
        patch("app.api.v1.health.check_postgres", new_callable=AsyncMock, return_value="ok"),
        patch("app.api.v1.health.check_redis", new_callable=AsyncMock, return_value="ok"),
        patch(
            "app.api.v1.health.check_embedding_provider",
            new_callable=AsyncMock,
            return_value={
                "status": "degraded",
                "mode": "remote",
                "release_id": "remote-v1",
                "model_id": "remote-model",
                "dimension": 1024,
                "store_vector_dimension": 1024,
                "index_schema_ok": True,
                "distance_metric": "cosine",
                "normalization": "unit_l2",
                "config_hash": "",
                "error_code": "embedding_provider_unavailable",
                "latency_ms": 1.0,
            },
        ),
        patch(
            "app.api.v1.health.check_llm_provider",
            new_callable=AsyncMock,
            return_value=_llm_health_payload(status="ok"),
        ),
    ):
        response = await client.get("/api/v1/health")

    app.dependency_overrides.clear()
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "degraded"
    assert body["embedding_provider"]["status"] == "degraded"


@pytest.mark.asyncio
async def test_check_postgres_returns_error_on_exception() -> None:
    with patch(
        "app.api.v1.health.peek_session_provider",
        side_effect=RuntimeError("boom"),
    ):
        assert await health_module.check_postgres("postgresql+asyncpg://x") == "error"


@pytest.mark.asyncio
async def test_check_redis_returns_error_on_exception() -> None:
    failing = AsyncMock()
    failing.ping.side_effect = RuntimeError("boom")
    with patch("app.api.v1.health._get_redis", return_value=failing):
        assert await health_module.check_redis("redis://x") == "error"
