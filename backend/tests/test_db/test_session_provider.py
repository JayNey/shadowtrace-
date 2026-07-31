"""SessionProvider lifecycle tests (ISSUE-118)."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Iterator
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import urlparse

import pytest
from sqlalchemy import text
from sqlalchemy.pool import NullPool, QueuePool

from app.api.v1.deps import reset_deps
from app.core.config import get_settings
from app.db.session_provider import (
    SessionProvider,
    dispose_session_provider,
    get_session_provider,
    init_worker_session_provider,
    reset_session_provider,
    set_session_provider,
)

DATABASE_URL = get_settings().database_url


def _postgres_reachable() -> bool:
    normalized = DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
    parsed = urlparse(normalized)
    host = parsed.hostname or "localhost"
    port = parsed.port or 5432
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


@pytest.fixture(autouse=True)
def _reset_provider_state() -> Iterator[None]:
    reset_session_provider()
    yield
    reset_session_provider()


def test_get_session_provider_defaults_to_pooled_policy() -> None:
    provider = get_session_provider()
    assert provider.pool_policy == "pooled"
    engine = provider.engine()
    assert isinstance(engine.pool, QueuePool)


def test_init_worker_session_provider_uses_nullpool() -> None:
    provider = init_worker_session_provider()
    assert provider.pool_policy == "nullpool"
    engine = provider.engine()
    assert isinstance(engine.pool, NullPool)


def test_set_session_provider_override() -> None:
    custom = SessionProvider("postgresql+asyncpg://override/db", pool="nullpool")
    set_session_provider(custom)
    assert get_session_provider() is custom


def test_reset_deps_clears_session_provider() -> None:
    get_session_provider()
    reset_deps()
    from app.db import session_provider as sp_module

    assert sp_module._provider is None


@pytest.mark.asyncio
async def test_dispose_clears_engine_and_factory() -> None:
    provider = SessionProvider(DATABASE_URL, pool="nullpool")
    set_session_provider(provider)
    _ = provider.engine()
    _ = provider.session_factory()
    await dispose_session_provider()
    assert provider._engine is None
    assert provider._factory is None


@pytest.mark.skipif(not _postgres_reachable(), reason="PostgreSQL not reachable")
def test_consecutive_asyncio_run_with_nullpool_provider() -> None:
    """Regression: Celery tasks using asyncio.run must not reuse loop-bound pools."""
    provider = SessionProvider(DATABASE_URL, pool="nullpool")
    set_session_provider(provider)

    async def _select_one() -> None:
        async with provider.engine().connect() as conn:
            await conn.execute(text("SELECT 1"))

    try:
        asyncio.run(_select_one())
        asyncio.run(_select_one())
    finally:
        asyncio.run(provider.dispose())
        reset_session_provider()


def test_celery_app_module_does_not_eagerly_create_engine() -> None:
    from app.db import session_provider as sp_module

    reset_session_provider()
    import importlib

    import app.core.celery_app as celery_module

    importlib.reload(celery_module)
    assert sp_module._provider is None


def test_init_worker_telemetry_uses_worker_provider_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[object] = []

    def _capture(**kwargs: object) -> None:
        calls.append(kwargs.get("engine"))

    monkeypatch.setattr("app.core.telemetry.setup_telemetry", _capture)
    from app.core.celery_app import init_worker_telemetry

    init_worker_telemetry(sender=None)
    assert len(calls) == 1
    engine = calls[0]
    assert engine is not None
    assert isinstance(engine.pool, NullPool)
    assert get_session_provider().engine() is engine


def test_check_postgres_uses_provider_ping(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.api.v1 import health as health_module

    mock_provider = MagicMock()
    mock_provider.ping_postgres = AsyncMock(return_value=True)
    monkeypatch.setattr(health_module, "get_session_provider", lambda: mock_provider)

    async def _run() -> str:
        return await health_module.check_postgres("ignored")

    assert asyncio.run(_run()) == "ok"
    mock_provider.ping_postgres.assert_awaited_once()
