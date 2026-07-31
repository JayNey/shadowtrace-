"""SessionProvider lifecycle tests (ISSUE-118)."""

from __future__ import annotations

import asyncio
import logging
import socket
from collections.abc import Iterator
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlparse

import pytest
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.pool import NullPool, QueuePool

from app.api.v1.deps import reset_deps
from app.core.config import get_settings
from app.db.session_provider import (
    SessionProvider,
    dispose_session_provider,
    get_session_provider,
    init_worker_session_provider,
    peek_session_provider,
    reset_session_provider,
    reset_session_provider_async,
    set_session_provider,
)
from app.services.evidence_projection import (
    get_evidence_projection,
    reset_evidence_projection_default,
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
    reset_evidence_projection_default()
    yield
    reset_session_provider()
    reset_evidence_projection_default()


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


def test_set_session_provider_disposes_previous_engine() -> None:
    first = SessionProvider(DATABASE_URL, pool="nullpool")
    second = SessionProvider(DATABASE_URL, pool="nullpool")
    set_session_provider(first)
    _ = first.engine()
    assert first.is_engine_initialized

    set_session_provider(second)
    assert not first.is_engine_initialized
    assert peek_session_provider() is second


def test_reset_deps_clears_session_provider() -> None:
    get_session_provider().engine()
    reset_deps()
    assert peek_session_provider() is None


def test_reset_deps_clears_evidence_projection_default() -> None:
    get_session_provider()
    _ = get_evidence_projection()
    reset_deps()
    from app.services import evidence_projection as ep_module

    assert ep_module._default_projection is None


def test_get_session_provider_warns_on_pool_mismatch() -> None:
    """A pooled provider exists; requesting nullpool must emit the ISSUE-118
    observability warning.

    The autouse fixture guarantees deterministic provider state (pooled created
    first, nullpool then mismatches). Capture the warning on the module logger
    directly instead of via ``caplog`` so the assertion no longer depends on root
    logger propagation, suite import order, or global logging config -- the prior
    source of flakiness.

    Migration tests (test_migrations.py) run Alembic ``command`` which calls
    ``fileConfig(disable_existing_loggers=True)`` in migrations/env.py, leaving the
    ``app.db.session_provider`` logger with ``disabled=True``. A disabled logger
    drops records before any handler, so the warning was silently swallowed when
    this case ran after a migration test. Force the logger enabled for the
    duration of the assertion and restore its prior state afterwards.
    """
    reset_session_provider()

    records: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Capture(level=logging.WARNING)
    provider_logger = logging.getLogger("app.db.session_provider")
    previous_level = provider_logger.level
    previous_disabled = provider_logger.disabled
    provider_logger.addHandler(handler)
    provider_logger.setLevel(logging.WARNING)
    provider_logger.disabled = False
    try:
        assert get_session_provider(pool="pooled").pool_policy == "pooled"
        get_session_provider(pool="nullpool")
    finally:
        provider_logger.removeHandler(handler)
        provider_logger.setLevel(previous_level)
        provider_logger.disabled = previous_disabled

    assert any(
        "get_session_provider(pool='nullpool') ignored" in record.getMessage() for record in records
    )


def test_reset_session_provider_disposes_engine() -> None:
    provider = SessionProvider(DATABASE_URL, pool="nullpool")
    set_session_provider(provider)
    _ = provider.engine()
    assert provider.is_engine_initialized
    reset_session_provider()
    assert peek_session_provider() is None
    assert not provider.is_engine_initialized


@pytest.mark.asyncio
async def test_reset_session_provider_async_disposes_engine() -> None:
    provider = SessionProvider(DATABASE_URL, pool="nullpool")
    set_session_provider(provider)
    _ = provider.engine()
    assert provider.is_engine_initialized

    await reset_session_provider_async()
    assert peek_session_provider() is None
    assert not provider.is_engine_initialized


@pytest.mark.asyncio
async def test_dispose_clears_engine_and_factory() -> None:
    provider = SessionProvider(DATABASE_URL, pool="nullpool")
    set_session_provider(provider)
    _ = provider.engine()
    _ = provider.session_factory()
    await dispose_session_provider()
    assert not provider.is_engine_initialized
    assert peek_session_provider() is None


def test_nullpool_connect_is_fresh_per_asyncio_run() -> None:
    """Regression: each asyncio.run must open a new connection under NullPool."""
    mock_engine = MagicMock()
    mock_conn = AsyncMock()
    mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_conn.__aexit__ = AsyncMock(return_value=None)
    mock_conn.execute = AsyncMock()
    mock_engine.connect = MagicMock(return_value=mock_conn)

    with patch("app.db.session_provider.create_async_engine", return_value=mock_engine):
        provider = SessionProvider("postgresql+asyncpg://test/db", pool="nullpool")

        async def _select_one() -> None:
            async with provider.engine().connect() as conn:
                await conn.execute(text("SELECT 1"))

        asyncio.run(_select_one())
        asyncio.run(_select_one())

    assert mock_engine.connect.call_count == 2


@pytest.mark.skipif(not _postgres_reachable(), reason="PostgreSQL not reachable")
def test_consecutive_asyncio_run_with_nullpool_provider() -> None:
    """Integration: Celery tasks using asyncio.run must not reuse loop-bound pools."""
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
    reset_session_provider()
    import importlib

    import app.core.celery_app as celery_module

    importlib.reload(celery_module)
    assert peek_session_provider() is None


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


def test_shutdown_worker_session_provider_disposes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dispose_mock = AsyncMock()
    monkeypatch.setattr("app.db.session_provider.dispose_session_provider", dispose_mock)
    from app.core.celery_app import shutdown_worker_session_provider

    shutdown_worker_session_provider(sender=None)
    dispose_mock.assert_awaited_once()


def test_check_postgres_uses_provider_when_url_matches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.api.v1 import health as health_module

    mock_provider = MagicMock()
    mock_provider.database_url = "postgresql+asyncpg://canonical/db"
    mock_provider.ping_postgres = AsyncMock(return_value=True)
    monkeypatch.setattr(health_module, "peek_session_provider", lambda: mock_provider)

    async def _run() -> str:
        return await health_module.check_postgres(mock_provider.database_url)

    assert asyncio.run(_run()) == "ok"
    mock_provider.ping_postgres.assert_awaited_once()


def test_check_postgres_uses_ephemeral_probe_when_url_differs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.api.v1 import health as health_module

    mock_provider = MagicMock()
    mock_provider.database_url = "postgresql+asyncpg://canonical/db"
    mock_provider.ping_postgres = AsyncMock(return_value=True)
    ping_mock = AsyncMock(return_value=True)
    monkeypatch.setattr(health_module, "peek_session_provider", lambda: mock_provider)
    monkeypatch.setattr(health_module, "ping_postgres_url", ping_mock)

    async def _run() -> str:
        return await health_module.check_postgres("postgresql+asyncpg://override/db")

    assert asyncio.run(_run()) == "ok"
    mock_provider.ping_postgres.assert_not_called()
    ping_mock.assert_awaited_once_with(
        "postgresql+asyncpg://override/db",
        pool="nullpool",
    )


@pytest.mark.asyncio
async def test_lifespan_disposes_session_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.main import _lifespan

    dispose_mock = AsyncMock()
    monkeypatch.setattr("app.main.dispose_session_provider", dispose_mock)
    monkeypatch.setattr("app.main._socketio_manager.start", AsyncMock())
    monkeypatch.setattr("app.main._socketio_manager.stop", AsyncMock())
    monkeypatch.setattr("app.main.shutdown_health_clients", AsyncMock())

    async with _lifespan(FastAPI()):
        pass

    dispose_mock.assert_awaited_once()
