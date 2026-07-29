"""Unit tests for Neo4jClient timeout bounds (ISSUE-083 review)."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.neo4j_client import Neo4jClient


@pytest.mark.asyncio
async def test_ping_returns_false_when_verify_connectivity_hangs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NEO4J_TIMEOUT_SECONDS", "0.05")
    from app.core.config import get_settings

    get_settings.cache_clear()

    async def _hang() -> None:
        await asyncio.sleep(5)

    fake_driver = MagicMock()
    fake_driver.verify_connectivity = AsyncMock(side_effect=_hang)
    fake_driver.close = AsyncMock()

    monkeypatch.setattr(
        "app.core.neo4j_client.AsyncGraphDatabase.driver",
        lambda *args, **kwargs: fake_driver,
    )

    client = Neo4jClient(timeout_seconds=0.05)
    assert await client.ping() is False
    await client.aclose()
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_run_cypher_raises_timeout_when_session_hangs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NEO4J_TIMEOUT_SECONDS", "0.05")
    from app.core.config import get_settings

    get_settings.cache_clear()

    class _HangingSession:
        async def __aenter__(self) -> _HangingSession:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def run(self, query: str, parameters: dict[str, Any] | None = None) -> Any:
            _ = query, parameters
            await asyncio.sleep(5)
            raise AssertionError("unreachable")

    fake_driver = MagicMock()
    fake_driver.session = MagicMock(return_value=_HangingSession())
    fake_driver.close = AsyncMock()

    monkeypatch.setattr(
        "app.core.neo4j_client.AsyncGraphDatabase.driver",
        lambda *args, **kwargs: fake_driver,
    )

    client = Neo4jClient(timeout_seconds=0.05)
    with pytest.raises(TimeoutError):
        await client.run_cypher("RETURN 1")
    await client.aclose()
    get_settings.cache_clear()
