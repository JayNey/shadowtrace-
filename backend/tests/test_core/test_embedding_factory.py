"""Embedding client factory tests (ISSUE-140)."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from app.core.config import Settings
from app.core.embedding.factory import (
    close_embedding_client,
    get_embedding_client,
    reset_embedding_client,
)
from app.core.embedding.service import EmbeddingService


def test_get_embedding_client_is_process_local_singleton() -> None:
    reset_embedding_client()
    first = get_embedding_client(settings=Settings(embedding_mode="mock"))
    second = get_embedding_client()
    assert first is second
    assert isinstance(first, EmbeddingService)
    reset_embedding_client()


def test_reset_embedding_client_clears_singleton() -> None:
    reset_embedding_client()
    first = get_embedding_client(settings=Settings(embedding_mode="mock"))
    reset_embedding_client()
    second = get_embedding_client(settings=Settings(embedding_mode="mock"))
    assert first is not second
    reset_embedding_client()


def test_reset_embedding_client_closes_remote_http() -> None:
    reset_embedding_client()
    svc = get_embedding_client(
        settings=Settings(
            embedding_mode="remote",
            embedding_api_base_url="http://stub.local",
        )
    )
    assert svc._remote is not None
    close_mock = AsyncMock()
    svc._remote.close = close_mock  # type: ignore[method-assign]
    reset_embedding_client()
    close_mock.assert_awaited_once()


def test_get_embedding_client_warns_when_settings_ignored(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    caplog.set_level(logging.WARNING)
    reset_embedding_client()
    get_embedding_client(settings=Settings(embedding_mode="mock", embedding_release_id="mock-v1"))
    get_embedding_client(
        settings=Settings(embedding_mode="mock", embedding_release_id="other-release")
    )
    assert any("ignored" in record.message for record in caplog.records)
    reset_embedding_client()


@pytest.mark.asyncio
async def test_close_embedding_client_disposes_singleton() -> None:
    reset_embedding_client()
    svc = get_embedding_client(settings=Settings(embedding_mode="mock"))
    await close_embedding_client()
    second = get_embedding_client(settings=Settings(embedding_mode="mock"))
    assert second is not svc
