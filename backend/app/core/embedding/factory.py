"""Process-local embedding client factory (ISSUE-140)."""

from __future__ import annotations

import asyncio
import logging

from app.core.config import Settings, get_settings
from app.core.embedding.service import EmbeddingService

logger = logging.getLogger(__name__)

_client: EmbeddingService | None = None


def get_embedding_client(*, settings: Settings | None = None) -> EmbeddingService:
    """Return the process-local embedding client without implicit mock fallback."""
    global _client
    if _client is None:
        _client = EmbeddingService(settings or get_settings())
    return _client


def _close_client_sync(client: EmbeddingService) -> None:
    """Best-effort synchronous close when no event loop is running."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.run(client.close())
    else:
        logger.warning(
            "Embedding client not closed synchronously because an event loop is running; "
            "await close_embedding_client() instead"
        )


def reset_embedding_client() -> None:
    """Close (when possible) and clear the process-local client (tests)."""
    global _client
    if _client is None:
        return
    client = _client
    _client = None
    _close_client_sync(client)


async def close_embedding_client() -> None:
    """Dispose network resources held by the process-local client."""
    global _client
    if _client is not None:
        await _client.close()
    _client = None


__all__ = ["close_embedding_client", "get_embedding_client", "reset_embedding_client"]
