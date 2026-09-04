"""Process-local embedding client factory (ISSUE-140)."""

from __future__ import annotations

import asyncio
import logging

from app.core.config import Settings, get_settings
from app.core.embedding.release import build_embedding_release
from app.core.embedding.service import EmbeddingService

logger = logging.getLogger(__name__)

_client: EmbeddingService | None = None


def get_embedding_client(*, settings: Settings | None = None) -> EmbeddingService:
    """Return the process-local embedding client without implicit mock fallback."""
    global _client
    if _client is None:
        _client = EmbeddingService(settings or get_settings())
    elif settings is not None:
        requested = build_embedding_release(settings)
        active = _client.release
        if (
            requested.release_id != active.release_id
            or requested.config_hash != active.config_hash
            or requested.provider_mode != active.provider_mode
        ):
            logger.warning(
                "get_embedding_client(settings=...) ignored: client already initialized "
                "with release_id=%r (requested %r); reset_embedding_client() first",
                active.release_id,
                requested.release_id,
            )
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


def reset_embedding_client(*, close: bool = True) -> None:
    """Clear the process-local client; async owners may already have closed it."""
    global _client
    if _client is None:
        return
    client = _client
    _client = None
    if close:
        _close_client_sync(client)


async def close_embedding_client() -> None:
    """Dispose network resources held by the process-local client."""
    global _client
    client = _client
    _client = None
    if client is not None:
        await client.close()


__all__ = ["close_embedding_client", "get_embedding_client", "reset_embedding_client"]
