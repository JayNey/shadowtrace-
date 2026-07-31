"""Process-local embedding client factory (ISSUE-140)."""

from __future__ import annotations

from app.core.config import Settings, get_settings
from app.core.embedding.service import EmbeddingService

_client: EmbeddingService | None = None


def get_embedding_client(*, settings: Settings | None = None) -> EmbeddingService:
    """Return the process-local embedding client without implicit mock fallback."""
    global _client
    if _client is None:
        _client = EmbeddingService(settings or get_settings())
    return _client


def reset_embedding_client() -> None:
    """Clear the process-local client (tests)."""
    global _client
    _client = None


async def close_embedding_client() -> None:
    """Dispose network resources held by the process-local client."""
    global _client
    if _client is not None:
        await _client.close()
    _client = None


__all__ = ["close_embedding_client", "get_embedding_client", "reset_embedding_client"]
