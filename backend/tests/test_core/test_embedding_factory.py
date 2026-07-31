"""Embedding client factory tests (ISSUE-140)."""

from __future__ import annotations

from app.core.config import Settings
from app.core.embedding.factory import get_embedding_client, reset_embedding_client
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
