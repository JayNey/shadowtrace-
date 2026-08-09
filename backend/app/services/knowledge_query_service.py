"""Knowledge catalog query service for ``GET /api/v1/knowledge`` (ISSUE-279)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.core.errors import ValidationError
from app.models.knowledge import KNOWLEDGE_KB_NAMES, ListedKnowledgeChunk, RetrievedChunk
from app.services.knowledge_store import KnowledgeStore


def _catalog_item(
    *,
    chunk_id: str,
    kb_name: str,
    content: str,
    metadata: dict[str, Any],
    created_at: datetime | None = None,
    score: float | None = None,
    retrieval_method: str | None = None,
) -> dict[str, Any]:
    """Stable catalog DTO shared by list and keyword search paths."""
    item: dict[str, Any] = {
        "chunk_id": chunk_id,
        "kb_name": kb_name,
        "content": content,
        "metadata": metadata,
        "created_at": created_at.isoformat() if created_at is not None else None,
    }
    if score is not None:
        item["score"] = score
    if retrieval_method is not None:
        item["retrieval_method"] = retrieval_method
    return item


def _listed_item(chunk: ListedKnowledgeChunk) -> dict[str, Any]:
    return _catalog_item(
        chunk_id=chunk.chunk_id,
        kb_name=chunk.kb_name,
        content=chunk.content,
        metadata=chunk.metadata,
        created_at=chunk.created_at,
    )


def _retrieved_item(chunk: RetrievedChunk) -> dict[str, Any]:
    return _catalog_item(
        chunk_id=chunk.chunk_id,
        kb_name=chunk.kb_name,
        content=chunk.content,
        metadata=chunk.metadata,
        created_at=chunk.created_at,
        score=chunk.score,
        retrieval_method=chunk.retrieval_method,
    )


class KnowledgeQueryService:
    """Paginated knowledge catalog backed by ``KnowledgeStore``."""

    def __init__(self, store: KnowledgeStore, *, require_tenant: bool = False) -> None:
        self._store = store
        self._require_tenant = require_tenant

    @staticmethod
    def _validate_kb_name(kb_name: str | None) -> None:
        if kb_name is not None and kb_name not in KNOWLEDGE_KB_NAMES:
            raise ValidationError(
                "invalid kb_name",
                details={
                    "kb_name": kb_name,
                    "allowed": sorted(KNOWLEDGE_KB_NAMES),
                },
            )

    def _validate_tenant(self, tenant_id: str | None) -> None:
        if not self._require_tenant:
            return
        if tenant_id is None or not str(tenant_id).strip():
            raise ValidationError(
                "tenant_id is required for knowledge catalog queries",
                details={"reason": "tenant_required"},
            )

    async def list_knowledge(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        kb_name: str | None = None,
        q: str | None = None,
        tenant_id: str | None = None,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Return ``(total, items)`` from the real knowledge store."""
        self._validate_kb_name(kb_name)
        self._validate_tenant(tenant_id)
        if q is not None:
            query = q.strip()
            if not query:
                raise ValidationError(
                    "q must contain non-whitespace characters",
                    details={"reason": "blank_query"},
                )
            total, hits = await self._store.keyword_search_paginated(
                query,
                kb_name=kb_name,
                page=page,
                page_size=page_size,
                tenant_id=tenant_id,
            )
            return total, [_retrieved_item(hit) for hit in hits]

        total = await self._store.count_chunks(kb_name=kb_name, tenant_id=tenant_id)
        chunks = await self._store.list_chunks(
            kb_name=kb_name,
            page=page,
            page_size=page_size,
            tenant_id=tenant_id,
        )
        return total, [_listed_item(chunk) for chunk in chunks]


__all__ = ["KnowledgeQueryService"]
