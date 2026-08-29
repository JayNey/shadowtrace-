"""AttackKBService: ATT&CK technique knowledge base operations (ISSUE-042 / #522)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.knowledge import KnowledgeChunk, RetrievedChunk
from app.rag.keyword_aliases import CHINESE_SOC_QUERY_BENCHMARKS, expand_keyword_query
from app.services.knowledge_store import KnowledgeStore

KB_NAME = "attack_kb"

# Re-export so existing tests keep importing from this module.
__all__ = [
    "AttackKBService",
    "CHINESE_SOC_QUERY_BENCHMARKS",
    "KB_NAME",
    "_format_content",
]


def _derive_chunk_id(technique_id: str, attack_version: str) -> str:
    raw = f"technique_id:{technique_id}:attack_version:{attack_version}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return f"atk-{digest}"


def _format_content(t: dict[str, Any]) -> str:
    tactics = ", ".join(t["tactics"])
    keywords = t.get("keywords") or []
    aliases = t.get("aliases") or []
    lines = [
        f"Technique: {t['technique_name']}",
        f"ID: {t['technique_id']}",
        f"Tactics: {tactics}",
        f"Description: {t['description']}",
        f"Detection: {t['detection']}",
    ]
    if keywords:
        lines.append(f"Keywords: {', '.join(str(item) for item in keywords)}")
    if aliases:
        lines.append(f"Aliases: {', '.join(str(item) for item in aliases)}")
    return "\n".join(lines)


class AttackKBService:
    """Manage the ATT&CK technique knowledge base.

    Provides file-based loading with idempotent upsert, precise technique
    lookup by technique_id, and semantic search over technique descriptions.
    """

    def __init__(
        self,
        store: KnowledgeStore,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self._store = store
        self._session_factory = session_factory

    async def load_from_file(self, path: str | Path) -> int:
        """Load techniques from a JSON file and upsert into attack_kb.

        Returns the number of techniques loaded.  Repeated loads are
        idempotent — chunk_id is derived from technique_id + attack_version.
        """
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        attack_version: str = data["attack_version"]
        techniques: list[dict[str, Any]] = data["techniques"]

        chunks: list[KnowledgeChunk] = []
        for t in techniques:
            chunk_id = _derive_chunk_id(t["technique_id"], attack_version)
            content = _format_content(t)
            metadata: dict[str, Any] = {
                "technique_id": t["technique_id"],
                "technique_name": t["technique_name"],
                "tactics": t["tactics"],
                "description": t["description"],
                "detection": t["detection"],
                "attack_version": attack_version,
            }
            if t.get("keywords"):
                metadata["keywords"] = list(t["keywords"])
            if t.get("aliases"):
                metadata["aliases"] = list(t["aliases"])
            chunks.append(
                KnowledgeChunk(
                    chunk_id=chunk_id,
                    kb_name=KB_NAME,
                    content=content,
                    metadata=metadata,
                )
            )

        await self._store.upsert_chunks(KB_NAME, chunks)
        return len(chunks)

    async def stamp_release_on_chunks(
        self,
        *,
        release_id: str,
        embedding_release_id: str,
    ) -> int:
        """Pin existing attack_kb rows to a knowledge query-plan release filter."""
        sql = text(
            """
            UPDATE knowledge_chunk
            SET metadata = COALESCE(metadata, '{}'::jsonb)
                || jsonb_build_object(
                    'release_id', CAST(:release_id AS text),
                    'embedding_release_id', CAST(:embedding_release_id AS text)
                )
            WHERE kb_name = :kb_name
            """
        )
        async with self._session_factory() as session:
            async with session.begin():
                result = await session.execute(
                    sql,
                    {
                        "kb_name": KB_NAME,
                        "release_id": release_id,
                        "embedding_release_id": embedding_release_id,
                    },
                )
                return int(getattr(result, "rowcount", 0) or 0)

    async def get_technique(self, technique_id: str) -> dict[str, Any] | None:
        """Look up a technique by its MITRE ATT&CK technique ID (e.g. T1078)."""
        sql = text(
            """
            SELECT metadata
            FROM knowledge_chunk
            WHERE kb_name = :kb_name
              AND metadata ->> 'technique_id' = :technique_id
            """
        )
        async with self._session_factory() as session:
            result = await session.execute(
                sql,
                {"kb_name": KB_NAME, "technique_id": technique_id},
            )
            row = result.fetchone()
            return dict(row.metadata) if row else None

    async def search_techniques(
        self,
        query_text: str,
        top_k: int = 5,
        *,
        tenant_id: str | None = None,
        query_plan: Any | None = None,
    ) -> list[RetrievedChunk]:
        """Search ATT&CK techniques.

        * ``embedding_mode=remote|local`` (semantic enabled): pure vector search.
        * ``embedding_mode=mock`` (P0 default): hybrid vector + keyword search with
          the minimal ``_KEYWORD_QUERY_ALIASES`` map for Chinese analyst queries.
        """
        release_id: str | None = None
        embedding_release_id: str | None = None
        if query_plan is not None:
            tenant_id = (getattr(query_plan, "tenant_id", None) or "").strip() or tenant_id
            release_id = getattr(query_plan, "active_release_id", None) or None
            embedding_release_id = getattr(query_plan, "embedding_release_id", None) or None
        if self._store.semantic_search_enabled:
            return await self._store.vector_search_query(
                KB_NAME,
                query_text,
                top_k=top_k,
                tenant_id=tenant_id,
                release_id=release_id,
                embedding_release_id=embedding_release_id,
            )

        stripped = query_text.strip()
        keyword_query = expand_keyword_query(stripped)
        return await self._store.hybrid_search(
            KB_NAME,
            query_text,
            keyword_query=keyword_query,
            top_k=top_k,
            tenant_id=tenant_id,
            release_id=release_id,
            embedding_release_id=embedding_release_id,
        )
