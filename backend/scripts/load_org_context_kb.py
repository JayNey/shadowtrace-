"""Load org_context_kb from the Python seed (no JSON corpus).

Production (non-mock SOURCE_MODE) upserts zero business-policy rows.
Mock XDR / demo bootstrap loads a handful of synthetic facts.

Usage::

    cd backend && python -m scripts.load_org_context_kb
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

_BACKEND = Path(__file__).resolve().parents[1]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from app.core.config import Settings, is_mock_source_mode  # noqa: E402
from app.core.embedding.service import EmbeddingService  # noqa: E402
from app.knowledge.org_context_seed import (  # noqa: E402
    records_for_settings,
    seed_org_context_store,
)
from app.models.knowledge import ORG_CONTEXT_KB_NAME  # noqa: E402
from app.services.knowledge_store import KnowledgeStore  # noqa: E402

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


async def main() -> None:
    settings = Settings()
    records = records_for_settings(settings)
    mode = "mock_xdr" if is_mock_source_mode(settings.source_mode) else settings.source_mode
    print(
        f"[load_org_context_kb] SOURCE_MODE={mode} seed_rows={len(records)} "
        f"(production default is empty)"
    )

    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    embed_service = EmbeddingService(settings)
    store = KnowledgeStore(session_factory, embed_service)
    try:
        count = await seed_org_context_store(store, settings)
        total = await store.count(ORG_CONTEXT_KB_NAME)
        print(f"[load_org_context_kb] {ORG_CONTEXT_KB_NAME} total chunks: {total} seeded={count}")
    finally:
        await embed_service.close()
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
