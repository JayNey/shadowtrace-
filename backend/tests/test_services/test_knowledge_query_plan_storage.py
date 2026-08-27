"""KnowledgeQueryPlan storage-layer integration tests (ISSUE-130 / #636 Phase A)."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.core.embedding.release import build_embedding_release
from app.core.embedding.service import EmbeddingService
from app.models.knowledge import KnowledgeChunk
from app.models.knowledge_release import (
    ATTACK_CORPUS_ID,
    ATTACK_KB_NAME,
    ATTACK_SOURCE_ID,
    KnowledgeFilterKind,
    KnowledgeQueryPlan,
    KnowledgeTypedFilter,
)
from app.rag.context import RetrievalContext
from app.rag.hybrid_retriever import HybridRetriever
from app.services.knowledge_query_plan_validator import validate_knowledge_query_plan
from app.services.knowledge_store import KnowledgeStore
from tests.helpers.knowledge_isolation import TEST_OWNED_CHUNK_DELETE

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


def _postgres_reachable() -> bool:
    import asyncio

    from app.db.session_provider import SessionProvider

    provider = SessionProvider(DATABASE_URL, pool="nullpool")
    try:
        return asyncio.run(provider.ping_postgres())
    except Exception:
        return False
    finally:
        asyncio.run(provider.dispose())


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


@pytest.fixture(scope="module")
def migrated() -> None:
    os.environ["DATABASE_URL"] = DATABASE_URL
    from app.core.config import get_settings

    get_settings.cache_clear()
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(
    migrated: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def clean_knowledge(session_factory: async_sessionmaker[AsyncSession]) -> None:
    async with session_factory() as session:
        await session.execute(TEST_OWNED_CHUNK_DELETE)
        await session.commit()


@pytest_asyncio.fixture
def embed_service() -> EmbeddingService:
    return EmbeddingService(Settings(embedding_mode="mock"))


def _chunk(
    chunk_id: str,
    kb_name: str,
    content: str,
    *,
    tenant_id: str,
    release_id: str,
    embedding_release_id: str,
    source_id: str = ATTACK_SOURCE_ID,
) -> KnowledgeChunk:
    return KnowledgeChunk(
        chunk_id=chunk_id,
        kb_name=kb_name,
        content=content,
        metadata={
            "tenant_id": tenant_id,
            "release_id": release_id,
            "embedding_release_id": embedding_release_id,
            "source_id": source_id,
            "content_type": "technique",
        },
    )


@pytest.mark.skipif(not _postgres_reachable(), reason="PostgreSQL not reachable")
class TestKnowledgeQueryPlanStorageIntegration:
    @pytest.mark.asyncio
    async def test_release_and_tenant_filters_exclude_cross_tenant_hits(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        embed_service: EmbeddingService,
        clean_knowledge: None,
    ) -> None:
        settings = Settings(embedding_mode="mock")
        active_emb = build_embedding_release(settings).release_id
        store = KnowledgeStore(session_factory, embed_service, tenant_isolation_strict=True)
        await store.upsert_chunks(
            ATTACK_KB_NAME,
            [
                _chunk(
                    "chk-tenant-a-release-a",
                    ATTACK_KB_NAME,
                    "Valid Accounts credential access technique",
                    tenant_id="tenant-a",
                    release_id="krel-a",
                    embedding_release_id=active_emb,
                ),
                _chunk(
                    "chk-tenant-b-release-a",
                    ATTACK_KB_NAME,
                    "Valid Accounts credential access technique",
                    tenant_id="tenant-b",
                    release_id="krel-a",
                    embedding_release_id=active_emb,
                ),
                _chunk(
                    "chk-tenant-a-release-b",
                    ATTACK_KB_NAME,
                    "Valid Accounts credential access technique",
                    tenant_id="tenant-a",
                    release_id="krel-b",
                    embedding_release_id=active_emb,
                ),
            ],
        )

        base_plan = KnowledgeQueryPlan(
            corpus_id=ATTACK_CORPUS_ID,
            kb_name=ATTACK_KB_NAME,
            active_release_id="krel-a",
            embedding_release_id=active_emb,
            typed_filters=(
                KnowledgeTypedFilter(kind=KnowledgeFilterKind.SOURCE_ID, value=ATTACK_SOURCE_ID),
            ),
            trace_id="trace-storage",
            pinned_at=datetime.now(UTC),
        )
        outcome = validate_knowledge_query_plan(
            base_plan,
            tenant_id="tenant-a",
            principal="investigation:test",
            kb_names=[ATTACK_KB_NAME],
            active_embedding_release_id=active_emb,
        )
        assert outcome.accepted is True
        assert outcome.plan is not None

        context = RetrievalContext(
            tenant_id="tenant-a",
            principal="investigation:test",
            event_id="evt-storage",
            trace_id="trace-storage",
            query_plan=outcome.plan,
        )
        retriever = HybridRetriever(store, embed_service)
        result_lists = await retriever.retrieve(
            ["Valid Accounts credential access"],
            [ATTACK_KB_NAME],
            top_k=3,
            context=context,
        )
        chunk_ids = {hit.chunk_id for hits in result_lists for hit in hits}
        assert chunk_ids == {"chk-tenant-a-release-a"}
