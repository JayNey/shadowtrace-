"""Shadow query pivot integration tests (ISSUE-135 / #641 Phase A)."""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.core.embedding.release import build_embedding_release
from app.core.llm.base import LLMMessage, LLMResponse
from app.db import models as orm
from app.db.orm.shadow_run import (
    ShadowDecisionRecordORM,
    ShadowQueryArtifactORM,
    ShadowRunORM,
)
from app.models.knowledge import RetrievalResult, RetrievedChunk
from app.models.knowledge_release import ATTACK_CORPUS_ID, ATTACK_KB_NAME, KnowledgeQueryPlan
from app.models.react import (
    ReActAction,
    ReActActionType,
    ReActGapCode,
    ReActReasonCode,
    ReActReflectOutput,
    ReActThinkOutput,
    ReActUncertaintyCode,
)
from app.models.shadow_run import ShadowQueryPivotRequest, ShadowRunStatus
from app.services.safe_tool_projection import SafeToolProjectionService
from app.services.shadow_query_pivot_service import ShadowQueryPivotService
from app.services.shadow_run_service import ShadowRunService
from app.services.tool_call_grant_service import ToolCallGrantService
from app.tools.executor import ToolExecutor
from app.tools.registry import ToolRegistry
from app.tools.tool_call_runtime import ReactToolExecutorFactory

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


class _ScriptedLLM:
    def __init__(self) -> None:
        self.think_queue: list = []
        self.reflect_queue: list = []

    def add_round(self, think: ReActThinkOutput, reflect: ReActReflectOutput) -> None:
        self.think_queue.append(think)
        self.reflect_queue.append(reflect)

    async def chat(
        self,
        messages: list[LLMMessage],
        *,
        event_id: str,
        agent_name: str,
        prompt_key: str,
        scenario_id: str | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
        json_mode: bool = False,
        response_model: type | None = None,
    ) -> LLMResponse:
        del messages, event_id, agent_name, scenario_id, temperature, max_tokens, json_mode
        queue = self.think_queue if prompt_key == "react_think" else self.reflect_queue
        payload = queue.pop(0)
        if isinstance(payload, Exception):
            raise payload
        parsed = payload if response_model is None else response_model.model_validate(payload.model_dump())
        return LLMResponse(content="{}", parsed=parsed, model_name="scripted-model")


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


def _active_attack_plan(settings: Settings, trace_id: str) -> KnowledgeQueryPlan:
    active_emb = build_embedding_release(settings).release_id
    return KnowledgeQueryPlan(
        corpus_id=ATTACK_CORPUS_ID,
        kb_name=ATTACK_KB_NAME,
        active_release_id="krel-pivot-test",
        embedding_release_id=active_emb,
        trace_id=trace_id,
        pinned_at=datetime.now(UTC),
    )


@pytest.fixture(scope="module")
def migrated_database() -> None:
    os.environ["DATABASE_URL"] = DATABASE_URL
    from app.core.config import get_settings

    get_settings.cache_clear()
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(
    migrated_database: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def clean_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(ShadowQueryArtifactORM))
            await session.execute(delete(ShadowDecisionRecordORM))
            await session.execute(delete(ShadowRunORM))
            await session.execute(delete(orm.ToolCallAttemptORM))
            await session.execute(delete(orm.ToolCallGrantORM))
    yield


requires_postgres = pytest.mark.skipif(
    not _postgres_reachable(),
    reason="PostgreSQL not reachable",
)


@pytest.mark.asyncio
@requires_postgres
async def test_shadow_pivot_produces_artifacts_without_production_mutation(
    session_factory: async_sessionmaker[AsyncSession],
    clean_tables: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sfx = uuid.uuid4().hex[:8]
    event_id = f"evt-pivot-{sfx}"
    trace_id = f"trace-{sfx}"
    settings = Settings(
        EMBEDDING_MODE="mock",
        TOOL_CALL_GRANT_REQUIRED=True,
        REACT_SHADOW_PIVOT_ENABLED=True,
        REACT_SHADOW_MAX_TOOL_CALLS=3,
        REACT_SHADOW_MAX_STEPS=3,
    )

    grant_service = ToolCallGrantService(session_factory)
    shadow_service = ShadowRunService(session_factory, retention_hours=settings.react_shadow_retention_hours)
    registry = ToolRegistry()
    registry.auto_discover()
    inner = ToolExecutor(registry=registry)
    react_factory = ReactToolExecutorFactory(
        inner_executor=inner,
        grant_service=grant_service,
        settings=settings,
        projection_service=SafeToolProjectionService(registry),
    )

    release_service = MagicMock()
    release_service.get_active_release = AsyncMock(return_value=MagicMock(release_id="krel-pivot-test"))
    base_plan = _active_attack_plan(settings, trace_id)
    monkeypatch.setattr(
        "app.services.react_mock_query_adapter.resolve_active_knowledge_query_plan",
        AsyncMock(return_value=base_plan),
    )

    pipeline = MagicMock()
    pipeline.retrieve = AsyncMock(
        return_value=RetrievalResult(
            query="exfil path",
            chunks=[
                RetrievedChunk(
                    chunk_id="chk-fixture",
                    kb_name=ATTACK_KB_NAME,
                    content="Exfiltration over Web Service",
                    metadata={
                        "source_id": "mitre_attack_stix",
                        "tenant_id": "tenant-a",
                        "release_id": "krel-pivot-test",
                    },
                    score=0.91,
                    retrieval_method="vector",
                )
            ],
            knowledge_query_plan=base_plan.model_dump(mode="json"),
        )
    )

    pivot = ShadowQueryPivotService(shadow_service, settings=settings)

    llm = _ScriptedLLM()
    llm.add_round(
        ReActThinkOutput(
            decision_summary="query mock knowledge for exfil evidence",
            reason_code=ReActReasonCode.FILL_EVIDENCE_GAP,
            action=ReActAction(
                action_type=ReActActionType.CALL_AGENT,
                target_name="mock_query_retrieval",
                params={"query": "exfil path", "kb_names": [ATTACK_KB_NAME]},
            ),
        ),
        ReActReflectOutput(
            decision_summary="found supplemental evidence",
            confidence=0.85,
            gap_code=ReActGapCode.EVIDENCE_MISSING,
            uncertainty_code=ReActUncertaintyCode.INCOMPLETE_COVERAGE,
        ),
    )

    async with session_factory() as session:
        prod_before = int(
            await session.scalar(
                select(func.count()).select_from(orm.DecisionRecord).where(
                    orm.DecisionRecord.event_id == event_id
                )
            )
            or 0
        )
        prod_attempts_before = await grant_service.count_production_attempts_for_event(event_id)

    result = await pivot.run_pivot(
        ShadowQueryPivotRequest(
            event_id=event_id,
            tenant_id="tenant-a",
            principal="investigation:test",
            trace_id=trace_id,
            goal="find supplemental exfil evidence",
            evidence_gaps=["missing exfil destination"],
            observation="host uploaded 2GB to unknown domain",
        ),
        llm_client=llm,
        react_factory=react_factory,
        pipeline=pipeline,
        knowledge_release_service=release_service,
    )

    assert result.shadow_run_id
    assert result.status is ShadowRunStatus.COMPLETED
    assert result.artifacts
    retrieval_artifacts = [
        artifact
        for artifact in result.artifacts
        if artifact.kind.value == "retrieval_hit"
    ]
    assert retrieval_artifacts
    assert retrieval_artifacts[0].payload.get("chunk_count") == 1
    assert retrieval_artifacts[0].payload.get("plan_hash")
    pipeline.retrieve.assert_awaited_once()

    async with session_factory() as session:
        prod_after = int(
            await session.scalar(
                select(func.count()).select_from(orm.DecisionRecord).where(
                    orm.DecisionRecord.event_id == event_id
                )
            )
            or 0
        )
        shadow_runs = int(
            await session.scalar(
                select(func.count()).select_from(ShadowRunORM).where(
                    ShadowRunORM.shadow_run_id == result.shadow_run_id
                )
            )
            or 0
        )
        shadow_records = int(
            await session.scalar(
                select(func.count())
                .select_from(ShadowDecisionRecordORM)
                .where(ShadowDecisionRecordORM.shadow_run_id == result.shadow_run_id)
            )
            or 0
        )

    prod_attempts_after = await grant_service.count_production_attempts_for_event(event_id)
    assert prod_before == prod_after == 0
    assert prod_attempts_before == prod_attempts_after == 0
    assert shadow_runs == 1
    assert shadow_records >= 1


@pytest.mark.asyncio
@requires_postgres
async def test_shadow_pivot_respects_max_steps(
    session_factory: async_sessionmaker[AsyncSession],
    clean_tables: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sfx = uuid.uuid4().hex[:8]
    event_id = f"evt-pivot-max-{sfx}"
    trace_id = f"trace-max-{sfx}"
    settings = Settings(
        EMBEDDING_MODE="mock",
        TOOL_CALL_GRANT_REQUIRED=True,
        REACT_SHADOW_PIVOT_ENABLED=True,
        REACT_SHADOW_MAX_TOOL_CALLS=5,
        REACT_SHADOW_MAX_STEPS=1,
    )

    grant_service = ToolCallGrantService(session_factory)
    shadow_service = ShadowRunService(session_factory)
    registry = ToolRegistry()
    registry.auto_discover()
    react_factory = ReactToolExecutorFactory(
        inner_executor=ToolExecutor(registry=registry),
        grant_service=grant_service,
        settings=settings,
        projection_service=SafeToolProjectionService(registry),
    )

    release_service = MagicMock()
    release_service.get_active_release = AsyncMock(return_value=MagicMock(release_id="krel-pivot-test"))
    monkeypatch.setattr(
        "app.services.react_mock_query_adapter.resolve_active_knowledge_query_plan",
        AsyncMock(return_value=_active_attack_plan(settings, trace_id)),
    )

    pipeline = MagicMock()
    pipeline.retrieve = AsyncMock(
        return_value=RetrievalResult(
            query="probe",
            chunks=[
                RetrievedChunk(
                    chunk_id="chk-probe",
                    kb_name=ATTACK_KB_NAME,
                    content="probe",
                    metadata={"tenant_id": "tenant-a"},
                    score=0.5,
                    retrieval_method="keyword",
                )
            ],
        )
    )

    pivot = ShadowQueryPivotService(shadow_service, settings=settings)
    llm = _ScriptedLLM()
    for _ in range(2):
        llm.add_round(
            ReActThinkOutput(
                decision_summary="continue querying",
                reason_code=ReActReasonCode.FILL_EVIDENCE_GAP,
                action=ReActAction(
                    action_type=ReActActionType.CALL_AGENT,
                    target_name="mock_query_retrieval",
                    params={"query": "probe", "kb_names": [ATTACK_KB_NAME]},
                ),
            ),
            ReActReflectOutput(
                decision_summary="still gathering evidence",
                confidence=0.4,
                gap_code=ReActGapCode.EVIDENCE_MISSING,
                uncertainty_code=ReActUncertaintyCode.INCOMPLETE_COVERAGE,
            ),
        )

    result = await pivot.run_pivot(
        ShadowQueryPivotRequest(
            event_id=event_id,
            tenant_id="tenant-a",
            principal="investigation:test",
            trace_id=trace_id,
            goal="bounded pivot",
            evidence_gaps=["gap"],
            observation="obs",
        ),
        llm_client=llm,
        react_factory=react_factory,
        pipeline=pipeline,
        knowledge_release_service=release_service,
    )

    assert result.react_stop_reason == "max_rounds"
    finalized = await shadow_service.get_run(result.shadow_run_id)
    assert finalized is not None
    assert finalized.step_count == 1
