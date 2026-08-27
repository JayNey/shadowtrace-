"""Memory governance review, promotion, conflict, and retention tests (ISSUE-081)."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.agents.memory_agent import MemoryAgent
from app.core.config import Settings
from app.core.embedding.service import EmbeddingService
from app.db.orm.memory_review import MemoryReviewORM
from app.db.orm.profile import EntityProfileORM
from app.models.agent_io import (
    FpRuleCandidate,
    InvestigationResult,
    MemoryAgentInput,
    ProfileUpdate,
)
from app.models.case import HistoryCase
from app.models.context import EventContext
from app.models.enums import (
    CaseLabel,
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    WritebackReadiness,
)
from app.models.memory import MemoryCandidate
from app.models.security_event import EventSummary
from app.services.case_kb_service import FP_KB_NAME, HISTORY_KB_NAME, CaseKBService
from app.services.knowledge_store import KnowledgeStore
from app.services.memory_governance import PROFILE_KB_NAME, MemoryGovernance
from app.services.profile_service import ProfileService
from tests.helpers.knowledge_isolation import PRESERVE_ORG_CONTEXT_DELETE

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


def _alembic_config() -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return config


@pytest.fixture(scope="module")
def migrated() -> None:
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(
    migrated: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def clean_memory_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        await session.execute(text("DELETE FROM memory_review"))
        await session.execute(PRESERVE_ORG_CONTEXT_DELETE)
        await session.execute(text("DELETE FROM entity_profile"))
        await session.commit()


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value


class _IneligibleHistorySource:
    async def prepare_history_case(self, event_id: str) -> HistoryCase:
        raise ValueError(f"event {event_id} is not eligible for history archival")


class _AgentContextStore:
    def __init__(self, context: EventContext) -> None:
        self.context = context

    async def get_full_context(self, event_id: str) -> EventContext:
        assert self.context.event is not None
        assert event_id == self.context.event.event_id
        return self.context


class _AgentWorkingMemory:
    def __init__(self, context: EventContext) -> None:
        self.context = context

    async def write(self, event_id: str, key: str, value: object) -> None:
        assert self.context.event is not None
        assert event_id == self.context.event.event_id
        assert key == "memory_output"
        assert isinstance(value, dict)
        self.context.memory_output = value


@pytest_asyncio.fixture
async def services(
    session_factory: async_sessionmaker[AsyncSession],
) -> tuple[MemoryGovernance, KnowledgeStore, CaseKBService, ProfileService, _Clock]:
    knowledge_store = KnowledgeStore(
        session_factory,
        EmbeddingService(Settings(embedding_mode="mock")),
    )
    case_kb = CaseKBService(knowledge_store, session_factory)
    profiles = ProfileService(session_factory)
    clock = _Clock()
    governance = MemoryGovernance(
        session_factory,
        case_kb_service=case_kb,
        profile_service=profiles,
        now=clock,
    )
    return governance, knowledge_store, case_kb, profiles, clock


def _fp_candidate(
    *,
    summary: str = "Approved backup service activity",
    signature: str = "Backup Service Login",
    confidence: float = 0.8,
    source_event_id: str = "evt-memory-review-1",
) -> MemoryCandidate:
    rule = FpRuleCandidate(
        rule_summary=summary,
        alert_signature=signature,
        confidence=confidence,
        source_event_id=source_event_id,
        pending_review=True,
    )
    return MemoryCandidate(
        kb_name=FP_KB_NAME,
        candidate_type="fp_rule",
        payload=rule.model_dump(mode="json"),
        confidence=confidence,
    )


def _history_candidate(clock: _Clock) -> MemoryCandidate:
    history = HistoryCase(
        case_id="case-acde1234",
        event_id="evt-history-1",
        event_type=EventType.MALICIOUS_PROCESS,
        case_label=CaseLabel.TRUE_POSITIVE,
        summary="Malicious PowerShell download was contained.",
        key_entities="host=PC-FIN-023; account=zhangsan",
        final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
        risk_score=91,
        resolution="Endpoint isolated",
        closed_at=clock.value,
    )
    return MemoryCandidate(
        kb_name=HISTORY_KB_NAME,
        candidate_type="history_case",
        payload=history.model_dump(mode="json"),
        confidence=0.91,
    )


def _false_positive_context() -> EventContext:
    return EventContext(
        event=EventSummary(
            event_id="evt-memory-agent-integration",
            event_type=EventType.DATA_EXFILTRATION,
            title="Approved backup service upload",
            status=EventStatus.CLOSED,
            severity=Severity.MEDIUM,
            risk_score=76,
            final_verdict=FinalVerdict.FALSE_POSITIVE,
            writeback_required=False,
            writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            disposition_policy=DispositionPolicy.NOT_REQUIRED,
        )
    )


def _memory_agent_input() -> MemoryAgentInput:
    return MemoryAgentInput(
        event_id="evt-memory-agent-integration",
        investigation_result=InvestigationResult(
            event_id="evt-memory-agent-integration",
            final_status=EventStatus.CLOSED,
            final_verdict=FinalVerdict.FALSE_POSITIVE,
        ),
    )


async def _review_row(
    session_factory: async_sessionmaker[AsyncSession],
    review_id: str,
) -> MemoryReviewORM:
    async with session_factory() as session:
        row = await session.get(MemoryReviewORM, review_id)
        assert row is not None
        return row


@pytest.mark.asyncio
async def test_candidate_is_pending_and_not_searchable_before_promotion(
    services: tuple[MemoryGovernance, KnowledgeStore, CaseKBService, ProfileService, _Clock],
) -> None:
    governance, knowledge_store, case_kb, _, _ = services

    review_id = await governance.ingest_candidate(_fp_candidate())

    pending = await governance.list_pending()
    assert [item.review_id for item in pending] == [review_id]
    assert await knowledge_store.count(FP_KB_NAME) == 0
    assert await case_kb.search_fp_cases("Backup Service Login") == []


@pytest.mark.asyncio
async def test_duplicate_fp_rule_candidates_are_deduplicated(
    services: tuple[MemoryGovernance, KnowledgeStore, CaseKBService, ProfileService, _Clock],
) -> None:
    governance, _, _, _, _ = services
    first = await governance.ingest_candidate(_fp_candidate(confidence=0.6))
    second = await governance.ingest_candidate(
        _fp_candidate(
            signature="  backup   service login ",
            confidence=0.9,
            source_event_id="evt-memory-review-2",
        )
    )

    assert await governance.dedupe(FP_KB_NAME) == 1

    pending = await governance.list_pending(FP_KB_NAME)
    assert [item.review_id for item in pending] == [second]
    assert first != second


@pytest.mark.asyncio
async def test_conflicting_fingerprint_keeps_highest_confidence_newest_candidate(
    services: tuple[MemoryGovernance, KnowledgeStore, CaseKBService, ProfileService, _Clock],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    governance, _, _, _, clock = services
    weaker = _fp_candidate(summary="Older interpretation", confidence=0.7)
    weaker_id = await governance.ingest_candidate(weaker)
    clock.value += timedelta(seconds=1)
    stronger = _fp_candidate(summary="Newer reviewed interpretation", confidence=0.95)
    stronger_id = await governance.ingest_candidate(stronger)

    await governance.resolve_conflict(FP_KB_NAME, governance.fingerprint(stronger))

    assert [item.review_id for item in await governance.list_pending(FP_KB_NAME)] == [stronger_id]
    demoted = await _review_row(session_factory, weaker_id)
    assert demoted.status == "demoted"
    assert demoted.payload["_review"]["demote_reason"] == f"conflict_winner:{stronger_id}"


@pytest.mark.asyncio
async def test_conflicting_fingerprint_uses_newest_candidate_as_tiebreaker(
    services: tuple[MemoryGovernance, KnowledgeStore, CaseKBService, ProfileService, _Clock],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    governance, _, _, _, clock = services
    older = _fp_candidate(summary="Older interpretation", confidence=0.9)
    older_id = await governance.ingest_candidate(older)
    clock.value += timedelta(seconds=1)
    newer = _fp_candidate(
        summary="Newer interpretation",
        confidence=0.9,
        source_event_id="evt-memory-review-newer",
    )
    newer_id = await governance.ingest_candidate(newer)

    await governance.resolve_conflict(FP_KB_NAME, governance.fingerprint(newer))

    assert [item.review_id for item in await governance.list_pending(FP_KB_NAME)] == [newer_id]
    assert (await _review_row(session_factory, older_id)).status == "demoted"


@pytest.mark.asyncio
async def test_promoted_fp_rule_is_retrievable_and_audited(
    services: tuple[MemoryGovernance, KnowledgeStore, CaseKBService, ProfileService, _Clock],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    governance, knowledge_store, case_kb, _, _ = services
    review_id = await governance.ingest_candidate(_fp_candidate())

    await governance.promote(review_id, "reviewer@example.com")
    await governance.promote(review_id, "reviewer@example.com")

    row = await _review_row(session_factory, review_id)
    hits = await case_kb.search_fp_cases("Backup Service Login")
    assert row.status == "promoted"
    assert row.operator == "reviewer@example.com"
    assert row.decided_at is not None
    assert await knowledge_store.count(FP_KB_NAME) == 1
    assert hits
    assert hits[0].metadata["alert_signature"] == "Backup Service Login"


@pytest.mark.asyncio
async def test_promote_rolls_back_target_write_when_review_transaction_fails(
    services: tuple[MemoryGovernance, KnowledgeStore, CaseKBService, ProfileService, _Clock],
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    governance, knowledge_store, _, _, _ = services
    review_id = await governance.ingest_candidate(_fp_candidate())
    original_promote_payload = governance._promote_payload

    async def fail_after_target_write(
        row: MemoryReviewORM,
        operator: str,
        session: AsyncSession,
    ) -> None:
        await original_promote_payload(row, operator, session)
        raise RuntimeError("simulated review transaction failure")

    monkeypatch.setattr(governance, "_promote_payload", fail_after_target_write)

    with pytest.raises(RuntimeError, match="simulated review transaction failure"):
        await governance.promote(review_id, "reviewer@example.com")

    row = await _review_row(session_factory, review_id)
    assert row.status == "pending"
    assert row.operator is None
    assert await knowledge_store.count(FP_KB_NAME) == 0


@pytest.mark.asyncio
async def test_demote_records_decision_without_writing_target_store(
    services: tuple[MemoryGovernance, KnowledgeStore, CaseKBService, ProfileService, _Clock],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    governance, knowledge_store, _, _, _ = services
    review_id = await governance.ingest_candidate(_fp_candidate())

    await governance.demote(review_id, "reviewer@example.com", "not broadly applicable")

    row = await _review_row(session_factory, review_id)
    assert row.status == "demoted"
    assert row.operator == "reviewer@example.com"
    assert row.decided_at is not None
    assert row.payload["_review"]["demote_reason"] == "not broadly applicable"
    assert await knowledge_store.count(FP_KB_NAME) == 0
    assert await governance.list_pending(FP_KB_NAME) == []


@pytest.mark.asyncio
async def test_history_and_profile_candidates_write_only_after_promotion(
    services: tuple[MemoryGovernance, KnowledgeStore, CaseKBService, ProfileService, _Clock],
) -> None:
    governance, knowledge_store, case_kb, profiles, clock = services
    profile = ProfileUpdate(
        entity_type="host",
        entity_value="PC-FIN-023",
        event_id="evt-history-1",
        risk_score=91,
        behavior_tags=["phase:execution"],
        pending_review=True,
    )
    history_id = await governance.ingest_candidate(_history_candidate(clock))
    profile_id = await governance.ingest_candidate(
        MemoryCandidate(
            kb_name=PROFILE_KB_NAME,
            candidate_type="profile",
            payload=profile.model_dump(mode="json"),
            confidence=0.91,
        )
    )

    assert await knowledge_store.count(HISTORY_KB_NAME) == 0
    assert await profiles.get("host", "PC-FIN-023") is None

    await governance.promote(history_id, "approver-1")
    await governance.promote(profile_id, "approver-1")

    history_hits = await case_kb.search_history_cases("Malicious PowerShell")
    stored_profile = await profiles.get("host", "pc-fin-023")
    assert len(history_hits) == 1
    assert history_hits[0].metadata["case_id"] == "case-acde1234"
    assert stored_profile is not None
    assert stored_profile.risk_history == [91]


@pytest.mark.asyncio
async def test_promoted_history_survives_retention(
    services: tuple[MemoryGovernance, KnowledgeStore, CaseKBService, ProfileService, _Clock],
) -> None:
    governance, knowledge_store, case_kb, _, clock = services
    review_id = await governance.ingest_candidate(_history_candidate(clock))
    await governance.promote(review_id, "history-reviewer")

    assert await governance.apply_retention(HISTORY_KB_NAME) == 0
    assert await knowledge_store.count(HISTORY_KB_NAME) == 1
    hits = await case_kb.search_history_cases("Malicious PowerShell")
    assert len(hits) == 1
    assert hits[0].metadata["case_id"] == "case-acde1234"


@pytest.mark.asyncio
async def test_memory_agent_candidate_requires_promotion_before_search(
    services: tuple[MemoryGovernance, KnowledgeStore, CaseKBService, ProfileService, _Clock],
) -> None:
    governance, _, case_kb, profiles, _ = services
    context = _false_positive_context()
    agent = MemoryAgent(
        case_kb_service=_IneligibleHistorySource(),  # type: ignore[arg-type]
        profile_service=profiles,
        memory_governance=governance,
        context_store=_AgentContextStore(context),
        working_memory=_AgentWorkingMemory(context),
    )

    output = await agent.execute(_memory_agent_input())

    assert len(output.fp_rules) == 1
    rule = output.fp_rules[0]
    assert rule.review_id is not None
    assert [item.review_id for item in await governance.list_pending(FP_KB_NAME)] == [
        rule.review_id
    ]
    assert await case_kb.search_fp_cases(rule.alert_signature) == []

    await governance.promote(rule.review_id, "integration-reviewer")

    hits = await case_kb.search_fp_cases(rule.alert_signature)
    assert hits
    assert hits[0].metadata["alert_signature"] == rule.alert_signature


@pytest.mark.asyncio
async def test_enqueue_failure_still_persists_pending_review_row(
    services: tuple[MemoryGovernance, KnowledgeStore, CaseKBService, ProfileService, _Clock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    governance, knowledge_store, _, profiles, _ = services
    context = _false_positive_context()
    attempts = 0

    async def fail_standard_enqueue(_candidate: MemoryCandidate) -> str:
        nonlocal attempts
        attempts += 1
        raise RuntimeError("simulated standard enqueue outage")

    monkeypatch.setattr(governance, "ingest_candidate", fail_standard_enqueue)
    agent = MemoryAgent(
        case_kb_service=_IneligibleHistorySource(),  # type: ignore[arg-type]
        profile_service=profiles,
        memory_governance=governance,
        context_store=_AgentContextStore(context),
        working_memory=_AgentWorkingMemory(context),
    )

    output = await agent.execute(_memory_agent_input())

    assert attempts == 3
    assert len(output.fp_rules) == 1
    review_id = output.fp_rules[0].review_id
    assert review_id is not None
    pending = await governance.list_pending(FP_KB_NAME)
    assert [item.review_id for item in pending] == [review_id]
    assert pending[0].payload["_review"]["enqueue_path"] == "fallback_after_retry"
    assert await knowledge_store.count(FP_KB_NAME) == 0


@pytest.mark.asyncio
async def test_expired_low_confidence_candidate_is_auto_demoted(
    services: tuple[MemoryGovernance, KnowledgeStore, CaseKBService, ProfileService, _Clock],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    governance, _, _, _, clock = services
    review_id = await governance.ingest_candidate(_fp_candidate(confidence=0.2))
    async with session_factory() as session:
        await session.execute(
            update(MemoryReviewORM)
            .where(MemoryReviewORM.review_id == review_id)
            .values(created_at=clock.value - timedelta(days=31))
        )
        await session.commit()

    assert await governance.apply_retention(FP_KB_NAME) == 1

    row = await _review_row(session_factory, review_id)
    assert row.status == "demoted"
    assert row.operator == "memory_governance"
    assert row.payload["_review"]["demote_reason"] == "pending_review_ttl_expired"


@pytest.mark.asyncio
async def test_profile_retention_keeps_only_latest_risk_history(
    services: tuple[MemoryGovernance, KnowledgeStore, CaseKBService, ProfileService, _Clock],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    governance, _, _, _, clock = services
    async with session_factory() as session:
        session.add(
            EntityProfileORM(
                profile_id="prf-retention",
                entity_type="host",
                entity_value="PC-FIN-023",
                event_count=12,
                last_event_id="evt-profile-0011",
                risk_history=list(range(12)),
                behavior_tags=[],
                updated_at=clock.value,
            )
        )
        await session.commit()

    assert await governance.apply_retention(PROFILE_KB_NAME) == 1

    async with session_factory() as session:
        row = await session.scalar(
            select(EntityProfileORM).where(EntityProfileORM.profile_id == "prf-retention")
        )
        assert row is not None
        assert row.risk_history == list(range(2, 12))
