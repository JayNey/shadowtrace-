"""Detection context snapshot projector tests (ISSUE-127 / #633)."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ValidationError
from app.core.redis_client import RedisClient
from app.evaluation.detection.fixture_loader import load_detection_fixture_index
from app.evaluation.detection.fixture_seeder import build_candidate_refs, seed_detection_replay_fixture
from app.ingestion.source_ingester import SourceIngester
from app.models.detection_context_snapshot import DetectionContextSnapshotQuery
from app.models.detection_governance import (
    DetectionGovernanceDecisionKind,
    DetectionGovernanceDecisionRequest,
)
from app.models.detection_promotion import DetectionPromotionRequest, DetectionPromotionStatus
from app.models.detection_rule import DetectionRuleDefinition, MissingDataPolicy, RuleOperatorKind
from app.models.feature_snapshot import FeatureWindowKind
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService
from app.services.detection_context_projector import DetectionContextProjector
from app.services.detection_context_resolver import (
    compute_snapshot_content_hash,
    extract_attack_refs_from_rule,
)
from app.services.detection_context_service import DetectionContextService
from app.services.detection_governance_service import DetectionGovernanceService
from app.services.detection_promotion_service import DetectionPromotionService
from app.services.detection_rule_runtime import DetectionRuleRuntimeService
from app.services.event_service import EventService
from app.evaluation.detection.fixture_seeder import clear_detection_tables
from app.db.orm.detection_context_snapshot import DetectionContextSnapshotORM
from app.db.orm.detection_governance import DetectionGovernanceDecisionORM
from app.db.orm.detection_promotion import DerivedDetectionConnectorORM, DetectionPromotionORM
from sqlalchemy import delete
from app.db import models as orm
from tests.test_services.test_detection_promotion import (
    DATASET_DIR,
    THRESHOLD_PATH,
    _artifact_for_seeded,
    _reviewer_principal,
    migrated_database,
    requires_postgres,
    session_factory,
)

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

pytestmark = requires_postgres


@pytest_asyncio.fixture
async def redis_client() -> AsyncIterator[RedisClient]:
    client = RedisClient(url=REDIS_URL)
    if not await client.ping():
        await client.aclose()
        pytest.skip("Redis not reachable; start Compose redis first")
    yield client
    await client.aclose()


def test_compute_snapshot_content_hash_is_deterministic() -> None:
    payload = {
        "tenant_id": "tenant-a",
        "event_id": "evt-1",
        "revision": 1,
        "scores": {"matched_value": 1.0, "severity": "high", "operator": "event_match"},
    }
    first = compute_snapshot_content_hash(payload)
    second = compute_snapshot_content_hash(dict(payload))
    assert first == second
    assert len(first) == 64


@pytest_asyncio.fixture(autouse=True)
async def clean_detection_context_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(DetectionContextSnapshotORM))
            await session.execute(delete(DetectionPromotionORM))
            await session.execute(delete(DerivedDetectionConnectorORM))
            await session.execute(delete(DetectionGovernanceDecisionORM))
            await session.execute(delete(orm.DispositionReceipt))
            await session.execute(delete(orm.DispositionOutbox))
            await session.execute(delete(orm.ActionExecutionJob))
            await session.execute(delete(orm.ToolCallLog))
            await session.execute(delete(orm.LLMCallLog))
            await session.execute(delete(orm.EventAuditLog))
            await session.execute(delete(orm.DecisionRecord))
            await session.execute(delete(orm.AgentTrace))
            await session.execute(delete(orm.Action))
            await session.execute(delete(orm.Report))
            await session.execute(delete(orm.Evidence))
            await session.execute(delete(orm.SourceEventLink))
            await session.execute(delete(orm.SourceObject))
            await session.execute(delete(orm.SecurityEvent))
    await clear_detection_tables(session_factory)
    yield


def test_extract_attack_refs_from_rule_deduplicates() -> None:
    rule = DetectionRuleDefinition(
        rule_id="rule-1",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_MATCH,
        feature_contract_version="fc-v1",
        detection_scope_id="dscope-1",
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=1.0,
        severity="high",
        missing_data_policy=MissingDataPolicy.SKIP,
        match_criteria={
            "attack_technique_ids": ["T1059", "T1059.001"],
            "mitre_technique_ids": [
                {
                    "technique_id": "T1059",
                    "technique_name": "Command and Scripting Interpreter",
                }
            ],
        },
    )
    refs = extract_attack_refs_from_rule(rule)
    assert len(refs) == 2
    assert {ref.technique_id for ref in refs} == {"T1059", "T1059.001"}


@pytest_asyncio.fixture
async def promotion_service_with_projector(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: RedisClient,
) -> DetectionPromotionService:
    store = EventContextStore(redis_client, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    events = EventService(session_factory, store, degraded_flags=degraded)
    ingester = SourceIngester(events, session_factory, source_mode="mock_xdr")
    return DetectionPromotionService(
        session_factory,
        event_service=events,
        source_ingester=ingester,
        context_projector=DetectionContextProjector(session_factory),
    )


@pytest.mark.asyncio
async def test_projector_happy_path_after_promotion(
    session_factory: async_sessionmaker[AsyncSession],
    promotion_service_with_projector: DetectionPromotionService,
) -> None:
    fixture_index = load_detection_fixture_index(DATASET_DIR)
    replay = fixture_index.by_case_id["threat_event_match"]
    seeded = await seed_detection_replay_fixture(session_factory, replay)

    runtime = DetectionRuleRuntimeService(session_factory)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    result = await runtime.execute_shadow(
        source_tenant_id=seeded.source_tenant_id,
        package_id=seeded.package_id,
        cutoff_at=cutoff,
    )
    candidate = result.candidates[0]
    candidate_refs = build_candidate_refs(replay, seeded)
    artifact = _artifact_for_seeded(
        seeded=seeded,
        candidate_refs=candidate_refs,
        candidate_set_hash="c" * 64,
    )
    governance = DetectionGovernanceService(session_factory)
    decision = await governance.record_decision(
        _reviewer_principal(seeded.source_tenant_id),
        artifact,
        DetectionGovernanceDecisionRequest(
            decision=DetectionGovernanceDecisionKind.APPROVE,
            reason_note="approved for context projection test",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        ),
        threshold_manifest_path=THRESHOLD_PATH,
    )

    promotion = await promotion_service_with_projector.promote_candidate(
        artifact,
        DetectionPromotionRequest(
            tenant_id=seeded.source_tenant_id,
            candidate_detection_id=candidate.candidate_detection_id,
            decision_id=decision.decision_id,
        ),
    )
    assert promotion.status is DetectionPromotionStatus.COMPLETED
    assert promotion.ingest_result is not None
    event_id = promotion.ingest_result.event_id
    assert event_id is not None

    projector = DetectionContextProjector(session_factory)
    projected = await projector.project_from_promotion(
        promotion.record.promotion_id,
        tenant_id=seeded.source_tenant_id,
    )
    assert projected is not None

    service = DetectionContextService(session_factory)
    snapshots = await service.query_snapshots(
        DetectionContextSnapshotQuery(
            tenant_id=seeded.source_tenant_id,
            event_id=event_id,
            latest_only=True,
        )
    )
    assert snapshots.total == 1
    snapshot = snapshots.items[0]
    assert snapshot.promotion_id == promotion.promotion_id
    assert snapshot.content_hash
    assert snapshot.revision == 1

    replay = await promotion_service_with_projector.promote_candidate(
        artifact,
        DetectionPromotionRequest(
            tenant_id=seeded.source_tenant_id,
            candidate_detection_id=candidate.candidate_detection_id,
            decision_id=decision.decision_id,
        ),
    )
    assert replay.resumed is True
    snapshots_again = await service.query_snapshots(
        DetectionContextSnapshotQuery(
            tenant_id=seeded.source_tenant_id,
            event_id=event_id,
            latest_only=True,
        )
    )
    assert snapshots_again.total == 1
    assert snapshots_again.items[0].snapshot_id == snapshot.snapshot_id
    assert snapshots_again.items[0].content_hash == snapshot.content_hash


@pytest.mark.asyncio
async def test_projector_fail_closed_for_wrong_tenant(
    session_factory: async_sessionmaker[AsyncSession],
    promotion_service_with_projector: DetectionPromotionService,
) -> None:
    fixture_index = load_detection_fixture_index(DATASET_DIR)
    replay = fixture_index.by_case_id["threat_event_match"]
    seeded = await seed_detection_replay_fixture(session_factory, replay)
    runtime = DetectionRuleRuntimeService(session_factory)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    result = await runtime.execute_shadow(
        source_tenant_id=seeded.source_tenant_id,
        package_id=seeded.package_id,
        cutoff_at=cutoff,
    )
    candidate = result.candidates[0]
    candidate_refs = build_candidate_refs(replay, seeded)
    artifact = _artifact_for_seeded(
        seeded=seeded,
        candidate_refs=candidate_refs,
        candidate_set_hash="d" * 64,
    )
    governance = DetectionGovernanceService(session_factory)
    decision = await governance.record_decision(
        _reviewer_principal(seeded.source_tenant_id),
        artifact,
        DetectionGovernanceDecisionRequest(
            decision=DetectionGovernanceDecisionKind.APPROVE,
            reason_note="approved",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        ),
        threshold_manifest_path=THRESHOLD_PATH,
    )
    promotion = await promotion_service_with_projector.promote_candidate(
        artifact,
        DetectionPromotionRequest(
            tenant_id=seeded.source_tenant_id,
            candidate_detection_id=candidate.candidate_detection_id,
            decision_id=decision.decision_id,
        ),
    )
    projector = DetectionContextProjector(session_factory)
    with pytest.raises(ValidationError):
        await projector.project_from_promotion(
            promotion.promotion_id,
            tenant_id="other-tenant",
        )
