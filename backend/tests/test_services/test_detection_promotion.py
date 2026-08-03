"""Detection promotion saga tests (ISSUE-124 / #629)."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.auth import Principal
from app.core.errors import ValidationError
from app.core.redis_client import RedisClient
from app.db import models as orm
from app.db.orm.detection_promotion import (
    DerivedDetectionConnectorORM,
    DetectionPromotionORM,
)
from app.db.orm.detection_governance import DetectionGovernanceDecisionORM
from app.evaluation.detection.artifact import finalize_detection_artifact
from app.evaluation.detection.fixture_loader import load_detection_fixture_index
from app.evaluation.detection.fixture_seeder import (
    build_candidate_refs,
    clear_detection_tables,
    seed_detection_replay_fixture,
)
from app.ingestion.source_ingester import SourceIngester
from app.models.detection_evaluation import (
    DetectionCandidateRefs,
    DetectionEvaluationArtifact,
    DetectionEvaluationConfig,
    DetectionResourceSummary,
    DetectionTenantSafetySummary,
)
from app.models.detection_governance import (
    DetectionGovernanceDecisionKind,
    DetectionGovernanceDecisionRequest,
)
from app.models.detection_promotion import (
    DetectionPromotionRequest,
    DetectionPromotionStatus,
    SourceIngestCorrelationOutcome,
    SourceIngestLinkDisposition,
)
from app.models.detection_rule import DetectionRuleRuntimeState, RuleOperatorKind
from app.models.enums import EventType, Severity, SourceObjectKind
from app.models.evaluation_quality import (
    EvaluationQualityReport,
    MetricDenominator,
    QualityMetricStatus,
    QualityMetricValue,
)
from app.models.evaluation_run import (
    EvaluationAggregateMetrics,
    EvaluationGateResult,
    EvaluationReleaseRefs,
    EvaluationRunStatus,
    GateVerdict,
)
from app.models.source import SourceReference
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService
from app.services.derived_detection_connector_service import (
    build_derived_detection_connector_id,
)
from app.services.detection_governance_service import DetectionGovernanceService
from app.services.detection_promotion_service import (
    DetectionPromotionService,
    build_promotion_key,
)
from app.services.detection_rule_runtime import DetectionRuleRuntimeService
from app.services.detection_rule_service import DetectionRuleService
from app.services.event_service import EventService, IngestableSource, ingest_result_to_typed

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_DIR.parent
DATASET_DIR = REPO_ROOT / "data" / "evaluation" / "detection_shadow_v1"
THRESHOLD_PATH = DATASET_DIR / "threshold_manifest.json"
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


requires_postgres = pytest.mark.skipif(
    not _postgres_reachable(),
    reason="PostgreSQL not reachable",
)


def _alembic_config() -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return config


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


@pytest_asyncio.fixture(autouse=True)
async def clean_promotion_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(DetectionPromotionORM))
            await session.execute(delete(DerivedDetectionConnectorORM))
            await session.execute(delete(DetectionGovernanceDecisionORM))
            await session.execute(delete(orm.SourceEventLink))
            await session.execute(delete(orm.SourceObject))
            await session.execute(delete(orm.SecurityEvent))
    await clear_detection_tables(session_factory)
    yield
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(DetectionPromotionORM))
            await session.execute(delete(DerivedDetectionConnectorORM))
            await session.execute(delete(DetectionGovernanceDecisionORM))
            await session.execute(delete(orm.SourceEventLink))
            await session.execute(delete(orm.SourceObject))
            await session.execute(delete(orm.SecurityEvent))
    await clear_detection_tables(session_factory)


def test_build_derived_detection_connector_id_is_stable() -> None:
    first = build_derived_detection_connector_id(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-abc",
    )
    second = build_derived_detection_connector_id(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-abc",
    )
    assert first == second
    assert first.startswith("ddet-")


def test_build_promotion_key_includes_candidate_and_decision() -> None:
    key = build_promotion_key(
        candidate_detection_id="cand-1",
        candidate_content_hash="a" * 64,
        decision_id="dgov-123",
    )
    assert "cand-1" in key
    assert "dgov-123" in key


def test_ingest_result_to_typed_maps_provisional_fields() -> None:
    from app.services.event_service import IngestResult

    typed = ingest_result_to_typed(
        IngestResult(
            source_record_id="src-abc",
            event_id="evt-abc",
            created=True,
            source_object_id="pdet-123",
            source_revision=1,
            correlation_outcome=SourceIngestCorrelationOutcome.CREATED,
            event_revision=2,
            link_disposition=SourceIngestLinkDisposition.PROVISIONAL,
        )
    )
    assert typed.correlation_outcome is SourceIngestCorrelationOutcome.CREATED
    assert typed.link_disposition is SourceIngestLinkDisposition.PROVISIONAL
    assert typed.source_object_id == "pdet-123"


@pytest_asyncio.fixture
async def promotion_service(
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
    )


@pytest_asyncio.fixture
async def event_service_for_promotion(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: RedisClient,
) -> EventService:
    store = EventContextStore(redis_client, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    return EventService(session_factory, store, degraded_flags=degraded)


@pytest.mark.asyncio
@requires_postgres
async def test_typed_ingest_result_populated_on_alert_create(
    event_service_for_promotion: EventService,
) -> None:
    events = event_service_for_promotion
    ref = SourceReference(
        source_kind=SourceObjectKind.ALERT,
        source_product="mock_xdr",
        source_tenant_id="tenant-promotion",
        connector_id="mock-tenant-promotion",
        source_object_id="alert-promotion-001",
        source_updated_at=datetime.now(UTC),
    )
    result = await events.ingest_source_object(
        IngestableSource(
            reference=ref,
            normalized={"title": "promotion typed ingest", "severity": "high"},
            title="promotion typed ingest",
            severity=Severity.HIGH,
            event_type=EventType.MALICIOUS_PROCESS,
            source_type="mock_xdr",
        )
    )
    typed = ingest_result_to_typed(result)
    assert typed.created is True
    assert typed.event_id is not None
    assert typed.correlation_outcome is SourceIngestCorrelationOutcome.CREATED
    assert typed.link_disposition is SourceIngestLinkDisposition.PROVISIONAL
    assert typed.source_object_id == "alert-promotion-001"
    assert typed.source_revision is not None


def _quality_report(*, dataset_hash: str) -> EvaluationQualityReport:
    return EvaluationQualityReport(
        dataset_id="detection_shadow_v1",
        dataset_version="2026.08.02",
        dataset_content_hash=dataset_hash,
        code_sha="abc1234",
        release_refs=EvaluationReleaseRefs(),
        sample_counts={"threat": 1, "benign": 1, "unevaluable": 0, "total": 2},
        metrics=[
            QualityMetricValue(
                metric_id="threat_recall",
                value=1.0,
                status=QualityMetricStatus.COMPUTED,
                denominator=MetricDenominator(numerator=1, denominator=1),
            ),
            QualityMetricValue(
                metric_id="benign_specificity",
                value=1.0,
                status=QualityMetricStatus.COMPUTED,
                denominator=MetricDenominator(numerator=1, denominator=1),
            ),
        ],
    )


def _artifact_for_seeded(
    *,
    seeded,
    candidate_refs: DetectionCandidateRefs,
    candidate_set_hash: str,
) -> DetectionEvaluationArtifact:
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    artifact = DetectionEvaluationArtifact(
        evaluation_id="deval-promotion-001",
        tenant_id=seeded.source_tenant_id,
        dataset_id="detection_shadow_v1",
        dataset_version="2026.08.02",
        dataset_content_hash="b" * 64,
        code_sha="abc1234",
        config=DetectionEvaluationConfig(
            seed=42,
            cutoff_at=cutoff,
            candidate_refs=candidate_refs,
            candidate_refs_entries=[candidate_refs],
            candidate_set_hash=candidate_set_hash,
            scorer_ids=["threat_detection"],
        ),
        started_at=datetime(2026, 8, 1, 15, 0, 0, tzinfo=UTC),
        completed_at=datetime(2026, 8, 1, 15, 5, 0, tzinfo=UTC),
        status=EvaluationRunStatus.COMPLETED,
        aggregates=EvaluationAggregateMetrics(
            case_count=1,
            pass_count=1,
            fail_count=0,
            error_count=0,
            unevaluable_count=0,
            pass_rate=1.0,
            required_scorer_error_count=0,
        ),
        gate=EvaluationGateResult(
            verdict=GateVerdict.PASS,
            manifest_version="2026.08.02",
            manifest_path=str(THRESHOLD_PATH),
            diffs=[],
        ),
        quality_report=_quality_report(dataset_hash="b" * 64),
        tenant_safety=DetectionTenantSafetySummary(probe_count=1, pass_count=1),
        resource_summary=DetectionResourceSummary(),
        case_results=[],
    )
    return finalize_detection_artifact(artifact)


@pytest.mark.asyncio
@requires_postgres
async def test_promotion_happy_path_creates_event_and_completes_ledger(
    session_factory: async_sessionmaker[AsyncSession],
    promotion_service: DetectionPromotionService,
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
    assert result.candidates, "expected shadow runtime to emit at least one candidate"
    candidate = result.candidates[0]

    candidate_refs = build_candidate_refs(replay, seeded)
    artifact = _artifact_for_seeded(
        seeded=seeded,
        candidate_refs=candidate_refs,
        candidate_set_hash="c" * 64,
    )

    principal = Principal(subject="reviewer@test", roles=["admin"], tenant_id=seeded.source_tenant_id)
    governance = DetectionGovernanceService(session_factory)
    decision = await governance.record_decision(
        principal,
        artifact,
        DetectionGovernanceDecisionRequest(
            decision=DetectionGovernanceDecisionKind.APPROVE,
            reason_note="approved for promotion test",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        ),
        threshold_manifest_path=THRESHOLD_PATH,
    )

    promotion = promotion_service
    first = await promotion.promote_candidate(
        artifact,
        DetectionPromotionRequest(
            tenant_id=seeded.source_tenant_id,
            candidate_detection_id=candidate.candidate_detection_id,
            decision_id=decision.decision_id,
        ),
    )
    assert first.status is DetectionPromotionStatus.COMPLETED
    assert first.ingest_result is not None
    assert first.ingest_result.event_id is not None
    assert first.ingest_result.correlation_outcome is SourceIngestCorrelationOutcome.CREATED
    assert first.ingest_result.link_disposition is SourceIngestLinkDisposition.PROVISIONAL
    assert first.record.source_record_id is not None
    assert first.record.derived_connector_id is not None

    package = await DetectionRuleService(session_factory).get_package(
        source_tenant_id=seeded.source_tenant_id,
        package_id=seeded.package_id,
    )
    assert package is not None
    assert package.runtime_state is DetectionRuleRuntimeState.PRODUCTION_ACTIVE

    second = await promotion.promote_candidate(
        artifact,
        DetectionPromotionRequest(
            tenant_id=seeded.source_tenant_id,
            candidate_detection_id=candidate.candidate_detection_id,
            decision_id=decision.decision_id,
        ),
    )
    assert second.resumed is True
    assert second.status is DetectionPromotionStatus.COMPLETED
    assert second.record.promotion_id == first.record.promotion_id
    assert second.ingest_result is not None
    assert second.ingest_result.event_id == first.ingest_result.event_id


@pytest.mark.asyncio
@requires_postgres
async def test_promotion_fail_closed_without_approval(
    session_factory: async_sessionmaker[AsyncSession],
    promotion_service: DetectionPromotionService,
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
    promotion = promotion_service
    with pytest.raises(ValidationError, match="governance gate closed"):
        await promotion.promote_candidate(
            artifact,
            DetectionPromotionRequest(
                tenant_id=seeded.source_tenant_id,
                candidate_detection_id=candidate.candidate_detection_id,
            ),
        )


@pytest.mark.asyncio
@requires_postgres
async def test_promotion_crash_recovery_from_source_persisted(
    session_factory: async_sessionmaker[AsyncSession],
    promotion_service: DetectionPromotionService,
    event_service_for_promotion: EventService,
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
    principal = Principal(subject="reviewer@test", roles=["admin"], tenant_id=seeded.source_tenant_id)
    governance = DetectionGovernanceService(session_factory)
    decision = await governance.record_decision(
        principal,
        artifact,
        DetectionGovernanceDecisionRequest(
            decision=DetectionGovernanceDecisionKind.APPROVE,
            reason_note="approved for crash recovery test",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        ),
        threshold_manifest_path=THRESHOLD_PATH,
    )

    promotion = promotion_service
    promotion_key = build_promotion_key(
        candidate_detection_id=candidate.candidate_detection_id,
        candidate_content_hash=candidate.content_hash,
        decision_id=decision.decision_id,
    )
    promotion_id = await promotion._allocate_promotion_id()
    typed = ingest_result_to_typed(
        await event_service_for_promotion.ingest_source_object(
            IngestableSource(
                reference=SourceReference(
                    source_kind=SourceObjectKind.ALERT,
                    source_product="mock_xdr",
                    source_tenant_id=seeded.source_tenant_id,
                    connector_id=build_derived_detection_connector_id(
                        source_tenant_id=seeded.source_tenant_id,
                        detection_scope_id=seeded.detection_scope_id,
                    ),
                    source_object_id="pdet-crash-recovery",
                    source_updated_at=cutoff,
                ),
                normalized={"title": "crash recovery", "severity": "high"},
                title="crash recovery",
                severity=Severity.HIGH,
                event_type=EventType.MALICIOUS_PROCESS,
                source_type="derived_detection",
            )
        )
    )
    async with session_factory() as session:
        async with session.begin():
            session.add(
                DetectionPromotionORM(
                    promotion_id=promotion_id,
                    tenant_id=seeded.source_tenant_id,
                    promotion_key=promotion_key,
                    status=DetectionPromotionStatus.SOURCE_PERSISTED.value,
                    decision_id=decision.decision_id,
                    candidate_detection_id=candidate.candidate_detection_id,
                    candidate_content_hash=candidate.content_hash,
                    package_id=seeded.package_id,
                    package_version=1,
                    package_content_hash=seeded.package_content_hash,
                    detection_scope_id=seeded.detection_scope_id,
                    scope_revision_id=seeded.scope_revision_id,
                    source_record_id=typed.source_record_id,
                    ingest_result=typed.model_dump(mode="json"),
                )
            )

    resumed = await promotion.promote_candidate(
        artifact,
        DetectionPromotionRequest(
            tenant_id=seeded.source_tenant_id,
            candidate_detection_id=candidate.candidate_detection_id,
            decision_id=decision.decision_id,
        ),
    )
    assert resumed.status is DetectionPromotionStatus.COMPLETED
    assert resumed.ingest_result is not None
    assert resumed.ingest_result.event_id == typed.event_id

    async with session_factory() as session:
        rows = list(
            await session.scalars(
                select(DetectionPromotionORM).where(
                    DetectionPromotionORM.promotion_key == promotion_key
                )
            )
        )
    assert len(rows) == 1
