"""Post-promotion detection comparison tests (ISSUE-126 / #631 Phase B)."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.auth import Principal
from app.core.redis_client import RedisClient
from app.db import models as orm
from app.db.orm.approval import ApprovalRecordORM
from app.db.orm.detection_context_snapshot import DetectionContextSnapshotORM
from app.db.orm.detection_governance import DetectionGovernanceDecisionORM
from app.db.orm.detection_promotion import DerivedDetectionConnectorORM, DetectionPromotionORM
from app.evaluation.detection.artifact import finalize_detection_artifact
from app.evaluation.detection.fixture_loader import load_detection_fixture_index
from app.evaluation.detection.fixture_seeder import (
    build_candidate_refs,
    clear_detection_tables,
    seed_detection_replay_fixture,
)
from app.evaluation.detection.production_artifact import finalize_production_comparison_artifact
from app.evaluation.detection.production_comparison_diff import (
    diff_production_comparison_against_baseline,
)
from app.evaluation.detection.production_diff import (
    compare_production_case,
    derive_production_recommendation,
    summarize_coverage_drift,
)
from app.evaluation.detection.production_fixture_loader import load_production_binding_manifest
from app.evaluation.detection.production_runner import run_production_comparison
from app.ingestion.source_ingester import SourceIngester
from app.models.detection_context_snapshot import (
    DetectionContextCoverageSummary,
    DetectionContextEvaluationRefs,
    DetectionContextGovernanceRefs,
    DetectionContextReleaseRefs,
    DetectionContextScoreSummary,
    DetectionContextSnapshot,
)
from app.models.detection_evaluation import (
    DetectionCandidateRefs,
    DetectionCaseObservation,
    DetectionCaseResult,
    DetectionEvaluationArtifact,
    DetectionEvaluationConfig,
    DetectionResourceSummary,
    DetectionTenantSafetySummary,
)
from app.models.detection_governance import (
    DetectionGovernanceDecisionKind,
    DetectionGovernanceDecisionRequest,
)
from app.models.detection_production_comparison import (
    DetectionProductionCaseBinding,
    DetectionProductionComparisonArtifact,
    DetectionProductionComparisonConfig,
    DetectionProductionCoverageDrift,
    DetectionProductionOutcomeStatus,
    DetectionProductionRecommendationKind,
)
from app.models.detection_promotion import (
    DetectionPromotionRecord,
    DetectionPromotionRequest,
    DetectionPromotionStatus,
)
from app.models.detection_rule import (
    CandidateDetection,
    CandidateDetectionProvenance,
    RuleOperatorKind,
)
from app.models.evaluation_quality import (
    EvaluationQualityReport,
    EvaluationReleaseRefs,
    MetricDenominator,
    QualityMetricStatus,
    QualityMetricValue,
)
from app.models.evaluation_run import (
    EvaluationAggregateMetrics,
    EvaluationGateResult,
    EvaluationRunStatus,
    GateVerdict,
)
from app.models.evaluation_truth import SliceType
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService
from app.services.detection_context_projector import DetectionContextProjector
from app.services.detection_governance_service import DetectionGovernanceService
from app.services.detection_promotion_service import DetectionPromotionService
from app.services.detection_rule_runtime import DetectionRuleRuntimeService
from app.services.event_service import EventService

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_DIR.parent
PRODUCTION_DATASET_DIR = REPO_ROOT / "data" / "evaluation" / "detection_production_v1"
SHADOW_DATASET_DIR = REPO_ROOT / "data" / "evaluation" / "detection_shadow_v1"
THRESHOLD_PATH = SHADOW_DATASET_DIR / "threshold_manifest.json"
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


def _alembic_config() -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return config


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


requires_postgres = pytest.mark.skipif(not _postgres_reachable(), reason="postgres unavailable")


@pytest_asyncio.fixture
async def clean_detection_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async def _clear_promotion_graph(session: AsyncSession) -> None:
        await session.execute(delete(DetectionContextSnapshotORM))
        await session.execute(delete(orm.DispositionReceipt))
        await session.execute(delete(orm.DispositionOutbox))
        await session.execute(delete(orm.ActionExecutionJob))
        await session.execute(delete(orm.ToolCallLog))
        await session.execute(delete(orm.LLMCallLog))
        await session.execute(delete(orm.EventAuditLog))
        await session.execute(delete(orm.DecisionRecord))
        await session.execute(delete(orm.AgentTrace))
        await session.execute(delete(ApprovalRecordORM))
        await session.execute(delete(orm.Action))
        await session.execute(delete(orm.Report))
        await session.execute(delete(orm.Evidence))
        await session.execute(delete(DetectionPromotionORM))
        await session.execute(delete(DerivedDetectionConnectorORM))
        await session.execute(delete(DetectionGovernanceDecisionORM))
        await session.execute(delete(orm.SourceEventLink))
        await session.execute(delete(orm.SourceObject))
        await session.execute(delete(orm.SecurityEvent))

    async with session_factory() as session:
        async with session.begin():
            await _clear_promotion_graph(session)
    await clear_detection_tables(session_factory)
    yield
    async with session_factory() as session:
        async with session.begin():
            await _clear_promotion_graph(session)
    await clear_detection_tables(session_factory)


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
async def redis_client() -> AsyncIterator[RedisClient]:
    """ISSUE-337: promotion comparison must fail-closed without Redis (not skip)."""
    client = RedisClient(url=REDIS_URL)
    if not await client.ping():
        await client.aclose()
        pytest.fail(
            "Redis is required for evaluation promotion comparison (ISSUE-337); "
            "backend-evaluation must provide REDIS_URL"
        )
    yield client
    await client.aclose()


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
        context_projector=DetectionContextProjector(session_factory),
    )


def _reviewer_principal(tenant_id: str) -> Principal:
    return Principal(subject="reviewer@test", roles=["admin"], tenant_id=tenant_id)


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


def _artifact_for_seeded_with_case(
    *,
    seeded,
    candidate_refs: DetectionCandidateRefs,
    candidate_set_hash: str,
    candidate: object,
) -> DetectionEvaluationArtifact:
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    artifact = DetectionEvaluationArtifact(
        evaluation_id="deval-phase-b-001",
        tenant_id=seeded.source_tenant_id,
        dataset_id="detection_shadow_v1",
        dataset_version="2026.08.02",
        dataset_content_hash="4786dcbb13e5b510df2960b80ac488d1dc1b7eee40f260e8c0e93f093990ae48",
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
            unevaluable_count=0,
            error_count=0,
            pass_rate=1.0,
            required_scorer_error_count=0,
        ),
        gate=EvaluationGateResult(
            verdict=GateVerdict.PASS,
            manifest_version="2026.08.02",
            manifest_path=str(THRESHOLD_PATH),
            diffs=[],
        ),
        quality_report=_quality_report(
            dataset_hash="4786dcbb13e5b510df2960b80ac488d1dc1b7eee40f260e8c0e93f093990ae48",
        ),
        tenant_safety=DetectionTenantSafetySummary(probe_count=1, pass_count=1),
        resource_summary=DetectionResourceSummary(),
        case_results=[
            DetectionCaseResult(
                case_id="threat_event_match",
                truth_id="truth-threat-event-match",
                truth_revision=1,
                truth_content_hash="e" * 64,
                slice_type=SliceType.THREAT,
                observation=DetectionCaseObservation(
                    case_id="threat_event_match",
                    slice_type=SliceType.THREAT,
                    candidates=[candidate],
                ),
                scorer_results=[],
                case_status=EvaluationRunStatus.COMPLETED,
                candidate_refs=candidate_refs,
            )
        ],
    )
    return finalize_detection_artifact(artifact)


def test_binding_manifest_loads_and_hashes() -> None:
    manifest = load_production_binding_manifest(PRODUCTION_DATASET_DIR)
    assert manifest.shadow_dataset_id == "detection_shadow_v1"
    assert len(manifest.bindings) == 1
    assert manifest.bindings[0].case_id == "threat_event_match"
    assert len(manifest.content_hash) == 64


def test_derive_recommendation_continue_when_not_applicable() -> None:
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    phase_a = DetectionEvaluationArtifact(
        evaluation_id="e1",
        tenant_id="tenant-a",
        dataset_id="d",
        dataset_version="v",
        dataset_content_hash="b" * 64,
        code_sha="abc1234",
        config=DetectionEvaluationConfig(
            seed=1,
            cutoff_at=cutoff,
            candidate_refs=DetectionCandidateRefs(
                package_id="p",
                package_version=1,
                package_content_hash="c" * 64,
                rule_ids=[],
                feature_contract_version="1.0",
                detection_scope_id="s",
            ),
        ),
        started_at=cutoff,
        completed_at=cutoff,
        status=EvaluationRunStatus.COMPLETED,
        aggregates=EvaluationAggregateMetrics(
            case_count=1,
            pass_count=1,
            fail_count=0,
            unevaluable_count=0,
            error_count=0,
            pass_rate=1.0,
            required_scorer_error_count=0,
        ),
    )
    comparisons = [
        compare_production_case(
            DetectionCaseResult(
                case_id="c1",
                truth_id="t1",
                truth_revision=1,
                truth_content_hash="a" * 64,
                slice_type=SliceType.BENIGN,
                observation=DetectionCaseObservation(case_id="c1", slice_type=SliceType.BENIGN),
                scorer_results=[],
                case_status=EvaluationRunStatus.COMPLETED,
            ),
            DetectionProductionCaseBinding(case_id="c1", expect_promotion=False),
            promotion=None,
            snapshot=None,
            phase_a_artifact=phase_a,
        )
    ]
    kind, _reasons = derive_production_recommendation(
        comparisons,
        DetectionProductionCoverageDrift(),
    )
    assert kind is DetectionProductionRecommendationKind.CONTINUE


@pytest.mark.evaluation
@pytest.mark.asyncio
@requires_postgres
async def test_production_comparison_happy_path_after_promotion(
    session_factory: async_sessionmaker[AsyncSession],
    promotion_service: DetectionPromotionService,
    clean_detection_tables: None,
) -> None:
    fixture_index = load_detection_fixture_index(SHADOW_DATASET_DIR)
    replay = fixture_index.by_case_id["threat_event_match"]
    seeded = await seed_detection_replay_fixture(session_factory, replay)
    runtime = DetectionRuleRuntimeService(session_factory)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    result = await runtime.execute_shadow(
        source_tenant_id=seeded.source_tenant_id,
        package_id=seeded.package_id,
        cutoff_at=cutoff,
    )
    assert result.candidates
    candidate = result.candidates[0]
    candidate_refs = build_candidate_refs(replay, seeded)
    phase_a = _artifact_for_seeded_with_case(
        seeded=seeded,
        candidate_refs=candidate_refs,
        candidate_set_hash="c" * 64,
        candidate=candidate,
    )
    phase_a_dump_before = phase_a.model_dump()

    governance = DetectionGovernanceService(session_factory)
    decision = await governance.record_decision(
        _reviewer_principal(seeded.source_tenant_id),
        phase_a,
        DetectionGovernanceDecisionRequest(
            decision=DetectionGovernanceDecisionKind.APPROVE,
            reason_note="phase b test approval",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        ),
        threshold_manifest_path=THRESHOLD_PATH,
    )
    promoted = await promotion_service.promote_candidate(
        phase_a,
        DetectionPromotionRequest(
            tenant_id=seeded.source_tenant_id,
            candidate_detection_id=candidate.candidate_detection_id,
            decision_id=decision.decision_id,
        ),
    )
    assert promoted.status is DetectionPromotionStatus.COMPLETED

    binding_manifest = load_production_binding_manifest(PRODUCTION_DATASET_DIR)
    comparison = await run_production_comparison(
        session_factory,
        phase_a_artifact=phase_a,
        binding_manifest=binding_manifest,
        code_sha="abc1234",
        seed=42,
    )

    assert comparison.phase_a_refs.artifact_hash == phase_a.artifact_hash
    assert comparison.recommendation is DetectionProductionRecommendationKind.CONTINUE
    assert comparison.artifact_hash
    threat_case = next(
        item for item in comparison.case_comparisons if item.case_id == "threat_event_match"
    )
    assert threat_case.outcome_status is DetectionProductionOutcomeStatus.ALIGNED
    assert threat_case.promotion_id == promoted.record.promotion_id
    assert threat_case.event_id is not None
    assert comparison.status is EvaluationRunStatus.COMPLETED
    assert phase_a.model_dump() == phase_a_dump_before


@pytest.mark.evaluation
@pytest.mark.asyncio
@requires_postgres
async def test_production_comparison_missing_promotion_is_insufficient_data(
    session_factory: async_sessionmaker[AsyncSession],
    clean_detection_tables: None,
) -> None:
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    candidate_refs = DetectionCandidateRefs(
        package_id="drpkg-det-threat-v1",
        package_version=1,
        package_content_hash="c" * 64,
        rule_ids=["rule-event-match"],
        feature_contract_version="1.0",
        detection_scope_id="scope-placeholder",
    )
    phase_a = finalize_detection_artifact(
        DetectionEvaluationArtifact(
            evaluation_id="deval-phase-b-missing",
            tenant_id="tenant-det-threat",
            dataset_id="detection_shadow_v1",
            dataset_version="2026.08.02",
            dataset_content_hash="4786dcbb13e5b510df2960b80ac488d1dc1b7eee40f260e8c0e93f093990ae48",
            code_sha="abc1234",
            config=DetectionEvaluationConfig(
                seed=42,
                cutoff_at=cutoff,
                candidate_refs=candidate_refs,
            ),
            started_at=cutoff,
            completed_at=cutoff,
            status=EvaluationRunStatus.COMPLETED,
            aggregates=EvaluationAggregateMetrics(
                case_count=1,
                pass_count=1,
                fail_count=0,
                unevaluable_count=0,
                error_count=0,
                pass_rate=1.0,
                required_scorer_error_count=0,
            ),
            case_results=[
                DetectionCaseResult(
                    case_id="threat_event_match",
                    truth_id="truth-1",
                    truth_revision=1,
                    truth_content_hash="e" * 64,
                    slice_type=SliceType.THREAT,
                    observation=DetectionCaseObservation(
                        case_id="threat_event_match",
                        slice_type=SliceType.THREAT,
                        candidates=[],
                    ),
                    scorer_results=[],
                    case_status=EvaluationRunStatus.COMPLETED,
                )
            ],
        )
    )
    binding_manifest = load_production_binding_manifest(PRODUCTION_DATASET_DIR)
    comparison = await run_production_comparison(
        session_factory,
        phase_a_artifact=phase_a,
        binding_manifest=binding_manifest,
        code_sha="abc1234",
    )
    assert comparison.recommendation is DetectionProductionRecommendationKind.INSUFFICIENT_DATA
    missing_status = DetectionProductionOutcomeStatus.MISSING_PROMOTION
    assert comparison.case_comparisons[0].outcome_status is missing_status


def test_production_comparison_baseline_diff_ignores_comparison_id() -> None:
    now = datetime(2026, 8, 4, 0, 0, 0, tzinfo=UTC)
    payload = DetectionProductionComparisonArtifact(
        comparison_id="cmp-1",
        tenant_id="tenant-a",
        code_sha="abc1234",
        phase_a_refs=DetectionContextEvaluationRefs(
            evaluation_id="e1",
            artifact_hash="a" * 64,
            dataset_id="detection_shadow_v1",
            dataset_version="2026.08.02",
            dataset_content_hash="b" * 64,
            code_sha="abc1234",
        ),
        config=DetectionProductionComparisonConfig(
            phase_a_artifact_hash="a" * 64,
            phase_a_evaluation_id="e1",
            binding_manifest_hash="c" * 64,
            seed=42,
        ),
        started_at=now,
        completed_at=now,
        status=EvaluationRunStatus.COMPLETED,
        recommendation=DetectionProductionRecommendationKind.CONTINUE,
    )
    first = finalize_production_comparison_artifact(payload)
    second = finalize_production_comparison_artifact(
        payload.model_copy(update={"comparison_id": "cmp-2"})
    )
    assert diff_production_comparison_against_baseline(first, second) == []


def _minimal_phase_a(*, artifact_hash: str = "a" * 64) -> DetectionEvaluationArtifact:
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    candidate_refs = DetectionCandidateRefs(
        package_id="pkg-1",
        package_version=1,
        package_content_hash="c" * 64,
        rule_ids=["rule-1"],
        feature_contract_version="1.0",
        detection_scope_id="scope-1",
    )
    return DetectionEvaluationArtifact(
        evaluation_id="eval-1",
        tenant_id="tenant-a",
        dataset_id="detection_shadow_v1",
        dataset_version="2026.08.02",
        dataset_content_hash="b" * 64,
        code_sha="abc1234",
        config=DetectionEvaluationConfig(
            seed=42,
            cutoff_at=cutoff,
            candidate_refs=candidate_refs,
        ),
        started_at=cutoff,
        completed_at=cutoff,
        status=EvaluationRunStatus.COMPLETED,
        aggregates=EvaluationAggregateMetrics(
            case_count=1,
            pass_count=1,
            fail_count=0,
            unevaluable_count=0,
            error_count=0,
            pass_rate=1.0,
            required_scorer_error_count=0,
        ),
        artifact_hash=artifact_hash,
    )


def _threat_case(*, candidate: CandidateDetection | None = None) -> DetectionCaseResult:
    candidates = [candidate] if candidate is not None else []
    return DetectionCaseResult(
        case_id="threat-1",
        truth_id="truth-1",
        truth_revision=1,
        truth_content_hash="e" * 64,
        slice_type=SliceType.THREAT,
        observation=DetectionCaseObservation(
            case_id="threat-1",
            slice_type=SliceType.THREAT,
            candidates=candidates,
        ),
        scorer_results=[],
        case_status=EvaluationRunStatus.COMPLETED,
        candidate_refs=DetectionCandidateRefs(
            package_id="pkg-1",
            package_version=1,
            package_content_hash="c" * 64,
            rule_ids=["rule-1"],
            feature_contract_version="1.0",
            detection_scope_id="scope-1",
        ),
    )


def _sample_candidate() -> CandidateDetection:
    cutoff = datetime(2026, 8, 1, 15, 0, 0, tzinfo=UTC)
    return CandidateDetection(
        candidate_detection_id="cand-1",
        source_tenant_id="tenant-a",
        detection_scope_id="scope-1",
        package_id="pkg-1",
        package_version=1,
        rule_id="rule-1",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_MATCH,
        cutoff_at=cutoff,
        window_kind="1h",
        matched_value=10.0,
        severity="medium",
        provenance=CandidateDetectionProvenance(),
        content_hash="d" * 64,
        idempotency_key="idem-cand-1",
    )


def _completed_promotion(*, candidate_hash: str = "d" * 64) -> DetectionPromotionRecord:
    now = datetime(2026, 8, 4, 0, 0, 0, tzinfo=UTC)
    return DetectionPromotionRecord(
        promotion_id="promo-1",
        tenant_id="tenant-a",
        promotion_key="key-1",
        status=DetectionPromotionStatus.COMPLETED,
        decision_id="decision-1",
        candidate_detection_id="cand-1",
        candidate_content_hash=candidate_hash,
        package_id="pkg-1",
        package_version=1,
        package_content_hash="c" * 64,
        detection_scope_id="scope-1",
        event_id="event-1",
        created_at=now,
        updated_at=now,
    )


def _snapshot_for_phase_a(
    phase_a: DetectionEvaluationArtifact,
    *,
    severity: str = "medium",
    ready_count: int = 1,
    feature_count: int = 1,
) -> DetectionContextSnapshot:
    return DetectionContextSnapshot(
        snapshot_id="snap-1",
        tenant_id="tenant-a",
        event_id="event-1",
        event_revision=1,
        promotion_id="promo-1",
        promotion_link_revision=1,
        promotion_key="key-1",
        release_refs=DetectionContextReleaseRefs(
            candidate_detection_id="cand-1",
            candidate_content_hash="d" * 64,
            package_id="pkg-1",
            package_version=1,
            package_content_hash="c" * 64,
            rule_id="rule-1",
            rule_version=1,
            feature_contract_version="1.0",
            detection_scope_id="scope-1",
        ),
        governance_refs=DetectionContextGovernanceRefs(
            decision_id="decision-1",
            binding_hash="f" * 64,
            decision_hash="g" * 64,
            candidate_set_hash="h" * 64,
        ),
        evaluation_refs=DetectionContextEvaluationRefs(
            evaluation_id=phase_a.evaluation_id,
            artifact_hash=phase_a.artifact_hash,
            dataset_id=phase_a.dataset_id,
            dataset_version=phase_a.dataset_version,
            dataset_content_hash=phase_a.dataset_content_hash,
            code_sha=phase_a.code_sha,
        ),
        scores=DetectionContextScoreSummary(
            matched_value=10.0,
            severity=severity,
            operator="gte",
        ),
        coverage=DetectionContextCoverageSummary(
            feature_snapshot_count=feature_count,
            ready_snapshot_count=ready_count,
        ),
        content_hash="i" * 64,
        idempotency_key="idem-1",
    )


def test_compare_production_case_threat_severity_drift() -> None:
    phase_a = _minimal_phase_a()
    candidate = _sample_candidate()
    comparison = compare_production_case(
        _threat_case(candidate=candidate),
        DetectionProductionCaseBinding(
            case_id="threat-1",
            expect_promotion=True,
            expected_production_severity="high",
        ),
        _completed_promotion(),
        _snapshot_for_phase_a(phase_a, severity="medium"),
        phase_a_artifact=phase_a,
    )
    assert comparison.outcome_status is DetectionProductionOutcomeStatus.DRIFT
    kind, _ = derive_production_recommendation(
        [comparison],
        DetectionProductionCoverageDrift(),
    )
    assert kind is DetectionProductionRecommendationKind.ROLLBACK_RECOMMENDED


def test_compare_production_case_benign_drift_monitors() -> None:
    phase_a = _minimal_phase_a()
    comparison = compare_production_case(
        DetectionCaseResult(
            case_id="benign-1",
            truth_id="truth-1",
            truth_revision=1,
            truth_content_hash="e" * 64,
            slice_type=SliceType.BENIGN,
            observation=DetectionCaseObservation(
                case_id="benign-1",
                slice_type=SliceType.BENIGN,
                candidates=[_sample_candidate()],
            ),
            scorer_results=[],
            case_status=EvaluationRunStatus.COMPLETED,
        ),
        DetectionProductionCaseBinding(case_id="benign-1", expect_promotion=True),
        _completed_promotion(candidate_hash="x" * 64),
        _snapshot_for_phase_a(phase_a),
        phase_a_artifact=phase_a,
    )
    assert comparison.outcome_status is DetectionProductionOutcomeStatus.DRIFT
    kind, _ = derive_production_recommendation(
        [comparison],
        DetectionProductionCoverageDrift(),
    )
    assert kind is DetectionProductionRecommendationKind.MONITOR


def test_compare_production_case_unexpected_promotion() -> None:
    phase_a = _minimal_phase_a()
    comparison = compare_production_case(
        DetectionCaseResult(
            case_id="benign-1",
            truth_id="truth-1",
            truth_revision=1,
            truth_content_hash="e" * 64,
            slice_type=SliceType.BENIGN,
            observation=DetectionCaseObservation(case_id="benign-1", slice_type=SliceType.BENIGN),
            scorer_results=[],
            case_status=EvaluationRunStatus.COMPLETED,
        ),
        DetectionProductionCaseBinding(case_id="benign-1", expect_promotion=False),
        _completed_promotion(),
        None,
        phase_a_artifact=phase_a,
    )
    assert comparison.outcome_status is DetectionProductionOutcomeStatus.UNEXPECTED_PROMOTION


def test_compare_production_case_snapshot_missing_is_insufficient_data() -> None:
    phase_a = _minimal_phase_a()
    comparison = compare_production_case(
        _threat_case(candidate=_sample_candidate()),
        DetectionProductionCaseBinding(case_id="threat-1", expect_promotion=True),
        _completed_promotion(),
        None,
        phase_a_artifact=phase_a,
    )
    assert comparison.outcome_status is DetectionProductionOutcomeStatus.SNAPSHOT_MISSING
    kind, _ = derive_production_recommendation(
        [comparison],
        DetectionProductionCoverageDrift(),
    )
    assert kind is DetectionProductionRecommendationKind.INSUFFICIENT_DATA


def test_summarize_coverage_drift_triggers_monitor() -> None:
    phase_a = _minimal_phase_a()
    snapshot = _snapshot_for_phase_a(phase_a, ready_count=1, feature_count=4)
    comparison = compare_production_case(
        _threat_case(candidate=_sample_candidate()),
        DetectionProductionCaseBinding(case_id="threat-1", expect_promotion=True),
        _completed_promotion(),
        snapshot,
        phase_a_artifact=phase_a,
    )
    drift = summarize_coverage_drift([comparison], [snapshot])
    assert drift.drift_detected is True
    kind, _ = derive_production_recommendation([comparison], drift)
    assert kind is DetectionProductionRecommendationKind.MONITOR


def test_production_dataset_manifest_matches_bindings() -> None:
    from app.evaluation.detection.production_fixture_loader import load_production_dataset_manifest

    dataset_manifest = load_production_dataset_manifest(PRODUCTION_DATASET_DIR)
    binding_manifest = load_production_binding_manifest(PRODUCTION_DATASET_DIR)
    assert dataset_manifest.shadow_dataset_id == binding_manifest.shadow_dataset_id
    assert dataset_manifest.content_hash == binding_manifest.content_hash
