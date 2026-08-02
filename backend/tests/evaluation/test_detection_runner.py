"""Detection evaluation pipeline tests (ISSUE-126 / #631 Phase A)."""

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

from app.evaluation.detection.artifact import compute_detection_artifact_hash, finalize_detection_artifact
from app.evaluation.detection.diff import diff_detection_against_baseline, diff_detection_artifacts
from app.evaluation.detection.fixture_loader import load_detection_fixture_index
from app.evaluation.detection.fixture_seeder import clear_detection_tables, derive_candidate_refs
from app.evaluation.detection.runner import DetectionEvaluationRunner, run_fixture_detection_evaluation
from app.evaluation.detection.scorers.registry import default_detection_scorer_registry
from app.evaluation.fixture_loader import load_fixture_dataset
from app.models.detection_rule import MissingDataPolicy, RuleOperatorKind
from app.models.evaluation_run import EvaluationRunStatus, GateVerdict, ScorerOutcome
from app.models.evaluation_truth import SliceType
from app.models.feature_snapshot import FEATURE_CONTRACT_VERSION, FeatureWindowKind
from app.services.evaluation_truth_service import EvaluationTruthService

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_DIR.parent
DATASET_DIR = REPO_ROOT / "data" / "evaluation" / "detection_shadow_v1"
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


def _alembic_config() -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return config


@pytest.fixture(scope="module")
def migrated_database() -> None:
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
async def clean_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    from app.db import models as orm

    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.EvaluationCaseTruth))
    await clear_detection_tables(session_factory)
    yield
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.EvaluationCaseTruth))
    await clear_detection_tables(session_factory)


@pytest_asyncio.fixture
async def truth_service(
    session_factory: async_sessionmaker[AsyncSession],
) -> EvaluationTruthService:
    return EvaluationTruthService(session_factory)


@pytest_asyncio.fixture
async def loaded_detection_dataset(
    truth_service: EvaluationTruthService,
) -> tuple[object, object]:
    truths, manifest = await load_fixture_dataset(
        truth_service,
        DATASET_DIR,
        tenant_id="tenant-detection-eval",
    )
    fixture_index = load_detection_fixture_index(DATASET_DIR)
    return manifest, fixture_index


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_detection_fixture_dataset_loads(
    loaded_detection_dataset: tuple[object, object],
) -> None:
    manifest, fixture_index = loaded_detection_dataset
    assert manifest.case_count == 4
    assert len(fixture_index.by_case_id) == 4


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_detection_evaluation_completes(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    manifest, fixture_index = loaded_detection_dataset
    first_replay = fixture_index.by_case_id["threat_event_match"]
    candidate_refs = await derive_candidate_refs(session_factory, first_replay)

    artifact = await run_fixture_detection_evaluation(
        truth_service,
        session_factory,
        manifest,
        fixture_index,
        seed=42,
        code_sha="abc1234",
        cutoff_at=datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC),
        candidate_refs=candidate_refs,
    )

    assert artifact.status == EvaluationRunStatus.COMPLETED
    assert artifact.aggregates.case_count == 4
    assert artifact.aggregates.fail_count == 0
    assert artifact.aggregates.error_count == 0
    assert artifact.artifact_hash
    assert artifact.approval_note.startswith("Not a governance approval")
    assert artifact.tenant_safety.probe_count >= 1
    assert artifact.tenant_safety.fail_count == 0
    assert artifact.quality_report is not None
    threat_recall = next(
        metric for metric in artifact.quality_report.metrics if metric.metric_id == "threat_recall"
    )
    assert threat_recall.value == 1.0


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_detection_evaluation_deterministic_hash(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    manifest, fixture_index = loaded_detection_dataset
    first_replay = fixture_index.by_case_id["threat_event_match"]
    candidate_refs = await derive_candidate_refs(session_factory, first_replay)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)

    first = await run_fixture_detection_evaluation(
        truth_service,
        session_factory,
        manifest,
        fixture_index,
        seed=42,
        code_sha="abc1234",
        cutoff_at=cutoff,
        candidate_refs=candidate_refs,
    )
    second = await run_fixture_detection_evaluation(
        truth_service,
        session_factory,
        manifest,
        fixture_index,
        seed=42,
        code_sha="abc1234",
        cutoff_at=cutoff,
        candidate_refs=candidate_refs,
    )

    assert first.artifact_hash == second.artifact_hash
    assert compute_detection_artifact_hash(first) == first.artifact_hash


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_threat_case_produces_candidates(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    manifest, fixture_index = loaded_detection_dataset
    candidate_refs = await derive_candidate_refs(
        session_factory,
        fixture_index.by_case_id["threat_event_match"],
    )
    artifact = await run_fixture_detection_evaluation(
        truth_service,
        session_factory,
        manifest,
        fixture_index,
        seed=42,
        code_sha="abc1234",
        cutoff_at=datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC),
        candidate_refs=candidate_refs,
    )
    threat_case = next(case for case in artifact.case_results if case.case_id == "threat_event_match")
    assert threat_case.slice_type == SliceType.THREAT
    assert len(threat_case.observation.candidates) >= 1
    assert all(result.outcome != ScorerOutcome.FAIL for result in threat_case.scorer_results)


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_benign_hard_negative_stays_silent(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    manifest, fixture_index = loaded_detection_dataset
    candidate_refs = await derive_candidate_refs(
        session_factory,
        fixture_index.by_case_id["threat_event_match"],
    )
    artifact = await run_fixture_detection_evaluation(
        truth_service,
        session_factory,
        manifest,
        fixture_index,
        seed=42,
        code_sha="abc1234",
        cutoff_at=datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC),
        candidate_refs=candidate_refs,
    )
    benign_case = next(
        case for case in artifact.case_results if case.case_id == "benign_hard_negative"
    )
    assert benign_case.slice_type == SliceType.BENIGN
    assert not benign_case.observation.candidates


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_unevaluable_not_counted_as_benign(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    manifest, fixture_index = loaded_detection_dataset
    candidate_refs = await derive_candidate_refs(
        session_factory,
        fixture_index.by_case_id["threat_event_match"],
    )
    artifact = await run_fixture_detection_evaluation(
        truth_service,
        session_factory,
        manifest,
        fixture_index,
        seed=42,
        code_sha="abc1234",
        cutoff_at=datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC),
        candidate_refs=candidate_refs,
    )
    unknown_case = next(
        case for case in artifact.case_results if case.case_id == "unevaluable_partial_telemetry"
    )
    assert unknown_case.case_status == EvaluationRunStatus.UNEVALUABLE
    coverage = next(
        result
        for result in unknown_case.scorer_results
        if result.scorer_id == "unevaluable_coverage"
    )
    assert coverage.outcome == ScorerOutcome.UNEVALUABLE


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_late_observation_does_not_fire(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    manifest, fixture_index = loaded_detection_dataset
    candidate_refs = await derive_candidate_refs(
        session_factory,
        fixture_index.by_case_id["threat_event_match"],
    )
    artifact = await run_fixture_detection_evaluation(
        truth_service,
        session_factory,
        manifest,
        fixture_index,
        seed=42,
        code_sha="abc1234",
        cutoff_at=datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC),
        candidate_refs=candidate_refs,
    )
    late_case = next(
        case for case in artifact.case_results if case.case_id == "benign_late_observation"
    )
    assert not late_case.observation.candidates


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_resource_failure_fail_closed(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
) -> None:
    from app.evaluation.detection.fixture_loader import parse_detection_replay_fixture
    from app.evaluation.fixture_loader import build_truth_from_fixture_case, load_fixture_cases
    from app.models.detection_rule import DetectionRuleDefinition

    case_payload = {
        "case_id": "resource_failure_case",
        "slice_expectation": {
            "slice_type": "threat",
            "expected_case_label": "true_positive",
            "expected_final_verdict": "confirmed_threat",
        },
        "label_provenance": {
            "adjudicator": "test",
            "adjudicated_at": "2026-08-01T08:00:00+00:00",
            "source_kind": "test",
        },
        "detection_replay": {
            "source_tenant_id": "tenant-det-resource-test",
            "cutoff_at": "2026-08-01T15:30:00+00:00",
            "scope_seed": {
                "integration_instance_id": "inst-resource-test",
                "connector_id": "conn-resource-test",
            },
            "package_id": "drpkg-det-resource-test",
            "package_version": 1,
            "max_observations_scanned": 2,
            "rules": [
                {
                    "rule_id": "rule-count",
                    "rule_version": 1,
                    "operator": "event_count",
                    "feature_contract_version": FEATURE_CONTRACT_VERSION,
                    "detection_scope_id": "scope-placeholder",
                    "window_kind": FeatureWindowKind.ONE_HOUR.value,
                    "group_key_fields": ["entity_type", "entity_id"],
                    "threshold": 1.0,
                    "severity": "medium",
                    "match_criteria": {},
                    "max_observation_scan": 2,
                }
            ],
            "observations": [
                {
                    "observation_id": f"obs-resource-{index}",
                    "observed_at": (
                        datetime(2026, 8, 1, 14, 30, 0, tzinfo=UTC) + timedelta(minutes=index * 5)
                    ).isoformat(),
                    "action": "create_process",
                    "category": "process_create",
                    "entity": {"entity_type": "ip", "entity_id": "10.0.0.99"},
                    "connector_id": "conn-resource-test",
                    "source_object_id": f"log-resource-{index}",
                }
                for index in range(4)
            ],
        },
    }

    truth_service = EvaluationTruthService(session_factory)
    truth = await truth_service.persist(
        build_truth_from_fixture_case(
            case_payload,
            tenant_id="tenant-detection-eval",
            dataset_id="detection_resource_test",
            dataset_version="2026.08.02",
        )
    )
    manifest = await truth_service.get_dataset_manifest(
        tenant_id="tenant-detection-eval",
        dataset_id="detection_resource_test",
        dataset_version="2026.08.02",
    )
    replay = parse_detection_replay_fixture(case_payload)
    assert replay is not None
    candidate_refs = await derive_candidate_refs(session_factory, replay)
    fixture_index = load_detection_fixture_index(DATASET_DIR)
    fixture_index.by_case_id["resource_failure_case"] = replay

    artifact = await run_fixture_detection_evaluation(
        truth_service,
        session_factory,
        manifest,
        fixture_index,
        seed=42,
        code_sha="abc1234",
        cutoff_at=datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC),
        candidate_refs=candidate_refs,
    )

    case = next(item for item in artifact.case_results if item.case_id == "resource_failure_case")
    assert case.case_status == EvaluationRunStatus.FAILED
    assert case.observation.runtime_errors
    threat = next(result for result in case.scorer_results if result.scorer_id == "threat_detection")
    assert threat.outcome == ScorerOutcome.ERROR


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_gate_fail_closed_on_missing_scorer(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    from app.evaluation.detection.runner import DetectionEvaluationRunRequest
    from app.evaluation.threshold import load_threshold_manifest
    from app.models.evaluation_run import EvaluationThresholdManifest

    manifest, fixture_index = loaded_detection_dataset
    candidate_refs = await derive_candidate_refs(
        session_factory,
        fixture_index.by_case_id["threat_event_match"],
    )
    threshold = EvaluationThresholdManifest(
        manifest_version="test",
        dataset_id=manifest.dataset_id,
        dataset_version=manifest.dataset_version,
        required_scorers=["threat_detection", "missing_scorer"],
        required_gate=True,
    )
    runner = DetectionEvaluationRunner(truth_service, session_factory)
    artifact = await runner.run(
        DetectionEvaluationRunRequest(
            tenant_id=manifest.tenant_id,
            dataset_id=manifest.dataset_id,
            dataset_version=manifest.dataset_version,
            dataset_content_hash=manifest.content_hash,
            seed=42,
            code_sha="abc1234",
            cutoff_at=datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC),
            candidate_refs=candidate_refs,
            fixture_index=fixture_index,
            threshold_manifest=threshold,
        )
    )
    assert artifact.gate is not None
    assert artifact.gate.verdict == GateVerdict.FAIL_CLOSED


@pytest.mark.evaluation
def test_default_detection_scorer_registry_has_required_scorers() -> None:
    registry = default_detection_scorer_registry()
    assert "threat_detection" in registry.scorer_ids
    assert "benign_detection" in registry.scorer_ids
    assert "tenant_isolation" in registry.all_required_ids()


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_diff_against_baseline_aligns_code_sha(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    manifest, fixture_index = loaded_detection_dataset
    candidate_refs = await derive_candidate_refs(
        session_factory,
        fixture_index.by_case_id["threat_event_match"],
    )
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    baseline = await run_fixture_detection_evaluation(
        truth_service,
        session_factory,
        manifest,
        fixture_index,
        seed=42,
        code_sha="baseline0001",
        cutoff_at=cutoff,
        candidate_refs=candidate_refs,
    )
    candidate = await run_fixture_detection_evaluation(
        truth_service,
        session_factory,
        manifest,
        fixture_index,
        seed=42,
        code_sha="different01",
        cutoff_at=cutoff,
        candidate_refs=candidate_refs,
    )
    assert diff_detection_against_baseline(baseline, candidate) == []


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_diff_detects_case_status_drift(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    manifest, fixture_index = loaded_detection_dataset
    candidate_refs = await derive_candidate_refs(
        session_factory,
        fixture_index.by_case_id["threat_event_match"],
    )
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    baseline = await run_fixture_detection_evaluation(
        truth_service,
        session_factory,
        manifest,
        fixture_index,
        seed=42,
        code_sha="abc1234",
        cutoff_at=cutoff,
        candidate_refs=candidate_refs,
    )
    mutated_case = baseline.case_results[0].model_copy(
        update={"case_status": EvaluationRunStatus.FAILED}
    )
    candidate = baseline.model_copy(
        update={"case_results": [mutated_case, *baseline.case_results[1:]]}
    )
    candidate = finalize_detection_artifact(candidate)
    diffs = diff_detection_artifacts(baseline, candidate)
    assert any(diff.field.endswith(".case_status") for diff in diffs)
