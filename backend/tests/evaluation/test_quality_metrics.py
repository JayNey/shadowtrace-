"""Tests for ISSUE-113 Phase B offline quality metrics and grouping scorers."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.db import models as orm
from app.evaluation.fixture_loader import load_fixture_dataset
from app.evaluation.quality_metrics import build_quality_report
from app.evaluation.runner import run_fixture_evaluation
from app.evaluation.scorers.base import ScorerRegistration
from app.evaluation.scorers.grouping_scorers import SeverityAlignmentScorer
from app.evaluation.scorers.registry import default_scorer_registry
from app.models.evaluation_quality import QualityMetricStatus
from app.models.evaluation_run import (
    CaseObservation,
    EvaluationCaseResult,
    EvaluationReleaseRefs,
    EvaluationRunStatus,
    EvaluationScorerResult,
    ScorerOutcome,
)
from app.models.evaluation_truth import SliceType, ThreatSliceExpectation
from app.services.evaluation_truth_service import EvaluationTruthService

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_DIR.parent
DATASET_DIR = REPO_ROOT / "data" / "evaluation" / "shadowtrace_demo_v1"
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
async def clean_evaluation_truth(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.EvaluationCaseTruth))
    yield
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.EvaluationCaseTruth))


@pytest_asyncio.fixture
async def truth_service(
    session_factory: async_sessionmaker[AsyncSession],
) -> EvaluationTruthService:
    return EvaluationTruthService(session_factory)


@pytest_asyncio.fixture
async def loaded_dataset(
    truth_service: EvaluationTruthService,
) -> tuple[list, object]:
    truths, manifest = await load_fixture_dataset(truth_service, DATASET_DIR)
    return truths, manifest


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_runner_attaches_quality_report(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple,
) -> None:
    _, manifest = loaded_dataset
    artifact = await run_fixture_evaluation(
        truth_service,
        manifest,
        seed=42,
        code_sha="deadbeef",
        threshold_manifest_path=DATASET_DIR / "threshold_manifest.json",
    )
    assert artifact.quality_report is not None
    assert artifact.quality_report.dataset_content_hash == manifest.content_hash
    assert artifact.quality_report.code_sha == "deadbeef"
    assert artifact.quality_report.sample_counts["total"] == 3
    metric_ids = {metric.metric_id for metric in artifact.quality_report.metrics}
    assert metric_ids == {
        "threat_recall",
        "threat_precision",
        "benign_specificity",
        "benign_fpr",
        "unevaluable_coverage",
    }


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_quality_metrics_computed_for_demo_dataset(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple,
) -> None:
    _, manifest = loaded_dataset
    artifact = await run_fixture_evaluation(
        truth_service,
        manifest,
        seed=42,
        code_sha="deadbeef",
    )
    report = artifact.quality_report
    assert report is not None
    recall = next(m for m in report.metrics if m.metric_id == "threat_recall")
    coverage = next(m for m in report.metrics if m.metric_id == "unevaluable_coverage")
    assert recall.status == QualityMetricStatus.COMPUTED
    assert recall.value == 1.0
    assert coverage.status == QualityMetricStatus.COMPUTED
    assert coverage.value == 1.0
    assert recall.confidence_interval is not None


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_quality_metrics_fail_closed_on_required_scorer_error(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple,
) -> None:
    _, manifest = loaded_dataset

    class BrokenThreatScorer:
        scorer_id = "threat_label"
        supported_slices = frozenset({SliceType.THREAT})

        def score(self, truth, observation, ctx) -> EvaluationScorerResult:
            raise RuntimeError("broken")

    registry = default_scorer_registry()
    registry.replace_scorer(
        ScorerRegistration(
            scorer_id="threat_label",
            scorer=BrokenThreatScorer(),
            required=True,
        )
    )
    artifact = await run_fixture_evaluation(
        truth_service,
        manifest,
        seed=42,
        code_sha="deadbeef",
        registry=registry,
    )
    report = artifact.quality_report
    assert report is not None
    recall = next(m for m in report.metrics if m.metric_id == "threat_recall")
    assert recall.status == QualityMetricStatus.FAIL_CLOSED
    assert recall.value is None


@pytest.mark.evaluation
def test_grouping_scorer_not_applicable_without_expectation() -> None:
    from app.evaluation.fixture_loader import build_truth_from_fixture_case, load_fixture_cases
    from app.evaluation.scorers.base import ScorerContext

    case_payload = load_fixture_cases(DATASET_DIR)[1]
    truth = build_truth_from_fixture_case(
        case_payload,
        tenant_id="tenant-evaluation-demo",
        dataset_id="shadowtrace_demo_v1",
        dataset_version="2026.07.31",
    )
    scorer = SeverityAlignmentScorer()
    ctx = ScorerContext(seed=42, dataset_id="shadowtrace_demo_v1", dataset_version="2026.07.31")
    result = scorer.score(
        truth,
        CaseObservation(case_id=truth.case_id, slice_type=SliceType.BENIGN),
        ctx,
    )
    assert result.outcome == ScorerOutcome.PASS
    assert result.reason_code == "not_applicable"


@pytest.mark.evaluation
def test_grouping_scorer_validates_configured_severity() -> None:
    from app.evaluation.scorers.base import ScorerContext
    from app.models.evaluation_truth import LabelProvenance
    from app.services.evaluation_truth_service import build_evaluation_case_truth

    truth = build_evaluation_case_truth(
        tenant_id="tenant-evaluation-demo",
        dataset_id="shadowtrace_demo_v1",
        dataset_version="2026.07.31",
        case_id="case-severity",
        slice_expectation=ThreatSliceExpectation(expected_risk_score=90),
        label_provenance=LabelProvenance(
            adjudicator="tester",
            adjudicated_at=datetime(2026, 7, 31, tzinfo=UTC),
            source_kind="unit_test",
        ),
    )
    scorer = SeverityAlignmentScorer()
    ctx = ScorerContext(seed=42, dataset_id="shadowtrace_demo_v1", dataset_version="2026.07.31")
    pass_result = scorer.score(
        truth,
        CaseObservation(
            case_id=truth.case_id,
            slice_type=SliceType.THREAT,
            observed_risk_score=90,
            observation_available=True,
        ),
        ctx,
    )
    fail_result = scorer.score(
        truth,
        CaseObservation(
            case_id=truth.case_id,
            slice_type=SliceType.THREAT,
            observed_risk_score=10,
            observation_available=True,
        ),
        ctx,
    )
    assert pass_result.outcome == ScorerOutcome.PASS
    assert fail_result.outcome == ScorerOutcome.FAIL


@pytest.mark.evaluation
def test_optional_grouping_scorer_failure_does_not_fail_case_status() -> None:
    from app.evaluation.runner import _case_status

    status = _case_status(
        SliceType.THREAT,
        [
            EvaluationScorerResult(scorer_id="threat_label", outcome=ScorerOutcome.PASS),
            EvaluationScorerResult(
                scorer_id="severity_alignment",
                outcome=ScorerOutcome.FAIL,
                reason_code="severity_mismatch",
            ),
        ],
        required_scorer_ids=frozenset({"threat_label"}),
    )
    assert status == EvaluationRunStatus.COMPLETED


@pytest.mark.evaluation
def test_build_quality_report_includes_grouping_summary() -> None:
    case = EvaluationCaseResult(
        case_id="case-1",
        truth_id="truth-1",
        truth_revision=1,
        truth_content_hash="a" * 64,
        slice_type=SliceType.THREAT,
        observation=CaseObservation(case_id="case-1", slice_type=SliceType.THREAT),
        scorer_results=[
            EvaluationScorerResult(
                scorer_id="severity_alignment",
                outcome=ScorerOutcome.PASS,
                reason_code="not_applicable",
            )
        ],
        case_status=EvaluationRunStatus.COMPLETED,
    )
    report = build_quality_report(
        dataset_id="shadowtrace_demo_v1",
        dataset_version="2026.07.31",
        dataset_content_hash="b" * 64,
        code_sha="deadbeef",
        release_refs=EvaluationReleaseRefs(),
        case_results=[case],
    )
    assert report.grouping_scorer_summaries
    assert report.grouping_scorer_summaries[0].scorer_id == "severity_alignment"
    assert report.grouping_scorer_summaries[0].not_applicable_count == 1


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_threat_case_uses_schema_version_1_1(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple,
) -> None:
    truths, _ = loaded_dataset
    threat = next(t for t in truths if t.case_id == "malicious_process_exfil")
    assert threat.slice_expectation.schema_version == "1.1"


@pytest.mark.evaluation
def test_threat_precision_fail_closed_only_on_threat_scorer_errors() -> None:
    benign_case = EvaluationCaseResult(
        case_id="benign-1",
        truth_id="truth-b",
        truth_revision=1,
        truth_content_hash="b" * 64,
        slice_type=SliceType.BENIGN,
        observation=CaseObservation(
            case_id="benign-1",
            slice_type=SliceType.BENIGN,
            observed_case_label="false_positive",
            observed_final_verdict="false_positive",
            observation_available=True,
        ),
        scorer_results=[
            EvaluationScorerResult(
                scorer_id="benign_label",
                outcome=ScorerOutcome.ERROR,
                reason_code="scorer_exception",
            )
        ],
        case_status=EvaluationRunStatus.FAILED,
    )
    threat_case = EvaluationCaseResult(
        case_id="threat-1",
        truth_id="truth-t",
        truth_revision=1,
        truth_content_hash="c" * 64,
        slice_type=SliceType.THREAT,
        observation=CaseObservation(
            case_id="threat-1",
            slice_type=SliceType.THREAT,
            observed_case_label="true_positive",
            observed_final_verdict="confirmed_threat",
            observation_available=True,
        ),
        scorer_results=[
            EvaluationScorerResult(scorer_id="threat_label", outcome=ScorerOutcome.PASS),
        ],
        case_status=EvaluationRunStatus.COMPLETED,
    )
    report = build_quality_report(
        dataset_id="shadowtrace_demo_v1",
        dataset_version="2026.07.31",
        dataset_content_hash="d" * 64,
        code_sha="deadbeef",
        release_refs=EvaluationReleaseRefs(),
        case_results=[benign_case, threat_case],
    )
    precision = next(m for m in report.metrics if m.metric_id == "threat_precision")
    assert precision.status == QualityMetricStatus.COMPUTED
    assert precision.value == 1.0


@pytest.mark.evaluation
def test_threat_recall_insufficient_sample_without_threat_cases() -> None:
    benign_case = EvaluationCaseResult(
        case_id="benign-only",
        truth_id="truth-b",
        truth_revision=1,
        truth_content_hash="b" * 64,
        slice_type=SliceType.BENIGN,
        observation=CaseObservation(case_id="benign-only", slice_type=SliceType.BENIGN),
        scorer_results=[
            EvaluationScorerResult(scorer_id="benign_label", outcome=ScorerOutcome.PASS),
        ],
        case_status=EvaluationRunStatus.COMPLETED,
    )
    report = build_quality_report(
        dataset_id="shadowtrace_demo_v1",
        dataset_version="2026.07.31",
        dataset_content_hash="d" * 64,
        code_sha="deadbeef",
        release_refs=EvaluationReleaseRefs(),
        case_results=[benign_case],
    )
    recall = next(m for m in report.metrics if m.metric_id == "threat_recall")
    assert recall.status == QualityMetricStatus.INSUFFICIENT_SAMPLE
    assert recall.value is None


@pytest.mark.evaluation
def test_attack_technique_coverage_fails_on_missing_technique() -> None:
    from app.evaluation.scorers.base import ScorerContext
    from app.evaluation.scorers.grouping_scorers import AttackTechniqueCoverageScorer
    from app.models.evaluation_truth import LabelProvenance
    from app.services.evaluation_truth_service import build_evaluation_case_truth

    truth = build_evaluation_case_truth(
        tenant_id="tenant-evaluation-demo",
        dataset_id="shadowtrace_demo_v1",
        dataset_version="2026.07.31",
        case_id="case-attck",
        slice_expectation=ThreatSliceExpectation(
            expected_attack_techniques=["T1059", "T1048"],
        ),
        label_provenance=LabelProvenance(
            adjudicator="tester",
            adjudicated_at=datetime(2026, 7, 31, tzinfo=UTC),
            source_kind="unit_test",
        ),
    )
    scorer = AttackTechniqueCoverageScorer()
    ctx = ScorerContext(seed=42, dataset_id="shadowtrace_demo_v1", dataset_version="2026.07.31")
    result = scorer.score(
        truth,
        CaseObservation(
            case_id=truth.case_id,
            slice_type=SliceType.THREAT,
            observed_attack_techniques=["T1059"],
            observation_available=True,
        ),
        ctx,
    )
    assert result.outcome == ScorerOutcome.FAIL
    assert result.reason_code == "technique_missing"


@pytest.mark.evaluation
def test_incident_grouping_fails_on_mismatch() -> None:
    from app.evaluation.scorers.base import ScorerContext
    from app.evaluation.scorers.grouping_scorers import IncidentGroupingConsistencyScorer
    from app.models.evaluation_truth import LabelProvenance
    from app.services.evaluation_truth_service import build_evaluation_case_truth

    truth = build_evaluation_case_truth(
        tenant_id="tenant-evaluation-demo",
        dataset_id="shadowtrace_demo_v1",
        dataset_version="2026.07.31",
        case_id="case-incident",
        slice_expectation=ThreatSliceExpectation(expected_incident_group_id="incident-a"),
        label_provenance=LabelProvenance(
            adjudicator="tester",
            adjudicated_at=datetime(2026, 7, 31, tzinfo=UTC),
            source_kind="unit_test",
        ),
    )
    scorer = IncidentGroupingConsistencyScorer()
    ctx = ScorerContext(seed=42, dataset_id="shadowtrace_demo_v1", dataset_version="2026.07.31")
    result = scorer.score(
        truth,
        CaseObservation(
            case_id=truth.case_id,
            slice_type=SliceType.THREAT,
            observed_incident_group_id="incident-b",
            observation_available=True,
        ),
        ctx,
    )
    assert result.outcome == ScorerOutcome.FAIL
    assert result.reason_code == "incident_group_mismatch"


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_demo_run_grouping_summaries_include_pass_counts(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple,
) -> None:
    _, manifest = loaded_dataset
    artifact = await run_fixture_evaluation(
        truth_service,
        manifest,
        seed=42,
        code_sha="deadbeef",
    )
    report = artifact.quality_report
    assert report is not None
    summaries = {item.scorer_id: item for item in report.grouping_scorer_summaries}
    assert summaries["severity_alignment"].pass_count == 1
    assert summaries["attack_technique_coverage"].pass_count == 1
    assert summaries["incident_grouping_consistency"].pass_count == 1


@pytest.mark.evaluation
def test_evaluation_run_artifact_validates_with_quality_report() -> None:
    from app.models.evaluation_run import EvaluationRunArtifact

    payload = {
        "run_id": "eval-test",
        "tenant_id": "tenant-evaluation-demo",
        "dataset_id": "shadowtrace_demo_v1",
        "dataset_version": "2026.07.31",
        "dataset_content_hash": "a" * 64,
        "code_sha": "deadbeef1",
        "config": {
            "seed": 42,
            "replay_mode": "mock_deterministic",
            "replay_fidelity": "echo_truth_stub",
            "release_refs": {"config_profile": "mock_p0"},
            "scorer_ids": [],
            "extra": {},
        },
        "started_at": "2026-07-31T08:00:00+00:00",
        "completed_at": "2026-07-31T08:00:01+00:00",
        "status": "completed",
        "case_results": [],
        "aggregates": {
            "case_count": 0,
            "pass_count": 0,
            "fail_count": 0,
            "unevaluable_count": 0,
            "error_count": 0,
            "pass_rate": 1.0,
            "required_scorer_error_count": 0,
        },
        "quality_report": {
            "dataset_id": "shadowtrace_demo_v1",
            "dataset_version": "2026.07.31",
            "dataset_content_hash": "a" * 64,
            "code_sha": "deadbeef1",
            "sample_counts": {"total": 0},
            "metrics": [],
            "grouping_scorer_summaries": [],
        },
    }
    artifact = EvaluationRunArtifact.model_validate(payload)
    assert artifact.quality_report is not None


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_committed_baseline_matches_demo_run(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple,
) -> None:
    import json

    from app.evaluation.diff import diff_against_baseline
    from app.models.evaluation_run import EvaluationRunArtifact

    _, manifest = loaded_dataset
    baseline_path = DATASET_DIR / "baseline_artifact.json"
    baseline = EvaluationRunArtifact.model_validate(
        json.loads(baseline_path.read_text(encoding="utf-8"))
    )
    candidate = await run_fixture_evaluation(
        truth_service,
        manifest,
        seed=42,
        code_sha="evaluation-baseline-v1",
        threshold_manifest_path=DATASET_DIR / "threshold_manifest.json",
    )
    assert diff_against_baseline(baseline, candidate) == []
