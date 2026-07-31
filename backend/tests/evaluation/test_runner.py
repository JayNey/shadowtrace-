"""Evaluation pipeline tests (ISSUE-105 / #608)."""

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

from app.core.errors import ValidationError
from app.db import models as orm
from app.evaluation.artifact import compute_artifact_hash
from app.evaluation.diff import diff_against_baseline, diff_artifacts
from app.evaluation.fixture_loader import load_fixture_dataset
from app.evaluation.replayer import MockDeterministicReplayer
from app.evaluation.runner import EvaluationRunner, EvaluationRunRequest, run_fixture_evaluation
from app.evaluation.scorers.base import ScorerRegistration
from app.evaluation.scorers.registry import ScorerRegistry, default_scorer_registry
from app.evaluation.threshold import (
    evaluate_gate,
    load_threshold_manifest,
    validate_threshold_manifest_for_run,
)
from app.models.evaluation_run import (
    EvaluationAggregateMetrics,
    EvaluationQuarantinePolicy,
    EvaluationRunStatus,
    EvaluationScorerResult,
    EvaluationThresholdManifest,
    GateVerdict,
    ScorerOutcome,
)
from app.models.evaluation_truth import (
    BenignSliceExpectation,
    EvaluationTruthQuery,
    LabelProvenance,
    SliceType,
)
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
async def test_demo_dataset_run_is_deterministic(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple,
) -> None:
    _, manifest = loaded_dataset
    first = await run_fixture_evaluation(
        truth_service,
        manifest,
        seed=42,
        code_sha="deadbeef",
        threshold_manifest_path=DATASET_DIR / "threshold_manifest.json",
    )
    second = await run_fixture_evaluation(
        truth_service,
        manifest,
        seed=42,
        code_sha="deadbeef",
        threshold_manifest_path=DATASET_DIR / "threshold_manifest.json",
    )

    assert first.artifact_hash == second.artifact_hash
    assert first.aggregates.case_count == 3
    assert first.aggregates.pass_count == 2
    assert first.aggregates.unevaluable_count == 1
    assert first.aggregates.error_count == 0
    assert first.status == EvaluationRunStatus.COMPLETED
    assert first.config.replay_fidelity == "echo_truth_stub"
    assert first.gate is not None
    assert first.gate.verdict == GateVerdict.PASS


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_artifact_hash_excludes_run_id_and_timestamps(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple,
) -> None:
    _, manifest = loaded_dataset
    artifact = await run_fixture_evaluation(
        truth_service,
        manifest,
        seed=7,
        code_sha="abc1234",
    )
    mutated = artifact.model_copy(
        update={
            "run_id": "eval-different",
            "started_at": artifact.started_at.replace(year=2020),
        }
    )
    assert compute_artifact_hash(artifact) == compute_artifact_hash(mutated)


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_required_scorer_error_fail_closed(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple,
) -> None:
    _, manifest = loaded_dataset

    class BrokenScorer:
        scorer_id = "threat_label"
        supported_slices = frozenset({SliceType.THREAT})

        def score(self, truth, observation, ctx) -> EvaluationScorerResult:
            raise RuntimeError("simulated scorer failure")

    registry = default_scorer_registry()
    registry.replace_scorer(
        ScorerRegistration(
            scorer_id="threat_label",
            scorer=BrokenScorer(),
            required=True,
        )
    )

    artifact = await run_fixture_evaluation(
        truth_service,
        manifest,
        seed=42,
        code_sha="deadbeef",
        threshold_manifest_path=DATASET_DIR / "threshold_manifest.json",
        registry=registry,
    )

    assert artifact.aggregates.error_count >= 1
    assert artifact.status == EvaluationRunStatus.FAILED
    assert artifact.gate is not None
    assert artifact.gate.verdict in {GateVerdict.FAIL, GateVerdict.FAIL_CLOSED}
    assert any(diff.field.startswith("scorer:threat_label") for diff in (artifact.gate.diffs or []))


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_missing_required_scorer_registration_fail_closed() -> None:
    registry = ScorerRegistry()
    registry.register(
        ScorerRegistration(
            scorer_id="benign_label",
            scorer=default_scorer_registry().get("benign_label").scorer,
            required=True,
        )
    )
    threshold = load_threshold_manifest(DATASET_DIR / "threshold_manifest.json")
    gate = evaluate_gate(
        threshold,
        aggregates=EvaluationAggregateMetrics(
            case_count=3,
            pass_count=2,
            fail_count=0,
            unevaluable_count=1,
            error_count=0,
            pass_rate=1.0,
        ),
        case_results=[],
        registry=registry,
        manifest_path=str(DATASET_DIR / "threshold_manifest.json"),
    )
    assert gate.verdict == GateVerdict.FAIL
    assert any(diff.field == "required_scorers" for diff in gate.diffs)


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_unevaluable_case_not_counted_as_pass(
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
    unevaluable = next(c for c in artifact.case_results if c.slice_type == SliceType.UNEVALUABLE)
    assert unevaluable.case_status == EvaluationRunStatus.UNEVALUABLE
    assert all(r.outcome == ScorerOutcome.UNEVALUABLE for r in unevaluable.scorer_results)


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_empty_scorer_results_fail_closed_on_threat_case(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple,
) -> None:
    _, manifest = loaded_dataset
    registry = ScorerRegistry()
    registry.register(
        ScorerRegistration(
            scorer_id="benign_label",
            scorer=default_scorer_registry().get("benign_label").scorer,
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
    threat = next(c for c in artifact.case_results if c.slice_type == SliceType.THREAT)
    assert threat.scorer_results == []
    assert threat.case_status == EvaluationRunStatus.FAILED
    assert artifact.status == EvaluationRunStatus.FAILED
    assert artifact.errors


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_partial_scorer_ids_missing_required_scorer_fail_gate(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple,
) -> None:
    _, manifest = loaded_dataset
    runner = EvaluationRunner(truth_service)
    artifact = await runner.run(
        EvaluationRunRequest(
            tenant_id=manifest.tenant_id,
            dataset_id=manifest.dataset_id,
            dataset_version=manifest.dataset_version,
            dataset_content_hash=manifest.content_hash,
            seed=42,
            code_sha="deadbeef",
            scorer_ids=["benign_label"],
            threshold_manifest=load_threshold_manifest(DATASET_DIR / "threshold_manifest.json"),
            threshold_manifest_path=str(DATASET_DIR / "threshold_manifest.json"),
        )
    )
    assert artifact.status == EvaluationRunStatus.FAILED
    assert artifact.gate is not None
    assert any(diff.actual == "missing" for diff in artifact.gate.diffs)


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_runner_rejects_dataset_content_hash_mismatch(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple,
) -> None:
    _, manifest = loaded_dataset
    runner = EvaluationRunner(truth_service)
    with pytest.raises(ValidationError, match="dataset content hash mismatch"):
        await runner.run(
            EvaluationRunRequest(
                tenant_id=manifest.tenant_id,
                dataset_id=manifest.dataset_id,
                dataset_version=manifest.dataset_version,
                dataset_content_hash="0" * 64,
                seed=42,
                code_sha="deadbeef",
            )
        )


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_runner_uses_latest_truth_revision_after_correction(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple,
) -> None:
    truths, manifest = loaded_dataset
    threat = next(t for t in truths if t.case_id == "malicious_process_exfil")
    corrected = await truth_service.append_correction(
        tenant_id=manifest.tenant_id,
        supersedes_truth_id=threat.truth_id,
        slice_expectation=BenignSliceExpectation(),
        label_provenance=LabelProvenance(
            adjudicator="reviewer",
            adjudicated_at=datetime(2026, 7, 31, 9, 0, tzinfo=UTC),
            source_kind="manual_review",
            revision_notes="corrected during evaluation test",
        ),
        correction_reason="adjudication overturned in test",
    )
    updated_manifest = await truth_service.get_dataset_manifest(
        tenant_id=manifest.tenant_id,
        dataset_id=manifest.dataset_id,
        dataset_version=manifest.dataset_version,
    )
    artifact = await run_fixture_evaluation(
        truth_service,
        updated_manifest,
        seed=42,
        code_sha="deadbeef",
    )
    case = next(c for c in artifact.case_results if c.case_id == "malicious_process_exfil")
    assert case.truth_id == corrected.truth_id
    assert case.truth_revision == corrected.revision
    assert case.slice_type == SliceType.BENIGN


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_artifact_diff_reports_field_deltas(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple,
) -> None:
    _, manifest = loaded_dataset
    baseline = await run_fixture_evaluation(
        truth_service,
        manifest,
        seed=42,
        code_sha="deadbeef",
    )
    candidate = await run_fixture_evaluation(
        truth_service,
        manifest,
        seed=99,
        code_sha="deadbeef",
    )
    diffs = diff_artifacts(baseline, candidate)
    assert any(diff.field == "artifact_hash" for diff in diffs)


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_runner_queries_latest_truth_revision_only(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple,
) -> None:
    _, manifest = loaded_dataset
    runner = EvaluationRunner(truth_service)
    artifact = await runner.run(
        EvaluationRunRequest(
            tenant_id=manifest.tenant_id,
            dataset_id=manifest.dataset_id,
            dataset_version=manifest.dataset_version,
            dataset_content_hash=manifest.content_hash,
            seed=99,
            code_sha="cafebabe",
        )
    )
    result = await truth_service.query_truths(
        EvaluationTruthQuery(
            tenant_id=manifest.tenant_id,
            dataset_id=manifest.dataset_id,
            dataset_version=manifest.dataset_version,
            latest_revision_only=True,
            page_size=200,
        )
    )
    assert artifact.aggregates.case_count == result.total


@pytest.mark.evaluation
def test_load_threshold_manifest_rejects_missing_file() -> None:
    with pytest.raises(ValidationError, match="threshold manifest not found"):
        load_threshold_manifest(Path("/tmp/does-not-exist-threshold.json"))


@pytest.mark.evaluation
def test_mock_replayer_is_deterministic_per_seed() -> None:
    from app.evaluation.fixture_loader import build_truth_from_fixture_case, load_fixture_cases

    case_payload = load_fixture_cases(DATASET_DIR)[0]
    truth = build_truth_from_fixture_case(
        case_payload,
        tenant_id="tenant-evaluation-demo",
        dataset_id="shadowtrace_demo_v1",
        dataset_version="2026.07.31",
    )
    replayer = MockDeterministicReplayer()
    first = replayer.replay(truth, seed=42)
    second = replayer.replay(truth, seed=42)
    assert first.model_dump() == second.model_dump()
    assert first.observed_case_label == truth.slice_expectation.expected_case_label.value  # type: ignore[attr-defined]


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_artifact_hash_invariant_across_gate_manifest_path(
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
    assert artifact.gate is not None
    mutated = artifact.model_copy(
        update={
            "gate": artifact.gate.model_copy(
                update={"manifest_path": "/tmp/other/threshold_manifest.json"}
            )
        }
    )
    assert compute_artifact_hash(artifact) == compute_artifact_hash(mutated)


@pytest.mark.evaluation
def test_validate_threshold_manifest_rejects_dataset_mismatch() -> None:
    threshold = load_threshold_manifest(DATASET_DIR / "threshold_manifest.json")
    with pytest.raises(ValidationError, match="dataset_id mismatch"):
        validate_threshold_manifest_for_run(
            threshold,
            dataset_id="wrong_dataset",
            dataset_version="2026.07.31",
        )


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_runner_rejects_mismatched_threshold_manifest_dataset(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple,
) -> None:
    _, manifest = loaded_dataset
    bad = load_threshold_manifest(DATASET_DIR / "threshold_manifest.json").model_copy(
        update={"dataset_id": "wrong_dataset"}
    )
    runner = EvaluationRunner(truth_service)
    with pytest.raises(ValidationError, match="dataset_id mismatch"):
        await runner.run(
            EvaluationRunRequest(
                tenant_id=manifest.tenant_id,
                dataset_id=manifest.dataset_id,
                dataset_version=manifest.dataset_version,
                dataset_content_hash=manifest.content_hash,
                seed=42,
                code_sha="deadbeef",
                threshold_manifest=bad,
                threshold_manifest_path="data/evaluation/shadowtrace_demo_v1/threshold_manifest.json",
            )
        )


@pytest.mark.evaluation
def test_required_gate_true_emits_fail_closed() -> None:
    threshold = EvaluationThresholdManifest(
        manifest_version="test",
        dataset_id="shadowtrace_demo_v1",
        dataset_version="2026.07.31",
        required_scorers=["threat_label"],
        min_pass_rate=1.0,
        max_error_count=0,
        required_gate=True,
    )
    gate = evaluate_gate(
        threshold,
        aggregates=EvaluationAggregateMetrics(
            case_count=1,
            pass_count=0,
            fail_count=1,
            unevaluable_count=0,
            error_count=0,
            pass_rate=0.0,
        ),
        case_results=[],
        registry=default_scorer_registry(),
    )
    assert gate.verdict == GateVerdict.FAIL_CLOSED


@pytest.mark.evaluation
def test_quarantine_expired_fail_closed() -> None:
    threshold = EvaluationThresholdManifest(
        manifest_version="test",
        dataset_id="shadowtrace_demo_v1",
        dataset_version="2026.07.31",
        required_gate=True,
        quarantine=EvaluationQuarantinePolicy(
            owner="eval-team",
            expires_at=datetime(2020, 1, 1, tzinfo=UTC),
            reason="stale quarantine",
        ),
    )
    gate = evaluate_gate(
        threshold,
        aggregates=EvaluationAggregateMetrics(
            case_count=1,
            pass_count=1,
            fail_count=0,
            unevaluable_count=0,
            error_count=0,
            pass_rate=1.0,
        ),
        case_results=[],
        registry=default_scorer_registry(),
        now=datetime(2026, 7, 31, tzinfo=UTC),
    )
    assert gate.verdict == GateVerdict.FAIL_CLOSED
    assert gate.quarantine_active is False
    assert gate.diffs[0].field == "quarantine"
    assert gate.diffs[0].actual == "expired"


@pytest.mark.evaluation
def test_quarantine_active_passes_despite_threshold_diffs() -> None:
    threshold = EvaluationThresholdManifest(
        manifest_version="test",
        dataset_id="shadowtrace_demo_v1",
        dataset_version="2026.07.31",
        required_gate=True,
        min_pass_rate=1.0,
        quarantine=EvaluationQuarantinePolicy(
            owner="eval-team",
            expires_at=datetime(2099, 1, 1, tzinfo=UTC),
            reason="temporary flake window",
        ),
    )
    gate = evaluate_gate(
        threshold,
        aggregates=EvaluationAggregateMetrics(
            case_count=2,
            pass_count=0,
            fail_count=2,
            unevaluable_count=0,
            error_count=0,
            pass_rate=0.0,
        ),
        case_results=[],
        registry=default_scorer_registry(),
        now=datetime(2026, 7, 31, tzinfo=UTC),
    )
    assert gate.verdict == GateVerdict.PASS
    assert gate.quarantine_active is True
    assert gate.diffs[0].field == "quarantine"
    assert gate.diffs[0].actual == "active"
    assert any(diff.field == "pass_rate" for diff in gate.diffs)


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_required_scorer_error_count_only_counts_manifest_scorers(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple,
) -> None:
    _, manifest = loaded_dataset

    class OptionalBrokenScorer:
        scorer_id = "optional_probe"
        supported_slices = frozenset({SliceType.THREAT})

        def score(self, truth, observation, ctx) -> EvaluationScorerResult:
            raise RuntimeError("optional scorer failure")

    registry = ScorerRegistry()
    default = default_scorer_registry()
    for scorer_id in default.scorer_ids:
        reg = default.get(scorer_id)
        registry.register(reg)
    registry.register(
        ScorerRegistration(
            scorer_id="optional_probe",
            scorer=OptionalBrokenScorer(),
            required=False,
        )
    )
    artifact = await run_fixture_evaluation(
        truth_service,
        manifest,
        seed=42,
        code_sha="deadbeef",
        registry=registry,
    )
    assert artifact.aggregates.error_count >= 1
    assert artifact.aggregates.required_scorer_error_count == 0


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_cli_skip_fixture_load_reuses_existing_truth(
    truth_service: EvaluationTruthService,
    session_factory: async_sessionmaker[AsyncSession],
    loaded_dataset: tuple,
) -> None:
    from scripts import run_evaluation as cli

    _, manifest = loaded_dataset
    count, resolved = await cli._resolve_manifest(
        truth_service,
        session_factory,
        DATASET_DIR,
        tenant_id=manifest.tenant_id,
        skip_fixture_load=True,
    )
    assert count == manifest.case_count
    assert resolved.content_hash == manifest.content_hash


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_unevaluable_scorer_error_fail_closed(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple,
) -> None:
    _, manifest = loaded_dataset

    class BrokenUnevaluableScorer:
        scorer_id = "unevaluable_coverage"
        supported_slices = frozenset({SliceType.UNEVALUABLE})

        def score(self, truth, observation, ctx) -> EvaluationScorerResult:
            raise RuntimeError("simulated unevaluable scorer failure")

    registry = default_scorer_registry()
    registry.replace_scorer(
        ScorerRegistration(
            scorer_id="unevaluable_coverage",
            scorer=BrokenUnevaluableScorer(),
            required=True,
        )
    )

    artifact = await run_fixture_evaluation(
        truth_service,
        manifest,
        seed=42,
        code_sha="deadbeef",
        threshold_manifest_path=DATASET_DIR / "threshold_manifest.json",
        registry=registry,
    )

    unevaluable = next(c for c in artifact.case_results if c.slice_type == SliceType.UNEVALUABLE)
    assert unevaluable.case_status == EvaluationRunStatus.FAILED
    assert artifact.aggregates.error_count >= 1
    assert artifact.aggregates.unevaluable_count == 0
    assert artifact.status == EvaluationRunStatus.FAILED


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_diff_against_baseline_ignores_code_sha(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple,
) -> None:
    _, manifest = loaded_dataset
    baseline = await run_fixture_evaluation(
        truth_service,
        manifest,
        seed=42,
        code_sha="evaluation-baseline-v1",
        threshold_manifest_path=DATASET_DIR / "threshold_manifest.json",
    )
    candidate = await run_fixture_evaluation(
        truth_service,
        manifest,
        seed=42,
        code_sha="different-commit-sha",
        threshold_manifest_path=DATASET_DIR / "threshold_manifest.json",
    )
    assert diff_artifacts(baseline, candidate)
    assert diff_against_baseline(baseline, candidate) == []


@pytest.mark.evaluation
def test_diff_artifacts_reports_replay_fidelity_change() -> None:
    from app.models.evaluation_run import (
        EvaluationAggregateMetrics,
        EvaluationRunArtifact,
        EvaluationRunConfig,
        EvaluationRunStatus,
        EvaluationReleaseRefs,
    )

    common = dict(
        run_id="eval-1",
        tenant_id="tenant-evaluation-demo",
        dataset_id="shadowtrace_demo_v1",
        dataset_version="2026.07.31",
        dataset_content_hash="a" * 64,
        code_sha="evaluation-baseline-v1",
        started_at=datetime(2026, 7, 31, tzinfo=UTC),
        completed_at=datetime(2026, 7, 31, tzinfo=UTC),
        status=EvaluationRunStatus.COMPLETED,
        case_results=[],
        aggregates=EvaluationAggregateMetrics(
            case_count=0,
            pass_count=0,
            fail_count=0,
            unevaluable_count=0,
            error_count=0,
            pass_rate=1.0,
        ),
        artifact_hash="b" * 64,
    )
    baseline = EvaluationRunArtifact(
        **common,
        config=EvaluationRunConfig(seed=42, replay_fidelity="echo_truth_stub"),
    )
    candidate = EvaluationRunArtifact(
        **common,
        config=EvaluationRunConfig(seed=42, replay_fidelity="real_replay"),
    )
    diffs = diff_artifacts(baseline, candidate)
    assert any(diff.field == "config.replay_fidelity" for diff in diffs)
