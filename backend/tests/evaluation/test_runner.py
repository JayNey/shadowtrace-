"""Evaluation pipeline tests (ISSUE-105 / #608)."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
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
from app.evaluation.fixture_loader import load_fixture_dataset
from app.evaluation.replayer import MockDeterministicReplayer
from app.evaluation.runner import EvaluationRunner, EvaluationRunRequest, run_fixture_evaluation
from app.evaluation.scorers.base import ScorerRegistration
from app.evaluation.scorers.registry import ScorerRegistry, default_scorer_registry
from app.evaluation.threshold import evaluate_gate, load_threshold_manifest
from app.models.evaluation_run import (
    EvaluationAggregateMetrics,
    EvaluationRunStatus,
    EvaluationScorerResult,
    GateVerdict,
    ScorerOutcome,
)
from app.models.evaluation_truth import EvaluationTruthQuery, SliceType
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
    registry._scorers["threat_label"] = ScorerRegistration(  # noqa: SLF001
        scorer_id="threat_label",
        scorer=BrokenScorer(),
        required=True,
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
