"""Agentic and coordination slice evaluation tests (ISSUE-136 / #642 Phase B/C)."""

from __future__ import annotations

import json
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
from app.evaluation.fixture_loader import load_fixture_cases, load_fixture_dataset
from app.evaluation.replayer import MockDeterministicReplayer, resolve_replay_fidelity
from app.evaluation.runner import run_fixture_evaluation
from app.evaluation.scorers.agentic_scorers import AgenticSliceScorer
from app.evaluation.scorers.base import ScorerContext
from app.evaluation.scorers.coordination_scorers import CoordinationSliceScorer
from app.evaluation.scorers.registry import default_scorer_registry
from app.evaluation.threshold import evaluate_gate
from app.models.evaluation_run import (
    AgenticCaseObservation,
    CaseObservation,
    CoordinationCaseObservation,
    EvaluationAggregateMetrics,
    EvaluationCaseResult,
    EvaluationRunStatus,
    EvaluationScorerResult,
    EvaluationThresholdManifest,
    GateVerdict,
    ScorerOutcome,
)
from app.models.evaluation_truth import (
    AgenticExpectationKind,
    AgenticSliceExpectation,
    CoordinationExpectationKind,
    CoordinationSliceExpectation,
    LabelProvenance,
    SliceType,
)
from app.services.evaluation_truth_service import (
    EvaluationTruthService,
    _parse_slice_expectation,
    build_evaluation_case_truth,
)

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_DIR.parent
DATASET_DIR = REPO_ROOT / "data" / "evaluation" / "agentic_coordination_v1"
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
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return config


requires_postgres = pytest.mark.skipif(
    not _postgres_reachable(),
    reason="PostgreSQL not reachable",
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
async def clean_evaluation_truth(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.EvaluationCaseTruth))
    yield


@pytest_asyncio.fixture
async def truth_service(
    session_factory: async_sessionmaker[AsyncSession],
) -> EvaluationTruthService:
    return EvaluationTruthService(session_factory)


@pytest_asyncio.fixture
async def loaded_dataset(
    truth_service: EvaluationTruthService,
    clean_evaluation_truth: None,
) -> tuple[list, object]:
    truths, manifest = await load_fixture_dataset(truth_service, DATASET_DIR)
    return truths, manifest


def _provenance() -> LabelProvenance:
    return LabelProvenance(
        adjudicator="test-adjudicator",
        adjudicated_at=datetime(2026, 8, 3, 12, 0, tzinfo=UTC),
        source_kind="manual_review",
        revision_notes="unit test seed",
    )


@pytest.mark.evaluation
def test_agentic_and_coordination_scorers_are_registered() -> None:
    registry = default_scorer_registry()
    assert "agentic_shadow" in registry.scorer_ids
    assert "coordination_ledger" in registry.scorer_ids


@pytest.mark.evaluation
def test_parse_slice_expectation_accepts_agentic_and_coordination() -> None:
    agentic = _parse_slice_expectation(
        {
            "slice_type": "agentic",
            "schema_version": "1.1",
            "expectation_kind": "shadow_isolation",
            "expected_shadow_namespace_used": True,
            "expected_production_store_mutated": False,
        }
    )
    assert isinstance(agentic, AgenticSliceExpectation)
    assert agentic.expectation_kind == AgenticExpectationKind.SHADOW_ISOLATION

    coordination = _parse_slice_expectation(
        {
            "slice_type": "coordination",
            "schema_version": "1.1",
            "expectation_kind": "stale_fencing_denied",
            "expected_stale_fencing_denied": True,
        }
    )
    assert isinstance(coordination, CoordinationSliceExpectation)
    assert coordination.expectation_kind == CoordinationExpectationKind.STALE_FENCING_DENIED


@pytest.mark.evaluation
def test_resolve_replay_fidelity_labels_agentic_coordination() -> None:
    agentic = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="agentic-case",
        slice_expectation=AgenticSliceExpectation(
            expectation_kind=AgenticExpectationKind.SHADOW_ISOLATION,
            expected_shadow_namespace_used=True,
        ),
        label_provenance=_provenance(),
    )
    coordination = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="coordination-case",
        slice_expectation=CoordinationSliceExpectation(
            expectation_kind=CoordinationExpectationKind.STALE_FENCING_DENIED,
            expected_stale_fencing_denied=True,
        ),
        label_provenance=_provenance(),
    )
    assert resolve_replay_fidelity([agentic]) == "slice_adapter_stub"
    assert resolve_replay_fidelity([coordination]) == "slice_adapter_stub"
    assert resolve_replay_fidelity([agentic, coordination]) == "slice_adapter_stub"


@pytest.mark.evaluation
def test_agentic_replayer_fail_variant_inverts_observation() -> None:
    truth = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="agentic-fail",
        slice_expectation=AgenticSliceExpectation(
            expectation_kind=AgenticExpectationKind.SHADOW_ISOLATION,
            expected_shadow_namespace_used=True,
            expected_production_store_mutated=False,
            replay_variant="fail",
        ),
        label_provenance=_provenance(),
    )
    observation = MockDeterministicReplayer().replay(truth, seed=42)
    assert observation.agentic is not None
    assert observation.agentic.shadow_namespace_used is False
    assert observation.agentic.production_store_mutated is True


@pytest.mark.evaluation
def test_coordination_scorer_rejects_fail_variant_observation() -> None:
    truth = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="coordination-fail",
        slice_expectation=CoordinationSliceExpectation(
            expectation_kind=CoordinationExpectationKind.STALE_FENCING_DENIED,
            expected_stale_fencing_denied=True,
            replay_variant="fail",
        ),
        label_provenance=_provenance(),
    )
    observation = MockDeterministicReplayer().replay(truth, seed=42)
    result = CoordinationSliceScorer().score(
        truth,
        observation,
        ctx=ScorerContext(seed=42, dataset_id="dataset-test", dataset_version="v1"),
    )
    assert result.outcome == ScorerOutcome.FAIL
    assert result.reason_code == "stale_fencing_denied_mismatch"


@pytest.mark.evaluation
def test_agentic_replayer_simulates_shadow_isolation() -> None:
    truth = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="agentic-case",
        slice_expectation=AgenticSliceExpectation(
            expectation_kind=AgenticExpectationKind.SHADOW_ISOLATION,
            expected_shadow_namespace_used=True,
            expected_production_store_mutated=False,
        ),
        label_provenance=_provenance(),
    )
    observation = MockDeterministicReplayer().replay(truth, seed=42)
    assert observation.agentic is not None
    assert observation.agentic.shadow_namespace_used is True
    assert observation.agentic.production_store_mutated is False


@pytest.mark.evaluation
def test_coordination_replayer_simulates_stale_fencing_denied() -> None:
    truth = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="coordination-case",
        slice_expectation=CoordinationSliceExpectation(
            expectation_kind=CoordinationExpectationKind.STALE_FENCING_DENIED,
            expected_stale_fencing_denied=True,
        ),
        label_provenance=_provenance(),
    )
    observation = MockDeterministicReplayer().replay(truth, seed=42)
    assert observation.coordination is not None
    assert observation.coordination.stale_fencing_denied is True


@pytest.mark.evaluation
def test_agentic_scorer_rejects_incomplete_expectation_config() -> None:
    truth = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="agentic-incomplete",
        slice_expectation=AgenticSliceExpectation(
            expectation_kind=AgenticExpectationKind.NO_RAW_COT,
            expected_raw_cot_persisted=None,
            expected_production_store_mutated=False,
        ),
        label_provenance=_provenance(),
    )
    observation = MockDeterministicReplayer().replay(truth, seed=1)
    result = AgenticSliceScorer().score(
        truth,
        observation,
        ctx=ScorerContext(seed=1, dataset_id="dataset-test", dataset_version="v1"),
    )
    assert result.outcome == ScorerOutcome.FAIL
    assert result.reason_code == "invalid_expectation_config"


@pytest.mark.evaluation
def test_coordination_scorer_rejects_incomplete_expectation_config() -> None:
    truth = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="coordination-incomplete",
        slice_expectation=CoordinationSliceExpectation(
            expectation_kind=CoordinationExpectationKind.ARTIFACT_IDEMPOTENT_REPLAY,
            expected_duplicate_logical_artifact=None,
            expected_content_hash_match=True,
        ),
        label_provenance=_provenance(),
    )
    observation = MockDeterministicReplayer().replay(truth, seed=1)
    result = CoordinationSliceScorer().score(
        truth,
        observation,
        ctx=ScorerContext(seed=1, dataset_id="dataset-test", dataset_version="v1"),
    )
    assert result.outcome == ScorerOutcome.FAIL
    assert result.reason_code == "invalid_expectation_config"


@pytest.mark.evaluation
def test_agentic_scorer_detects_mismatch() -> None:
    truth = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="agentic-mismatch",
        slice_expectation=AgenticSliceExpectation(
            expectation_kind=AgenticExpectationKind.SHADOW_ISOLATION,
            expected_shadow_namespace_used=True,
            expected_production_store_mutated=False,
        ),
        label_provenance=_provenance(),
    )
    observation = MockDeterministicReplayer().replay(
        build_evaluation_case_truth(
            tenant_id=truth.tenant_id,
            dataset_id=truth.dataset_id,
            dataset_version=truth.dataset_version,
            case_id=truth.case_id,
            slice_expectation=AgenticSliceExpectation(
                expectation_kind=AgenticExpectationKind.SHADOW_ISOLATION,
                expected_shadow_namespace_used=True,
                expected_production_store_mutated=False,
                replay_variant="fail",
            ),
            label_provenance=_provenance(),
        ),
        seed=7,
    )
    result = AgenticSliceScorer().score(
        truth,
        observation,
        ctx=ScorerContext(seed=7, dataset_id="dataset-test", dataset_version="v1"),
    )
    assert result.outcome == ScorerOutcome.FAIL


@pytest.mark.evaluation
def test_agentic_scorer_fails_on_dependency_degraded() -> None:
    truth = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="agentic-degraded",
        slice_expectation=AgenticSliceExpectation(
            expectation_kind=AgenticExpectationKind.SHADOW_ISOLATION,
            expected_shadow_namespace_used=True,
            expected_production_store_mutated=False,
        ),
        label_provenance=_provenance(),
    )
    observation = CaseObservation(
        case_id=truth.case_id,
        slice_type=SliceType.AGENTIC,
        observation_available=True,
        agentic=AgenticCaseObservation(
            expectation_kind="shadow_isolation",
            shadow_namespace_used=True,
            production_store_mutated=False,
            dependency_degraded=True,
        ),
    )
    result = AgenticSliceScorer().score(
        truth,
        observation,
        ctx=ScorerContext(seed=1, dataset_id="dataset-test", dataset_version="v1"),
    )
    assert result.outcome == ScorerOutcome.FAIL
    assert result.reason_code == "required_dependency_degraded"


@pytest.mark.evaluation
def test_agentic_scorer_requires_dependency_degraded_for_fail_closed_kind() -> None:
    truth = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="agentic-degraded-missing",
        slice_expectation=AgenticSliceExpectation(
            expectation_kind=AgenticExpectationKind.SHADOW_DEGRADED_FAIL_CLOSED,
            expected_degraded_fail_closed=True,
            expected_production_store_mutated=False,
        ),
        label_provenance=_provenance(),
    )
    observation = CaseObservation(
        case_id=truth.case_id,
        slice_type=SliceType.AGENTIC,
        observation_available=True,
        agentic=AgenticCaseObservation(
            expectation_kind="shadow_degraded_fail_closed",
            degraded_fail_closed=True,
            production_store_mutated=False,
            dependency_degraded=False,
        ),
    )
    result = AgenticSliceScorer().score(
        truth,
        observation,
        ctx=ScorerContext(seed=1, dataset_id="dataset-test", dataset_version="v1"),
    )
    assert result.outcome == ScorerOutcome.FAIL
    assert result.reason_code == "dependency_degraded_required"


@pytest.mark.evaluation
def test_gate_fail_closed_on_unexpected_agentic_dependency_degraded() -> None:
    threshold = EvaluationThresholdManifest(
        manifest_version="test",
        dataset_id="agentic_coordination_v1",
        max_unexpected_dependency_degraded=0,
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
        case_results=[
            EvaluationCaseResult(
                case_id="agentic-degraded-unexpected",
                truth_id="truth-1",
                truth_revision=1,
                truth_content_hash="a" * 64,
                slice_type=SliceType.AGENTIC,
                observation=CaseObservation(
                    case_id="agentic-degraded-unexpected",
                    slice_type=SliceType.AGENTIC,
                    observation_available=True,
                    agentic=AgenticCaseObservation(
                        expectation_kind="shadow_isolation",
                        shadow_namespace_used=True,
                        production_store_mutated=False,
                        dependency_degraded=True,
                    ),
                ),
                scorer_results=[
                    EvaluationScorerResult(
                        scorer_id="agentic_shadow",
                        outcome=ScorerOutcome.FAIL,
                        reason_code="required_dependency_degraded",
                    )
                ],
                case_status=EvaluationRunStatus.FAILED,
            )
        ],
        registry=default_scorer_registry(),
    )
    assert gate.verdict == GateVerdict.FAIL_CLOSED
    assert any(diff.field == "unexpected_dependency_degraded_count" for diff in gate.diffs)


@pytest.mark.evaluation
def test_gate_fail_closed_on_unexpected_coordination_dependency_degraded() -> None:
    threshold = EvaluationThresholdManifest(
        manifest_version="test",
        dataset_id="agentic_coordination_v1",
        max_unexpected_dependency_degraded=0,
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
        case_results=[
            EvaluationCaseResult(
                case_id="coordination-degraded-unexpected",
                truth_id="truth-1",
                truth_revision=1,
                truth_content_hash="a" * 64,
                slice_type=SliceType.COORDINATION,
                observation=CaseObservation(
                    case_id="coordination-degraded-unexpected",
                    slice_type=SliceType.COORDINATION,
                    observation_available=True,
                    coordination=CoordinationCaseObservation(
                        expectation_kind="stale_fencing_denied",
                        stale_fencing_denied=True,
                        dependency_degraded=True,
                    ),
                ),
                scorer_results=[
                    EvaluationScorerResult(
                        scorer_id="coordination_ledger",
                        outcome=ScorerOutcome.FAIL,
                        reason_code="required_dependency_degraded",
                    )
                ],
                case_status=EvaluationRunStatus.FAILED,
            )
        ],
        registry=default_scorer_registry(),
    )
    assert gate.verdict == GateVerdict.FAIL_CLOSED
    assert any(diff.field == "unexpected_dependency_degraded_count" for diff in gate.diffs)


@pytest.mark.evaluation
def test_manifest_documents_slice_adapter_stub_replay_fidelity() -> None:
    manifest = json.loads((DATASET_DIR / "manifest.json").read_text(encoding="utf-8"))
    notes = manifest["evaluation_notes"]
    assert "slice_adapter_stub" in notes
    assert "replay_variant=pass" in notes


@pytest.mark.evaluation
def test_committed_fixtures_use_pass_replay_variant() -> None:
    cases = load_fixture_cases(DATASET_DIR)
    assert cases
    assert all(case["slice_expectation"].get("replay_variant", "pass") == "pass" for case in cases)


@pytest.mark.evaluation
def test_fixture_cases_cover_phase_b_and_c_variants() -> None:
    cases = load_fixture_cases(DATASET_DIR)
    agentic_kinds = {
        case["slice_expectation"]["expectation_kind"]
        for case in cases
        if case["slice_expectation"]["slice_type"] == "agentic"
    }
    coordination_kinds = {
        case["slice_expectation"]["expectation_kind"]
        for case in cases
        if case["slice_expectation"]["slice_type"] == "coordination"
    }
    assert agentic_kinds == {
        "shadow_isolation",
        "bounded_pivot_success",
        "evidence_fidelity",
        "no_raw_cot",
        "shadow_cross_tenant_denied",
        "shadow_budget_race",
        "shadow_degraded_fail_closed",
        "shadow_unsupported_tool_denied",
    }
    assert coordination_kinds == {
        "stale_fencing_denied",
        "artifact_idempotent_replay",
        "attempt_history_auditable",
        "cross_tenant_task_denied",
        "prompt_injection_projection_denied",
        "forged_grant_denied",
        "crash_retry_no_duplicate_terminal",
        "side_effect_unknown_manual",
    }


@pytest.mark.evaluation
@pytest.mark.asyncio
@requires_postgres
async def test_agentic_coordination_dataset_runs_all_cases(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple[list, object],
) -> None:
    _, manifest = loaded_dataset
    artifact = await run_fixture_evaluation(
        truth_service,
        manifest,
        seed=42,
        code_sha="evaluation-baseline-v1",
        threshold_manifest_path=DATASET_DIR / "threshold_manifest.json",
        dataset_dir=DATASET_DIR,
    )
    assert artifact.status == EvaluationRunStatus.COMPLETED
    assert artifact.aggregates.case_count == 16
    assert artifact.aggregates.pass_rate == 1.0
    assert artifact.aggregates.fail_count == 0
    assert artifact.aggregates.error_count == 0
    assert artifact.gate is not None
    assert artifact.gate.verdict == GateVerdict.PASS
    assert all(result.case_status == EvaluationRunStatus.COMPLETED for result in artifact.case_results)
    assert {result.slice_type for result in artifact.case_results} == {
        SliceType.AGENTIC,
        SliceType.COORDINATION,
    }


@pytest.mark.evaluation
@pytest.mark.asyncio
@requires_postgres
async def test_critical_agentic_failure_fail_closed_gate(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple[list, object],
) -> None:
    _, manifest = loaded_dataset
    await truth_service.persist(
        build_evaluation_case_truth(
            tenant_id=manifest.tenant_id,
            dataset_id=manifest.dataset_id,
            dataset_version=manifest.dataset_version,
            case_id="critical-agentic-fail-extra",
            slice_expectation=AgenticSliceExpectation(
                expectation_kind=AgenticExpectationKind.SHADOW_ISOLATION,
                critical=True,
                expected_shadow_namespace_used=True,
                expected_production_store_mutated=False,
                replay_variant="fail",
            ),
            label_provenance=_provenance(),
        )
    )
    manifest = await truth_service.get_dataset_manifest(
        tenant_id=manifest.tenant_id,
        dataset_id=manifest.dataset_id,
        dataset_version=manifest.dataset_version,
    )
    artifact = await run_fixture_evaluation(
        truth_service,
        manifest,
        seed=42,
        code_sha="evaluation-baseline-v1",
        threshold_manifest_path=DATASET_DIR / "threshold_manifest.json",
        dataset_dir=DATASET_DIR,
    )
    assert artifact.aggregates.fail_count >= 1
    assert artifact.gate is not None
    assert artifact.gate.verdict in {GateVerdict.FAIL, GateVerdict.FAIL_CLOSED}
    assert any(diff.field.startswith("critical:") for diff in artifact.gate.diffs)


@pytest.mark.evaluation
@pytest.mark.asyncio
@requires_postgres
async def test_critical_coordination_failure_fail_closed_gate(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple[list, object],
) -> None:
    _, manifest = loaded_dataset
    await truth_service.persist(
        build_evaluation_case_truth(
            tenant_id=manifest.tenant_id,
            dataset_id=manifest.dataset_id,
            dataset_version=manifest.dataset_version,
            case_id="critical-coordination-fail-extra",
            slice_expectation=CoordinationSliceExpectation(
                expectation_kind=CoordinationExpectationKind.STALE_FENCING_DENIED,
                critical=True,
                expected_stale_fencing_denied=True,
                replay_variant="fail",
            ),
            label_provenance=_provenance(),
        )
    )
    manifest = await truth_service.get_dataset_manifest(
        tenant_id=manifest.tenant_id,
        dataset_id=manifest.dataset_id,
        dataset_version=manifest.dataset_version,
    )
    artifact = await run_fixture_evaluation(
        truth_service,
        manifest,
        seed=42,
        code_sha="evaluation-baseline-v1",
        threshold_manifest_path=DATASET_DIR / "threshold_manifest.json",
        dataset_dir=DATASET_DIR,
    )
    assert artifact.aggregates.fail_count >= 1
    assert artifact.gate is not None
    assert artifact.gate.verdict in {GateVerdict.FAIL, GateVerdict.FAIL_CLOSED}
    assert any(diff.field.startswith("critical:") for diff in artifact.gate.diffs)


@pytest.mark.evaluation
def test_baseline_artifact_matches_current_runner() -> None:
    baseline_path = DATASET_DIR / "baseline_artifact.json"
    assert baseline_path.is_file()
    payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert payload["aggregates"]["case_count"] == 16
    assert payload["aggregates"]["pass_rate"] == 1.0
    assert payload["gate"]["verdict"] == "pass"


@pytest.mark.evaluation
@pytest.mark.asyncio
@requires_postgres
async def test_committed_agentic_coordination_baseline_matches_fixture_run(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple[list, object],
) -> None:
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
        dataset_dir=DATASET_DIR,
    )
    assert diff_against_baseline(baseline, candidate) == []
