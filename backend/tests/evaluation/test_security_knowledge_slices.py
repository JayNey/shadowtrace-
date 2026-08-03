"""Security and knowledge slice evaluation tests (ISSUE-136 / #642 Phase A)."""

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
from app.evaluation.fixture_loader import (
    load_fixture_cases,
    load_fixture_dataset,
)
from app.evaluation.replayer import MockDeterministicReplayer, resolve_replay_fidelity
from app.evaluation.runner import run_fixture_evaluation
from app.evaluation.scorers.base import ScorerContext, ScorerRegistration
from app.evaluation.scorers.knowledge_scorers import KnowledgeSliceScorer
from app.evaluation.scorers.registry import ScorerRegistry, default_scorer_registry
from app.evaluation.scorers.security_scorers import SecuritySliceScorer
from app.evaluation.threshold import evaluate_gate, load_threshold_manifest
from app.models.evaluation_run import (
    CaseObservation,
    EvaluationAggregateMetrics,
    EvaluationCaseResult,
    EvaluationRunStatus,
    EvaluationScorerResult,
    EvaluationThresholdManifest,
    GateVerdict,
    KnowledgeCaseObservation,
    ScorerOutcome,
)
from app.models.evaluation_truth import (
    KnowledgeExpectationKind,
    KnowledgeSliceExpectation,
    LabelProvenance,
    SecurityExpectationKind,
    SecuritySliceExpectation,
    SliceType,
    ThreatSliceExpectation,
)
from app.services.evaluation_truth_service import (
    EvaluationTruthService,
    _parse_slice_expectation,
    build_evaluation_case_truth,
)

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_DIR.parent
DATASET_DIR = REPO_ROOT / "data" / "evaluation" / "security_knowledge_v1"
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
        adjudicated_at=datetime(2026, 8, 1, 8, 0, tzinfo=UTC),
        source_kind="manual_review",
        revision_notes="unit test seed",
    )


@pytest.mark.evaluation
def test_security_and_knowledge_scorers_are_registered() -> None:
    registry = default_scorer_registry()
    assert "security_gate" in registry.scorer_ids
    assert "knowledge_retrieval" in registry.scorer_ids


@pytest.mark.evaluation
def test_parse_slice_expectation_accepts_security_and_knowledge() -> None:
    security = _parse_slice_expectation(
        {
            "slice_type": "security",
            "schema_version": "1.1",
            "expectation_kind": "cross_tenant_denied",
            "expected_cross_tenant_denied": True,
            "expected_production_store_mutated": False,
        }
    )
    assert isinstance(security, SecuritySliceExpectation)
    assert security.expectation_kind == SecurityExpectationKind.CROSS_TENANT_DENIED

    knowledge = _parse_slice_expectation(
        {
            "slice_type": "knowledge",
            "schema_version": "1.1",
            "expectation_kind": "tenant_filter",
            "expected_tenant_filter_applied": True,
            "expected_degraded": False,
            "expected_empty_results": False,
        }
    )
    assert isinstance(knowledge, KnowledgeSliceExpectation)
    assert knowledge.expectation_kind == KnowledgeExpectationKind.TENANT_FILTER


@pytest.mark.evaluation
def test_resolve_replay_fidelity_labels_dataset_mix() -> None:
    security = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="security-case",
        slice_expectation=SecuritySliceExpectation(
            expectation_kind=SecurityExpectationKind.CROSS_TENANT_DENIED,
            expected_cross_tenant_denied=True,
        ),
        label_provenance=_provenance(),
    )
    threat = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="threat-only",
        slice_expectation=ThreatSliceExpectation(),
        label_provenance=_provenance(),
    )
    assert resolve_replay_fidelity([threat]) == "echo_truth_stub"
    assert resolve_replay_fidelity([security]) == "slice_adapter_stub"
    assert resolve_replay_fidelity([threat, security]) == "mixed_echo_and_slice_adapter"


@pytest.mark.evaluation
def test_security_replayer_simulates_grant_boundary() -> None:
    truth = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="security-case",
        slice_expectation=SecuritySliceExpectation(
            expectation_kind=SecurityExpectationKind.CROSS_TENANT_DENIED,
            expected_cross_tenant_denied=True,
            expected_production_store_mutated=False,
        ),
        label_provenance=_provenance(),
    )
    observation = MockDeterministicReplayer().replay(truth, seed=42)
    assert observation.security is not None
    assert observation.security.cross_tenant_denied is True
    assert observation.security.production_store_mutated is False


@pytest.mark.evaluation
def test_knowledge_replayer_fail_variant_inverts_observation() -> None:
    truth = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="knowledge-case",
        slice_expectation=KnowledgeSliceExpectation(
            expectation_kind=KnowledgeExpectationKind.TENANT_FILTER,
            expected_tenant_filter_applied=True,
            expected_degraded=False,
            expected_empty_results=False,
            replay_variant="fail",
        ),
        label_provenance=_provenance(),
    )
    observation = MockDeterministicReplayer().replay(truth, seed=42)
    assert observation.knowledge is not None
    assert observation.knowledge.tenant_filter_applied is False


@pytest.mark.evaluation
def test_security_scorer_rejects_incomplete_expectation_config() -> None:
    truth = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="security-incomplete",
        slice_expectation=SecuritySliceExpectation(
            expectation_kind=SecurityExpectationKind.CROSS_TENANT_DENIED,
            expected_cross_tenant_denied=None,
            expected_production_store_mutated=False,
        ),
        label_provenance=_provenance(),
    )
    observation = MockDeterministicReplayer().replay(truth, seed=1)
    result = SecuritySliceScorer().score(
        truth,
        observation,
        ctx=ScorerContext(seed=1, dataset_id="dataset-test", dataset_version="v1"),
    )
    assert result.outcome == ScorerOutcome.FAIL
    assert result.reason_code == "invalid_expectation_config"


@pytest.mark.evaluation
def test_knowledge_scorer_rejects_incomplete_expectation_config() -> None:
    truth = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="knowledge-incomplete",
        slice_expectation=KnowledgeSliceExpectation(
            expectation_kind=KnowledgeExpectationKind.CITATION_CORRECTNESS,
            expected_citation_chunk_ids=[],
            expected_degraded=False,
            expected_empty_results=False,
        ),
        label_provenance=_provenance(),
    )
    observation = MockDeterministicReplayer().replay(truth, seed=1)
    result = KnowledgeSliceScorer().score(
        truth,
        observation,
        ctx=ScorerContext(seed=1, dataset_id="dataset-test", dataset_version="v1"),
    )
    assert result.outcome == ScorerOutcome.FAIL
    assert result.reason_code == "invalid_expectation_config"


@pytest.mark.evaluation
def test_slice_replay_derives_plan_hash_for_release_pinned() -> None:
    from app.evaluation.slice_replay import derive_plan_hash

    truth = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="knowledge-release-pinned",
        slice_expectation=KnowledgeSliceExpectation(
            expectation_kind=KnowledgeExpectationKind.RELEASE_PINNED_RETRIEVAL,
            expected_release_id="kbr-2026.08.01-mock",
            expected_degraded=False,
            expected_empty_results=False,
        ),
        label_provenance=_provenance(),
    )
    observation = MockDeterministicReplayer().replay(truth, seed=42)
    assert observation.knowledge is not None
    expected_hash = derive_plan_hash(
        release_id="kbr-2026.08.01-mock",
        case_id="knowledge-release-pinned",
        seed=42,
    )
    assert observation.knowledge.plan_hash == expected_hash


@pytest.mark.evaluation
def test_gate_fail_closed_on_unexpected_dependency_degraded() -> None:
    threshold = EvaluationThresholdManifest(
        manifest_version="test",
        dataset_id="security_knowledge_v1",
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
                case_id="knowledge-degraded-unexpected",
                truth_id="truth-1",
                truth_revision=1,
                truth_content_hash="a" * 64,
                slice_type=SliceType.KNOWLEDGE,
                observation=CaseObservation(
                    case_id="knowledge-degraded-unexpected",
                    slice_type=SliceType.KNOWLEDGE,
                    observation_available=True,
                    knowledge=KnowledgeCaseObservation(
                        expectation_kind="tenant_filter",
                        tenant_filter_applied=True,
                        degraded=False,
                        empty_results=False,
                        dependency_degraded=True,
                    ),
                ),
                scorer_results=[
                    EvaluationScorerResult(
                        scorer_id="knowledge_retrieval",
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
def test_gate_min_case_count_exceeded() -> None:
    threshold = EvaluationThresholdManifest(
        manifest_version="test",
        dataset_id="security_knowledge_v1",
        min_case_count=11,
    )
    gate = evaluate_gate(
        threshold,
        aggregates=EvaluationAggregateMetrics(
            case_count=10,
            pass_count=10,
            fail_count=0,
            unevaluable_count=0,
            error_count=0,
            pass_rate=1.0,
        ),
        case_results=[],
        registry=default_scorer_registry(),
    )
    assert gate.verdict == GateVerdict.FAIL
    assert any(diff.field == "case_count" for diff in gate.diffs)


@pytest.mark.evaluation
def test_gate_max_unevaluable_exceeded() -> None:
    threshold = EvaluationThresholdManifest(
        manifest_version="test",
        dataset_id="security_knowledge_v1",
        max_unevaluable_count=0,
    )
    gate = evaluate_gate(
        threshold,
        aggregates=EvaluationAggregateMetrics(
            case_count=2,
            pass_count=1,
            fail_count=0,
            unevaluable_count=1,
            error_count=0,
            pass_rate=1.0,
        ),
        case_results=[],
        registry=default_scorer_registry(),
    )
    assert gate.verdict == GateVerdict.FAIL
    assert any(diff.field == "unevaluable_count" for diff in gate.diffs)


@pytest.mark.evaluation
def test_required_scorer_error_fail_closed() -> None:
    threshold = EvaluationThresholdManifest(
        manifest_version="test",
        dataset_id="security_knowledge_v1",
        required_scorers=["security_gate"],
        required_gate=True,
    )
    gate = evaluate_gate(
        threshold,
        aggregates=EvaluationAggregateMetrics(
            case_count=1,
            pass_count=0,
            fail_count=0,
            unevaluable_count=0,
            error_count=1,
            pass_rate=0.0,
        ),
        case_results=[
            EvaluationCaseResult(
                case_id="security-error",
                truth_id="truth-1",
                truth_revision=1,
                truth_content_hash="a" * 64,
                slice_type=SliceType.SECURITY,
                observation=CaseObservation(
                    case_id="security-error",
                    slice_type=SliceType.SECURITY,
                    observation_available=False,
                ),
                scorer_results=[
                    EvaluationScorerResult(
                        scorer_id="security_gate",
                        outcome=ScorerOutcome.ERROR,
                        reason_code="scorer_exception",
                    )
                ],
                case_status=EvaluationRunStatus.FAILED,
                critical=True,
            )
        ],
        registry=default_scorer_registry(),
    )
    assert gate.verdict == GateVerdict.FAIL_CLOSED
    assert any(diff.field == "scorer:security_gate" for diff in gate.diffs)


@pytest.mark.evaluation
@pytest.mark.asyncio
@requires_postgres
async def test_security_knowledge_dataset_run_passes(
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
        dataset_dir=DATASET_DIR,
    )

    assert artifact.config.replay_fidelity == "slice_adapter_stub"
    assert artifact.config.release_refs.kb_release_id == "kbr-2026.08.01-mock"
    assert artifact.aggregates.case_count == 11
    assert artifact.aggregates.pass_count == 11
    assert artifact.aggregates.fail_count == 0
    assert artifact.aggregates.error_count == 0
    assert artifact.aggregates.unevaluable_count == 0
    assert artifact.status == EvaluationRunStatus.COMPLETED
    assert artifact.gate is not None
    assert artifact.gate.verdict == GateVerdict.PASS

    security_cases = [c for c in artifact.case_results if c.slice_type == SliceType.SECURITY]
    knowledge_cases = [c for c in artifact.case_results if c.slice_type == SliceType.KNOWLEDGE]
    assert len(security_cases) == 7
    assert len(knowledge_cases) == 4
    assert all(c.critical for c in security_cases)
    assert all(not c.critical for c in knowledge_cases)


@pytest.mark.evaluation
@pytest.mark.asyncio
@requires_postgres
async def test_critical_failure_overrides_high_pass_rate(
    truth_service: EvaluationTruthService,
    loaded_dataset: tuple,
) -> None:
    _, manifest = loaded_dataset
    await truth_service.persist(
        build_evaluation_case_truth(
            tenant_id=manifest.tenant_id,
            dataset_id=manifest.dataset_id,
            dataset_version=manifest.dataset_version,
            case_id="critical-security-fail-extra",
            slice_expectation=SecuritySliceExpectation(
                expectation_kind=SecurityExpectationKind.PRODUCTION_ISOLATION,
                critical=True,
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
        code_sha="deadbeef",
        threshold_manifest_path=DATASET_DIR / "threshold_manifest.json",
        dataset_dir=DATASET_DIR,
    )
    assert artifact.aggregates.pass_rate > 0.0
    assert artifact.aggregates.fail_count >= 1
    assert artifact.status == EvaluationRunStatus.FAILED
    assert artifact.gate is not None
    assert artifact.gate.verdict == GateVerdict.FAIL
    assert any(diff.field.startswith("critical:") for diff in artifact.gate.diffs)


@pytest.mark.evaluation
def test_critical_gate_unit() -> None:
    threshold = load_threshold_manifest(DATASET_DIR / "threshold_manifest.json")
    gate = evaluate_gate(
        threshold,
        aggregates=EvaluationAggregateMetrics(
            case_count=2,
            pass_count=1,
            fail_count=1,
            unevaluable_count=0,
            error_count=0,
            pass_rate=0.5,
        ),
        case_results=[
            EvaluationCaseResult(
                case_id="critical-security-fail",
                truth_id="truth-1",
                truth_revision=1,
                truth_content_hash="a" * 64,
                slice_type=SliceType.SECURITY,
                observation=MockDeterministicReplayer().replay(
                    build_evaluation_case_truth(
                        tenant_id="tenant-a",
                        dataset_id="d",
                        dataset_version="v1",
                        case_id="critical-security-fail",
                        slice_expectation=SecuritySliceExpectation(
                            expectation_kind=SecurityExpectationKind.CROSS_TENANT_DENIED,
                            expected_cross_tenant_denied=True,
                        ),
                        label_provenance=_provenance(),
                    ),
                    seed=1,
                ),
                scorer_results=[
                    EvaluationScorerResult(
                        scorer_id="security_gate",
                        outcome=ScorerOutcome.FAIL,
                        reason_code="production_isolation_violation",
                    )
                ],
                case_status=EvaluationRunStatus.FAILED,
                critical=True,
            )
        ],
        registry=default_scorer_registry(),
    )
    assert gate.verdict == GateVerdict.FAIL
    assert any(diff.field == "critical:critical-security-fail" for diff in gate.diffs)


@pytest.mark.evaluation
def test_security_scorer_detects_mismatch() -> None:
    truth = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="security-mismatch",
        slice_expectation=SecuritySliceExpectation(
            expectation_kind=SecurityExpectationKind.GRANT_FORGERY_REJECTED,
            expected_grant_forgery_rejected=True,
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
            slice_expectation=SecuritySliceExpectation(
                expectation_kind=SecurityExpectationKind.GRANT_FORGERY_REJECTED,
                expected_grant_forgery_rejected=True,
                expected_production_store_mutated=False,
                replay_variant="fail",
            ),
            label_provenance=_provenance(),
        ),
        seed=7,
    )
    ctx = ScorerContext(seed=7, dataset_id="dataset-test", dataset_version="v1")
    result = SecuritySliceScorer().score(truth, observation, ctx=ctx)
    assert result.outcome == ScorerOutcome.FAIL


@pytest.mark.evaluation
def test_knowledge_scorer_detects_citation_mismatch() -> None:
    truth = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="knowledge-citation",
        slice_expectation=KnowledgeSliceExpectation(
            expectation_kind=KnowledgeExpectationKind.CITATION_CORRECTNESS,
            expected_citation_chunk_ids=["chunk-a", "chunk-b"],
            expected_degraded=False,
            expected_empty_results=False,
        ),
        label_provenance=_provenance(),
    )
    observation = MockDeterministicReplayer().replay(
        build_evaluation_case_truth(
            tenant_id=truth.tenant_id,
            dataset_id=truth.dataset_id,
            dataset_version=truth.dataset_version,
            case_id=truth.case_id,
            slice_expectation=KnowledgeSliceExpectation(
                expectation_kind=KnowledgeExpectationKind.CITATION_CORRECTNESS,
                expected_citation_chunk_ids=["chunk-a", "chunk-b"],
                expected_degraded=False,
                expected_empty_results=False,
                replay_variant="fail",
            ),
            label_provenance=_provenance(),
        ),
        seed=7,
    )
    ctx = ScorerContext(seed=7, dataset_id="dataset-test", dataset_version="v1")
    result = KnowledgeSliceScorer().score(truth, observation, ctx=ctx)
    assert result.outcome == ScorerOutcome.FAIL
    assert result.reason_code == "citation_mismatch"


@pytest.mark.evaluation
def test_fixture_cases_cover_phase_a_variants() -> None:
    cases = load_fixture_cases(DATASET_DIR)
    security_kinds = {
        case["slice_expectation"]["expectation_kind"]
        for case in cases
        if case["slice_expectation"]["slice_type"] == "security"
    }
    knowledge_kinds = {
        case["slice_expectation"]["expectation_kind"]
        for case in cases
        if case["slice_expectation"]["slice_type"] == "knowledge"
    }
    assert security_kinds == {
        "cross_tenant_denied",
        "grant_forgery_rejected",
        "grant_budget_race",
        "side_effect_blocked",
        "side_effect_unknown",
        "prompt_injection_contained",
        "production_isolation",
    }
    assert knowledge_kinds == {
        "release_pinned_retrieval",
        "citation_correctness",
        "tenant_filter",
        "degraded_no_release",
    }


@pytest.mark.evaluation
@pytest.mark.asyncio
@requires_postgres
async def test_runner_scorer_exception_surfaces_as_error(
    truth_service: EvaluationTruthService,
    clean_evaluation_truth: None,
) -> None:
    truth = build_evaluation_case_truth(
        tenant_id="tenant-evaluation-security-knowledge",
        dataset_id="security_knowledge_v1",
        dataset_version="2026.08.01",
        case_id="security-scorer-exception",
        slice_expectation=SecuritySliceExpectation(
            expectation_kind=SecurityExpectationKind.CROSS_TENANT_DENIED,
            expected_cross_tenant_denied=True,
            expected_production_store_mutated=False,
        ),
        label_provenance=_provenance(),
    )
    await truth_service.persist(truth)
    manifest = await truth_service.get_dataset_manifest(
        tenant_id=truth.tenant_id,
        dataset_id=truth.dataset_id,
        dataset_version=truth.dataset_version,
    )

    class _ExplodingScorer:
        scorer_id = "security_gate"
        supported_slices = frozenset({SliceType.SECURITY})

        def score(self, _truth, _observation, ctx) -> EvaluationScorerResult:
            del ctx
            raise RuntimeError("scorer exploded")

    registry = ScorerRegistry()
    registry.register(
        ScorerRegistration(
            scorer_id="security_gate",
            scorer=_ExplodingScorer(),
            required=True,
        )
    )
    for reg in default_scorer_registry().list_for_slice(SliceType.KNOWLEDGE):
        registry.register(reg)

    artifact = await run_fixture_evaluation(
        truth_service,
        manifest,
        seed=42,
        code_sha="deadbeef",
        threshold_manifest_path=DATASET_DIR / "threshold_manifest.json",
        registry=registry,
        dataset_dir=DATASET_DIR,
    )

    security_case = next(c for c in artifact.case_results if c.case_id == truth.case_id)
    assert any(
        r.scorer_id == "security_gate" and r.outcome == ScorerOutcome.ERROR
        for r in security_case.scorer_results
    )
    assert artifact.aggregates.error_count >= 1
    assert artifact.gate is not None
    assert artifact.gate.verdict in {GateVerdict.FAIL, GateVerdict.FAIL_CLOSED}


@pytest.mark.evaluation
@pytest.mark.asyncio
@requires_postgres
async def test_committed_security_knowledge_baseline_matches_fixture_run(
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
        dataset_dir=DATASET_DIR,
    )
    assert diff_against_baseline(baseline, candidate) == []
