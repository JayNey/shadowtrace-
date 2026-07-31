"""Tests for EvaluationCaseTruth canonical contract (ISSUE-113 Phase A)."""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.errors import ResourceNotFoundError, ValidationError
from app.db import models as orm
from app.evaluation.fixture_loader import load_fixture_dataset
from app.models.enums import CaseLabel, FinalVerdict
from app.models.evaluation_truth import (
    BenignSliceExpectation,
    EvaluationTruthQuery,
    LabelProvenance,
    SliceType,
    ThreatSliceExpectation,
    TruthObservationRef,
    UnevaluableSliceExpectation,
)
from app.services.evaluation_truth_service import (
    EvaluationTruthService,
    _parse_slice_expectation,
    build_evaluation_case_truth,
    compute_content_hash,
)

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


@pytest.fixture
def service(session_factory: async_sessionmaker[AsyncSession]) -> EvaluationTruthService:
    return EvaluationTruthService(session_factory)


def _tenant() -> str:
    return f"tenant-{uuid.uuid4().hex[:8]}"


def _provenance() -> LabelProvenance:
    return LabelProvenance(
        adjudicator="test-adjudicator",
        adjudicated_at=datetime(2026, 7, 31, 8, 0, tzinfo=UTC),
        source_kind="manual_review",
        revision_notes="unit test seed",
    )


def _threat_truth(*, tenant_id: str, case_id: str):
    return build_evaluation_case_truth(
        tenant_id=tenant_id,
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id=case_id,
        slice_expectation=ThreatSliceExpectation(),
        label_provenance=_provenance(),
        observation_refs=[
            TruthObservationRef(ref_type="scenario_pack", ref_id="malicious_process")
        ],
    )


def test_slice_expectation_discriminated_union_rejects_unknown_type() -> None:
    with pytest.raises(ValidationError):
        _parse_slice_expectation({"slice_type": "security", "schema_version": "1.0"})


def test_unevaluable_slice_does_not_default_to_benign() -> None:
    truth = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="case-unevaluable",
        slice_expectation=UnevaluableSliceExpectation(
            reason_code="insufficient_observations",
            detail="missing channels",
        ),
        label_provenance=_provenance(),
    )
    assert truth.slice_expectation.slice_type == SliceType.UNEVALUABLE.value
    assert truth.slice_expectation.reason_code == "insufficient_observations"


def test_content_hash_is_stable_for_same_payload() -> None:
    truth_a = _threat_truth(tenant_id="tenant-a", case_id="case-1")
    truth_b = _threat_truth(tenant_id="tenant-a", case_id="case-1")
    assert truth_a.content_hash == truth_b.content_hash
    assert truth_a.content_hash != truth_b.truth_id


@pytest.mark.asyncio
async def test_persist_is_idempotent(service: EvaluationTruthService) -> None:
    tenant_id = _tenant()
    truth = _threat_truth(tenant_id=tenant_id, case_id="case-idempotent")
    first = await service.persist(truth)
    replay = build_evaluation_case_truth(
        tenant_id=tenant_id,
        dataset_id=truth.dataset_id,
        dataset_version=truth.dataset_version,
        case_id=truth.case_id,
        slice_expectation=ThreatSliceExpectation(),
        label_provenance=_provenance(),
        observation_refs=truth.observation_refs,
        revision=truth.revision,
    )
    second = await service.persist(replay)
    assert first.truth_id == second.truth_id
    assert first.truth_hash == second.truth_hash


@pytest.mark.asyncio
async def test_idempotency_replay_with_different_hash_fails(
    service: EvaluationTruthService,
) -> None:
    tenant_id = _tenant()
    truth = await service.persist(_threat_truth(tenant_id=tenant_id, case_id="case-hash-guard"))
    replay = truth.model_copy(
        update={
            "truth_id": f"truth-{uuid.uuid4().hex[:12]}",
            "label_provenance": truth.label_provenance.model_copy(
                update={"revision_notes": "mutated notes"}
            ),
        }
    )
    payload = replay.model_dump(mode="json", exclude={"truth_hash"})
    replay = replay.model_copy(
        update={"content_hash": compute_content_hash(payload)},
    )
    from app.services.evaluation_truth_service import compute_truth_hash

    replay = replay.model_copy(
        update={
            "truth_hash": compute_truth_hash(
                replay.model_dump(mode="json", exclude={"truth_hash"})
            )
        }
    )
    with pytest.raises(ValidationError):
        await service.persist(replay)


@pytest.mark.asyncio
async def test_append_correction_creates_new_revision(
    service: EvaluationTruthService,
) -> None:
    tenant_id = _tenant()
    original = await service.persist(_threat_truth(tenant_id=tenant_id, case_id="case-revise"))
    corrected = await service.append_correction(
        tenant_id=tenant_id,
        supersedes_truth_id=original.truth_id,
        slice_expectation=BenignSliceExpectation(),
        label_provenance=_provenance(),
        correction_reason="Adjudication overturned after analyst review",
    )
    assert corrected.revision == original.revision + 1
    assert corrected.supersedes_truth_id == original.truth_id
    assert corrected.slice_expectation.slice_type == SliceType.BENIGN.value

    latest = await service.get_latest_truth(
        tenant_id=tenant_id,
        dataset_id=original.dataset_id,
        case_id=original.case_id,
    )
    assert latest is not None
    assert latest.truth_id == corrected.truth_id


@pytest.mark.asyncio
async def test_cross_tenant_reads_are_isolated(service: EvaluationTruthService) -> None:
    tenant_a = _tenant()
    tenant_b = _tenant()
    truth = await service.persist(_threat_truth(tenant_id=tenant_a, case_id="case-tenant"))

    assert await service.get_truth(truth.truth_id, tenant_id=tenant_a) is not None
    assert await service.get_truth(truth.truth_id, tenant_id=tenant_b) is None

    result = await service.query_truths(
        EvaluationTruthQuery(tenant_id=tenant_b, dataset_id=truth.dataset_id)
    )
    assert result.total == 0
    assert result.items == []


@pytest.mark.asyncio
async def test_query_truths_filters_by_slice_type(service: EvaluationTruthService) -> None:
    tenant_id = _tenant()
    await service.persist(_threat_truth(tenant_id=tenant_id, case_id="case-threat"))
    await service.persist(
        build_evaluation_case_truth(
            tenant_id=tenant_id,
            dataset_id="dataset-test",
            dataset_version="v1",
            case_id="case-benign",
            slice_expectation=BenignSliceExpectation(),
            label_provenance=_provenance(),
        )
    )

    threat_only = await service.query_truths(
        EvaluationTruthQuery(
            tenant_id=tenant_id,
            dataset_id="dataset-test",
            slice_type=SliceType.THREAT,
        )
    )
    assert threat_only.total == 1
    assert threat_only.items[0].slice_expectation.slice_type == SliceType.THREAT.value


@pytest.mark.asyncio
async def test_get_dataset_manifest_uses_latest_revision_per_case(
    service: EvaluationTruthService,
) -> None:
    tenant_id = _tenant()
    original = await service.persist(_threat_truth(tenant_id=tenant_id, case_id="case-manifest"))
    await service.append_correction(
        tenant_id=tenant_id,
        supersedes_truth_id=original.truth_id,
        slice_expectation=BenignSliceExpectation(),
        label_provenance=_provenance(),
        correction_reason="manifest revision test",
    )
    manifest = await service.get_dataset_manifest(
        tenant_id=tenant_id,
        dataset_id=original.dataset_id,
        dataset_version=original.dataset_version,
    )
    assert manifest.case_count == 1
    assert len(manifest.content_hash) == 64


@pytest.mark.asyncio
async def test_fixture_loader_persists_demo_dataset(
    service: EvaluationTruthService,
) -> None:
    truths, manifest = await load_fixture_dataset(service, DATASET_DIR)
    assert len(truths) == 3
    assert manifest.case_count == 3
    expected_hash = "8e15545dfa63e63233a434e96a06211c60fa58706ff137effa56f23fe70406f4"
    assert manifest.content_hash == expected_hash

    slice_types = {truth.slice_expectation.slice_type for truth in truths}
    assert slice_types == {
        SliceType.THREAT.value,
        SliceType.BENIGN.value,
        SliceType.UNEVALUABLE.value,
    }


@pytest.mark.asyncio
async def test_append_correction_requires_existing_truth(
    service: EvaluationTruthService,
) -> None:
    tenant_id = _tenant()
    with pytest.raises(ResourceNotFoundError):
        await service.append_correction(
            tenant_id=tenant_id,
            supersedes_truth_id="truth-does-not-exist",
            slice_expectation=ThreatSliceExpectation(),
            label_provenance=_provenance(),
            correction_reason="missing prior",
        )


@pytest.mark.asyncio
async def test_revision_chain_is_queryable(
    service: EvaluationTruthService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tenant_id = _tenant()
    first = await service.persist(_threat_truth(tenant_id=tenant_id, case_id="case-chain"))
    second = await service.append_correction(
        tenant_id=tenant_id,
        supersedes_truth_id=first.truth_id,
        slice_expectation=BenignSliceExpectation(
            expected_case_label=CaseLabel.FALSE_POSITIVE,
            expected_final_verdict=FinalVerdict.FALSE_POSITIVE,
        ),
        label_provenance=_provenance(),
        correction_reason="chain test",
    )

    async with session_factory() as session:
        rows = await session.scalars(
            select(orm.EvaluationCaseTruth)
            .where(
                orm.EvaluationCaseTruth.tenant_id == tenant_id,
                orm.EvaluationCaseTruth.case_id == first.case_id,
            )
            .order_by(orm.EvaluationCaseTruth.revision.asc())
        )
        chain = list(rows)
    assert len(chain) == 2
    assert chain[0].truth_id == first.truth_id
    assert chain[1].supersedes_truth_id == first.truth_id
    assert chain[1].truth_id == second.truth_id


def test_build_truth_redacts_sensitive_provenance() -> None:
    secret = "Bearer adjudicator-secret-token-113"
    truth = build_evaluation_case_truth(
        tenant_id="tenant-a",
        dataset_id="dataset-test",
        dataset_version="v1",
        case_id="case-pii",
        slice_expectation=ThreatSliceExpectation(),
        label_provenance=LabelProvenance(
            adjudicator=f"reviewer {secret}",
            adjudicated_at=datetime(2026, 7, 31, 8, 0, tzinfo=UTC),
            source_kind="manual_review",
            revision_notes=f"notes contain {secret}",
        ),
    )
    serialized = str(truth.label_provenance.model_dump(mode="json"))
    assert secret not in serialized
    assert "[REDACTED]" in truth.label_provenance.adjudicator


@pytest.mark.asyncio
async def test_query_truths_latest_revision_only_excludes_superseded(
    service: EvaluationTruthService,
) -> None:
    tenant_id = _tenant()
    original = await service.persist(_threat_truth(tenant_id=tenant_id, case_id="case-latest-only"))
    await service.append_correction(
        tenant_id=tenant_id,
        supersedes_truth_id=original.truth_id,
        slice_expectation=BenignSliceExpectation(),
        label_provenance=_provenance(),
        correction_reason="latest-only query test",
    )

    latest_only = await service.query_truths(
        EvaluationTruthQuery(
            tenant_id=tenant_id,
            dataset_id=original.dataset_id,
        )
    )
    assert latest_only.total == 1
    assert latest_only.items[0].revision == 2
    assert latest_only.items[0].slice_expectation.slice_type == SliceType.BENIGN.value

    include_history = await service.query_truths(
        EvaluationTruthQuery(
            tenant_id=tenant_id,
            dataset_id=original.dataset_id,
            latest_revision_only=False,
        )
    )
    assert include_history.total == 2


@pytest.mark.asyncio
async def test_append_correction_rejects_cross_tenant_supersedes(
    service: EvaluationTruthService,
) -> None:
    tenant_a = _tenant()
    tenant_b = _tenant()
    truth = await service.persist(_threat_truth(tenant_id=tenant_a, case_id="case-cross-tenant"))
    with pytest.raises(ResourceNotFoundError):
        await service.append_correction(
            tenant_id=tenant_b,
            supersedes_truth_id=truth.truth_id,
            slice_expectation=BenignSliceExpectation(),
            label_provenance=_provenance(),
            correction_reason="cross tenant must fail",
        )


@pytest.mark.asyncio
async def test_append_correction_requires_non_empty_reason(
    service: EvaluationTruthService,
) -> None:
    tenant_id = _tenant()
    truth = await service.persist(_threat_truth(tenant_id=tenant_id, case_id="case-empty-reason"))
    with pytest.raises(ValidationError, match="correction_reason is required"):
        await service.append_correction(
            tenant_id=tenant_id,
            supersedes_truth_id=truth.truth_id,
            slice_expectation=BenignSliceExpectation(),
            label_provenance=_provenance(),
            correction_reason="   ",
        )


@pytest.mark.asyncio
async def test_fixture_loader_manifest_matches_service_after_load(
    service: EvaluationTruthService,
) -> None:
    truths, loader_manifest = await load_fixture_dataset(service, DATASET_DIR)
    service_manifest = await service.get_dataset_manifest(
        tenant_id=loader_manifest.tenant_id,
        dataset_id=loader_manifest.dataset_id,
        dataset_version=loader_manifest.dataset_version,
    )
    assert loader_manifest.content_hash == service_manifest.content_hash
    assert loader_manifest.case_count == service_manifest.case_count == len(truths)
