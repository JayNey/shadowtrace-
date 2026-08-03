"""Policy release service integration tests (ISSUE-129 / #635)."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.core.errors import ValidationError
from app.db import models as orm
from app.models.attack_control_mapping import MappingApprovalState
from app.models.knowledge_release import KnowledgeReleaseLifecycleState, KnowledgeReleaseProvenance
from app.models.organization_policy_profile import OrganizationPolicyProfileUpsertRequest
from app.models.policy_citation import ApplicabilityStatus
from app.models.policy_release import POLICY_CORPUS_ID, PolicyControlRef
from app.services.organization_policy_profile_service import OrganizationPolicyProfileService
from app.services.policy_applicability_service import build_technique_policy_citations
from app.services.policy_query_plan_service import (
    resolve_active_policy_query_plan,
    validate_pinned_policy_query_plan,
)
from app.services.policy_release_resolver import compute_policy_control_hash, default_policy_provenance
from app.services.policy_release_service import PolicyReleaseService
from app.services.knowledge_release_resolver import kb_name_to_corpus

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_DIR.parent
DATA_FILE = REPO_ROOT / "data" / "knowledge" / "policy_controls.json"

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
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


def _run_migrations() -> None:
    os.environ["DATABASE_URL"] = DATABASE_URL
    from app.core.config import get_settings

    get_settings.cache_clear()
    command.upgrade(_alembic_config(), "head")


@pytest.fixture(scope="module")
def migrated() -> None:
    _run_migrations()


@pytest_asyncio.fixture
async def session_factory(
    migrated: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def clean_policy_tables(session_factory: async_sessionmaker[AsyncSession]) -> AsyncIterator[None]:
    async with session_factory() as session:
        async with session.begin():
            await session.execute(text("DELETE FROM attack_control_mapping"))
            await session.execute(text("DELETE FROM policy_release_object"))
            await session.execute(text("DELETE FROM organization_policy_profile"))
            await session.execute(
                text("DELETE FROM knowledge_release WHERE corpus_id = :corpus_id"),
                {"corpus_id": POLICY_CORPUS_ID},
            )
    yield


def test_policy_kb_name_maps_to_corpus() -> None:
    assert kb_name_to_corpus("policy_kb") == POLICY_CORPUS_ID


@pytest.mark.asyncio
@requires_postgres
async def test_stage_activate_and_pin_policy_release(
    session_factory: async_sessionmaker[AsyncSession],
    clean_policy_tables: None,
) -> None:
    settings = Settings(embedding_mode="mock")
    release_service = PolicyReleaseService(session_factory, settings=settings)
    profile_service = OrganizationPolicyProfileService(session_factory)
    bundle = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    provenance = KnowledgeReleaseProvenance.model_validate(
        default_policy_provenance(str(DATA_FILE))
    )

    staged = await release_service.stage_policy_bundle(
        bundle,
        release_version="v1",
        provenance=provenance,
    )
    assert staged.lifecycle_state.value == "staged"
    active = await release_service.activate_release(staged.release_id)
    assert active.lifecycle_state is KnowledgeReleaseLifecycleState.ACTIVE

    tenant_id = f"tenant-policy-{uuid.uuid4().hex[:8]}"
    await profile_service.upsert_profile(
        OrganizationPolicyProfileUpsertRequest(
            tenant_id=tenant_id,
            owner_principal="principal-policy",
            framework_allowlist=("nist_csf",),
            jurisdiction_codes=("US",),
            industry_codes=("finance",),
        ),
        actor_principal="principal-policy",
    )

    plan = await resolve_active_policy_query_plan(
        release_service,
        profile_service,
        settings,
        tenant_id=tenant_id,
        principal="principal-policy",
        trace_id="trace-policy-001",
    )
    assert plan is not None
    assert plan.knowledge_plan.active_release_id == active.release_id
    assert plan.knowledge_plan.tenant_id == tenant_id
    assert plan.knowledge_plan.principal == "principal-policy"
    assert plan.profile_revision == 1
    assert plan.plan_hash

    approved = await release_service.list_approved_mappings(active.release_id, technique_id="T1059")
    assert len(approved) == 1
    assert approved[0].approval_state is MappingApprovalState.APPROVED

    async with session_factory() as session:
        from sqlalchemy import func

        candidate_count = await session.scalar(
            select(func.count())
            .select_from(orm.AttackControlMappingORM)
            .where(
                orm.AttackControlMappingORM.release_id == active.release_id,
                orm.AttackControlMappingORM.approval_state == MappingApprovalState.CANDIDATE.value,
            )
        )
        assert candidate_count == 1

    async with session_factory() as session:
        obj = await session.scalar(
            select(orm.PolicyReleaseObjectORM).where(
                orm.PolicyReleaseObjectORM.release_id == active.release_id,
                orm.PolicyReleaseObjectORM.control_id == approved[0].control_id,
            )
        )
        assert obj is not None
        from app.models.policy_release import PolicyControl

        control = PolicyControl.model_validate(obj.payload)

    profile = await profile_service.get_effective_profile(
        tenant_id=tenant_id,
        principal="principal-policy",
    )
    citations = build_technique_policy_citations(
        technique_id="T1059",
        release_id=active.release_id,
        mappings=await release_service.list_approved_mappings(active.release_id),
        controls_by_id={control.control_id: control},
        profile=profile,
    )
    assert len(citations) == 1
    assert citations[0].applicability_status is ApplicabilityStatus.APPLICABLE

    ref = PolicyControlRef(
        control_id=control.control_id,
        framework_id=control.framework_id,
        release_id=active.release_id,
        release_version=active.release_version,
        content_hash=compute_policy_control_hash(control),
        bundle_content_hash=active.content_hash,
        text_locator=control.text_locator,
    )
    resolved_control, resolved_release = await release_service.resolve_control_ref(ref)
    assert resolved_control.control_id == control.control_id
    assert resolved_release.release_id == active.release_id


@pytest.mark.asyncio
@requires_postgres
async def test_unknown_profile_query_plan_pins_release_without_profile(
    session_factory: async_sessionmaker[AsyncSession],
    clean_policy_tables: None,
) -> None:
    settings = Settings(embedding_mode="mock")
    release_service = PolicyReleaseService(session_factory, settings=settings)
    profile_service = OrganizationPolicyProfileService(session_factory)
    bundle = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    provenance = KnowledgeReleaseProvenance.model_validate(
        default_policy_provenance(str(DATA_FILE))
    )
    staged = await release_service.stage_policy_bundle(
        bundle,
        release_version="v1",
        provenance=provenance,
    )
    await release_service.activate_release(staged.release_id)

    plan = await resolve_active_policy_query_plan(
        release_service,
        profile_service,
        settings,
        tenant_id=f"tenant-unknown-{uuid.uuid4().hex[:8]}",
        principal="principal-x",
        trace_id="trace-policy-002",
    )
    assert plan is not None
    assert plan.profile_id is None
    assert plan.profile_revision is None


@pytest.mark.asyncio
@requires_postgres
async def test_stage_policy_bundle_idempotent_replay(
    session_factory: async_sessionmaker[AsyncSession],
    clean_policy_tables: None,
) -> None:
    release_service = PolicyReleaseService(session_factory, settings=Settings(embedding_mode="mock"))
    bundle = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    provenance = KnowledgeReleaseProvenance.model_validate(
        default_policy_provenance(str(DATA_FILE))
    )
    first = await release_service.stage_policy_bundle(
        bundle,
        release_version="v1",
        provenance=provenance,
    )
    second = await release_service.stage_policy_bundle(
        bundle,
        release_version="v1",
        provenance=provenance,
    )
    assert first.release_id == second.release_id


@pytest.mark.asyncio
@requires_postgres
async def test_activate_rejects_failed_release(
    session_factory: async_sessionmaker[AsyncSession],
    clean_policy_tables: None,
) -> None:
    release_service = PolicyReleaseService(session_factory, settings=Settings(embedding_mode="mock"))
    bundle = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    provenance = KnowledgeReleaseProvenance.model_validate(
        default_policy_provenance(str(DATA_FILE))
    )
    staged = await release_service.stage_policy_bundle(
        bundle,
        release_version="v1",
        provenance=provenance,
    )
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.KnowledgeReleaseORM, staged.release_id)
            assert row is not None
            row.lifecycle_state = KnowledgeReleaseLifecycleState.FAILED.value
    with pytest.raises(ValidationError, match="failed policy release"):
        await release_service.activate_release(staged.release_id)


@pytest.mark.asyncio
@requires_postgres
async def test_resolve_control_ref_rejects_content_hash_mismatch(
    session_factory: async_sessionmaker[AsyncSession],
    clean_policy_tables: None,
) -> None:
    release_service = PolicyReleaseService(session_factory, settings=Settings(embedding_mode="mock"))
    bundle = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    provenance = KnowledgeReleaseProvenance.model_validate(
        default_policy_provenance(str(DATA_FILE))
    )
    staged = await release_service.stage_policy_bundle(
        bundle,
        release_version="v1",
        provenance=provenance,
    )
    active = await release_service.activate_release(staged.release_id)
    async with session_factory() as session:
        obj = await session.scalar(
            select(orm.PolicyReleaseObjectORM).where(
                orm.PolicyReleaseObjectORM.release_id == active.release_id,
            )
        )
        assert obj is not None
        from app.models.policy_release import PolicyControl

        control = PolicyControl.model_validate(obj.payload)
    ref = PolicyControlRef(
        control_id=control.control_id,
        framework_id=control.framework_id,
        release_id=active.release_id,
        release_version=active.release_version,
        content_hash="f" * 64,
        bundle_content_hash=active.content_hash,
        text_locator=control.text_locator,
    )
    with pytest.raises(ValidationError, match="content hash mismatch"):
        await release_service.resolve_control_ref(ref)


@pytest.mark.asyncio
@requires_postgres
async def test_resolve_control_ref_rejects_framework_drift(
    session_factory: async_sessionmaker[AsyncSession],
    clean_policy_tables: None,
) -> None:
    release_service = PolicyReleaseService(session_factory, settings=Settings(embedding_mode="mock"))
    bundle = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    provenance = KnowledgeReleaseProvenance.model_validate(
        default_policy_provenance(str(DATA_FILE))
    )
    staged = await release_service.stage_policy_bundle(
        bundle,
        release_version="v1",
        provenance=provenance,
    )
    active = await release_service.activate_release(staged.release_id)
    async with session_factory() as session:
        obj = await session.scalar(
            select(orm.PolicyReleaseObjectORM).where(
                orm.PolicyReleaseObjectORM.release_id == active.release_id,
            )
        )
        assert obj is not None
        from app.models.policy_release import PolicyControl

        control = PolicyControl.model_validate(obj.payload)
    ref = PolicyControlRef(
        control_id=control.control_id,
        framework_id="iso27001",
        release_id=active.release_id,
        release_version=active.release_version,
        content_hash=compute_policy_control_hash(control),
        bundle_content_hash=active.content_hash,
        text_locator=control.text_locator,
    )
    with pytest.raises(ValidationError, match="framework mismatch"):
        await release_service.resolve_control_ref(ref)


@pytest.mark.asyncio
@requires_postgres
async def test_validate_pinned_policy_query_plan_uses_historical_revision(
    session_factory: async_sessionmaker[AsyncSession],
    clean_policy_tables: None,
) -> None:
    settings = Settings(embedding_mode="mock")
    release_service = PolicyReleaseService(session_factory, settings=settings)
    profile_service = OrganizationPolicyProfileService(session_factory)
    bundle = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    provenance = KnowledgeReleaseProvenance.model_validate(
        default_policy_provenance(str(DATA_FILE))
    )
    staged = await release_service.stage_policy_bundle(
        bundle,
        release_version="v1",
        provenance=provenance,
    )
    await release_service.activate_release(staged.release_id)
    tenant_id = f"tenant-policy-{uuid.uuid4().hex[:8]}"
    await profile_service.upsert_profile(
        OrganizationPolicyProfileUpsertRequest(
            tenant_id=tenant_id,
            owner_principal="principal-policy",
            framework_allowlist=("nist_csf",),
        ),
        actor_principal="principal-policy",
    )
    plan = await resolve_active_policy_query_plan(
        release_service,
        profile_service,
        settings,
        tenant_id=tenant_id,
        principal="principal-policy",
        trace_id="trace-policy-stale",
    )
    assert plan is not None
    await profile_service.upsert_profile(
        OrganizationPolicyProfileUpsertRequest(
            tenant_id=tenant_id,
            owner_principal="principal-policy",
            framework_allowlist=("nist_csf", "iso27001"),
        ),
        actor_principal="principal-policy",
    )
    pinned_profile = await validate_pinned_policy_query_plan(
        plan,
        profile_service,
        tenant_id=tenant_id,
        principal="principal-policy",
    )
    assert pinned_profile is not None
    assert pinned_profile.revision == 1
    assert pinned_profile.framework_allowlist == ("nist_csf",)


@pytest.mark.asyncio
@requires_postgres
async def test_activate_retires_previous_active_policy_release(
    session_factory: async_sessionmaker[AsyncSession],
    clean_policy_tables: None,
) -> None:
    release_service = PolicyReleaseService(session_factory, settings=Settings(embedding_mode="mock"))
    bundle = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    provenance = KnowledgeReleaseProvenance.model_validate(
        default_policy_provenance(str(DATA_FILE))
    )
    staged_v1 = await release_service.stage_policy_bundle(
        bundle,
        release_version="v1",
        provenance=provenance,
    )
    bundle_v2 = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    bundle_v2["controls"][0]["title"] = "Identity and Access Management (rev2)"
    staged_v2 = await release_service.stage_policy_bundle(
        bundle_v2,
        release_version="v2",
        provenance=provenance,
    )
    active_v1 = await release_service.activate_release(staged_v1.release_id)
    assert active_v1.lifecycle_state is KnowledgeReleaseLifecycleState.ACTIVE

    active_v2 = await release_service.activate_release(staged_v2.release_id)
    assert active_v2.lifecycle_state is KnowledgeReleaseLifecycleState.ACTIVE

    retired_v1 = await release_service.get_release(staged_v1.release_id)
    assert retired_v1 is not None
    assert retired_v1.lifecycle_state is KnowledgeReleaseLifecycleState.RETIRED


@pytest.mark.asyncio
@requires_postgres
async def test_stage_policy_bundle_rejects_incomplete_replay(
    session_factory: async_sessionmaker[AsyncSession],
    clean_policy_tables: None,
) -> None:
    release_service = PolicyReleaseService(session_factory, settings=Settings(embedding_mode="mock"))
    bundle = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    provenance = KnowledgeReleaseProvenance.model_validate(
        default_policy_provenance(str(DATA_FILE))
    )
    staged = await release_service.stage_policy_bundle(
        bundle,
        release_version="v1",
        provenance=provenance,
    )
    async with session_factory() as session:
        async with session.begin():
            await session.execute(
                text("DELETE FROM policy_release_object WHERE release_id = :release_id"),
                {"release_id": staged.release_id},
            )
    with pytest.raises(ValidationError, match="policy release bundle incomplete"):
        await release_service.stage_policy_bundle(
            bundle,
            release_version="v1",
            provenance=provenance,
        )


@pytest.mark.asyncio
@requires_postgres
async def test_resolve_active_policy_query_plan_rejects_cross_tenant_scope(
    session_factory: async_sessionmaker[AsyncSession],
    clean_policy_tables: None,
) -> None:
    settings = Settings(embedding_mode="mock")
    release_service = PolicyReleaseService(session_factory, settings=settings)
    profile_service = OrganizationPolicyProfileService(session_factory)
    bundle = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    provenance = KnowledgeReleaseProvenance.model_validate(
        default_policy_provenance(str(DATA_FILE))
    )
    staged = await release_service.stage_policy_bundle(
        bundle,
        release_version="v1",
        provenance=provenance,
    )
    await release_service.activate_release(staged.release_id)
    tenant_id = f"tenant-policy-{uuid.uuid4().hex[:8]}"
    await profile_service.upsert_profile(
        OrganizationPolicyProfileUpsertRequest(
            tenant_id=tenant_id,
            owner_principal="principal-policy",
            framework_allowlist=("nist_csf",),
        ),
        actor_principal="principal-policy",
        authorized_tenant_id=tenant_id,
    )
    plan = await resolve_active_policy_query_plan(
        release_service,
        profile_service,
        settings,
        tenant_id=tenant_id,
        principal="principal-policy",
        trace_id="trace-policy-cross-tenant",
    )
    assert plan is not None
    with pytest.raises(ValidationError, match="cross-tenant"):
        await validate_pinned_policy_query_plan(
            plan,
            profile_service,
            tenant_id=tenant_id,
            principal="principal-policy",
            authorized_tenant_id="tenant-other",
        )
