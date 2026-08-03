"""Organization policy profile service tests (ISSUE-129 / #635)."""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.errors import ValidationError
from app.models.organization_policy_profile import OrganizationPolicyProfileUpsertRequest
from app.services.organization_policy_profile_service import OrganizationPolicyProfileService

BACKEND_DIR = Path(__file__).resolve().parents[2]

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


@pytest.fixture(scope="module")
def migrated() -> None:
    os.environ["DATABASE_URL"] = DATABASE_URL
    from app.core.config import get_settings

    get_settings.cache_clear()
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(
    migrated: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def clean_profile_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async with session_factory() as session:
        async with session.begin():
            await session.execute(text("DELETE FROM organization_policy_profile"))
    yield


@pytest.mark.asyncio
@requires_postgres
async def test_upsert_profile_increments_revision(
    session_factory: async_sessionmaker[AsyncSession],
    clean_profile_tables: None,
) -> None:
    service = OrganizationPolicyProfileService(session_factory)
    tenant_id = f"tenant-profile-{uuid.uuid4().hex[:8]}"
    first = await service.upsert_profile(
        OrganizationPolicyProfileUpsertRequest(
            tenant_id=tenant_id,
            owner_principal="owner-a",
            framework_allowlist=("nist_csf",),
        ),
        actor_principal="admin-a",
    )
    second = await service.upsert_profile(
        OrganizationPolicyProfileUpsertRequest(
            tenant_id=tenant_id,
            owner_principal="owner-a",
            framework_allowlist=("nist_csf", "iso27001"),
        ),
        actor_principal="admin-a",
    )
    assert first.profile_id == second.profile_id
    assert first.revision == 1
    assert second.revision == 2
    assert second.framework_allowlist == ("nist_csf", "iso27001")


@pytest.mark.asyncio
@requires_postgres
async def test_validate_profile_revision_not_found_raises(
    session_factory: async_sessionmaker[AsyncSession],
    clean_profile_tables: None,
) -> None:
    service = OrganizationPolicyProfileService(session_factory)
    tenant_id = f"tenant-profile-{uuid.uuid4().hex[:8]}"
    profile = await service.upsert_profile(
        OrganizationPolicyProfileUpsertRequest(
            tenant_id=tenant_id,
            owner_principal="owner-a",
            framework_allowlist=("nist_csf",),
        ),
        actor_principal="admin-a",
    )
    with pytest.raises(ValidationError, match="profile revision not found"):
        await service.validate_profile_revision(
            tenant_id=tenant_id,
            profile_id=profile.profile_id,
            profile_revision=99,
        )


@pytest.mark.asyncio
@requires_postgres
async def test_get_effective_profile_requires_non_empty_principal(
    session_factory: async_sessionmaker[AsyncSession],
    clean_profile_tables: None,
) -> None:
    service = OrganizationPolicyProfileService(session_factory)
    with pytest.raises(ValidationError, match="authenticated principal required"):
        await service.get_effective_profile(tenant_id="tenant-a", principal="  ")


@pytest.mark.asyncio
@requires_postgres
async def test_upsert_profile_requires_actor_principal(
    session_factory: async_sessionmaker[AsyncSession],
    clean_profile_tables: None,
) -> None:
    service = OrganizationPolicyProfileService(session_factory)
    with pytest.raises(ValidationError, match="actor principal required"):
        await service.upsert_profile(
            OrganizationPolicyProfileUpsertRequest(
                tenant_id=f"tenant-profile-{uuid.uuid4().hex[:8]}",
                owner_principal="owner-a",
            ),
            actor_principal="",
        )


@pytest.mark.asyncio
@requires_postgres
async def test_concurrent_first_upsert_profile_single_lineage(
    session_factory: async_sessionmaker[AsyncSession],
    clean_profile_tables: None,
) -> None:
    service = OrganizationPolicyProfileService(session_factory)
    tenant_id = f"tenant-concurrent-{uuid.uuid4().hex[:8]}"
    request = OrganizationPolicyProfileUpsertRequest(
        tenant_id=tenant_id,
        owner_principal="owner-a",
        framework_allowlist=("nist_csf",),
    )
    first, second = await asyncio.gather(
        service.upsert_profile(request, actor_principal="admin-a"),
        service.upsert_profile(request, actor_principal="admin-a"),
    )
    profile_ids = {first.profile_id, second.profile_id}
    assert len(profile_ids) == 1
    revisions = sorted({first.revision, second.revision})
    assert revisions == [1, 2]


@pytest.mark.asyncio
@requires_postgres
async def test_get_effective_profile_rejects_cross_tenant_scope(
    session_factory: async_sessionmaker[AsyncSession],
    clean_profile_tables: None,
) -> None:
    service = OrganizationPolicyProfileService(session_factory)
    tenant_id = f"tenant-profile-{uuid.uuid4().hex[:8]}"
    await service.upsert_profile(
        OrganizationPolicyProfileUpsertRequest(
            tenant_id=tenant_id,
            owner_principal="owner-a",
            framework_allowlist=("nist_csf",),
        ),
        actor_principal="admin-a",
        authorized_tenant_id=tenant_id,
    )
    with pytest.raises(ValidationError, match="cross-tenant"):
        await service.get_effective_profile(
            tenant_id=tenant_id,
            principal="owner-a",
            authorized_tenant_id="tenant-other",
        )


@pytest.mark.asyncio
@requires_postgres
async def test_upsert_profile_rejects_empty_framework_allowlist(
    session_factory: async_sessionmaker[AsyncSession],
    clean_profile_tables: None,
) -> None:
    service = OrganizationPolicyProfileService(session_factory)
    with pytest.raises(ValidationError, match="framework allowlist must be non-empty"):
        await service.upsert_profile(
            OrganizationPolicyProfileUpsertRequest(
                tenant_id=f"tenant-profile-{uuid.uuid4().hex[:8]}",
                owner_principal="owner-a",
                framework_allowlist=(),
            ),
            actor_principal="admin-a",
        )
