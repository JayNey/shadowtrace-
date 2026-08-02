"""ToolCallGrant service tests (ISSUE-134 / #640)."""

from __future__ import annotations

import asyncio
import os
import uuid
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

from app.core.errors import ToolCallGrantDeniedError, ToolCallGrantUnavailableError
from app.db import models as orm
from app.models.tool_call_grant import (
    BoundExecutionPrincipal,
    ToolCallGrantCreateRequest,
    ToolCallGrantScope,
    ToolCallMode,
)
from app.services.tool_call_grant_service import ToolCallGrantService, build_react_grant_request

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


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
async def clean_grant_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.ToolCallAttemptORM))
            await session.execute(delete(orm.ToolCallGrantORM))
    yield
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.ToolCallAttemptORM))
            await session.execute(delete(orm.ToolCallGrantORM))


@pytest_asyncio.fixture
def service(session_factory: async_sessionmaker[AsyncSession]) -> ToolCallGrantService:
    return ToolCallGrantService(session_factory)


async def _issue(
    service: ToolCallGrantService,
    *,
    event_id: str,
    max_calls: int = 3,
    mode: ToolCallMode = ToolCallMode.PRODUCTION,
    shadow_run_id: str | None = None,
) -> tuple[object, str]:
    request = build_react_grant_request(
        event_id=event_id,
        tenant_id="tenant-a",
        allowed_tools=["query_dns", "query_edr_process"],
        max_calls=max_calls,
        mode=mode,
        shadow_run_id=shadow_run_id,
    )
    issued = await service.issue_grant(request)
    assert issued.grant_token
    return issued.grant, issued.grant_token


@pytest.mark.asyncio
async def test_issue_and_load_grant(service: ToolCallGrantService) -> None:
    sfx = _sfx()
    event_id = f"evt-grant-{sfx}"
    grant, token = await _issue(service, event_id=event_id)
    loaded = await service.load_grant(grant.grant_id, grant_token=token)
    assert loaded.grant_id == grant.grant_id
    assert loaded.event_id == event_id
    assert loaded.mode is ToolCallMode.PRODUCTION
    assert loaded.namespace_key == f"production:{event_id}"


@pytest.mark.asyncio
async def test_invalid_token_rejected(service: ToolCallGrantService) -> None:
    sfx = _sfx()
    grant, _token = await _issue(service, event_id=f"evt-grant-{sfx}")
    with pytest.raises(ToolCallGrantDeniedError, match="token"):
        await service.load_grant(grant.grant_id, grant_token="wrong-token")


@pytest.mark.asyncio
async def test_reserve_attempt_counts_denied_paths(service: ToolCallGrantService) -> None:
    sfx = _sfx()
    event_id = f"evt-grant-{sfx}"
    grant, _token = await _issue(service, event_id=event_id, max_calls=2)
    first, _ = await service.reserve_attempt(
        grant.grant_id,
        tool_name="query_dns",
        params={"domain": "example.com"},
        event_id=event_id,
    )
    second, _ = await service.reserve_attempt(
        grant.grant_id,
        tool_name="query_dns",
        params={"domain": "example.org"},
        event_id=event_id,
    )
    assert first.attempt_seq == 1
    assert second.attempt_seq == 2
    with pytest.raises(ToolCallGrantDeniedError, match="max_calls"):
        await service.reserve_attempt(
            grant.grant_id,
            tool_name="query_dns",
            params={},
            event_id=event_id,
        )
    assert await service.count_attempts(grant.grant_id) == 2


@pytest.mark.asyncio
async def test_cross_event_reuse_denied(service: ToolCallGrantService) -> None:
    sfx = _sfx()
    grant, _token = await _issue(service, event_id=f"evt-a-{sfx}")
    with pytest.raises(ToolCallGrantDeniedError, match="cross-event"):
        await service.reserve_attempt(
            grant.grant_id,
            tool_name="query_dns",
            params={},
            event_id=f"evt-b-{sfx}",
        )


@pytest.mark.asyncio
async def test_expired_grant_denied(service: ToolCallGrantService) -> None:
    sfx = _sfx()
    event_id = f"evt-exp-{sfx}"
    request = ToolCallGrantCreateRequest(
        event_id=event_id,
        tenant_id="tenant-a",
        scope=ToolCallGrantScope(allowed_tools=["query_dns"]),
        execution_principal=BoundExecutionPrincipal(
            principal_id=f"tcp-{sfx}",
            agent_name="react_engine",
            actor_type="react_engine",
        ),
        max_calls=2,
        valid_for_seconds=1,
        idempotency_key=f"idk-{sfx}",
    )
    issued = await service.issue_grant(request)
    async with service._session_factory() as session:  # noqa: SLF001 — test setup
        row = await session.get(orm.ToolCallGrantORM, issued.grant.grant_id)
        assert row is not None
        row.valid_from = datetime.now(tz=UTC) - timedelta(hours=1)
        row.expires_at = datetime.now(tz=UTC) - timedelta(seconds=1)
        await session.commit()
    with pytest.raises(ToolCallGrantDeniedError, match="expired"):
        await service.reserve_attempt(
            issued.grant.grant_id,
            tool_name="query_dns",
            params={},
            event_id=event_id,
        )


@pytest.mark.asyncio
async def test_shadow_namespace_isolated(service: ToolCallGrantService) -> None:
    sfx = _sfx()
    shadow_run_id = f"shadow-{sfx}"
    grant, _token = await _issue(
        service,
        event_id=f"evt-shadow-{sfx}",
        mode=ToolCallMode.SHADOW,
        shadow_run_id=shadow_run_id,
    )
    assert grant.mode is ToolCallMode.SHADOW
    assert grant.namespace_key == f"shadow:{shadow_run_id}"
    await service.reserve_attempt(
        grant.grant_id,
        tool_name="query_dns",
        params={},
        event_id=grant.event_id,
    )
    prod_attempts = await service.count_production_attempts_for_event(grant.event_id)
    assert prod_attempts == 0


@pytest.mark.asyncio
async def test_concurrent_reserve_respects_max_calls(service: ToolCallGrantService) -> None:
    sfx = _sfx()
    event_id = f"evt-conc-{sfx}"
    grant, _token = await _issue(service, event_id=event_id, max_calls=5)

    async def _one() -> int | None:
        try:
            attempt, _ = await service.reserve_attempt(
                grant.grant_id,
                tool_name="query_dns",
                params={"seq": uuid.uuid4().hex},
                event_id=event_id,
            )
            return attempt.attempt_seq
        except ToolCallGrantDeniedError:
            return None

    results = await asyncio.gather(*[_one() for _ in range(20)])
    successes = [value for value in results if value is not None]
    assert len(successes) == 5


@pytest.mark.asyncio
async def test_budget_seq_mismatch_fail_closed(service: ToolCallGrantService) -> None:
    sfx = _sfx()
    event_id = f"evt-seq-{sfx}"
    grant, _token = await _issue(service, event_id=event_id, max_calls=3)
    original_reserve = service._budget_reservation.reserve  # noqa: SLF001 — test hook
    call_count = 0

    async def _flaky_reserve(**kwargs: object) -> int:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return await original_reserve(**kwargs)  # type: ignore[arg-type]
        return 999

    service._budget_reservation.reserve = _flaky_reserve  # type: ignore[method-assign]  # noqa: SLF001

    await service.reserve_attempt(
        grant.grant_id,
        tool_name="query_dns",
        params={},
        event_id=event_id,
    )
    with pytest.raises(ToolCallGrantDeniedError, match="budget seq mismatch"):
        await service.reserve_attempt(
            grant.grant_id,
            tool_name="query_dns",
            params={"retry": True},
            event_id=event_id,
        )
    assert await service.count_attempts(grant.grant_id) == 1


@pytest.mark.asyncio
async def test_idempotency_replay(service: ToolCallGrantService) -> None:
    sfx = _sfx()
    request = build_react_grant_request(
        event_id=f"evt-idem-{sfx}",
        tenant_id="tenant-a",
        allowed_tools=["query_dns"],
        max_calls=2,
    )
    request.idempotency_key = f"idem-{sfx}"
    first = await service.issue_grant(request)
    second = await service.issue_grant(request)
    assert first.grant.grant_id == second.grant.grant_id
    assert second.grant_token == ""


@pytest.mark.asyncio
async def test_revoked_grant_denied_on_subsequent_call(service: ToolCallGrantService) -> None:
    sfx = _sfx()
    event_id = f"evt-revoke-{sfx}"
    grant, _token = await _issue(service, event_id=event_id, max_calls=3)
    await service.revoke_grant(grant.grant_id)
    with pytest.raises(ToolCallGrantDeniedError, match="revoked"):
        await service.reserve_attempt(
            grant.grant_id,
            tool_name="query_dns",
            params={},
            event_id=event_id,
        )
