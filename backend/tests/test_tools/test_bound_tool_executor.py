"""BoundToolExecutor mediation tests (ISSUE-134)."""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.errors import ToolCallGrantDeniedError
from app.db import models as orm
from app.models.enums import ActionCategory, ToolCategory
from app.models.tool_meta import RoutingKind, SideEffectLevel, ToolMeta, ToolResultStatus
from app.providers.tools.mock_provider import MockToolProvider, bind_mock_tool_provider
from app.services.evidence_projection import (
    EvidenceProjection,
    EvidenceQueryScope,
    bind_evidence_projection,
    bind_evidence_query_scope,
)
from app.services.safe_tool_projection import SafeToolProjectionService
from app.services.tool_call_grant_service import ToolCallGrantService, build_react_grant_request
from app.tools.bound_tool_executor import BoundToolExecutor
from app.tools.circuit_breaker import CircuitBreakerRegistry
from app.tools.executor import ToolExecutor
from app.tools.mock_state import MockEnvironmentState
from app.tools.query.fixture_loader import load_fixture_records
from app.tools.registry import ToolRegistry

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_DIR.parent
MOCK_DATA = REPO_ROOT / "data" / "mock"
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)

DEFAULT_SCOPE = EvidenceQueryScope(
    source_tenant_id="test-tenant",
    connector_ids=frozenset({"fixture-evidence"}),
)


WINDOW = {
    "start": "2024-06-15T08:00:00Z",
    "end": "2024-06-15T10:00:00Z",
}


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


@contextmanager
def _bound_evidence_scope(projection: EvidenceProjection) -> Iterator[None]:
    with bind_evidence_projection(projection), bind_evidence_query_scope(DEFAULT_SCOPE):
        yield


@pytest_asyncio.fixture
async def evidence_projection() -> EvidenceProjection:
    projection = EvidenceProjection.in_memory()
    loaded = await load_fixture_records(projection, MOCK_DATA)
    assert loaded > 0
    return projection


def _query_meta(name: str) -> ToolMeta:
    return ToolMeta(
        tool_name=name,
        tool_category=ToolCategory.QUERY,
        routing_kind=RoutingKind.TOOL_PROVIDER_ONLY,
        input_schema={"type": "object", "properties": {}, "additionalProperties": True},
        output_schema={"type": "object", "additionalProperties": True},
    )


def _side_effect_meta(name: str) -> ToolMeta:
    return ToolMeta(
        tool_name=name,
        tool_category=ToolCategory.RESPONSE,
        action_category=ActionCategory.RESPONSE,
        routing_kind=RoutingKind.OWNER_ROUTED,
        side_effect_level=SideEffectLevel.HIGH,
        input_schema={"type": "object", "properties": {}, "additionalProperties": True},
        output_schema={"type": "object", "additionalProperties": True},
    )


@pytest.fixture(scope="module")
def migrated_database() -> None:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    command.upgrade(cfg, "head")


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


@pytest_asyncio.fixture
def registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.auto_discover()
    return reg


@pytest_asyncio.fixture
def mock_provider() -> MockToolProvider:
    return MockToolProvider(MockEnvironmentState())


@pytest_asyncio.fixture
def executor(registry: ToolRegistry, mock_provider: MockToolProvider) -> ToolExecutor:
    return ToolExecutor(
        registry=registry,
        breaker_registry=CircuitBreakerRegistry(),
        provider_context=lambda: bind_mock_tool_provider(mock_provider),
    )


@pytest_asyncio.fixture
def grant_service(session_factory: async_sessionmaker[AsyncSession]) -> ToolCallGrantService:
    return ToolCallGrantService(session_factory)


async def _bound_executor(
    grant_service: ToolCallGrantService,
    executor: ToolExecutor,
    registry: ToolRegistry,
    *,
    event_id: str,
    allowed_tools: list[str] | None = None,
    max_calls: int = 5,
) -> BoundToolExecutor:
    issued = await grant_service.issue_grant(
        build_react_grant_request(
            event_id=event_id,
            tenant_id="tenant-a",
            allowed_tools=allowed_tools or ["query_dns"],
            max_calls=max_calls,
        )
    )
    grant = await grant_service.load_grant(issued.grant.grant_id, grant_token=issued.grant_token)
    return BoundToolExecutor(
        inner=executor,
        grant=grant,
        grant_service=grant_service,
        registry=registry,
        projection_service=SafeToolProjectionService(registry),
        grant_token=issued.grant_token,
    )


@pytest.mark.asyncio
async def test_bound_executor_allows_granted_query_tool(
    grant_service: ToolCallGrantService,
    executor: ToolExecutor,
    registry: ToolRegistry,
    evidence_projection: EvidenceProjection,
) -> None:
    sfx = _sfx()
    event_id = f"evt-bound-{sfx}"
    bound = await _bound_executor(grant_service, executor, registry, event_id=event_id)
    with _bound_evidence_scope(evidence_projection):
        result = await bound.call(
            "query_dns",
            {"domain": "unknown-upload-example.com", "time_range": WINDOW},
            event_id,
        )
    assert result.result.status in {ToolResultStatus.SUCCESS, ToolResultStatus.ACCEPTED}
    assert result.projection.projection_hash


@pytest.mark.asyncio
async def test_forged_tool_name_denied(
    grant_service: ToolCallGrantService,
    executor: ToolExecutor,
    registry: ToolRegistry,
) -> None:
    sfx = _sfx()
    event_id = f"evt-bound-{sfx}"
    bound = await _bound_executor(
        grant_service,
        executor,
        registry,
        event_id=event_id,
        allowed_tools=["query_dns"],
    )
    with pytest.raises(ToolCallGrantDeniedError, match="allow-list"):
        await bound.call("query_edr_process", {}, event_id)


@pytest.mark.asyncio
async def test_dynamic_response_tool_zero_calls(
    grant_service: ToolCallGrantService,
    executor: ToolExecutor,
    registry: ToolRegistry,
) -> None:
    sfx = _sfx()
    event_id = f"evt-bound-{sfx}"
    bound = await _bound_executor(
        grant_service,
        executor,
        registry,
        event_id=event_id,
        allowed_tools=["query_dns", "isolate_host"],
    )
    with pytest.raises(ToolCallGrantDeniedError, match="non-query"):
        await bound.call("isolate_host", {"host_id": "h1"}, event_id)


@pytest.mark.asyncio
async def test_forged_agent_name_ignored(
    grant_service: ToolCallGrantService,
    executor: ToolExecutor,
    registry: ToolRegistry,
    evidence_projection: EvidenceProjection,
) -> None:
    sfx = _sfx()
    event_id = f"evt-bound-{sfx}"
    bound = await _bound_executor(grant_service, executor, registry, event_id=event_id)
    with _bound_evidence_scope(evidence_projection):
        await bound.call(
            "query_dns",
            {"domain": "unknown-upload-example.com", "time_range": WINDOW},
            event_id,
            agent_name="forged_agent",
        )
    assert bound.trusted_agent_name == "react_engine"


@pytest.mark.asyncio
async def test_connector_scope_denied_when_param_missing(
    grant_service: ToolCallGrantService,
    executor: ToolExecutor,
    registry: ToolRegistry,
) -> None:
    sfx = _sfx()
    event_id = f"evt-bound-{sfx}"
    issued = await grant_service.issue_grant(
        build_react_grant_request(
            event_id=event_id,
            tenant_id="tenant-a",
            allowed_tools=["query_dns"],
            connector_ids=["fixture-evidence"],
            max_calls=3,
        )
    )
    grant = await grant_service.load_grant(issued.grant.grant_id, grant_token=issued.grant_token)
    bound = BoundToolExecutor(
        inner=executor,
        grant=grant,
        grant_service=grant_service,
        registry=registry,
        projection_service=SafeToolProjectionService(registry),
        grant_token=issued.grant_token,
    )
    with pytest.raises(ToolCallGrantDeniedError, match="connector scope"):
        await bound.call(
            "query_dns",
            {"domain": "example.com", "time_range": WINDOW},
            event_id,
        )


@pytest.mark.asyncio
async def test_inner_executor_failure_finalizes_attempt(
    grant_service: ToolCallGrantService,
    registry: ToolRegistry,
) -> None:
    class _FailingInner:
        registry = registry

        async def call(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("provider crashed")

    sfx = _sfx()
    event_id = f"evt-bound-{sfx}"
    bound = await _bound_executor(
        grant_service,
        _FailingInner(),  # type: ignore[arg-type]
        registry,
        event_id=event_id,
    )
    with pytest.raises(RuntimeError, match="provider crashed"):
        await bound.call(
            "query_dns",
            {"domain": "example.com", "time_range": WINDOW},
            event_id,
        )
    assert await grant_service.count_attempts(bound.grant.grant_id) == 1
