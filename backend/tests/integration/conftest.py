"""Real PostgreSQL/Redis fixtures for the ISSUE-017 quality gate and ISSUE-039 e2e."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from httpx import ASGITransport
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.adapters.mock_xdr import MockXDRSourceAdapter
from app.core.redis_client import RedisClient
from app.data_generators.scenarios import build_scenario, write_scenario_artifacts
from app.db.base import Base
from app.ingestion.source_ingester import SourceIngester
from app.mock_xdr.api import create_app
from app.mock_xdr.state import MockXDRState
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService
from app.services.event_service import EventService

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
BUSINESS_TABLES = tuple(sorted(Base.metadata.tables))


def _alembic_config() -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return config


@pytest.fixture(scope="session")
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


@pytest_asyncio.fixture
async def db_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    async with session_factory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def redis_client() -> AsyncIterator[RedisClient]:
    client = RedisClient(url=REDIS_URL)
    if not await client.ping():
        await client.aclose()
        pytest.fail("Redis is required for integration tests; run `make integration-test`")
    yield client
    await client.aclose()


async def _truncate_business_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    quoted = ", ".join(f'"{table}"' for table in BUSINESS_TABLES)
    async with session_factory() as session:
        async with session.begin():
            await session.execute(text(f"TRUNCATE TABLE {quoted} RESTART IDENTITY CASCADE"))


async def _clear_shadowtrace_keys(redis_client: RedisClient) -> None:
    client = redis_client.get_client()
    keys = [key async for key in client.scan_iter(match="shadowtrace:*", count=500)]
    if keys:
        await client.delete(*keys)


@pytest_asyncio.fixture
async def clean_state(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: RedisClient,
) -> AsyncIterator[None]:
    """Reset PG/Redis around a test.

    Not autouse: ``tool_system`` chains in this package are in-memory and must
    not pull Dockerized Postgres/Redis. Real ``@pytest.mark.integration``
    modules opt in via ``pytest.mark.usefixtures("clean_state")``.
    """
    await _truncate_business_tables(session_factory)
    await _clear_shadowtrace_keys(redis_client)
    yield
    await _clear_shadowtrace_keys(redis_client)
    await _truncate_business_tables(session_factory)


@pytest.fixture
def mock_data_dir(tmp_path: Path) -> Path:
    target = tmp_path / "mock-data"
    scenario = build_scenario("insider_data_exfiltration", seed=42)
    write_scenario_artifacts(scenario, target)
    return target


@pytest.fixture
def mock_xdr_state() -> MockXDRState:
    state = MockXDRState()
    state.load_scenario(build_scenario("insider_data_exfiltration", seed=42))
    return state


@pytest_asyncio.fixture
async def mock_xdr_client(
    mock_xdr_state: MockXDRState,
) -> AsyncIterator[httpx.AsyncClient]:
    transport = ASGITransport(app=create_app(state=mock_xdr_state))
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://mock-xdr",
        timeout=30.0,
    ) as client:
        yield client


@pytest.fixture
def source_adapter(mock_xdr_client: httpx.AsyncClient) -> MockXDRSourceAdapter:
    return MockXDRSourceAdapter(
        base_url="http://mock-xdr",
        read_token="mock-read-token",
        write_token="mock-write-token",
        client=mock_xdr_client,
        max_retries=0,
    )


@pytest.fixture
def context_store(
    redis_client: RedisClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> EventContextStore:
    return EventContextStore(redis_client, session_factory)


@pytest.fixture
def event_service(
    context_store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> EventService:
    degraded = DegradedFlagService(context_store, session_factory)
    return EventService(
        session_factory,
        context_store,
        degraded_flags=degraded,
    )


@pytest.fixture
def source_ingester(
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> SourceIngester:
    return SourceIngester(
        event_service,
        session_factory,
        source_mode="mock_xdr",
    )


@pytest.fixture
def state_machine(
    context_store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
    degraded_flags_service: DegradedFlagService,
) -> Any:
    """StateMachineService with audit log persistence (ISSUE-039)."""
    from app.services.event_audit_log_service import EventAuditLogService
    from app.services.state_machine_service import StateMachineService

    audit_log = EventAuditLogService(session_factory)
    return StateMachineService(
        session_factory,
        context_store,
        audit_log=audit_log,
        degraded_flags=degraded_flags_service,
    )


@pytest.fixture
def degraded_flags_service(
    context_store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> DegradedFlagService:
    """Standalone DegradedFlagService (for use alongside state_machine)."""
    return DegradedFlagService(context_store, session_factory)


# --------------------------------------------------------------------------- #
# ISSUE-039 fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def mock_llm_client() -> Any:
    """Mock LLM client with golden responses (ISSUE-039 e2e_basic)."""
    from app.core.llm.mock_client import MockLLMClient

    return MockLLMClient()


@pytest.fixture
def failing_llm_client() -> Any:
    """LLM client that raises LLMError on every call (ISSUE-039 scenario 4).

    Uses LLMError (not RuntimeError) so Agent except LLMError handlers
    correctly trigger the degradation path.
    """
    from app.core.errors import LLMError

    class _FailingLLMClient:
        primary_model = "failing-mock"

        async def chat(self, *args: Any, **kwargs: Any) -> Any:
            raise LLMError(
                "llm unavailable",
                error_code="llm_provider_error",
                retryable=False,
            )

    return _FailingLLMClient()


@pytest.fixture
def working_memory(
    context_store: EventContextStore,
    redis_client: RedisClient,
    degraded_flags_service: DegradedFlagService,
) -> Any:
    """Shared WorkingMemory for integration tests (ISSUE-039)."""
    from app.services.working_memory import WorkingMemory

    return WorkingMemory(
        store=context_store,
        redis=redis_client,
        degraded_flags=degraded_flags_service,
    )


@pytest.fixture
def mock_xdr_state_fp() -> MockXDRState:
    """MockXDRState loaded with account_anomaly_fp scenario.

    DEPRECATED: Not referenced by any current test. Scenario 2 uses
    _create_event directly rather than the fp ingestion path. Kept for
    future adopter scenarios that need a false-positive mock XDR state.
    """
    state = MockXDRState()
    state.load_scenario(build_scenario("account_anomaly_fp", seed=42))
    return state


@pytest_asyncio.fixture
async def mock_xdr_client_fp(
    mock_xdr_state_fp: MockXDRState,
) -> AsyncIterator[httpx.AsyncClient]:
    """HTTP client pointed at the account_anomaly_fp mock XDR app.

    DEPRECATED: Not referenced by any current test. See mock_xdr_state_fp.
    """
    transport = ASGITransport(app=create_app(state=mock_xdr_state_fp))
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://mock-xdr-fp",
        timeout=30.0,
    ) as client:
        yield client


@pytest.fixture
def source_adapter_fp(
    mock_xdr_client_fp: httpx.AsyncClient,
) -> MockXDRSourceAdapter:
    """MockXDRSourceAdapter for account_anomaly_fp scenario.

    DEPRECATED: Not referenced by any current test. See mock_xdr_state_fp.
    """
    return MockXDRSourceAdapter(
        base_url="http://mock-xdr-fp",
        read_token="mock-read-token",
        write_token="mock-write-token",
        client=mock_xdr_client_fp,
        max_retries=0,
    )


@pytest.fixture
def source_ingester_fp(
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> SourceIngester:
    """SourceIngester for account_anomaly_fp scenario.

    DEPRECATED: Not referenced by any current test. See mock_xdr_state_fp.
    """
    return SourceIngester(
        event_service,
        session_factory,
        source_mode="mock_xdr",
    )
