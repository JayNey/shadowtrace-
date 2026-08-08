"""Fixtures for adversarial agent audits (isolated from demo scenario registry)."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from httpx import ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.mock_xdr import MockXDRDispositionAdapter, MockXDRSourceAdapter
from app.adapters.registry import DispositionAdapterRegistry
from app.core.config import Settings, get_settings
from app.core.event_bus import EventBus
from app.core.llm.base import InMemoryLLMCallAuditRecorder
from app.core.llm.factory import get_llm_client
from app.core.llm.mock_client import MockLLMClient
from app.core.redis_client import RedisClient
from app.data_generators.scenarios import write_scenario_artifacts
from app.mock_xdr.api import create_app
from app.mock_xdr.state import MockXDRState
from app.services.budget_service import BudgetService
from app.services.context_service import EventContextStore
from app.services.decision_record_service import DecisionRecordService
from app.services.degraded_flag_service import DegradedFlagService
from app.services.disposition_command_factory import DispositionCommandFactory
from app.services.disposition_sync_service import DispositionSyncService
from app.services.event_disposition_service import EventDispositionService
from tests.adversarial.scenario_credential_db_staging_exfil import (
    build_adversarial_credential_db_staging_exfil,
)
from tests.adversarial.xdr_verify_observation import (
    AdversarialTerminalDispositionResolver,
    XdrManagedVerifyToolExecutor,
)


def _host_llm_mode() -> str:
    return os.environ.get("LLM_MODE", "mock").strip().lower()


@pytest.fixture
def e2e_tool_executor(
    tool_executor: Any,
    budget_service: BudgetService,
    session_factory: async_sessionmaker[AsyncSession],
) -> XdrManagedVerifyToolExecutor:
    wrapped = XdrManagedVerifyToolExecutor(tool_executor, session_factory)
    wrapped.budget_service = budget_service
    return wrapped


@pytest.fixture
def e2e_settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    """Honor host LLM_* env for live adversarial audits; default remains mock."""
    llm_mode = _host_llm_mode()
    monkeypatch.setenv("SOURCE_MODE", "mock_xdr")
    monkeypatch.setenv("DISPOSITION_MODE", "mock_xdr")
    monkeypatch.setenv("ALLOW_LIVE_SIDE_EFFECTS", "false")
    monkeypatch.setenv("ALLOW_XDR_WRITEBACK", "false")
    monkeypatch.setenv("LLM_MODE", llm_mode)
    monkeypatch.setenv("ORCHESTRATION_MODE", "graph")
    monkeypatch.setenv("BUDGET_ENABLED", "false")
    if llm_mode == "openai_compatible":
        for key in (
            "LLM_API_BASE_URL",
            "LLM_API_KEY",
            "LLM_PRIMARY_MODEL",
            "LLM_FALLBACK_MODELS",
            "LLM_TIMEOUT_SECONDS",
        ):
            if key in os.environ:
                monkeypatch.setenv(key, os.environ[key])
    get_settings.cache_clear()
    settings = get_settings()
    yield settings
    get_settings.cache_clear()


@pytest.fixture
def mock_llm_client(budget_service: BudgetService, e2e_settings: Settings) -> Any:
    """Use real provider when LLM_MODE=openai_compatible (e.g. from .env.live)."""
    if e2e_settings.llm_mode.strip().lower() == "openai_compatible":
        return get_llm_client(
            settings=e2e_settings,
            audit_recorder=InMemoryLLMCallAuditRecorder(),
            budget_service=budget_service,
        )
    return MockLLMClient(
        audit_recorder=InMemoryLLMCallAuditRecorder(),
        budget_service=budget_service,
    )


@pytest.fixture(scope="session")
def adversarial_scenario():
    return build_adversarial_credential_db_staging_exfil(seed=9918)


@pytest.fixture
def adversarial_mock_dir(tmp_path: Path, adversarial_scenario) -> Path:
    target = tmp_path / "adversarial-mock-data"
    write_scenario_artifacts(adversarial_scenario, target)
    return target


@pytest.fixture
def adversarial_mock_state(adversarial_scenario) -> MockXDRState:
    state = MockXDRState()
    state.load_scenario(adversarial_scenario)
    return state


@pytest_asyncio.fixture
async def adversarial_mock_client(
    adversarial_mock_state: MockXDRState,
) -> AsyncIterator[httpx.AsyncClient]:
    transport = ASGITransport(app=create_app(state=adversarial_mock_state))
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://mock-xdr",
        timeout=30.0,
    ) as client:
        yield client


@pytest.fixture
def adversarial_source_adapter(
    adversarial_mock_client: httpx.AsyncClient,
) -> MockXDRSourceAdapter:
    return MockXDRSourceAdapter(
        base_url="http://mock-xdr",
        read_token="mock-read-token",
        write_token="mock-write-token",
        client=adversarial_mock_client,
        max_retries=0,
    )


@pytest_asyncio.fixture
async def adversarial_disposition_sync_service(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    adversarial_mock_client: httpx.AsyncClient,
) -> DispositionSyncService:
    adapter = MockXDRDispositionAdapter(
        base_url="http://mock-xdr",
        read_token="mock-read-token",
        write_token="mock-write-token",
        client=adversarial_mock_client,
        max_retries=0,
    )
    registry = DispositionAdapterRegistry()
    registry.register("mock_xdr", adapter)
    return DispositionSyncService(
        session_factory,
        context_store=context_store,
        adapter_registry=registry,
    )


@pytest_asyncio.fixture
async def adversarial_event_disposition_service(
    session_factory: async_sessionmaker[AsyncSession],
    adversarial_disposition_sync_service: DispositionSyncService,
    context_store: EventContextStore,
    redis_client: RedisClient,
    degraded_flags: DegradedFlagService,
) -> EventDispositionService:
    return EventDispositionService(
        session_factory,
        disposition_sync=adversarial_disposition_sync_service,
        context_store=context_store,
        resolver=AdversarialTerminalDispositionResolver(),
        factory=DispositionCommandFactory(),
        event_bus=EventBus(redis_client),
        event_disposition_supported=True,
        decision_record_service=DecisionRecordService(
            session_factory,
            degraded_flag_service=degraded_flags,
        ),
    )
