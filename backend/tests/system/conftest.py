"""Fixtures for ISSUE-086 system tests (Postgres + Redis required)."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import pytest_asyncio
from httpx import ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.mock_xdr import MockXDRDispositionAdapter, MockXDRSourceAdapter
from app.adapters.registry import DispositionAdapterRegistry
from app.core.event_bus import EventBus
from app.core.redis_client import RedisClient
from app.mock_xdr.api import create_app
from app.mock_xdr.state import MockXDRState
from app.services.context_service import EventContextStore
from app.services.decision_record_service import DecisionRecordService
from app.services.degraded_flag_service import DegradedFlagService
from app.services.disposition_command_factory import DispositionCommandFactory
from app.services.disposition_sync_service import DispositionSyncService
from app.services.event_audit_log_service import EventAuditLogService
from app.services.event_disposition_service import EventDispositionService
from app.services.state_machine_service import StateMachineService
from app.services.terminal_disposition_resolver import TerminalDispositionResolver

pytestmark = [pytest.mark.system, pytest.mark.integration]


@pytest_asyncio.fixture
async def mock_xdr_client(mock_xdr_state: MockXDRState) -> Any:
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


@pytest_asyncio.fixture
async def disposition_sync_service(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
) -> DispositionSyncService:
    adapter = MockXDRDispositionAdapter(
        base_url="http://mock-xdr",
        read_token="mock-read-token",
        write_token="mock-write-token",
        client=mock_xdr_client,
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
async def event_disposition_service(
    session_factory: async_sessionmaker[AsyncSession],
    disposition_sync_service: DispositionSyncService,
    context_store: EventContextStore,
    redis_client: RedisClient,
    degraded_flags: DegradedFlagService,
) -> EventDispositionService:
    return EventDispositionService(
        session_factory,
        disposition_sync=disposition_sync_service,
        context_store=context_store,
        resolver=TerminalDispositionResolver(),
        factory=DispositionCommandFactory(),
        event_bus=EventBus(redis_client),
        event_disposition_supported=True,
        decision_record_service=DecisionRecordService(
            session_factory,
            degraded_flag_service=degraded_flags,
        ),
    )


@pytest_asyncio.fixture
async def state_machine_service(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    degraded_flags: DegradedFlagService,
) -> StateMachineService:
    audit_log = EventAuditLogService(session_factory)
    return StateMachineService(
        session_factory,
        context_store,
        audit_log=audit_log,
        degraded_flags=degraded_flags,
    )
