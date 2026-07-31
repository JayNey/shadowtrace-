"""Regression-only fixtures (ISSUE-087).

Disposition services mirror ``tests/system/conftest.py`` but live here so we do
not nest ``pytest_plugins``. Integration fixtures (``mock_xdr_client``,
``session_factory``, ``state_machine_service``, …) come from the root
``tests/conftest.py`` registration of ``integration_fixtures``.
"""

from __future__ import annotations

import httpx
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.mock_xdr import MockXDRDispositionAdapter
from app.adapters.registry import DispositionAdapterRegistry
from app.core.event_bus import EventBus
from app.core.redis_client import RedisClient
from app.services.context_service import EventContextStore
from app.services.decision_record_service import DecisionRecordService
from app.services.degraded_flag_service import DegradedFlagService
from app.services.disposition_command_factory import DispositionCommandFactory
from app.services.disposition_sync_service import DispositionSyncService
from app.services.event_disposition_service import EventDispositionService
from app.services.terminal_disposition_resolver import TerminalDispositionResolver


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
