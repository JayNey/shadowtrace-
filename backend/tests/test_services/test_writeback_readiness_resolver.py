"""WritebackReadinessResolver unit tests (ISSUE-280)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.adapters.disposition.base import DispositionAdapterCapabilities
from app.models.disposition import SourceObjectLocator
from app.models.enums import (
    CapabilityState,
    ConnectorStatus,
    DispositionIntentKind,
    SourceObjectKind,
    WritebackReadiness,
)
from app.services.writeback_readiness_resolver import WritebackReadinessResolver


def _locator() -> SourceObjectLocator:
    return SourceObjectLocator(
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-disposition",
        source_kind=SourceObjectKind.INCIDENT,
        source_object_id="INC-1",
    )


def _connector(*, cred: str | None = None) -> MagicMock:
    return MagicMock(disposition_credential_ref=cred)


@pytest.mark.asyncio
async def test_ready_when_capability_supported_and_online() -> None:
    adapter = MagicMock()
    adapter.health_check = AsyncMock(return_value=ConnectorStatus.ONLINE)
    adapter.capabilities.return_value = DispositionAdapterCapabilities(
        intents={DispositionIntentKind.EVENT_STATUS_UPDATE: CapabilityState.SUPPORTED}
    )
    resolver = WritebackReadinessResolver()
    readiness, blocked = await resolver.resolve_for_locator(
        locator=_locator(),
        connector=_connector(),
        adapter=adapter,
    )
    assert readiness is WritebackReadiness.READY
    assert blocked is None


@pytest.mark.asyncio
async def test_connector_offline_blocks_readiness() -> None:
    adapter = MagicMock()
    adapter.health_check = AsyncMock(return_value=ConnectorStatus.OFFLINE)
    adapter.capabilities.return_value = DispositionAdapterCapabilities(
        intents={DispositionIntentKind.EVENT_STATUS_UPDATE: CapabilityState.SUPPORTED}
    )
    resolver = WritebackReadinessResolver()
    readiness, blocked = await resolver.resolve_for_locator(
        locator=_locator(),
        connector=_connector(),
        adapter=adapter,
    )
    assert readiness is WritebackReadiness.CONNECTOR_UNAVAILABLE
    assert blocked == "connector_offline"


@pytest.mark.asyncio
async def test_missing_connector_blocks_readiness() -> None:
    adapter = MagicMock()
    adapter.health_check = AsyncMock(return_value=ConnectorStatus.ONLINE)
    resolver = WritebackReadinessResolver()
    readiness, blocked = await resolver.resolve_for_locator(
        locator=_locator(),
        connector=None,
        adapter=adapter,
    )
    assert readiness is WritebackReadiness.CONNECTOR_UNAVAILABLE
    assert blocked == "connector_missing"
    adapter.health_check.assert_not_awaited()


@pytest.mark.asyncio
async def test_missing_env_credential_blocks_readiness(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MISSING_DISPOSITION_CRED", raising=False)
    adapter = MagicMock()
    adapter.health_check = AsyncMock(return_value=ConnectorStatus.ONLINE)
    adapter.capabilities.return_value = DispositionAdapterCapabilities()
    resolver = WritebackReadinessResolver()
    readiness, blocked = await resolver.resolve_for_locator(
        locator=_locator(),
        connector=_connector(cred="MISSING_DISPOSITION_CRED"),
        adapter=adapter,
    )
    assert readiness is WritebackReadiness.PERMISSION_DENIED
    assert blocked == "credential_unavailable"
    adapter.health_check.assert_not_awaited()


@pytest.mark.asyncio
async def test_secret_uri_credential_ref_does_not_skip_adapter_probe() -> None:
    adapter = MagicMock()
    adapter.health_check = AsyncMock(return_value=ConnectorStatus.ONLINE)
    adapter.capabilities.return_value = DispositionAdapterCapabilities(
        intents={DispositionIntentKind.EVENT_STATUS_UPDATE: CapabilityState.SUPPORTED}
    )
    resolver = WritebackReadinessResolver()
    readiness, blocked = await resolver.resolve_for_locator(
        locator=_locator(),
        connector=_connector(cred="secret://mock/disposition"),
        adapter=adapter,
    )
    assert readiness is WritebackReadiness.READY
    assert blocked is None
    adapter.health_check.assert_awaited()
