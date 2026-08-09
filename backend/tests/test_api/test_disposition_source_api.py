"""API tests for disposition-source and readiness recheck (ISSUE-280)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.disposition.base import DispositionAdapterCapabilities
from app.api.v1.deps import get_disposition_source_service, reset_deps
from app.db import models as orm
from app.main import app
from app.models.enums import (
    CapabilityState,
    ConnectorStatus,
    DispositionIntentKind,
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    SourceObjectKind,
    WritebackReadiness,
)
from app.models.source import SourceReference
from app.services.disposition_source_service import DispositionSourceService
from app.services.event_service import _ref_dump
from app.services.writeback_readiness_resolver import WritebackReadinessResolver

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("clean_state")]

_DEV_TOKENS = json.dumps(
    {
        "operator-token": {"subject": "op-1", "roles": ["disposition_operator"]},
        "analyst-token": {"subject": "analyst-1", "roles": ["analyst"]},
    }
)

# Old product fixture allowlist id — must NOT succeed when unlinked on a real event.
_FIXTURE_ALLOWLIST_SOURCE_ID = "src-associated-1"


@pytest.fixture(autouse=True)
def _dev_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.config import get_settings

    monkeypatch.setenv("DEV_AUTH_TOKENS", _DEV_TOKENS)
    get_settings.cache_clear()
    reset_deps()
    yield
    reset_deps()
    app.dependency_overrides.pop(get_disposition_source_service, None)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def _hdr() -> dict[str, str]:
    return {"Authorization": "Bearer operator-token"}


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


async def _seed(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    link_primary: bool = True,
) -> tuple[str, str]:
    """Seed connector → source_object → event → link with explicit flush ordering."""
    sfx = _sfx()
    event_id = f"evt-{sfx}"
    source_record_id = f"src-{sfx}"
    ref = SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-disposition",
        source_object_id=f"INC-{sfx}",
        ingested_at=datetime.now(UTC),
    )
    async with session_factory() as session:
        async with session.begin():
            connector = await session.get(orm.SourceConnector, "conn-disposition")
            if connector is None:
                session.add(
                    orm.SourceConnector(
                        connector_id="conn-disposition",
                        source_product="mock_xdr",
                        display_name="Mock XDR",
                        disposition_policy_default=DispositionPolicy.REQUIRED.value,
                    )
                )
            await session.flush()
            session.add(
                orm.SourceObject(
                    source_record_id=source_record_id,
                    source_product=ref.source_product,
                    source_tenant_id=ref.source_tenant_id,
                    connector_id=ref.connector_id,
                    source_kind=ref.source_kind.value,
                    source_object_id=ref.source_object_id,
                    normalized={},
                    raw_payload={},
                )
            )
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type=EventType.INSIDER_THREAT.value,
                    title="api disposition source",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.NONE.value,
                    creation_source_ref=_ref_dump(ref),
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            if link_primary:
                session.add(
                    orm.SourceEventLink(
                        source_record_id=source_record_id,
                        event_id=event_id,
                        role="primary",
                    )
                )
    return event_id, source_record_id


@pytest.mark.asyncio
async def test_api_select_disposition_source_persists(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id, source_record_id = await _seed(session_factory)

    resp = client.put(
        f"/api/v1/events/{event_id}/disposition-source",
        headers=_hdr(),
        json={
            "source_record_id": source_record_id,
            "expected_event_version": 1,
            "comment": "pick incident",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["event_id"] == event_id
    assert body["event_version"] == 2
    assert body["disposition_source_ref"]["source_object_id"].startswith("INC-")

    # Durable readback via DB (avoid TestClient/asyncio loop clash on shared engine).
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None
        assert row.row_version == 2
        assert row.disposition_source_ref is not None
        assert row.disposition_source_ref["source_object_id"].startswith("INC-")


@pytest.mark.asyncio
async def test_api_permission_denied_even_when_source_id_is_fixture_allowlisted(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Regression: unlinked fixture allowlist id must 403 — never fixture success."""
    event_id, _ = await _seed(session_factory, link_primary=True)

    resp = client.put(
        f"/api/v1/events/{event_id}/disposition-source",
        headers=_hdr(),
        json={
            "source_record_id": _FIXTURE_ALLOWLIST_SOURCE_ID,
            "expected_event_version": 1,
        },
    )
    assert resp.status_code == 403, resp.text
    body = resp.json()
    assert body["error_code"] == "disposition_permission_denied"
    assert "INC-1001" not in resp.text
    assert body.get("event_version") is None


@pytest.mark.asyncio
async def test_api_select_version_conflict_returns_409(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id, source_record_id = await _seed(session_factory)
    resp = client.put(
        f"/api/v1/events/{event_id}/disposition-source",
        headers=_hdr(),
        json={
            "source_record_id": source_record_id,
            "expected_event_version": 999,
        },
    )
    assert resp.status_code == 409, resp.text
    assert resp.json()["error_code"] == "writeback_conflict"


@pytest.mark.asyncio
async def test_api_readiness_recheck_from_resolver(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
    event_service,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, source_record_id = await _seed(session_factory)
    selected = client.put(
        f"/api/v1/events/{event_id}/disposition-source",
        headers=_hdr(),
        json={"source_record_id": source_record_id, "expected_event_version": 1},
    )
    assert selected.status_code == 200
    version = selected.json()["event_version"]

    adapter = MagicMock()
    adapter.health_check = AsyncMock(return_value=ConnectorStatus.ONLINE)
    adapter.capabilities.return_value = DispositionAdapterCapabilities(
        intents={DispositionIntentKind.EVENT_STATUS_UPDATE: CapabilityState.SUPPORTED}
    )
    registry = MagicMock()
    registry.get.return_value = adapter
    service = DispositionSourceService(
        session_factory,
        event_service=event_service,
        adapter_registry=registry,
        readiness_resolver=WritebackReadinessResolver(),
    )
    app.dependency_overrides[get_disposition_source_service] = lambda: service

    resp = client.post(
        f"/api/v1/events/{event_id}/disposition-readiness/recheck",
        headers=_hdr(),
        json={"expected_event_version": version},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["writeback_readiness"] == WritebackReadiness.READY.value
    assert body["blocked_reason"] is None
    assert body["event_version"] == version

    again = client.post(
        f"/api/v1/events/{event_id}/disposition-readiness/recheck",
        headers=_hdr(),
        json={"expected_event_version": version},
    )
    assert again.status_code == 200
    assert again.json() == body
