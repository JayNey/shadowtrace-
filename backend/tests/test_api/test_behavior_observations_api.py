"""BehaviorObservation read-only ops API tests (ISSUE-156)."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1.deps import reset_deps
from app.core.config import get_settings
from app.db import models as orm
from app.main import app
from app.models.behavior_observation import (
    BehaviorObservationProjectionStatus,
    BehaviorObservationQuery,
)
from app.models.enums import SourceDisposition, SourceObjectKind
from app.services.behavior_observation_service import BehaviorObservationService

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("clean_state")]

_DEV_TOKENS = json.dumps(
    {
        "analyst-token": {"subject": "analyst-1", "roles": ["analyst"]},
    }
)


@pytest.fixture(autouse=True)
def _api_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("DEV_AUTH_TOKENS", _DEV_TOKENS)
    monkeypatch.setenv("SOURCE_MODE", "mock_xdr")
    monkeypatch.setenv("LLM_MODE", "mock")
    get_settings.cache_clear()
    reset_deps()
    yield
    get_settings.cache_clear()
    reset_deps()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def _hdr() -> dict[str, str]:
    return {"Authorization": "Bearer analyst-token"}


async def _seed_connector(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    connector_id: str,
    tenant_id: str,
) -> None:
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SourceConnector(
                    connector_id=connector_id,
                    source_product="mock_xdr",
                    display_name=f"Test {connector_id}",
                    status="online",
                    schema_version="1",
                    connector_metadata={
                        "source_tenant_id": tenant_id,
                        "integration_instance_id": "inst-primary",
                        "connector_set_version": 1,
                    },
                )
            )


async def _seed_source_log(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    suffix: str,
    tenant_id: str,
    connector_id: str,
) -> str:
    record_id = f"src-api-{suffix}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SourceObject(
                    source_record_id=record_id,
                    source_product="mock_xdr",
                    source_tenant_id=tenant_id,
                    connector_id=connector_id,
                    source_kind=SourceObjectKind.LOG.value,
                    source_object_id=f"log-{suffix}",
                    source_object_type="edr",
                    source_status_raw="indexed",
                    source_disposition=SourceDisposition.UNKNOWN.value,
                    schema_version="1",
                    ingested_at=datetime(2026, 8, 1, tzinfo=UTC),
                    raw_payload_hash=f"hash-{suffix}",
                    normalized={
                        "channel": "endpoint",
                        "category": "process_create",
                        "action": "create_process",
                        "src_ip": "10.0.0.10",
                        "detection_score": 55,
                        "logged_at": "2026-08-01T00:00:00+00:00",
                    },
                    raw_payload={"cmdline": "sensitive"},
                    current_source_status_raw="indexed",
                    current_source_disposition=SourceDisposition.UNKNOWN.value,
                    current_state_version=1,
                    source_updated_at=datetime(2026, 8, 1, tzinfo=UTC),
                    source_sync_state="synced",
                )
            )
    return record_id


@pytest.mark.asyncio
async def test_list_projection_failures_read_only(
    session_factory: async_sessionmaker[AsyncSession],
    client: TestClient,
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-api-{suffix}"
    service = BehaviorObservationService(session_factory)
    await service.record_projection_failure(
        source_record_id=f"src-api-{suffix}",
        source_tenant_id=tenant_id,
        error_category="projection_failed",
        detail={"message": "ops-visible"},
    )

    response = client.get(
        "/api/v1/behavior-observation-projection-failures",
        params={"status": "pending_retry", "source_tenant_id": tenant_id},
        headers=_hdr(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["items"][0]["status"] == BehaviorObservationProjectionStatus.PENDING_RETRY.value
    assert payload["items"][0]["source_tenant_id"] == tenant_id


@pytest.mark.asyncio
async def test_list_projection_failures_requires_tenant(
    client: TestClient,
) -> None:
    response = client.get(
        "/api/v1/behavior-observation-projection-failures",
        headers=_hdr(),
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_list_projection_failures_defaults_to_open_backlog_only(
    session_factory: async_sessionmaker[AsyncSession],
    client: TestClient,
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-open-{suffix}"
    other_tenant = f"tenant-other-{suffix}"
    service = BehaviorObservationService(session_factory)
    await service.record_projection_failure(
        source_record_id=f"src-open-{suffix}",
        source_tenant_id=tenant_id,
        error_category="projection_failed",
        detail={"message": "open"},
    )
    await service.record_projection_failure(
        source_record_id=f"src-dead-{suffix}",
        source_tenant_id=tenant_id,
        error_category="projection_failed",
        detail={"message": "dead"},
        force_dead_letter=True,
    )
    connector_id = f"conn-{suffix}"
    await _seed_connector(session_factory, connector_id=connector_id, tenant_id=tenant_id)
    record_id = await _seed_source_log(
        session_factory,
        suffix=f"resolved-{suffix}",
        tenant_id=tenant_id,
        connector_id=connector_id,
    )
    await service.record_projection_failure(
        source_record_id=record_id,
        source_tenant_id=tenant_id,
        error_category="projection_failed",
        detail={"message": "resolved"},
    )
    await service.project_source_object(record_id)

    await service.record_projection_failure(
        source_record_id=f"src-other-{suffix}",
        source_tenant_id=other_tenant,
        error_category="projection_failed",
        detail={"message": "other-tenant"},
    )

    response = client.get(
        "/api/v1/behavior-observation-projection-failures",
        params={"source_tenant_id": tenant_id},
        headers=_hdr(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 2
    statuses = {item["status"] for item in payload["items"]}
    assert statuses == {
        BehaviorObservationProjectionStatus.PENDING_RETRY.value,
        BehaviorObservationProjectionStatus.DEAD_LETTER.value,
    }


@pytest.mark.asyncio
async def test_list_projection_failures_dead_letter_filter(
    session_factory: async_sessionmaker[AsyncSession],
    client: TestClient,
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-dead-{suffix}"
    service = BehaviorObservationService(session_factory)
    await service.record_projection_failure(
        source_record_id=f"src-pending-{suffix}",
        source_tenant_id=tenant_id,
        error_category="projection_failed",
        detail={"message": "pending"},
    )
    await service.record_projection_failure(
        source_record_id=f"src-dead-{suffix}",
        source_tenant_id=tenant_id,
        error_category="projection_failed",
        detail={"message": "dead"},
        force_dead_letter=True,
    )

    response = client.get(
        "/api/v1/behavior-observation-projection-failures",
        params={"source_tenant_id": tenant_id, "status": "dead_letter"},
        headers=_hdr(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["items"][0]["status"] == BehaviorObservationProjectionStatus.DEAD_LETTER.value


@pytest.mark.asyncio
async def test_list_behavior_observations_requires_tenant(
    client: TestClient,
) -> None:
    response = client.get(
        "/api/v1/behavior-observations",
        headers=_hdr(),
    )
    assert response.status_code == 422

    empty = client.get(
        "/api/v1/behavior-observations",
        params={"source_tenant_id": "tenant-missing"},
        headers=_hdr(),
    )
    assert empty.status_code == 200
    assert empty.json()["total"] == 0


@pytest.mark.asyncio
async def test_list_behavior_observations_returns_projected_row(
    session_factory: async_sessionmaker[AsyncSession],
    client: TestClient,
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-obs-{suffix}"
    connector_id = f"conn-{suffix}"
    await _seed_connector(session_factory, connector_id=connector_id, tenant_id=tenant_id)
    record_id = await _seed_source_log(
        session_factory,
        suffix=suffix,
        tenant_id=tenant_id,
        connector_id=connector_id,
    )
    observation = await BehaviorObservationService(session_factory).project_source_object(record_id)
    assert observation is not None

    response = client.get(
        "/api/v1/behavior-observations",
        params={"source_tenant_id": tenant_id},
        headers=_hdr(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["items"][0]["observation_id"] == observation.observation_id
    assert payload["items"][0]["source_tenant_id"] == tenant_id

    scoped = await BehaviorObservationService(session_factory).query_observations(
        BehaviorObservationQuery(source_tenant_id=tenant_id)
    )
    assert scoped.total == 1
