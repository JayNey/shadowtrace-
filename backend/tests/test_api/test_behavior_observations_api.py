"""BehaviorObservation read-only ops API tests (ISSUE-156)."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1.deps import reset_deps
from app.core.config import get_settings
from app.main import app
from app.models.behavior_observation import (
    BehaviorObservationProjectionStatus,
    BehaviorObservationQuery,
)
from app.services.behavior_observation_service import BehaviorObservationService
from tests.test_services.behavior_observation_fixtures import (
    seed_behavior_observation_connector,
    seed_behavior_observation_source_log,
)

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


@pytest.mark.asyncio
async def test_list_projection_failures_requires_auth(client: TestClient) -> None:
    response = client.get(
        "/api/v1/behavior-observation-projection-failures",
        params={"source_tenant_id": "tenant-auth"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_list_behavior_observations_requires_auth(client: TestClient) -> None:
    response = client.get(
        "/api/v1/behavior-observations",
        params={"source_tenant_id": "tenant-auth"},
    )
    assert response.status_code == 401


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
    await seed_behavior_observation_connector(
        session_factory, connector_id=connector_id, tenant_id=tenant_id
    )
    record_id = await seed_behavior_observation_source_log(
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
async def test_list_projection_failures_scoped_to_tenant(
    session_factory: async_sessionmaker[AsyncSession],
    client: TestClient,
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_a = f"tenant-a-{suffix}"
    tenant_b = f"tenant-b-{suffix}"
    service = BehaviorObservationService(session_factory)
    await service.record_projection_failure(
        source_record_id=f"src-a-{suffix}",
        source_tenant_id=tenant_a,
        error_category="projection_failed",
        detail={"message": "tenant-a"},
    )
    await service.record_projection_failure(
        source_record_id=f"src-b-{suffix}",
        source_tenant_id=tenant_b,
        error_category="projection_failed",
        detail={"message": "tenant-b"},
    )

    response = client.get(
        "/api/v1/behavior-observation-projection-failures",
        params={"source_tenant_id": tenant_a},
        headers=_hdr(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["items"][0]["source_tenant_id"] == tenant_a


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
    await seed_behavior_observation_connector(
        session_factory, connector_id=connector_id, tenant_id=tenant_id
    )
    record_id = await seed_behavior_observation_source_log(
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
