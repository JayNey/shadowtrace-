"""SourceIngester hook tests for BehaviorObservation projection (ISSUE-119 / #624)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.source.base import SourcePage
from app.ingestion.source_ingester import SourceIngester
from app.models.behavior_observation import BehaviorObservationQuery
from app.models.enums import SourceDisposition, SourceObjectKind
from app.models.source import SourceConnector, SourceLog, SourceReference
from app.services.behavior_observation_service import BehaviorObservationService
from app.services.event_service import EventService
from tests.test_ingestion.test_source_ingester import FakePagedAdapter


def _suffix() -> str:
    return uuid.uuid4().hex[:8]


def _connector(connector_id: str) -> SourceConnector:
    return SourceConnector(
        connector_id=connector_id,
        source_product="mock_xdr",
        display_name=f"Test {connector_id}",
    )


class HookAdapter(FakePagedAdapter):
    def __init__(
        self,
        name: str,
        pages: dict,
        *,
        connectors: list[SourceConnector],
    ) -> None:
        super().__init__(name, pages)
        self._connectors = connectors

    async def list_connectors(self) -> list[SourceConnector]:
        return list(self._connectors)


def _log_item(suffix: str, connector_id: str, tenant_id: str) -> SourceLog:
    return SourceLog(
        reference=SourceReference(
            source_kind=SourceObjectKind.LOG,
            source_product="mock_xdr",
            source_tenant_id=tenant_id,
            connector_id=connector_id,
            source_object_type="edr",
            source_object_id=f"log-{suffix}",
            source_status_raw="indexed",
            source_disposition=SourceDisposition.UNKNOWN,
            source_updated_at=datetime(2026, 8, 1, tzinfo=UTC),
            schema_version="1",
            ingested_at=datetime(2026, 8, 1, tzinfo=UTC),
            raw_payload_hash=f"hash-{suffix}",
        ),
        raw_payload={"cmdline": "keep-in-source-store-only"},
        normalized={
            "channel": "endpoint",
            "category": "process_create",
            "action": "create_process",
            "src_ip": "10.1.1.1",
            "detection_score": 42,
            "logged_at": "2026-08-01T00:00:00+00:00",
        },
        device_source="edr",
        logged_at=datetime(2026, 8, 1, tzinfo=UTC),
        src_ip="10.1.1.1",
        category="process_create",
    )


@pytest.mark.asyncio
async def test_source_ingester_projects_behavior_observation_for_supporting_object(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
) -> None:
    suffix = _suffix()
    tenant_id = f"tenant-{suffix}"
    connector_id = f"conn-{suffix}"
    connector = _connector(connector_id)
    adapter = HookAdapter(
        "mock_xdr",
        {
            (SourceObjectKind.LOG.value, connector_id, None): SourcePage(
                items=[_log_item(suffix, connector_id, tenant_id)],
                object_kind=SourceObjectKind.LOG,
                connector_id=connector_id,
                next_cursor=None,
                has_more=False,
            ),
        },
        connectors=[connector],
    )
    ingester = SourceIngester(event_service, session_factory)
    summary = await ingester.poll(
        adapter,
        [SourceObjectKind.LOG],
        batch_size=10,
    )
    assert summary.accepted >= 1
    assert summary.degraded is False

    observations = await BehaviorObservationService(session_factory).query_observations(
        BehaviorObservationQuery(source_tenant_id=tenant_id)
    )
    assert observations.total >= 1
    item = observations.items[0]
    assert item.detection_score == 42.0
    assert item.provenance.raw_payload_hash == f"hash-{suffix}"
    assert "cmdline" not in item.normalized_attributes
