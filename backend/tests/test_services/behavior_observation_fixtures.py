"""Shared DB seed helpers for BehaviorObservation tests (ISSUE-119 / ISSUE-156)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import models as orm
from app.models.enums import SourceDisposition, SourceObjectKind


async def seed_behavior_observation_connector(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    connector_id: str,
    tenant_id: str,
    integration_instance_id: str = "inst-primary",
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
                        "integration_instance_id": integration_instance_id,
                        "connector_set_version": 1,
                    },
                )
            )


async def seed_behavior_observation_source_log(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    suffix: str,
    tenant_id: str,
    connector_id: str,
    source_revision: int = 1,
    record_id: str | None = None,
) -> str:
    resolved_record_id = record_id or f"src-{suffix}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SourceObject(
                    source_record_id=resolved_record_id,
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
                    current_state_version=source_revision,
                    source_updated_at=datetime(2026, 8, 1, tzinfo=UTC),
                    source_sync_state="synced",
                )
            )
    return resolved_record_id
