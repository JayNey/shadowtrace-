"""Derived detection connector identity (ISSUE-124 / #629)."""

from __future__ import annotations

import hashlib

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ValidationError
from app.db import models as orm
from app.db.orm.detection_promotion import DerivedDetectionConnectorORM
from app.models.detection_promotion import (
    DERIVED_DETECTION_ADAPTER_KIND,
    DERIVED_DETECTION_ADAPTER_VERSION,
    DerivedDetectionConnectorRecord,
)
from app.models.detection_scope import DetectionScopeConnectorSet
from app.services.detection_scope_resolver import DetectionScopeResolver


def build_derived_detection_connector_id(
    *,
    source_tenant_id: str,
    detection_scope_id: str,
    adapter_kind: str = DERIVED_DETECTION_ADAPTER_KIND,
    adapter_version: str = DERIVED_DETECTION_ADAPTER_VERSION,
) -> str:
    material = (
        f"{source_tenant_id}|{detection_scope_id}|{adapter_kind}|{adapter_version}"
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
    return f"ddet-{digest}"


class DerivedDetectionConnectorService:
    """Register per-scope derived connectors excluded from upstream scope sets."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def ensure_connector(
        self,
        *,
        source_tenant_id: str,
        detection_scope_id: str,
        scope_revision_id: str | None,
        connector_set: DetectionScopeConnectorSet,
        source_product: str = "mock_xdr",
    ) -> DerivedDetectionConnectorRecord:
        connector_id = build_derived_detection_connector_id(
            source_tenant_id=source_tenant_id,
            detection_scope_id=detection_scope_id,
        )
        DetectionScopeResolver.assert_derived_connector_excluded_from_set(
            connector_id,
            connector_set,
        )
        record = DerivedDetectionConnectorRecord(
            connector_id=connector_id,
            source_tenant_id=source_tenant_id,
            detection_scope_id=detection_scope_id,
            scope_revision_id=scope_revision_id,
            metadata={
                "role": "derived_detection",
                "source_product": source_product,
                "disposition": "not_required",
            },
        )
        async with self._session_factory() as session:
            async with session.begin():
                existing = await session.get(DerivedDetectionConnectorORM, connector_id)
                if existing is not None:
                    if existing.detection_scope_id != detection_scope_id:
                        raise ValidationError(
                            "derived connector scope mismatch",
                            details={
                                "connector_id": connector_id,
                                "expected_scope": detection_scope_id,
                                "stored_scope": existing.detection_scope_id,
                            },
                        )
                    return _row_to_record(existing)

                session.add(
                    DerivedDetectionConnectorORM(
                        connector_id=record.connector_id,
                        source_tenant_id=record.source_tenant_id,
                        detection_scope_id=record.detection_scope_id,
                        scope_revision_id=record.scope_revision_id,
                        adapter_kind=record.adapter_kind,
                        adapter_version=record.adapter_version,
                        disposition_policy=record.disposition_policy,
                        connector_metadata=record.metadata,
                    )
                )
                await self._ensure_source_connector_row(
                    session,
                    record=record,
                    source_product=source_product,
                )
        return record

    async def get_connector(
        self,
        connector_id: str,
        *,
        source_tenant_id: str | None = None,
    ) -> DerivedDetectionConnectorRecord | None:
        async with self._session_factory() as session:
            row = await session.get(DerivedDetectionConnectorORM, connector_id)
            if row is None:
                return None
            if source_tenant_id is not None and row.source_tenant_id != source_tenant_id:
                return None
            return _row_to_record(row)

    async def _ensure_source_connector_row(
        self,
        session: AsyncSession,
        *,
        record: DerivedDetectionConnectorRecord,
        source_product: str,
    ) -> None:
        connector = await session.get(orm.SourceConnector, record.connector_id)
        if connector is not None:
            metadata = dict(connector.connector_metadata or {})
            metadata.update(
                {
                    "source_tenant_id": record.source_tenant_id,
                    "detection_scope_id": record.detection_scope_id,
                    "derived_detection": True,
                    "adapter_kind": record.adapter_kind,
                    "adapter_version": record.adapter_version,
                }
            )
            connector.connector_metadata = metadata
            connector.disposition_policy_default = record.disposition_policy
            return
        session.add(
            orm.SourceConnector(
                connector_id=record.connector_id,
                source_product=source_product,
                display_name=f"Derived detection ({record.detection_scope_id})",
                status="active",
                disposition_policy_default=record.disposition_policy,
                connector_metadata={
                    "source_tenant_id": record.source_tenant_id,
                    "detection_scope_id": record.detection_scope_id,
                    "derived_detection": True,
                    "adapter_kind": record.adapter_kind,
                    "adapter_version": record.adapter_version,
                },
            )
        )
        try:
            await session.flush()
        except IntegrityError:
            existing = await session.get(orm.SourceConnector, record.connector_id)
            if existing is None:
                raise


def _row_to_record(row: DerivedDetectionConnectorORM) -> DerivedDetectionConnectorRecord:
    return DerivedDetectionConnectorRecord(
        connector_id=row.connector_id,
        source_tenant_id=row.source_tenant_id,
        detection_scope_id=row.detection_scope_id,
        scope_revision_id=row.scope_revision_id,
        adapter_kind=row.adapter_kind,
        adapter_version=row.adapter_version,
        disposition_policy=row.disposition_policy,
        metadata=dict(row.connector_metadata or {}),
    )
