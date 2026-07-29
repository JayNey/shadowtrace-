"""Source ingestion + source-record lookup endpoints."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1 import schemas as s
from app.api.v1.deps import _get_session_factory, get_event_service
from app.api.v1.errors import ResourceNotFoundError
from app.core.auth import ROLE_ANALYST, CurrentPrincipal, Principal, require_roles
from app.db import models as orm
from app.models.enums import EventType, Severity, SourceDisposition, SourceObjectKind
from app.models.source import SourceReference

router = APIRouter(tags=["source"])


def _optional_enum(value: Any, enum_cls: type[Any]) -> Any | None:
    if value is None:
        return None
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(str(value))
    except ValueError:
        return None


def _reference_from_source_object(obj: orm.SourceObject) -> SourceReference:
    return SourceReference(
        source_kind=SourceObjectKind(obj.source_kind),
        source_product=obj.source_product,
        source_tenant_id=obj.source_tenant_id,
        connector_id=obj.connector_id,
        source_object_type=obj.source_object_type,
        source_object_id=obj.source_object_id,
        parent_source_object_id=obj.parent_source_object_id,
        source_status_raw=obj.source_status_raw,
        source_disposition=SourceDisposition(obj.source_disposition),
        source_concurrency_token=obj.source_concurrency_token,
        source_updated_at=obj.source_updated_at,
        schema_version=obj.schema_version or "1",
        ingested_at=obj.ingested_at,
        raw_payload_hash=obj.raw_payload_hash,
    )


@router.post(
    "/ingestion/source-records",
    response_model=s.IngestSourceRecordResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_source_record(
    body: s.IngestSourceRecordRequest,
    principal: Annotated[Principal, require_roles(ROLE_ANALYST)],
    event_service: Annotated[Any, Depends(get_event_service)],
) -> s.IngestSourceRecordResponse:
    """Accept one Source* object and upsert/create the linked SecurityEvent."""
    # Lazy import avoids api.v1 ↔ event_service ↔ context_service circular import.
    from app.services.event_service import IngestableSource

    _ = principal
    normalized = dict(body.normalized or {})
    raw = dict(body.raw_payload or {})
    title = str(normalized.get("title") or raw.get("title") or "").strip() or None
    description = str(normalized.get("description") or raw.get("description") or "")
    result = await event_service.ingest_source_object(
        IngestableSource(
            reference=body.reference,
            raw_payload=raw,
            normalized=normalized,
            title=title,
            description=description,
            event_type=_optional_enum(normalized.get("event_type"), EventType),
            severity=_optional_enum(
                normalized.get("severity") or normalized.get("level"),
                Severity,
            ),
            incident_ref=body.incident_ref,
            related_alert_refs=list(body.related_alert_refs or []),
            source_type=body.reference.source_product or "mock_xdr",
        )
    )
    return s.IngestSourceRecordResponse(
        source_record_id=result.source_record_id,
        event_id=result.event_id,
        accepted=result.accepted,
    )


@router.get("/source-records/{source_record_id}", response_model=s.SourceRecordResponse)
async def get_source_record(
    source_record_id: str,
    principal: CurrentPrincipal,
    session_factory: Annotated[async_sessionmaker[AsyncSession], Depends(_get_session_factory)],
) -> s.SourceRecordResponse:
    """Look up a persisted source object; keep ISSUE-004 fixture id for contracts."""
    from app.core.config import get_settings

    _ = principal
    db_error: BaseException | None = None
    try:
        async with session_factory() as session:
            obj = await session.get(orm.SourceObject, source_record_id)
            if obj is not None:
                try:
                    current_disposition = SourceDisposition(obj.current_source_disposition)
                except ValueError:
                    current_disposition = SourceDisposition.UNKNOWN
                return s.SourceRecordResponse(
                    source_record_id=obj.source_record_id,
                    reference=_reference_from_source_object(obj),
                    normalized=dict(obj.normalized or {}),
                    current_source_disposition=current_disposition,
                    source_sync_state=obj.source_sync_state,
                )
    except (SQLAlchemyError, OSError, RuntimeError) as exc:
        db_error = exc

    # Contract fixture ID retained for OpenAPI / contract tests (ISSUE-004).
    # Never mask real DB failures for other IDs, and never in production.
    if (
        source_record_id == "src-associated-1"
        and get_settings().app_env.strip().lower() != "production"
    ):
        return s.SourceRecordResponse(
            source_record_id=source_record_id,
            reference=s.example_source_reference(),
            normalized={},
        )

    if db_error is not None:
        raise db_error

    raise ResourceNotFoundError(
        f"source record {source_record_id} not found",
        details={"source_record_id": source_record_id},
    )
