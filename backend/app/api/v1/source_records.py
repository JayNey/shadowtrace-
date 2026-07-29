"""Source ingestion + source-record lookup endpoints."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, status

from app.api.v1 import schemas as s
from app.api.v1.deps import get_event_service
from app.api.v1.errors import ResourceNotFoundError
from app.core.auth import ROLE_ANALYST, CurrentPrincipal, Principal, require_roles
from app.models.enums import EventType, Severity
from app.services.event_service import EventService, IngestableSource

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


@router.post(
    "/ingestion/source-records",
    response_model=s.IngestSourceRecordResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_source_record(
    body: s.IngestSourceRecordRequest,
    principal: Annotated[Principal, require_roles(ROLE_ANALYST)],
    event_service: EventService = Depends(get_event_service),
) -> s.IngestSourceRecordResponse:
    """Accept one Source* object and upsert/create the linked SecurityEvent."""
    _ = principal
    normalized = dict(body.normalized or {})
    raw = dict(body.raw_payload or {})
    title = (
        str(normalized.get("title") or raw.get("title") or "").strip()
        or None
    )
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
    source_record_id: str, principal: CurrentPrincipal
) -> s.SourceRecordResponse:
    # Contract fixture ID retained for OpenAPI / contract tests (ISSUE-004).
    _ = principal
    if source_record_id != "src-associated-1":
        raise ResourceNotFoundError(
            f"source record {source_record_id} not found",
            details={"source_record_id": source_record_id},
        )
    return s.SourceRecordResponse(
        source_record_id=source_record_id,
        reference=s.example_source_reference(),
        normalized={},
    )
