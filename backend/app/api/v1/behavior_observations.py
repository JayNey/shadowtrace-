"""Read-only BehaviorObservation ops API (ISSUE-156)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.v1.deps import get_behavior_observation_service
from app.core.auth import ROLE_ANALYST, Principal, require_roles
from app.models.behavior_observation import (
    BehaviorObservationListResult,
    BehaviorObservationProjectionFailureListResult,
    BehaviorObservationProjectionFailureQuery,
    BehaviorObservationProjectionStatus,
    BehaviorObservationQuery,
)
from app.services.behavior_observation_service import BehaviorObservationService

router = APIRouter(tags=["behavior-observations"])


@router.get(
    "/behavior-observations",
    response_model=BehaviorObservationListResult,
    status_code=status.HTTP_200_OK,
)
async def list_behavior_observations(
    principal: Annotated[Principal, require_roles(ROLE_ANALYST)],
    service: Annotated[BehaviorObservationService, Depends(get_behavior_observation_service)],
    source_tenant_id: Annotated[str, Query(min_length=1, max_length=128)],
    detection_scope_id: Annotated[str | None, Query(max_length=128)] = None,
    connector_id: Annotated[str | None, Query(max_length=128)] = None,
    source_kind: Annotated[str | None, Query(max_length=32)] = None,
    source_object_id: Annotated[str | None, Query(max_length=256)] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 50,
) -> BehaviorObservationListResult:
    """Tenant-scoped read path for persisted behavior observations."""
    _ = principal
    query = BehaviorObservationQuery(
        source_tenant_id=source_tenant_id,
        detection_scope_id=detection_scope_id,
        connector_id=connector_id,
        source_kind=source_kind,
        source_object_id=source_object_id,
        page=page,
        page_size=page_size,
    )
    return await service.query_observations(query)


@router.get(
    "/behavior-observation-projection-failures",
    response_model=BehaviorObservationProjectionFailureListResult,
    status_code=status.HTTP_200_OK,
)
async def list_behavior_observation_projection_failures(
    principal: Annotated[Principal, require_roles(ROLE_ANALYST)],
    service: Annotated[BehaviorObservationService, Depends(get_behavior_observation_service)],
    source_tenant_id: Annotated[str, Query(min_length=1, max_length=128)],
    failure_status: Annotated[
        BehaviorObservationProjectionStatus | None,
        Query(
            alias="status",
            description="Optional filter; omit to list open backlog (pending_retry + dead_letter)",
        ),
    ] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 50,
) -> BehaviorObservationProjectionFailureListResult:
    """Read-only open backlog for semantic projection failures (resolved excluded by default)."""
    _ = principal
    query = BehaviorObservationProjectionFailureQuery(
        status=failure_status,
        source_tenant_id=source_tenant_id,
        page=page,
        page_size=page_size,
    )
    return await service.query_projection_failures(query)
