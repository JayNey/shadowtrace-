"""Execution job + async task status endpoints."""

from __future__ import annotations

from typing import cast

from fastapi import APIRouter

from app.api.v1 import schemas as s
from app.api.v1.deps import ExecutionJobQueryDep
from app.api.v1.errors import ResourceNotFoundError
from app.core.auth import ReadPrincipal
from app.tasks.investigation_tasks import resolve_task_state

router = APIRouter(tags=["platform"])


@router.get("/execution-jobs/{job_id}", response_model=s.ExecutionJobResponse)
async def get_execution_job(
    job_id: str,
    principal: ReadPrincipal,
    query: ExecutionJobQueryDep,
) -> s.ExecutionJobResponse:
    response = await query.get_execution_job(job_id, principal=principal)
    return cast(s.ExecutionJobResponse, response)


@router.get("/tasks/{task_id}", response_model=s.TaskResponse)
async def get_task(task_id: str, principal: ReadPrincipal) -> s.TaskResponse:
    """Return Celery task state for an investigation dispatched via ``TASK_MODE=celery``."""
    state, event_id = await resolve_task_state(task_id)
    if event_id is None:
        raise ResourceNotFoundError(
            f"task {task_id} not found",
            details={"task_id": task_id},
        )
    return s.TaskResponse(task_id=task_id, state=state, event_id=event_id)
