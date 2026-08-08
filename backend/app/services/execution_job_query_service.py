"""Read-only execution job lookup from the authoritative PG store (ISSUE-271).

Loads ``ActionExecutionJob`` rows plus ``ActionTargetResult`` bindings under a
read-only session, verifies action/event ownership, applies tenant-scoped
authorization, and returns a safe API projection (no provider raw payloads).
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1 import schemas as api_schemas
from app.core.auth import ROLE_ADMIN, Principal
from app.core.errors import DependencyUnavailableError, ResourceNotFoundError
from app.core.guardrails import allowlisted_message_code
from app.db import models as orm
from app.models.source import SourceReference

logger = logging.getLogger(__name__)

DEMO_EXECUTION_JOB_ID = "job-0a1b2c3d"
_SAFE_TARGET_KEYS = frozenset({"canonical_target", "status", "code", "message"})


def assert_execution_job_tenant_access(principal: Principal, tenant_id: str) -> None:
    """Fail closed when a non-admin principal cannot prove tenant scope."""
    if principal.has_any_role([ROLE_ADMIN]):
        return
    scoped = principal.tenant_id
    if not scoped or scoped != tenant_id:
        raise ResourceNotFoundError(
            f"execution job not found",
            details={"reason": "tenant_scope_denied"},
        )


def _event_tenant_id(event_row: orm.SecurityEvent) -> str | None:
    ref_payload = event_row.creation_source_ref or {}
    try:
        return SourceReference.model_validate(ref_payload).source_tenant_id
    except Exception:  # noqa: BLE001 - treat malformed refs as unprovable ownership
        return None


def _safe_target_dict(row: orm.ActionTargetResult) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "canonical_target": row.canonical_target,
        "status": row.status,
    }
    if row.code:
        payload["code"] = row.code
    if row.message:
        safe_message = allowlisted_message_code(row.message)
        if safe_message:
            payload["message"] = safe_message
    return payload


def _targets_from_embedded_raw(raw_result: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Best-effort target extraction from persisted raw_result without leaking secrets."""
    if not isinstance(raw_result, dict):
        return []
    embedded = raw_result.get("target_results")
    if not isinstance(embedded, list):
        return []
    projected: list[dict[str, Any]] = []
    for item in embedded:
        if not isinstance(item, dict):
            continue
        safe = {key: item[key] for key in _SAFE_TARGET_KEYS if key in item}
        canonical = safe.get("canonical_target")
        status = safe.get("status")
        if not isinstance(canonical, str) or not isinstance(status, str):
            continue
        if "message" in safe:
            safe["message"] = allowlisted_message_code(str(safe["message"]))
        projected.append(safe)
    return projected


def project_execution_job_response(
    job_row: orm.ActionExecutionJob,
    target_rows: list[orm.ActionTargetResult],
) -> api_schemas.ExecutionJobResponse:
    """Build the public execution-job contract without provider internals."""
    if target_rows:
        target_results = [_safe_target_dict(row) for row in target_rows]
    else:
        target_results = _targets_from_embedded_raw(job_row.raw_result)

    return api_schemas.ExecutionJobResponse(
        job_id=job_row.job_id,
        event_id=job_row.event_id,
        action_id=job_row.action_id,
        status=job_row.status,
        attempt=job_row.attempt,
        target_results=target_results,
    )


def demo_execution_job_response(job_id: str) -> api_schemas.ExecutionJobResponse | None:
    """Explicit demo/test fixture — never used unless fixture mode is enabled."""
    if job_id != DEMO_EXECUTION_JOB_ID:
        return None
    return api_schemas.ExecutionJobResponse(
        job_id=job_id,
        event_id=api_schemas.EXAMPLE_EVENT_ID,
        action_id="act-0a1b2c3d",
        status="partial_success",
        attempt=1,
        target_results=[
            {"canonical_target": "ip:203.0.113.9", "status": "success"},
            {"canonical_target": "ip:203.0.113.10", "status": "failed"},
        ],
    )


class ExecutionJobQueryService:
    """Authoritative read path for ``GET /execution-jobs/{job_id}``."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        fixture_enabled: bool = False,
    ) -> None:
        self._session_factory = session_factory
        self._fixture_enabled = fixture_enabled

    async def get_execution_job(
        self,
        job_id: str,
        *,
        principal: Principal,
    ) -> api_schemas.ExecutionJobResponse:
        try:
            async with self._session_factory() as session:
                job_row = await session.get(orm.ActionExecutionJob, job_id)
                if job_row is None:
                    fixture = self._fixture_response(job_id)
                    if fixture is not None:
                        return fixture
                    raise ResourceNotFoundError(
                        f"execution job {job_id} not found",
                        details={"job_id": job_id},
                    )

                action_row = await session.get(orm.Action, job_row.action_id)
                if (
                    action_row is None
                    or action_row.event_id != job_row.event_id
                    or action_row.execution_job_id != job_row.job_id
                ):
                    logger.warning(
                        "execution job binding could not be proven job_id=%s action_id=%s",
                        job_id,
                        job_row.action_id,
                    )
                    raise ResourceNotFoundError(
                        f"execution job {job_id} not found",
                        details={"job_id": job_id},
                    )

                event_row = await session.get(orm.SecurityEvent, job_row.event_id)
                if event_row is None:
                    raise ResourceNotFoundError(
                        f"execution job {job_id} not found",
                        details={"job_id": job_id},
                    )

                tenant_id = _event_tenant_id(event_row)
                if tenant_id is None:
                    logger.warning(
                        "execution job event tenant could not be resolved job_id=%s event_id=%s",
                        job_id,
                        job_row.event_id,
                    )
                    raise ResourceNotFoundError(
                        f"execution job {job_id} not found",
                        details={"job_id": job_id},
                    )
                assert_execution_job_tenant_access(principal, tenant_id)

                target_rows = list(
                    await session.scalars(
                        select(orm.ActionTargetResult)
                        .where(orm.ActionTargetResult.job_id == job_id)
                        .order_by(orm.ActionTargetResult.id.asc())
                    )
                )
                return project_execution_job_response(job_row, target_rows)
        except ResourceNotFoundError:
            raise
        except SQLAlchemyError as exc:
            logger.exception("execution job store read failed job_id=%s", job_id)
            raise DependencyUnavailableError(
                "execution job store unavailable",
                details={"job_id": job_id, "dependency": "postgresql"},
            ) from exc

    def _fixture_response(self, job_id: str) -> api_schemas.ExecutionJobResponse | None:
        if not self._fixture_enabled:
            return None
        return demo_execution_job_response(job_id)


__all__ = [
    "DEMO_EXECUTION_JOB_ID",
    "ExecutionJobQueryService",
    "assert_execution_job_tenant_access",
    "demo_execution_job_response",
    "project_execution_job_response",
]
