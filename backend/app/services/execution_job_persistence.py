"""Atomic ActionExecutionJob target-row persistence helpers (ISSUE-272)."""

from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters._util import sanitize_raw_result
from app.core.sanitization import redact_sensitive_text
from app.db import models as orm
from app.models.enums import ExecutionJobStatus, TargetExecutionStatus
from app.models.execution import ActionExecutionJob, TargetExecutionResult


def sanitize_target_execution_result(result: TargetExecutionResult) -> TargetExecutionResult:
    """Redact sensitive target fields before persistence."""

    return result.model_copy(
        update={
            "code": redact_sensitive_text(result.code) if result.code is not None else None,
            "message": (
                redact_sensitive_text(result.message) if result.message is not None else None
            ),
            "artifact_id": (
                redact_sensitive_text(result.artifact_id)
                if result.artifact_id is not None
                else None
            ),
            "raw_result": sanitize_raw_result(dict(result.raw_result)),
        }
    )


def target_result_from_row(row: orm.ActionTargetResult) -> TargetExecutionResult:
    return TargetExecutionResult(
        canonical_target=row.canonical_target,
        status=TargetExecutionStatus(row.status),
        code=row.code,
        message=row.message,
        artifact_id=row.artifact_id,
        raw_result=row.raw_result or {},
    )


def _target_identity_key(
    result: TargetExecutionResult,
) -> tuple[str, str, str | None, str | None, str | None]:
    return (
        result.canonical_target,
        result.status.value,
        result.code,
        result.message,
        result.artifact_id,
    )


def _normalize_targets(targets: list[TargetExecutionResult]) -> list[TargetExecutionResult]:
    sanitized = [sanitize_target_execution_result(item) for item in targets]
    return sorted(sanitized, key=lambda item: item.canonical_target)


def targets_match(
    existing: list[TargetExecutionResult],
    incoming: list[TargetExecutionResult],
) -> bool:
    if len(existing) != len(incoming):
        return False
    existing_sorted = sorted(existing, key=lambda item: item.canonical_target)
    incoming_sorted = sorted(incoming, key=lambda item: item.canonical_target)
    return [_target_identity_key(item) for item in existing_sorted] == [
        _target_identity_key(item) for item in incoming_sorted
    ]


async def load_target_results_for_job(
    session: AsyncSession,
    job_id: str,
    attempt: int,
) -> list[TargetExecutionResult]:
    rows = (
        await session.scalars(
            select(orm.ActionTargetResult)
            .where(
                orm.ActionTargetResult.job_id == job_id,
                orm.ActionTargetResult.attempt == attempt,
            )
            .order_by(orm.ActionTargetResult.canonical_target.asc())
        )
    ).all()
    return [target_result_from_row(row) for row in rows]


async def load_target_results_by_job_ids(
    session: AsyncSession,
    jobs: list[orm.ActionExecutionJob],
) -> dict[str, list[TargetExecutionResult]]:
    if not jobs:
        return {}
    attempt_by_job = {job.job_id: int(job.attempt) for job in jobs}
    job_ids = list(attempt_by_job)
    rows = (
        await session.scalars(
            select(orm.ActionTargetResult)
            .where(orm.ActionTargetResult.job_id.in_(job_ids))
            .order_by(
                orm.ActionTargetResult.job_id.asc(),
                orm.ActionTargetResult.canonical_target.asc(),
            )
        )
    ).all()
    loaded: dict[str, list[TargetExecutionResult]] = defaultdict(list)
    for row in rows:
        if attempt_by_job.get(row.job_id) != int(row.attempt):
            continue
        loaded[row.job_id].append(target_result_from_row(row))
    return {job_id: loaded.get(job_id, []) for job_id in job_ids}


def job_from_row(
    row: orm.ActionExecutionJob,
    *,
    target_results: list[TargetExecutionResult] | None = None,
) -> ActionExecutionJob:
    resolved = target_results if target_results is not None else []
    return ActionExecutionJob(
        job_id=row.job_id,
        event_id=row.event_id,
        action_id=row.action_id,
        provider_name=row.provider_name,
        idempotency_key=row.idempotency_key,
        provider_job_id=row.provider_job_id,
        status=ExecutionJobStatus(row.status),
        claimed_by=row.claimed_by,
        lease_expires_at=row.lease_expires_at,
        poll_after_ms=row.poll_after_ms,
        attempt=row.attempt,
        provider_code=row.provider_code,
        provider_message=row.provider_message,
        raw_result=row.raw_result or {},
        created_at=row.created_at,
        updated_at=row.updated_at,
        started_at=row.started_at,
        finished_at=row.finished_at,
        target_results=resolved,
        legacy_target_results=len(resolved) == 0,
    )


async def sync_target_results_in_tx(
    session: AsyncSession,
    *,
    job_id: str,
    attempt: int,
    targets: list[TargetExecutionResult],
) -> bool:
    """Insert rows for ``(job_id, attempt)``. Fail-closed on duplicate/conflict."""

    if not targets:
        return True

    normalized = _normalize_targets(targets)
    canonicals = [item.canonical_target for item in normalized]
    if len(canonicals) != len(set(canonicals)):
        return False

    existing = await load_target_results_for_job(session, job_id, attempt)
    if existing:
        if targets_match(existing, normalized):
            return True
        return False

    for target in normalized:
        session.add(
            orm.ActionTargetResult(
                job_id=job_id,
                attempt=attempt,
                canonical_target=target.canonical_target,
                status=target.status.value,
                code=target.code,
                message=target.message,
                artifact_id=target.artifact_id,
                raw_result=target.raw_result,
            )
        )
    return True


__all__ = [
    "job_from_row",
    "load_target_results_by_job_ids",
    "load_target_results_for_job",
    "sanitize_target_execution_result",
    "sync_target_results_in_tx",
    "target_result_from_row",
    "targets_match",
]
