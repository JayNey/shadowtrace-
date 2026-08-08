"""DB-free unit tests for execution job target persistence helpers (ISSUE-272)."""

from __future__ import annotations

import json

from app.db import models as orm
from app.models.enums import ExecutionJobStatus, TargetExecutionStatus
from app.models.execution import TargetExecutionResult
from app.services.execution_job_persistence import (
    job_from_row,
    sanitize_target_execution_result,
    targets_match,
)
from app.services.execution_job_query_service import project_execution_job_response


def _target(
    canonical: str,
    *,
    status: TargetExecutionStatus = TargetExecutionStatus.SUCCESS,
    code: str | None = "applied",
) -> TargetExecutionResult:
    return TargetExecutionResult(
        canonical_target=canonical,
        status=status,
        code=code,
        message=code,
        raw_result={"code": code} if code else {},
    )


def test_sanitize_target_execution_result_redacts_secrets() -> None:
    dirty = TargetExecutionResult(
        canonical_target="ip:203.0.113.9",
        status=TargetExecutionStatus.FAILED,
        code="token=sk-abcdefghijklmnopqrstuvwxyz012345",
        message="Bearer sk-abcdefghijklmnopqrstuvwxyz012345",
        raw_result={"api_key": "secret-value", "ok": True},
    )
    clean = sanitize_target_execution_result(dirty)
    blob = json.dumps(clean.model_dump(mode="json"))
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in blob
    assert "secret-value" not in blob
    assert clean.raw_result.get("api_key") == "***"
    assert clean.raw_result.get("ok") is True


def test_targets_match_detects_status_conflict() -> None:
    left = [_target("ip:1.1.1.1")]
    right = [_target("ip:1.1.1.1", status=TargetExecutionStatus.FAILED, code="device_offline")]
    assert targets_match(left, left) is True
    assert targets_match(left, right) is False


def test_targets_match_is_order_independent() -> None:
    a = [_target("host:b"), _target("host:a")]
    b = [_target("host:a"), _target("host:b")]
    assert targets_match(a, b) is True


def test_job_from_row_marks_legacy_when_no_child_rows() -> None:
    row = orm.ActionExecutionJob(
        job_id="job-legacy",
        event_id="evt-1",
        action_id="act-1",
        provider_name="mock",
        idempotency_key="idem-1",
        status=ExecutionJobStatus.PARTIAL_SUCCESS.value,
        attempt=1,
        raw_result={"target_results": [{"canonical_target": "ip:1", "status": "success"}]},
    )
    job = job_from_row(row, target_results=[])
    assert job.legacy_target_results is True
    assert job.target_results == []


def test_job_from_row_clears_legacy_when_persisted_targets_exist() -> None:
    row = orm.ActionExecutionJob(
        job_id="job-ok",
        event_id="evt-1",
        action_id="act-1",
        provider_name="mock",
        idempotency_key="idem-1",
        status=ExecutionJobStatus.PARTIAL_SUCCESS.value,
        attempt=1,
        raw_result={},
    )
    job = job_from_row(row, target_results=[_target("host:a"), _target("host:b")])
    assert job.legacy_target_results is False
    assert [item.canonical_target for item in job.target_results] == ["host:a", "host:b"]


def test_project_execution_job_response_does_not_invent_from_raw() -> None:
    job_row = orm.ActionExecutionJob(
        job_id="job-api",
        event_id="evt-1",
        action_id="act-1",
        provider_name="mock",
        idempotency_key="idem-1",
        status=ExecutionJobStatus.PARTIAL_SUCCESS.value,
        attempt=2,
        raw_result={
            "target_results": [
                {"canonical_target": "ip:203.0.113.9", "status": "success"},
                {"canonical_target": "ip:203.0.113.10", "status": "failed"},
            ]
        },
    )
    response = project_execution_job_response(job_row, [])
    assert response.target_results == []
    assert response.legacy_target_results is True
    assert response.attempt == 2


def test_project_execution_job_response_filters_are_caller_responsibility() -> None:
    """Projection only sees rows already scoped to the current attempt."""
    job_row = orm.ActionExecutionJob(
        job_id="job-api",
        event_id="evt-1",
        action_id="act-1",
        provider_name="mock",
        idempotency_key="idem-1",
        status=ExecutionJobStatus.PARTIAL_SUCCESS.value,
        attempt=1,
        raw_result={},
    )
    rows = [
        orm.ActionTargetResult(
            job_id="job-api",
            attempt=1,
            canonical_target="host:b",
            status="failed",
            code="device_offline",
            raw_result={},
        ),
        orm.ActionTargetResult(
            job_id="job-api",
            attempt=1,
            canonical_target="host:a",
            status="success",
            code="applied",
            raw_result={},
        ),
    ]
    # Caller supplies attempt-scoped rows; projection preserves given order.
    response = project_execution_job_response(job_row, rows)
    assert response.legacy_target_results is False
    assert [item["canonical_target"] for item in response.target_results] == [
        "host:b",
        "host:a",
    ]
