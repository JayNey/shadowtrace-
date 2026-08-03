"""AgentTask coordinator unit tests without database (ISSUE-133)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.errors import AgentTaskDeniedError, AgentTaskUnavailableError
from app.models.agent_io import RiskAssessment, ScoringMode
from app.models.agent_task import (
    AGENT_ARTIFACT_SCHEMA_VERSION,
    AgentArtifact,
    AgentTask,
    AgentTaskClaim,
    AgentTaskGoal,
    AgentTaskStatus,
    AgentTaskType,
)
from app.models.enums import Severity
from app.services.agent_task_coordinator import run_risk_score_with_ledger


def _risk(*, score: int = 85) -> RiskAssessment:
    return RiskAssessment(
        risk_score=score,
        severity=Severity.HIGH,
        confidence=0.9,
        risk_factors=[],
        scoring_mode=ScoringMode.RULE_ONLY,
    )


def _completed_task(*, task_id: str = "task-risk-001") -> AgentTask:
    now = datetime.now(UTC)
    return AgentTask(
        task_id=task_id,
        event_id="evt-001",
        tenant_id="tenant-a",
        task_type=AgentTaskType.RISK_SCORE,
        goal=AgentTaskGoal(task_type=AgentTaskType.RISK_SCORE),
        status=AgentTaskStatus.COMPLETED,
        idempotency_key="idem-risk-001",
        created_at=now,
        updated_at=now,
    )


def _queued_task(*, task_id: str = "task-risk-002") -> AgentTask:
    now = datetime.now(UTC)
    return AgentTask(
        task_id=task_id,
        event_id="evt-001",
        tenant_id="tenant-a",
        task_type=AgentTaskType.RISK_SCORE,
        goal=AgentTaskGoal(task_type=AgentTaskType.RISK_SCORE),
        status=AgentTaskStatus.QUEUED,
        idempotency_key="idem-risk-002",
        created_at=now,
        updated_at=now,
    )


def _claim(*, task_id: str) -> AgentTaskClaim:
    return AgentTaskClaim(
        task_id=task_id,
        fencing_token="fencing-token-0123456789ab",
        lease_expires_at=datetime.now(UTC) + timedelta(minutes=5),
        attempt=1,
        worker_principal="worker-a",
        revision=1,
    )


def _risk_artifact(*, task_id: str, payload: dict) -> AgentArtifact:
    return AgentArtifact(
        artifact_id="art-risk-001",
        task_id=task_id,
        event_id="evt-001",
        tenant_id="tenant-a",
        logical_artifact_key="risk_assessment",
        producer_revision=1,
        producer_attempt=1,
        schema_version=AGENT_ARTIFACT_SCHEMA_VERSION,
        content_hash="0" * 64,
        payload=payload,
        created_at=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_completed_task_replays_cached_artifact_without_execute() -> None:
    task = _completed_task()
    cached = _risk(score=72)
    task_service = MagicMock()
    task_service.enqueue = AsyncMock(return_value=task)
    task_service.claim = AsyncMock()
    artifact_service = MagicMock()
    artifact_service.load_latest = AsyncMock(
        return_value=_risk_artifact(task_id=task.task_id, payload=cached.model_dump(mode="json"))
    )
    execute = AsyncMock(return_value=_risk(score=99))

    result = await run_risk_score_with_ledger(
        task_service,
        artifact_service,
        event_id="evt-001",
        tenant_id="tenant-a",
        worker_principal="worker-a",
        idempotency_key="idem-risk-001",
        execute=execute,
    )

    assert result.risk_score == 72
    execute.assert_not_awaited()
    task_service.claim.assert_not_called()


@pytest.mark.asyncio
async def test_completed_task_without_artifact_falls_back_to_execute() -> None:
    task = _completed_task()
    fresh = _risk(score=88)
    task_service = MagicMock()
    task_service.enqueue = AsyncMock(return_value=task)
    artifact_service = MagicMock()
    artifact_service.load_latest = AsyncMock(return_value=None)
    execute = AsyncMock(return_value=fresh)

    result = await run_risk_score_with_ledger(
        task_service,
        artifact_service,
        event_id="evt-001",
        tenant_id="tenant-a",
        worker_principal="worker-a",
        idempotency_key="idem-risk-001",
        execute=execute,
    )

    assert result.risk_score == 88
    execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_artifact_persist_failure_marks_task_failed_not_completed() -> None:
    task = _queued_task()
    claim = _claim(task_id=task.task_id)
    fresh = _risk()
    task_service = MagicMock()
    task_service.enqueue = AsyncMock(return_value=task)
    task_service.claim = AsyncMock(return_value=claim)
    task_service.start = AsyncMock()
    task_service.complete = AsyncMock()
    task_service.fail = AsyncMock()
    artifact_service = MagicMock()
    artifact_service.persist = AsyncMock(side_effect=RuntimeError("db write failed"))
    execute = AsyncMock(return_value=fresh)

    result = await run_risk_score_with_ledger(
        task_service,
        artifact_service,
        event_id="evt-001",
        tenant_id="tenant-a",
        worker_principal="worker-a",
        idempotency_key="idem-risk-002",
        execute=execute,
    )

    assert result.risk_score == 85
    task_service.fail.assert_awaited_once()
    task_service.complete.assert_not_awaited()
    assert "artifact_persist_failed" in task_service.fail.await_args.kwargs["error_summary"]


@pytest.mark.asyncio
async def test_full_ledger_cycle_claims_persists_and_completes() -> None:
    task = _queued_task()
    claim = _claim(task_id=task.task_id)
    fresh = _risk(score=91)
    task_service = MagicMock()
    task_service.enqueue = AsyncMock(return_value=task)
    task_service.claim = AsyncMock(return_value=claim)
    task_service.start = AsyncMock()
    task_service.complete = AsyncMock()
    task_service.fail = AsyncMock()
    artifact_service = MagicMock()
    artifact_service.persist = AsyncMock()
    execute = AsyncMock(return_value=fresh)

    result = await run_risk_score_with_ledger(
        task_service,
        artifact_service,
        event_id="evt-001",
        tenant_id="tenant-a",
        worker_principal="worker-a",
        idempotency_key="idem-risk-002",
        execute=execute,
    )

    assert result.risk_score == 91
    task_service.claim.assert_awaited_once()
    task_service.start.assert_awaited_once_with(claim, tenant_id="tenant-a")
    artifact_service.persist.assert_awaited_once()
    task_service.complete.assert_awaited_once_with(claim)
    task_service.fail.assert_not_awaited()


@pytest.mark.asyncio
async def test_ledger_denied_degrades_to_execute() -> None:
    task = _queued_task()
    fresh = _risk(score=77)
    task_service = MagicMock()
    task_service.enqueue = AsyncMock(return_value=task)
    task_service.claim = AsyncMock(side_effect=AgentTaskDeniedError("stale worker"))
    execute = AsyncMock(return_value=fresh)

    result = await run_risk_score_with_ledger(
        task_service,
        MagicMock(),
        event_id="evt-001",
        tenant_id="tenant-a",
        worker_principal="worker-a",
        idempotency_key="idem-risk-002",
        execute=execute,
    )

    assert result.risk_score == 77
    execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_unavailable_ledger_degrades_to_execute() -> None:
    fresh = _risk(score=66)
    task_service = MagicMock()
    task_service.enqueue = AsyncMock(side_effect=AgentTaskUnavailableError("db down"))
    execute = AsyncMock(return_value=fresh)

    result = await run_risk_score_with_ledger(
        task_service,
        MagicMock(),
        event_id="evt-001",
        tenant_id="tenant-a",
        worker_principal="worker-a",
        idempotency_key="idem-risk-003",
        execute=execute,
    )

    assert result.risk_score == 66
    execute.assert_awaited_once()
