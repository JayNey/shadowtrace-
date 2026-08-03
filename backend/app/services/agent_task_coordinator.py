"""Phase A coordinator hooks — enqueue typed tasks from existing pipelines (ISSUE-133)."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from app.core.errors import AgentTaskDeniedError, AgentTaskUnavailableError
from app.models.agent_task import (
    TERMINAL_AGENT_TASK_STATUSES,
    AgentArtifactPersistRequest,
    AgentTask,
    AgentTaskClaimRequest,
    AgentTaskContextRef,
    AgentTaskEnqueueRequest,
    AgentTaskGoal,
    AgentTaskStatus,
    AgentTaskType,
)
from app.services.agent_artifact_service import AgentArtifactService
from app.services.agent_task_service import AgentTaskService

logger = logging.getLogger(__name__)

_T = TypeVar("_T")


async def enqueue_risk_score_task(
    agent_task_service: AgentTaskService | None,
    *,
    event_id: str,
    tenant_id: str,
    idempotency_key: str,
    parameters: dict[str, Any] | None = None,
) -> AgentTask | None:
    """Best-effort ledger enqueue before RiskAgent execution (Phase A boundary)."""
    if agent_task_service is None:
        return None
    try:
        return await agent_task_service.enqueue(
            AgentTaskEnqueueRequest(
                event_id=event_id,
                tenant_id=tenant_id,
                goal=AgentTaskGoal(
                    task_type=AgentTaskType.RISK_SCORE,
                    context_refs=[
                        AgentTaskContextRef(ref_kind="event_context_field", ref_id="triage_result"),
                        AgentTaskContextRef(ref_kind="event_context_field", ref_id="evidence_output"),
                        AgentTaskContextRef(ref_kind="event_context_field", ref_id="rag_output"),
                        AgentTaskContextRef(ref_kind="event_context_field", ref_id="graph_output"),
                    ],
                    parameters=parameters or {},
                ),
                idempotency_key=idempotency_key,
            )
        )
    except AgentTaskUnavailableError:
        logger.warning(
            "AgentTask ledger unavailable; skipping risk_score enqueue for event=%s",
            event_id,
        )
        return None


async def _maybe_requeue_recoverable(task: AgentTask, agent_task_service: AgentTaskService, *, tenant_id: str) -> AgentTask:
    if task.status not in {AgentTaskStatus.FAILED, AgentTaskStatus.EXPIRED}:
        return task
    try:
        return await agent_task_service.retry_to_queue(task.task_id, tenant_id=tenant_id)
    except AgentTaskDeniedError:
        return task


async def run_risk_score_with_ledger(
    agent_task_service: AgentTaskService | None,
    artifact_service: AgentArtifactService | None,
    *,
    event_id: str,
    tenant_id: str,
    worker_principal: str,
    idempotency_key: str,
    execute: Callable[[], Awaitable[_T]],
    parameters: dict[str, Any] | None = None,
) -> _T:
    """Run RiskAgent under a synchronous claim→start→artifact→complete ledger cycle."""
    task = await enqueue_risk_score_task(
        agent_task_service,
        event_id=event_id,
        tenant_id=tenant_id,
        idempotency_key=idempotency_key,
        parameters=parameters,
    )
    if agent_task_service is None or task is None:
        return await execute()

    if task.status in TERMINAL_AGENT_TASK_STATUSES:
        if task.status is AgentTaskStatus.COMPLETED:
            return await execute()
        task = await _maybe_requeue_recoverable(task, agent_task_service, tenant_id=tenant_id)
        if task.status in TERMINAL_AGENT_TASK_STATUSES:
            return await execute()

    try:
        claim = await agent_task_service.claim(
            AgentTaskClaimRequest(
                task_id=task.task_id,
                worker_principal=worker_principal,
                tenant_id=tenant_id,
            )
        )
        await agent_task_service.start(claim, tenant_id=tenant_id)
        result = await execute()
        if artifact_service is not None:
            payload = result.model_dump(mode="json") if hasattr(result, "model_dump") else result
            if isinstance(payload, dict):
                try:
                    await artifact_service.persist(
                        claim,
                        AgentArtifactPersistRequest(
                            logical_artifact_key="risk_assessment",
                            payload=payload,
                            source_refs=[
                                AgentTaskContextRef(
                                    ref_kind="event_context_field",
                                    ref_id="evidence_output",
                                ),
                                AgentTaskContextRef(
                                    ref_kind="event_context_field",
                                    ref_id="graph_output",
                                ),
                            ],
                        ),
                        tenant_id=tenant_id,
                        event_id=event_id,
                    )
                except Exception:
                    logger.warning(
                        "AgentArtifact persist failed for event=%s task=%s",
                        event_id,
                        task.task_id,
                        exc_info=True,
                    )
        await agent_task_service.complete(claim)
        return result
    except (AgentTaskDeniedError, AgentTaskUnavailableError) as exc:
        logger.warning(
            "AgentTask ledger cycle degraded for event=%s: %s",
            event_id,
            exc,
        )
        return await execute()


__all__ = ["enqueue_risk_score_task", "run_risk_score_with_ledger"]
