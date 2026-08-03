"""Phase A coordinator hooks — enqueue typed tasks from existing pipelines (ISSUE-133)."""

from __future__ import annotations

import logging
from typing import Any

from app.core.errors import AgentTaskUnavailableError
from app.models.agent_task import (
    AgentTask,
    AgentTaskContextRef,
    AgentTaskEnqueueRequest,
    AgentTaskGoal,
    AgentTaskType,
)
from app.services.agent_task_service import AgentTaskService

logger = logging.getLogger(__name__)


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


__all__ = ["enqueue_risk_score_task"]
