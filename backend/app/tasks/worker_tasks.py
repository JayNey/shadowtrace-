"""Lightweight Celery worker tasks for ops smoke (ISSUE-117 / #622 Phase A)."""

from __future__ import annotations

from app.core.celery_app import celery_app
from app.tasks.investigation_tasks import TASK_QUEUE

WORKER_PING_TASK = "shadowtrace.worker_ping"


@celery_app.task(  # type: ignore[untyped-decorator]
    name=WORKER_PING_TASK,
    acks_late=True,
    queue=TASK_QUEUE,
)
def worker_ping() -> dict[str, str]:
    """Minimal queue consumer smoke — no DB/Agent side effects."""
    return {"status": "ok", "task": WORKER_PING_TASK}


__all__ = ["WORKER_PING_TASK", "worker_ping"]
