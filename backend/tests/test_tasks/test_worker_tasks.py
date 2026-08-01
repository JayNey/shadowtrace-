"""Worker ping task tests (ISSUE-117 / #622 Phase A)."""

from __future__ import annotations

from app.tasks.worker_tasks import WORKER_PING_TASK, worker_ping


def test_worker_ping_eager(celery_eager: None) -> None:
    result = worker_ping.apply().result
    assert result == {"status": "ok", "task": WORKER_PING_TASK}


def test_worker_ping_task_name_registered() -> None:
    from app.core.celery_app import celery_app

    assert celery_app.tasks[WORKER_PING_TASK].name == WORKER_PING_TASK
