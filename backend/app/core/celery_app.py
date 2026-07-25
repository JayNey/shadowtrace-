"""Celery application factory (ISSUE-056).

Broker and result backend default to ``CELERY_BROKER_URL`` (falling back to
``REDIS_URL``). Investigation tasks route to the ``investigation`` queue.
"""

from __future__ import annotations

from celery import Celery

from app.core.config import get_settings


def _resolve_broker_url() -> str:
    settings = get_settings()
    broker = (settings.celery_broker_url or "").strip()
    return broker or settings.redis_url


celery_app = Celery("shadowtrace")

celery_app.conf.update(
    broker_url=_resolve_broker_url(),
    result_backend=_resolve_broker_url(),
    task_default_queue="investigation",
    task_routes={
        "shadowtrace.run_investigation": {"queue": "investigation"},
    },
    task_acks_late=True,
    task_soft_time_limit=600,
    imports=("app.tasks.investigation_tasks",),
)

__all__ = ["celery_app"]
