"""Celery application factory (ISSUE-056).

Broker and result backend default to ``CELERY_BROKER_URL`` (falling back to
``REDIS_URL``). Investigation tasks route to the ``investigation`` queue.
"""

from __future__ import annotations

import logging

from celery import Celery
from celery.signals import worker_process_init

from app.core.config import get_settings

logger = logging.getLogger(__name__)


def _resolve_broker_url() -> str:
    settings = get_settings()
    broker = (settings.celery_broker_url or "").strip()
    return broker or settings.redis_url


def init_worker_telemetry(**kwargs: object) -> None:
    """Bootstrap OpenTelemetry inside each Celery worker process (ISSUE-092)."""
    del kwargs
    from app.core.telemetry import setup_telemetry
    from app.db.session import get_engine

    setup_telemetry(engine=get_engine())
    logger.debug("Celery worker telemetry initialized")


worker_process_init.connect(init_worker_telemetry, weak=False)

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

__all__ = ["celery_app", "init_worker_telemetry"]
