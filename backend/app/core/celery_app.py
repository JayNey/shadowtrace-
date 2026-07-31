"""Celery application factory (ISSUE-056).

Broker and result backend default to ``CELERY_BROKER_URL`` (falling back to
``REDIS_URL``). Investigation tasks route to the ``investigation`` queue.
"""

from __future__ import annotations

import asyncio
import logging

from celery import Celery
from celery.signals import worker_process_init, worker_process_shutdown

from app.core.config import get_settings

logger = logging.getLogger(__name__)


def _resolve_broker_url() -> str:
    settings = get_settings()
    broker = (settings.celery_broker_url or "").strip()
    return broker or settings.redis_url


def init_worker_telemetry(**kwargs: object) -> None:
    """Bootstrap SessionProvider + OpenTelemetry in each Celery child (ISSUE-118/092)."""
    del kwargs
    from app.core.telemetry import setup_telemetry
    from app.db.session_provider import init_worker_session_provider

    provider = init_worker_session_provider()
    setup_telemetry(engine=provider.engine())
    logger.debug("Celery worker session provider + telemetry initialized")


def shutdown_worker_session_provider(**kwargs: object) -> None:
    """Dispose the worker child SessionProvider on process shutdown (ISSUE-118)."""
    del kwargs
    from app.db.session_provider import dispose_session_provider

    asyncio.run(dispose_session_provider())
    logger.debug("Celery worker session provider disposed")


worker_process_init.connect(init_worker_telemetry, weak=False)
worker_process_shutdown.connect(shutdown_worker_session_provider, weak=False)

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

__all__ = [
    "celery_app",
    "init_worker_telemetry",
    "shutdown_worker_session_provider",
]
