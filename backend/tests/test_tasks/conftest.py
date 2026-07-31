"""Fixtures for Celery investigation task tests (ISSUE-056)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from app.core.celery_app import celery_app
from app.db.session_provider import init_worker_session_provider, reset_session_provider


@pytest.fixture
def celery_eager() -> Iterator[None]:
    """Run Celery tasks inline for deterministic unit tests."""
    previous = {
        "task_always_eager": celery_app.conf.task_always_eager,
        "task_eager_propagates": celery_app.conf.task_eager_propagates,
        "task_store_eager_result": celery_app.conf.task_store_eager_result,
        "result_backend": celery_app.conf.result_backend,
        "broker_url": celery_app.conf.broker_url,
    }
    celery_app.conf.task_always_eager = True
    celery_app.conf.task_eager_propagates = True
    celery_app.conf.task_store_eager_result = True
    celery_app.conf.result_backend = "cache+memory://"
    celery_app.conf.broker_url = "memory://"
    # Eager mode skips worker_process_init — use NullPool like a real worker child.
    init_worker_session_provider()
    yield
    reset_session_provider()
    celery_app.conf.task_always_eager = previous["task_always_eager"]
    celery_app.conf.task_eager_propagates = previous["task_eager_propagates"]
    celery_app.conf.task_store_eager_result = previous["task_store_eager_result"]
    celery_app.conf.result_backend = previous["result_backend"]
    celery_app.conf.broker_url = previous["broker_url"]
