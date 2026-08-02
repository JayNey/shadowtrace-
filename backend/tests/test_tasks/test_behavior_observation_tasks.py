"""BehaviorObservation Celery retry task tests (ISSUE-156)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.core.config import get_settings
from app.tasks.behavior_observation_tasks import (
    RETRY_PENDING_TASK,
    retry_behavior_observation_pending,
)


def test_retry_pending_task_name_registered() -> None:
    from app.core.celery_app import celery_app

    assert celery_app.tasks[RETRY_PENDING_TASK].name == RETRY_PENDING_TASK


def test_beat_schedule_empty_when_retry_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BEHAVIOR_OBSERVATION_RETRY_ENABLED", "false")
    monkeypatch.setenv("INGESTION_SCHEDULER_ENABLED", "false")
    monkeypatch.setenv("AUTO_INVESTIGATE_ENABLED", "false")
    get_settings.cache_clear()
    from app.core.celery_app import _build_beat_schedule

    assert "shadowtrace-behavior-observation-retry-pending" not in _build_beat_schedule()
    get_settings.cache_clear()


def test_beat_schedule_present_when_retry_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BEHAVIOR_OBSERVATION_RETRY_ENABLED", "true")
    monkeypatch.setenv("BEHAVIOR_OBSERVATION_RETRY_INTERVAL_S", "180")
    monkeypatch.setenv("INGESTION_SCHEDULER_ENABLED", "false")
    monkeypatch.setenv("AUTO_INVESTIGATE_ENABLED", "false")
    get_settings.cache_clear()
    from app.core.celery_app import _build_beat_schedule

    schedule = _build_beat_schedule()
    entry = schedule["shadowtrace-behavior-observation-retry-pending"]
    assert entry["task"] == RETRY_PENDING_TASK
    assert entry["schedule"] == 180.0
    assert entry["options"] == {"queue": "ingestion"}
    get_settings.cache_clear()


def test_retry_pending_task_eager(celery_eager: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BEHAVIOR_OBSERVATION_RETRY_BATCH_LIMIT", "25")
    get_settings.cache_clear()

    async def _fake_retry_pending(*, limit: int) -> int:
        assert limit == 25
        return 2

    with patch(
        "app.tasks.behavior_observation_tasks.BehaviorObservationService.retry_pending",
        new=AsyncMock(side_effect=_fake_retry_pending),
    ):
        with patch(
            "app.tasks.behavior_observation_tasks._snapshot_failure_counts",
            new=AsyncMock(side_effect=[(3, 1), (1, 0)]),
        ):
            result = retry_behavior_observation_pending.apply().result

    assert result["retried"] == 2
    assert result["limit"] == 25
    assert result["pending_retry_before"] == 3
    assert result["pending_retry_after"] == 1
    get_settings.cache_clear()
