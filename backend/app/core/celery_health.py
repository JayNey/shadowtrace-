"""Celery broker vs worker health probes (ISSUE-117 / #622 Phase A).

Broker liveness and worker consumption are separate signals. These probes are
for operations / health reporting only — never call ``probe_celery_workers`` as
a pre-publish gate (no inspect-before-publish race).
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from redis.asyncio import Redis

logger = logging.getLogger(__name__)

DEFAULT_INSPECT_TIMEOUT_SECONDS = 2.0
INTENT_BEAT_HEARTBEAT_KEY = "shadowtrace:celery:investigation-intent-beat:last_ok"
_HEARTBEAT_STALE_FACTOR = 3


async def check_celery_broker(broker_url: str) -> str:
    """Return ``ok`` when the broker URL accepts PING (Redis broker)."""
    if not broker_url.strip():
        return "error"
    client = Redis.from_url(broker_url, decode_responses=True)
    try:
        pong = await client.ping()
        return "ok" if pong else "error"
    except Exception:  # noqa: BLE001 — health must never raise
        logger.debug("celery broker ping failed", exc_info=True)
        return "error"
    finally:
        await client.aclose()


def probe_celery_workers(*, timeout: float = DEFAULT_INSPECT_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Synchronous Celery inspect ping — run via ``asyncio.to_thread`` from async handlers."""
    from app.core.celery_app import celery_app

    try:
        inspector = celery_app.control.inspect(timeout=timeout)
        replies = inspector.ping()
        if not replies:
            return {
                "status": "degraded",
                "workers": 0,
                "worker_ids": [],
                "reason": "no_workers_responding",
            }
        worker_ids = sorted(replies.keys())
        return {
            "status": "ok",
            "workers": len(worker_ids),
            "worker_ids": worker_ids,
        }
    except Exception as exc:  # noqa: BLE001 — health must never raise
        logger.debug("celery worker inspect failed", exc_info=True)
        return {
            "status": "error",
            "workers": 0,
            "worker_ids": [],
            "reason": type(exc).__name__,
        }


async def check_celery_workers(
    *, timeout: float = DEFAULT_INSPECT_TIMEOUT_SECONDS
) -> dict[str, Any]:
    """Async wrapper for worker inspect (non-blocking event loop)."""
    return await asyncio.to_thread(probe_celery_workers, timeout=timeout)


async def build_celery_health(
    *,
    task_mode: str,
    broker_url: str,
    inspect_timeout: float = DEFAULT_INSPECT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Aggregate broker + worker health for ``GET /health``."""
    mode = (task_mode or "background").strip().lower()
    broker_status = await check_celery_broker(broker_url)
    beat_schedule = check_investigation_intent_beat_schedule(task_mode=mode)

    if mode != "celery":
        return {
            "task_mode": mode,
            "broker": broker_status,
            "worker": {"status": "not_applicable", "workers": 0, "worker_ids": []},
            "investigation_intent_beat": beat_schedule,
        }

    worker = await check_celery_workers(timeout=inspect_timeout)
    return {
        "task_mode": mode,
        "broker": broker_status,
        "worker": worker,
        "investigation_intent_beat": beat_schedule,
    }


async def stamp_investigation_intent_beat_heartbeat(redis: Any) -> None:
    """Record that a beat-scheduled intent task actually ran.

    Distinguishes a live Beat dispatch from merely being able to build a Celery schedule.
    """
    try:
        client = redis.get_client()
        await client.set(INTENT_BEAT_HEARTBEAT_KEY, str(int(time.time())))
    except Exception:  # noqa: BLE001 — health stamp must never break dispatch
        logger.debug("investigation intent beat heartbeat stamp failed", exc_info=True)


def _intent_beat_heartbeat_age_s() -> float | None:
    """Age of the last dispatch/reconcile heartbeat, or None when missing/unreadable."""
    from app.core.config import get_settings

    settings = get_settings()
    url = (settings.celery_broker_url or settings.redis_url or "").strip()
    if not url:
        return None
    from redis import Redis as SyncRedis

    client = SyncRedis.from_url(
        url,
        decode_responses=True,
        socket_connect_timeout=0.5,
        socket_timeout=0.5,
    )
    try:
        raw = client.get(INTENT_BEAT_HEARTBEAT_KEY)
        if raw is None:
            return None
        return max(0.0, time.time() - float(raw))
    except Exception:  # noqa: BLE001 — health must never raise
        logger.debug("investigation intent beat heartbeat read failed", exc_info=True)
        return None
    finally:
        try:
            client.close()
        except Exception:
            pass


def check_investigation_intent_beat_schedule(*, task_mode: str) -> dict[str, Any]:
    """Verify intent recovery is both registered for celery mode and actually ticking.

    Building a celery schedule in the API process is not proof that scheduler-beat
    ran with TASK_MODE=celery. Dispatch/reconcile stamp a Redis heartbeat when they run.
    """
    mode = (task_mode or "background").strip().lower()
    if mode != "celery":
        return {
            "status": "not_applicable",
            "dispatch_scheduled": False,
            "reconcile_scheduled": False,
            "beat_heartbeat_age_s": None,
        }

    from app.core.celery_app import _build_beat_schedule
    from app.core.config import TaskMode, get_settings

    schedule = _build_beat_schedule(task_mode=TaskMode(mode))
    dispatch_key = "shadowtrace-dispatch-investigation-intents"
    reconcile_key = "shadowtrace-reconcile-investigation-intents"
    dispatch_scheduled = dispatch_key in schedule
    reconcile_scheduled = reconcile_key in schedule
    heartbeat_age_s = _intent_beat_heartbeat_age_s()
    settings = get_settings()
    stale_after_s = _HEARTBEAT_STALE_FACTOR * max(
        int(settings.auto_investigate_dispatch_interval_s),
        int(settings.auto_investigate_reconcile_interval_s),
    )
    heartbeat_ok = heartbeat_age_s is not None and heartbeat_age_s <= stale_after_s
    if dispatch_scheduled and reconcile_scheduled and heartbeat_ok:
        status = "ok"
        reason = None
    elif not (dispatch_scheduled and reconcile_scheduled):
        status = "degraded"
        reason = "schedule_incomplete"
    else:
        status = "degraded"
        reason = "beat_heartbeat_stale" if heartbeat_age_s is not None else "beat_heartbeat_missing"
    payload: dict[str, Any] = {
        "status": status,
        "dispatch_scheduled": dispatch_scheduled,
        "reconcile_scheduled": reconcile_scheduled,
        "beat_heartbeat_age_s": heartbeat_age_s,
    }
    if reason is not None:
        payload["reason"] = reason
    return payload
