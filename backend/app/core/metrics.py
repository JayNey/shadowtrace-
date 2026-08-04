"""Business metrics for disposition / writeback observability (ISSUE-092).

Label dimensions are intentionally low-cardinality: ``status`` and ``adapter``
only. Never attach ``source_object_id``, IP addresses, or raw payloads.
"""

from __future__ import annotations

import logging
from typing import Any

from app.core import telemetry

logger = logging.getLogger(__name__)

_meter: Any | None = None
_writeback_total: Any | None = None
_writeback_queue_age: Any | None = None
_writeback_retry_total: Any | None = None
_action_unknown_total: Any | None = None
_checkpoint_fallback_total: Any | None = None
_checkpoint_memory_fallback_gauge: Any | None = None
_initialized = False
_process_checkpoint_fallback_active = False
_process_checkpoint_fallback_triggers = 0


def _ensure_metrics() -> None:
    global _meter, _writeback_total, _writeback_queue_age, _writeback_retry_total
    global _action_unknown_total, _checkpoint_fallback_total
    global _checkpoint_memory_fallback_gauge, _initialized

    if not telemetry.is_telemetry_enabled():
        return
    if _initialized:
        return

    try:
        _meter = telemetry.get_meter("shadowtrace.metrics")
        _writeback_total = _meter.create_counter(
            name="shadowtrace_writeback_total",
            description="Disposition writeback terminal outcomes",
            unit="1",
        )
        _writeback_queue_age = _meter.create_histogram(
            name="shadowtrace_writeback_queue_age_seconds",
            description="Age of outbox rows when claimed for delivery",
            unit="s",
        )
        _writeback_retry_total = _meter.create_counter(
            name="shadowtrace_writeback_retry_total",
            description="Writeback delivery retries and manual re-enqueues",
            unit="1",
        )
        _action_unknown_total = _meter.create_counter(
            name="shadowtrace_action_unknown_total",
            description="Actions promoted to UNKNOWN after writeback ambiguity",
            unit="1",
        )
        _checkpoint_fallback_total = _meter.create_counter(
            name="shadowtrace_checkpoint_fallback_total",
            description="LangGraph checkpoint Redis failures that triggered memory fallback",
            unit="1",
        )
        _checkpoint_memory_fallback_gauge = _meter.create_up_down_counter(
            name="shadowtrace_checkpoint_memory_fallback",
            description="1 when any checkpointer in this process uses memory fallback, else 0",
            unit="1",
        )
    except Exception:
        logger.debug("Business metric registration failed", exc_info=True)
    _initialized = True


def record_writeback(*, status: str, adapter: str) -> None:
    """Increment ``shadowtrace_writeback_total{status,adapter}``."""
    _ensure_metrics()
    if _writeback_total is None:
        return
    try:
        _writeback_total.add(1, {"status": status, "adapter": adapter})
    except Exception:
        logger.debug("writeback metric export failed", exc_info=True)


def observe_writeback_queue_age(seconds: float) -> None:
    """Record outbox queue age in seconds."""
    _ensure_metrics()
    if _writeback_queue_age is None:
        return
    try:
        _writeback_queue_age.record(max(0.0, seconds))
    except Exception:
        logger.debug("queue age metric export failed", exc_info=True)


def record_writeback_retry(*, adapter: str) -> None:
    """Increment ``shadowtrace_writeback_retry_total{adapter}``."""
    _ensure_metrics()
    if _writeback_retry_total is None:
        return
    try:
        _writeback_retry_total.add(1, {"adapter": adapter})
    except Exception:
        logger.debug("writeback retry metric export failed", exc_info=True)


def record_action_unknown(*, adapter: str = "unknown") -> None:
    """Increment ``shadowtrace_action_unknown_total``."""
    _ensure_metrics()
    if _action_unknown_total is None:
        return
    try:
        _action_unknown_total.add(1, {"adapter": adapter})
    except Exception:
        logger.debug("action unknown metric export failed", exc_info=True)


def record_checkpoint_fallback(*, reason: str) -> None:
    """Increment checkpoint fallback counter and process trigger tally."""
    global _process_checkpoint_fallback_triggers
    _process_checkpoint_fallback_triggers += 1
    _ensure_metrics()
    if _checkpoint_fallback_total is None:
        return
    try:
        _checkpoint_fallback_total.add(1, {"reason": reason})
    except Exception:
        logger.debug("checkpoint fallback metric export failed", exc_info=True)


def set_checkpoint_memory_fallback(active: bool) -> None:
    """Set process-wide checkpoint memory fallback gauge (0/1)."""
    global _process_checkpoint_fallback_active
    if active == _process_checkpoint_fallback_active:
        return
    _process_checkpoint_fallback_active = active
    _ensure_metrics()
    if _checkpoint_memory_fallback_gauge is None:
        return
    try:
        delta = 1 if active else -1
        _checkpoint_memory_fallback_gauge.add(delta)
    except Exception:
        logger.debug("checkpoint memory fallback gauge export failed", exc_info=True)


def checkpoint_health_snapshot() -> dict[str, int | bool]:
    """Low-cardinality checkpoint observability for health probes."""
    return {
        "memory_fallback": _process_checkpoint_fallback_active,
        "fallback_triggers": _process_checkpoint_fallback_triggers,
    }


def reset_metrics_for_tests() -> None:
    """Allow tests to re-register instruments after telemetry reset."""
    global _meter, _writeback_total, _writeback_queue_age, _writeback_retry_total
    global _action_unknown_total, _checkpoint_fallback_total
    global _checkpoint_memory_fallback_gauge, _initialized
    global _process_checkpoint_fallback_active, _process_checkpoint_fallback_triggers
    _meter = None
    _writeback_total = None
    _writeback_queue_age = None
    _writeback_retry_total = None
    _action_unknown_total = None
    _checkpoint_fallback_total = None
    _checkpoint_memory_fallback_gauge = None
    _initialized = False
    _process_checkpoint_fallback_active = False
    _process_checkpoint_fallback_triggers = 0


def reset_checkpoint_metrics_for_tests() -> None:
    """Reset only checkpoint metric process counters (alias for tests)."""
    global _process_checkpoint_fallback_active, _process_checkpoint_fallback_triggers
    _process_checkpoint_fallback_active = False
    _process_checkpoint_fallback_triggers = 0


__all__ = [
    "checkpoint_health_snapshot",
    "observe_writeback_queue_age",
    "record_action_unknown",
    "record_checkpoint_fallback",
    "record_writeback",
    "record_writeback_retry",
    "reset_checkpoint_metrics_for_tests",
    "reset_metrics_for_tests",
    "set_checkpoint_memory_fallback",
]
