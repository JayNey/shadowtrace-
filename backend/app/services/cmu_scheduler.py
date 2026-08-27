"""Aging cμ-rule for auto-investigate intent claim order.

Non-preemptive cμ (Buyukkoc–Varaiya–Walrand) plus Kleinrock-style delay:

    π = c(severity) * μ + γ * w

This is cμ + aging, not the textbook cμ-rule: holding cost is event
severity, and expected duration depends on whether the intent is
analysis-only or a full response loop. Same holding cost and same expected
duration ⇒ order ≡ FIFO (created_at ASC, intent_id ASC). Missing/invalid
severity is treated as LOW so claim never drops a row.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import case, func, literal

from app.db import models as orm

HOLDING_COST: dict[str, float] = {
    "low": 1.0,
    "medium": 2.0,
    "high": 4.0,
    "critical": 8.0,
}

# Full-loop expected duration; matches Celery task_soft_time_limit.
DEFAULT_EXPECTED_S = 600.0
# Analysis-only intents skip response/approval/execute.
ANALYSIS_ONLY_EXPECTED_S = 300.0

# γ is set so a LOW job waiting this long matches a fresh HIGH (same μ).
AGING_HIGH_CATCHUP_S = 1800.0


def expected_duration_s(*, include_response_execution: bool = False) -> float:
    if include_response_execution:
        return DEFAULT_EXPECTED_S
    return ANALYSIS_ONLY_EXPECTED_S


def aging_gamma(*, expected_s: float = DEFAULT_EXPECTED_S) -> float:
    """γ such that π(LOW, wait=AGING_HIGH_CATCHUP_S) = π(HIGH, wait=0)."""
    duration = max(float(expected_s), 1.0)
    return 3.0 / (duration * AGING_HIGH_CATCHUP_S)


def holding_cost(severity: str | None) -> float:
    key = (severity or "low").strip().lower()
    return HOLDING_COST.get(key, HOLDING_COST["low"])


def wait_seconds(created_at: datetime, now: datetime) -> float:
    return max(0.0, (now - created_at).total_seconds())


def dispatch_priority(
    severity: str | None,
    created_at: datetime,
    now: datetime,
    *,
    expected_s: float | None = None,
    include_response_execution: bool = False,
) -> float:
    """Scalar π used by tests; SQL uses the same terms in ``priority_expression``."""
    duration = (
        float(expected_s)
        if expected_s is not None
        else expected_duration_s(include_response_execution=include_response_execution)
    )
    duration = max(duration, 1.0)
    mu = 1.0 / duration
    return holding_cost(severity) * mu + aging_gamma(expected_s=duration) * wait_seconds(
        created_at, now
    )


def rank_key(
    severity: str | None,
    created_at: datetime,
    intent_id: str,
    now: datetime,
    *,
    expected_s: float | None = None,
    include_response_execution: bool = False,
) -> tuple[float, datetime, str]:
    """Sort ascending: higher π first via negated priority in the first slot."""
    priority = dispatch_priority(
        severity,
        created_at,
        now,
        expected_s=expected_s,
        include_response_execution=include_response_execution,
    )
    return (-priority, created_at, intent_id)


def priority_expression(now: datetime) -> Any:
    """SQLAlchemy expression for π (outerjoin SecurityEvent.severity)."""
    holding = case(
        (func.lower(orm.SecurityEvent.severity) == "critical", literal(8.0)),
        (func.lower(orm.SecurityEvent.severity) == "high", literal(4.0)),
        (func.lower(orm.SecurityEvent.severity) == "medium", literal(2.0)),
        else_=literal(1.0),
    )
    duration = case(
        (
            orm.InvestigationIntent.include_response_execution.is_(True),
            literal(DEFAULT_EXPECTED_S),
        ),
        else_=literal(ANALYSIS_ONLY_EXPECTED_S),
    )
    wait_s = func.greatest(
        literal(0.0),
        func.extract("epoch", literal(now) - orm.InvestigationIntent.created_at),
    )
    return holding / duration + (literal(3.0) / (duration * literal(AGING_HIGH_CATCHUP_S))) * wait_s


def priority_order_columns(now: datetime) -> tuple[Any, ...]:
    """ORDER BY π DESC, created_at ASC, intent_id ASC."""
    return (
        priority_expression(now).desc(),
        orm.InvestigationIntent.created_at.asc(),
        orm.InvestigationIntent.intent_id.asc(),
    )


__all__ = [
    "AGING_HIGH_CATCHUP_S",
    "ANALYSIS_ONLY_EXPECTED_S",
    "DEFAULT_EXPECTED_S",
    "HOLDING_COST",
    "aging_gamma",
    "dispatch_priority",
    "expected_duration_s",
    "holding_cost",
    "priority_expression",
    "priority_order_columns",
    "rank_key",
    "wait_seconds",
]
