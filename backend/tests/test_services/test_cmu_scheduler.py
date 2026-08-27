"""Aging cμ dispatch identity and ranking tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.services.cmu_scheduler import (
    AGING_HIGH_CATCHUP_S,
    ANALYSIS_ONLY_EXPECTED_S,
    DEFAULT_EXPECTED_S,
    dispatch_priority,
    holding_cost,
    rank_key,
)


def test_holding_cost_unknown_is_low() -> None:
    assert holding_cost(None) == holding_cost("low")
    assert holding_cost("not-a-severity") == holding_cost("low")
    assert holding_cost("CRITICAL") == holding_cost("critical")


def test_same_severity_order_matches_fifo() -> None:
    now = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
    older = now - timedelta(minutes=5)
    newer = now - timedelta(seconds=10)
    items = [
        ("high", newer, "iin-b"),
        ("high", older, "iin-a"),
        ("HIGH", older + timedelta(seconds=1), "iin-c"),
    ]
    by_cmu = sorted(items, key=lambda row: rank_key(row[0], row[1], row[2], now))
    by_fifo = sorted(items, key=lambda row: (row[1], row[2]))
    assert [row[2] for row in by_cmu] == [row[2] for row in by_fifo]


def test_same_timestamp_critical_before_low() -> None:
    now = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
    created = now
    assert dispatch_priority("critical", created, now) > dispatch_priority("low", created, now)
    ranked = sorted(
        [("low", created, "iin-low"), ("critical", created, "iin-crit")],
        key=lambda row: rank_key(row[0], row[1], row[2], now),
    )
    assert [row[2] for row in ranked] == ["iin-crit", "iin-low"]


def test_low_wait_catchup_matches_fresh_high() -> None:
    now = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
    low_created = now - timedelta(seconds=AGING_HIGH_CATCHUP_S)
    high_created = now
    low_pi = dispatch_priority("low", low_created, now)
    high_pi = dispatch_priority("high", high_created, now)
    assert low_pi == pytest.approx(high_pi, rel=1e-9, abs=1e-12)
    fresh_critical = dispatch_priority("critical", now, now)
    assert fresh_critical > low_pi


def test_expected_duration_scales_mu() -> None:
    now = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
    created = now
    faster = dispatch_priority("high", created, now, expected_s=300.0)
    slower = dispatch_priority("high", created, now, expected_s=DEFAULT_EXPECTED_S)
    assert faster > slower


def test_priority_sql_compiles_with_for_update_of_intent() -> None:
    from sqlalchemy import select
    from sqlalchemy.dialects import postgresql

    from app.db import models as orm
    from app.services.cmu_scheduler import priority_order_columns

    now = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
    stmt = (
        select(orm.InvestigationIntent)
        .outerjoin(
            orm.SecurityEvent,
            orm.SecurityEvent.event_id == orm.InvestigationIntent.event_id,
        )
        .order_by(*priority_order_columns(now))
        .with_for_update(of=orm.InvestigationIntent, skip_locked=True)
    )
    compiled = str(stmt.compile(dialect=postgresql.dialect()))
    sql = compiled.upper().replace("\n", " ")
    assert "FOR UPDATE OF INVESTIGATION_INTENT" in sql
    assert "SKIP LOCKED" in sql
    assert "SECURITY_EVENT" in sql
    assert "INCLUDE_RESPONSE_EXECUTION" in sql


def test_analysis_only_high_before_full_loop_high_at_same_timestamp() -> None:
    now = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
    created = now
    analysis = dispatch_priority("high", created, now, include_response_execution=False)
    full_loop = dispatch_priority("high", created, now, include_response_execution=True)
    assert analysis == pytest.approx(4.0 / ANALYSIS_ONLY_EXPECTED_S)
    assert full_loop == pytest.approx(4.0 / DEFAULT_EXPECTED_S)
    assert analysis > full_loop
    ranked = sorted(
        [
            ("high", created, "iin-full", True),
            ("high", created, "iin-analysis", False),
        ],
        key=lambda row: rank_key(
            row[0],
            row[1],
            row[2],
            now,
            include_response_execution=row[3],
        ),
    )
    assert [row[2] for row in ranked] == ["iin-analysis", "iin-full"]
