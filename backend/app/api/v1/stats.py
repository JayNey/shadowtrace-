"""Platform statistics endpoint (ISSUE-085 SOC dashboard).

Aggregates event distributions and three orthogonal disposition rates:
action execution success, effect verification, and required writeback
confirmation. Never exposes a single folded ``action_success_rate``.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1 import schemas as s
from app.core.auth import CurrentPrincipal
from app.core.errors import DependencyUnavailableError
from app.db import models as orm
from app.models.enums import ActionStatus, EventStatus, WritebackStatus

logger = logging.getLogger(__name__)

router = APIRouter(tags=["stats"])

# Terminal execution outcomes that can be scored as success/failure.
_JUDGEABLE_ACTION_STATUSES = (
    ActionStatus.SUCCESS.value,
    ActionStatus.FAILED.value,
    ActionStatus.PARTIAL_SUCCESS.value,
)

# Effect verification outcomes that entered the verification path.
_EFFECT_VERIFIED = "verified"
_EFFECT_FAILED = "failed"
_EFFECT_JUDGEABLE = (_EFFECT_VERIFIED, _EFFECT_FAILED)


def _try_get_session_factory() -> async_sessionmaker[AsyncSession] | None:
    """Return the session factory, or None if DB wiring is unavailable."""
    try:
        from app.api.v1.deps import _get_session_factory

        return _get_session_factory()
    except (ImportError, ModuleNotFoundError, RuntimeError, ValueError, TypeError, OSError):
        logger.warning("Stats session factory unavailable", exc_info=True)
        return None


def _rate(numerator: int, denominator: int) -> s.RateStat:
    if denominator <= 0:
        return s.RateStat(rate=None, numerator=numerator, denominator=0)
    return s.RateStat(
        rate=round(numerator / denominator, 6),
        numerator=numerator,
        denominator=denominator,
    )


async def _aggregate_stats(session: AsyncSession) -> s.StatsResponse:
    """Run aggregation queries (event dims + action rates + hourly trend)."""
    now = datetime.now(UTC)
    window_start = now - timedelta(hours=24)

    # --- Event distributions (one grouped scan, then pivot in Python) ------
    event_rows = (
        await session.execute(
            select(
                orm.SecurityEvent.status,
                orm.SecurityEvent.severity,
                orm.SecurityEvent.event_type,
                func.count().label("cnt"),
            ).group_by(
                orm.SecurityEvent.status,
                orm.SecurityEvent.severity,
                orm.SecurityEvent.event_type,
            )
        )
    ).all()

    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_event_type: dict[str, int] = {}
    total_events = 0
    for status, severity, event_type, cnt in event_rows:
        n = int(cnt)
        total_events += n
        by_status[status] = by_status.get(status, 0) + n
        by_severity[severity] = by_severity.get(severity, 0) + n
        by_event_type[event_type] = by_event_type.get(event_type, 0) + n

    closed_events = by_status.get(EventStatus.CLOSED.value, 0)
    open_events = total_events - closed_events

    # Average investigation duration for closed events with closed_at set.
    avg_row = (
        await session.execute(
            select(
                func.avg(
                    func.extract(
                        "epoch",
                        orm.SecurityEvent.closed_at - orm.SecurityEvent.created_at,
                    )
                )
            ).where(
                orm.SecurityEvent.closed_at.is_not(None),
                orm.SecurityEvent.status == EventStatus.CLOSED.value,
            )
        )
    ).scalar_one_or_none()
    avg_investigation_seconds: float | None
    if avg_row is None:
        avg_investigation_seconds = None
    else:
        avg_investigation_seconds = float(avg_row)

    # External unsynced + pending approvals / writebacks (legacy counters).
    external_unsynced_events = int(
        (
            await session.execute(
                select(func.count()).where(orm.SecurityEvent.external_unsynced.is_(True))
            )
        ).scalar_one()
        or 0
    )
    pending_approvals = int(
        (
            await session.execute(
                select(func.count()).where(orm.Action.status == ActionStatus.WAITING_APPROVAL.value)
            )
        ).scalar_one()
        or 0
    )
    pending_writebacks = int(
        (
            await session.execute(
                select(func.count()).where(
                    orm.Action.writeback_required.is_(True),
                    orm.Action.writeback_status.in_(
                        (
                            WritebackStatus.PENDING.value,
                            WritebackStatus.SENDING.value,
                            WritebackStatus.ACCEPTED.value,
                        )
                    ),
                )
            )
        ).scalar_one()
        or 0
    )

    # --- Three orthogonal rates from action table (single scan) -----------
    rate_row = (
        await session.execute(
            select(
                func.count()
                .filter(orm.Action.status == ActionStatus.SUCCESS.value)
                .label("action_success_num"),
                func.count()
                .filter(orm.Action.status.in_(_JUDGEABLE_ACTION_STATUSES))
                .label("action_success_den"),
                func.count()
                .filter(orm.Action.effect_verification_status == _EFFECT_VERIFIED)
                .label("effect_num"),
                func.count()
                .filter(orm.Action.effect_verification_status.in_(_EFFECT_JUDGEABLE))
                .label("effect_den"),
                func.count()
                .filter(
                    orm.Action.writeback_required.is_(True),
                    orm.Action.writeback_status == WritebackStatus.CONFIRMED.value,
                )
                .label("wb_num"),
                func.count().filter(orm.Action.writeback_required.is_(True)).label("wb_den"),
            )
        )
    ).one()

    action_execution_success_rate = _rate(
        int(rate_row.action_success_num or 0),
        int(rate_row.action_success_den or 0),
    )
    effect_verification_rate = _rate(
        int(rate_row.effect_num or 0),
        int(rate_row.effect_den or 0),
    )
    writeback_confirmation_rate = _rate(
        int(rate_row.wb_num or 0),
        int(rate_row.wb_den or 0),
    )

    # --- Hourly event counts for last 24h (trend chart) --------------------
    hour_bucket = func.date_trunc("hour", orm.SecurityEvent.created_at)
    hourly_rows = (
        await session.execute(
            select(hour_bucket.label("hour"), func.count().label("cnt"))
            .where(orm.SecurityEvent.created_at >= window_start)
            .group_by(hour_bucket)
            .order_by(hour_bucket)
        )
    ).all()
    counts_by_hour: dict[datetime, int] = {}
    for hour, cnt in hourly_rows:
        if hour is None:
            continue
        key = hour if hour.tzinfo is not None else hour.replace(tzinfo=UTC)
        counts_by_hour[key] = int(cnt)

    # Fill every hour in the window so the chart has a continuous series.
    events_last_24h: list[s.HourlyEventCount] = []
    # Align to hour boundaries.
    cursor = window_start.replace(minute=0, second=0, microsecond=0)
    end_hour = now.replace(minute=0, second=0, microsecond=0)
    while cursor <= end_hour:
        events_last_24h.append(
            s.HourlyEventCount(
                hour=cursor.isoformat().replace("+00:00", "Z"),
                count=counts_by_hour.get(cursor, 0),
            )
        )
        cursor += timedelta(hours=1)

    return s.StatsResponse(
        total_events=total_events,
        by_status=by_status,
        by_severity=by_severity,
        by_event_type=by_event_type,
        action_execution_success_rate=action_execution_success_rate,
        effect_verification_rate=effect_verification_rate,
        writeback_confirmation_rate=writeback_confirmation_rate,
        avg_investigation_seconds=avg_investigation_seconds,
        events_last_24h=events_last_24h,
        open_events=open_events,
        closed_events=closed_events,
        pending_approvals=pending_approvals,
        pending_writebacks=pending_writebacks,
        external_unsynced_events=external_unsynced_events,
    )


@router.get("/stats", response_model=s.StatsResponse)
async def get_stats(principal: CurrentPrincipal) -> s.StatsResponse:
    """Return SOC dashboard aggregations (ISSUE-085)."""
    _ = principal  # auth gate only
    sf = _try_get_session_factory()
    if sf is None:
        raise DependencyUnavailableError(
            "stats database session factory unavailable",
            details={"endpoint": "/api/v1/stats"},
        )
    try:
        async with sf() as session:
            return await _aggregate_stats(session)
    except DependencyUnavailableError:
        raise
    except (SQLAlchemyError, OSError, TimeoutError, RuntimeError) as exc:
        logger.warning("Stats aggregation failed: %s", exc, exc_info=True)
        raise DependencyUnavailableError(
            "stats aggregation failed",
            details={"endpoint": "/api/v1/stats"},
        ) from exc
