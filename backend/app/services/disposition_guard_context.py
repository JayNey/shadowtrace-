"""Guard context helpers for disposition outbox (ISSUE-224)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import models as orm
from app.models.enums import ActionStatus

_ACTIVE_APPROVAL_STATUSES = (
    ActionStatus.APPROVED.value,
    ActionStatus.EXECUTING.value,
)


async def resolve_approved_action_ids(
    session: AsyncSession,
    *,
    event_id: str,
    plan_revision: int,
) -> list[str]:
    """Return action_ids approved or actively executing on the event plan.

    Covers the APPROVED→EXECUTING window for action execution enqueue as well
    as deferred terminal disposition activation (still APPROVED at enqueue).
    """
    rows = (
        await session.scalars(
            select(orm.Action.action_id).where(
                orm.Action.event_id == event_id,
                orm.Action.plan_revision == plan_revision,
                orm.Action.status.in_(_ACTIVE_APPROVAL_STATUSES),
                orm.Action.superseded_by_revision.is_(None),
            )
        )
    ).all()
    return sorted({str(row) for row in rows})


__all__ = ["resolve_approved_action_ids"]
