"""Idempotent entity-profile updates for MemoryAgent (ISSUE-080)."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.orm.profile import EntityProfileORM
from app.models.agent_io import ProfileUpdate

RISK_HISTORY_LIMIT = 10


def profile_id_for(entity_type: str, entity_value: str) -> str:
    """Return the stable ``prf-{8 hex}`` identity for an entity."""
    identity = f"{entity_type.strip().lower()}:{entity_value.strip().casefold()}"
    return f"prf-{hashlib.sha256(identity.encode()).hexdigest()[:8]}"


class ProfileService:
    """Persist entity behavior across closed investigations.

    Replaying the same event is idempotent: it refreshes the latest pointer and
    tags but does not increment ``event_count`` or duplicate risk history.
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def upsert(self, update: ProfileUpdate) -> EntityProfileORM:
        entity_type = update.entity_type.strip().lower()
        entity_value = update.entity_value.strip()
        if not entity_type or not entity_value:
            raise ValueError("entity_type and entity_value are required")

        profile_id = profile_id_for(entity_type, entity_value)
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.scalar(
                    select(EntityProfileORM)
                    .where(EntityProfileORM.profile_id == profile_id)
                    .with_for_update()
                )
                initial_history = [update.risk_score] if update.risk_score is not None else []
                if row is None:
                    row = EntityProfileORM(
                        profile_id=profile_id,
                        entity_type=entity_type,
                        entity_value=entity_value,
                        event_count=1,
                        last_event_id=update.event_id,
                        risk_history=initial_history,
                        behavior_tags=sorted(set(update.behavior_tags)),
                        updated_at=datetime.now(UTC),
                    )
                    session.add(row)
                else:
                    history = list(row.risk_history or [])
                    seen_event = row.last_event_id == update.event_id
                    if not seen_event:
                        row.event_count += 1
                        if update.risk_score is not None:
                            history.append(update.risk_score)
                    row.risk_history = history[-RISK_HISTORY_LIMIT:]
                    row.last_event_id = update.event_id
                    row.behavior_tags = sorted(
                        set(row.behavior_tags or []).union(update.behavior_tags)
                    )
                    row.updated_at = datetime.now(UTC)
                await session.flush()
            await session.refresh(row)
            return row

    async def get(self, entity_type: str, entity_value: str) -> EntityProfileORM | None:
        async with self._session_factory() as session:
            profile_id = profile_id_for(entity_type, entity_value)
            row = await session.scalar(
                select(EntityProfileORM).where(EntityProfileORM.profile_id == profile_id)
            )
            return row
