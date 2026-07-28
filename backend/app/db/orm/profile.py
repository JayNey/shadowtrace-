"""Entity profile ORM used by MemoryAgent knowledge consolidation (ISSUE-080)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

_TS = DateTime(timezone=True)


class EntityProfileORM(Base):
    __tablename__ = "entity_profile"
    __table_args__ = (
        UniqueConstraint(
            "entity_type",
            "entity_value",
            name="uq_entity_profile_type_value",
        ),
    )

    profile_id: Mapped[str] = mapped_column(String, primary_key=True)
    entity_type: Mapped[str] = mapped_column(String, nullable=False, index=True)
    entity_value: Mapped[str] = mapped_column(String, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_event_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    risk_history: Mapped[list[int]] = mapped_column(JSONB, default=list, nullable=False)
    behavior_tags: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        _TS,
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
