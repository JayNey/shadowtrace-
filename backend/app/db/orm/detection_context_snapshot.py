"""Detection context snapshot ORM (ISSUE-127 / #633)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

_TS = DateTime(timezone=True)


class DetectionContextSnapshotORM(Base):
    __tablename__ = "detection_context_snapshot"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_detection_context_snapshot_idempotency"),
        UniqueConstraint(
            "tenant_id",
            "event_id",
            "revision",
            name="uq_detection_context_snapshot_event_revision",
        ),
        Index("ix_detection_context_snapshot_promotion", "promotion_id"),
    )

    snapshot_id: Mapped[str] = mapped_column(String, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    event_id: Mapped[str] = mapped_column(String, nullable=False)
    event_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    promotion_id: Mapped[str] = mapped_column(String, nullable=False)
    promotion_link_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    promotion_key: Mapped[str] = mapped_column(String, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    supersedes_snapshot_id: Mapped[str | None] = mapped_column(String, nullable=True)
    content_hash: Mapped[str] = mapped_column(String, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String, nullable=False)
    schema_version: Mapped[str] = mapped_column(String, nullable=False)
    body: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
