"""Memory review queue ORM for governed knowledge promotion (ISSUE-081)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from sqlalchemy import CheckConstraint, DateTime, Float, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

_TS = DateTime(timezone=True)


class MemoryReviewORM(Base):
    __tablename__ = "memory_review"
    __table_args__ = (
        CheckConstraint(
            "candidate_type IN ('fp_rule', 'history_case', 'profile')",
            name="ck_memory_review_candidate_type",
        ),
        CheckConstraint(
            "status IN ('pending', 'promoted', 'demoted')",
            name="ck_memory_review_status",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_memory_review_confidence",
        ),
        Index("ix_memory_review_kb_status", "kb_name", "status"),
    )

    review_id: Mapped[str] = mapped_column(String, primary_key=True)
    kb_name: Mapped[str] = mapped_column(String, nullable=False)
    candidate_type: Mapped[Literal["fp_rule", "history_case", "profile"]] = mapped_column(
        String, nullable=False
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    status: Mapped[Literal["pending", "promoted", "demoted"]] = mapped_column(
        String, default="pending", nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    decided_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    operator: Mapped[str | None] = mapped_column(String, nullable=True)
