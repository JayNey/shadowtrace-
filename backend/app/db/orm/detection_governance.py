"""Detection governance decision ORM (ISSUE-125 / #630 Phase A)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

_TS = DateTime(timezone=True)


class DetectionGovernanceDecisionORM(Base):
    __tablename__ = "detection_governance_decision"
    __table_args__ = (
        CheckConstraint(
            "decision IN ('approve', 'reject', 'expire', 'revoke')",
            name="ck_detection_governance_decision_kind",
        ),
        Index("ix_detection_governance_tenant_binding", "tenant_id", "binding_hash"),
        Index("ix_detection_governance_supersedes", "supersedes_decision_id"),
    )

    decision_id: Mapped[str] = mapped_column(String, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    decision: Mapped[str] = mapped_column(String, nullable=False)
    binding_hash: Mapped[str] = mapped_column(String, nullable=False)
    decision_hash: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    reviewer_subject: Mapped[str] = mapped_column(String, nullable=False)
    supersedes_decision_id: Mapped[str | None] = mapped_column(String, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    decided_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
