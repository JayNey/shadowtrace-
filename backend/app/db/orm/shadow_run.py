"""Shadow run ORM (ISSUE-135 / #641 Phase A)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Index, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

_TS = DateTime(timezone=True)


class ShadowRunORM(Base):
    __tablename__ = "shadow_run"
    __table_args__ = (
        CheckConstraint(
            "status IN ('running', 'completed', 'failed', 'rejected')",
            name="ck_shadow_run_status",
        ),
        Index("ix_shadow_run_event_id", "event_id"),
        Index("ix_shadow_run_tenant_id", "tenant_id"),
        Index("ix_shadow_run_namespace_key", "namespace_key"),
    )

    shadow_run_id: Mapped[str] = mapped_column(String, primary_key=True)
    event_id: Mapped[str] = mapped_column(String, nullable=False)
    tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    namespace_key: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    max_steps: Mapped[int] = mapped_column(Integer, nullable=False)
    step_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_tool_calls: Mapped[int] = mapped_column(Integer, nullable=False)
    tool_call_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    result_summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    rejected_reasons: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    retention_expires_at: Mapped[datetime] = mapped_column(_TS, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)


class ShadowDecisionRecordORM(Base):
    """Shadow-scoped DecisionRecord rows — never visible to production reconcilers."""

    __tablename__ = "shadow_decision_record"
    __table_args__ = (
        Index("ix_shadow_decision_record_shadow_run_id", "shadow_run_id"),
        Index("ix_shadow_decision_record_event_id", "event_id"),
    )

    record_id: Mapped[str] = mapped_column(String, primary_key=True)
    shadow_run_id: Mapped[str] = mapped_column(String, nullable=False)
    event_id: Mapped[str] = mapped_column(String, nullable=False)
    namespace_key: Mapped[str] = mapped_column(String, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    record_hash: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    retention_expires_at: Mapped[datetime] = mapped_column(_TS, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class ShadowQueryArtifactORM(Base):
    __tablename__ = "shadow_query_artifact"
    __table_args__ = (Index("ix_shadow_query_artifact_shadow_run_id", "shadow_run_id"),)

    artifact_id: Mapped[str] = mapped_column(String, primary_key=True)
    shadow_run_id: Mapped[str] = mapped_column(String, nullable=False)
    kind: Mapped[str] = mapped_column(String, nullable=False)
    content_hash: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
