"""AgentTask coordination ledger ORM (ISSUE-133 / #639 Phase A)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

_TS = DateTime(timezone=True)


class AgentTaskORM(Base):
    __tablename__ = "agent_task"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued','claimed','running','completed','failed',"
            "'cancelled','expired','dead','manual')",
            name="ck_agent_task_status",
        ),
        CheckConstraint("revision >= 1", name="ck_agent_task_revision"),
        CheckConstraint("attempt >= 0", name="ck_agent_task_attempt"),
        UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_agent_task_tenant_idempotency_key",
        ),
        Index("ix_agent_task_event_id", "event_id"),
        Index("ix_agent_task_tenant_id", "tenant_id"),
        Index("ix_agent_task_status_updated", "status", "updated_at"),
        Index("ix_agent_task_lease_expires", "lease_expires_at"),
    )

    task_id: Mapped[str] = mapped_column(String, primary_key=True)
    event_id: Mapped[str] = mapped_column(String, nullable=False)
    tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    task_type: Mapped[str] = mapped_column(String, nullable=False)
    goal: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    claim_owner: Mapped[str | None] = mapped_column(String, nullable=True)
    fencing_token_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    side_effect_status: Mapped[str] = mapped_column(String, nullable=False, default="none")
    idempotency_key: Mapped[str] = mapped_column(String, nullable=False)
    schema_version: Mapped[str] = mapped_column(String, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class AgentTaskAttemptORM(Base):
    __tablename__ = "agent_task_attempt"
    __table_args__ = (
        UniqueConstraint("task_id", "attempt_seq", name="uq_agent_task_attempt_seq"),
        Index("ix_agent_task_attempt_task_id", "task_id"),
    )

    attempt_id: Mapped[str] = mapped_column(String, primary_key=True)
    task_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("agent_task.task_id", ondelete="CASCADE"),
        nullable=False,
    )
    attempt_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    worker_principal: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    fencing_token_hash: Mapped[str] = mapped_column(String, nullable=False)
    started_at: Mapped[datetime] = mapped_column(_TS, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    error_summary: Mapped[str | None] = mapped_column(Text, nullable=True)


class AgentArtifactORM(Base):
    __tablename__ = "agent_artifact"
    __table_args__ = (
        UniqueConstraint(
            "task_id",
            "logical_artifact_key",
            "producer_revision",
            name="uq_agent_artifact_logical_revision",
        ),
        Index("ix_agent_artifact_task_id", "task_id"),
        Index("ix_agent_artifact_event_id", "event_id"),
        Index("ix_agent_artifact_tenant_id", "tenant_id"),
    )

    artifact_id: Mapped[str] = mapped_column(String, primary_key=True)
    task_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("agent_task.task_id", ondelete="CASCADE"),
        nullable=False,
    )
    event_id: Mapped[str] = mapped_column(String, nullable=False)
    tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    logical_artifact_key: Mapped[str] = mapped_column(String, nullable=False)
    producer_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    producer_attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    schema_version: Mapped[str] = mapped_column(String, nullable=False)
    content_hash: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    source_refs: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    decision_record_refs: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
