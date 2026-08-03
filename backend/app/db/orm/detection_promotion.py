"""Detection promotion saga ORM (ISSUE-124 / #629)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

_TS = DateTime(timezone=True)


class DetectionPromotionORM(Base):
    __tablename__ = "detection_promotion"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'source_persisted', 'event_linked', 'completed', "
            "'retry', 'dead', 'manual')",
            name="ck_detection_promotion_status",
        ),
        UniqueConstraint("promotion_key", name="uq_detection_promotion_key"),
        Index("ix_detection_promotion_tenant_status", "tenant_id", "status"),
        Index("ix_detection_promotion_candidate", "candidate_detection_id"),
    )

    promotion_id: Mapped[str] = mapped_column(String, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    promotion_key: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    decision_id: Mapped[str] = mapped_column(String, nullable=False)
    candidate_detection_id: Mapped[str] = mapped_column(String, nullable=False)
    candidate_content_hash: Mapped[str] = mapped_column(String, nullable=False)
    package_id: Mapped[str] = mapped_column(String, nullable=False)
    package_version: Mapped[int] = mapped_column(Integer, nullable=False)
    package_content_hash: Mapped[str] = mapped_column(String, nullable=False)
    detection_scope_id: Mapped[str] = mapped_column(String, nullable=False)
    scope_revision_id: Mapped[str | None] = mapped_column(String, nullable=True)
    derived_connector_id: Mapped[str | None] = mapped_column(String, nullable=True)
    source_record_id: Mapped[str | None] = mapped_column(String, nullable=True)
    event_id: Mapped[str | None] = mapped_column(String, nullable=True)
    link_revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    ingest_result: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    reason_codes: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    reason_message: Mapped[str] = mapped_column(String, default="", nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        _TS, server_default=func.now(), onupdate=func.now(), nullable=False
    )


class DerivedDetectionConnectorORM(Base):
    __tablename__ = "derived_detection_connector"
    __table_args__ = (
        UniqueConstraint(
            "source_tenant_id",
            "detection_scope_id",
            "adapter_kind",
            "adapter_version",
            name="uq_derived_detection_connector_scope",
        ),
        Index("ix_derived_detection_connector_scope", "detection_scope_id"),
    )

    connector_id: Mapped[str] = mapped_column(String, primary_key=True)
    source_tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    detection_scope_id: Mapped[str] = mapped_column(String, nullable=False)
    scope_revision_id: Mapped[str | None] = mapped_column(String, nullable=True)
    adapter_kind: Mapped[str] = mapped_column(String, nullable=False)
    adapter_version: Mapped[str] = mapped_column(String, nullable=False)
    disposition_policy: Mapped[str] = mapped_column(String, default="not_required", nullable=False)
    connector_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
