"""KnowledgeChunk ORM model (ISSUE-041)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

_TS = DateTime(timezone=True)

# P0 knowledge_chunk.embedding column width; #634 knowledge_vector must match active release.
KNOWLEDGE_CHUNK_VECTOR_DIM = 1024


class KnowledgeChunkORM(Base):
    __tablename__ = "knowledge_chunk"

    chunk_id: Mapped[str] = mapped_column(String, primary_key=True)
    kb_name: Mapped[str] = mapped_column(String, nullable=False, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    chunk_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, nullable=False
    )
    embedding: Mapped[list[float] | None] = mapped_column(
        Vector(KNOWLEDGE_CHUNK_VECTOR_DIM), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
