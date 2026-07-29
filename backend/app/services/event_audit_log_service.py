"""EventAuditLogService for persisting EventStatus transitions (ISSUE-028).

Every controlled state change is recorded as an append-only audit log entry
keyed by event_id, ordered by created_at.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.opensearch_client import AUDIT_LOGS_SUFFIX, OpenSearchClient
from app.core.sanitization import redact_sensitive_text
from app.db import models as orm

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(UTC)


class EventAuditLogService:
    """Appends status-transition audit entries to ``event_audit_log``."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        opensearch: OpenSearchClient | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._opensearch = opensearch

    async def _index_document_to_opensearch(self, doc_id: str, body: dict[str, Any]) -> None:
        """Fire-and-forget index an audit log document into OpenSearch.

        Never raises — all failures are caught and logged.
        """
        if self._opensearch is None or not self._opensearch.enabled:
            return
        try:
            await self._opensearch.index_document(AUDIT_LOGS_SUFFIX, doc_id, body)
        except Exception:
            logger.warning("OpenSearch index failed for audit log %s", doc_id, exc_info=True)

    @staticmethod
    def _audit_index_payload(row: orm.EventAuditLog) -> dict[str, Any]:
        """Snapshot row fields before the session closes (ISSUE-084)."""
        return {
            "id": row.id,
            "event_id": row.event_id,
            "from_status": row.from_status,
            "to_status": row.to_status,
            "operator": row.operator,
            "reason": row.reason,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }

    async def log_transition(
        self,
        event_id: str,
        from_status: str | None,
        to_status: str | None,
        operator: str | None,
        reason: str | None,
    ) -> str:
        """Persist one state transition and return its generated id as a string.

        The caller (StateMachineService) is responsible for calling this inside
        the same transaction that performs the status change so the log entry is
        atomically consistent with the new state.
        """
        row = orm.EventAuditLog(
            event_id=event_id,
            from_status=from_status,
            to_status=to_status,
            operator=redact_sensitive_text(operator) if operator else None,
            reason=redact_sensitive_text(reason)[:4096] if reason else None,
            created_at=_utc_now(),
        )
        index_payload: dict[str, Any] | None = None
        doc_id: str | None = None
        async with self._session_factory() as session:
            async with session.begin():
                session.add(row)
                await session.flush()
                index_payload = self._audit_index_payload(row)
                doc_id = str(row.id)
        # Fire-and-forget OpenSearch indexing (ISSUE-084).
        if (
            self._opensearch is not None
            and self._opensearch.enabled
            and index_payload is not None
            and doc_id is not None
        ):
            asyncio.create_task(self._index_document_to_opensearch(doc_id, index_payload))
        return doc_id or ""

    async def log_transition_in_session(
        self,
        session: AsyncSession,
        event_id: str,
        from_status: str | None,
        to_status: str | None,
        operator: str | None,
        reason: str | None,
    ) -> str:
        """Same as ``log_transition`` but within a caller-provided transaction."""
        row = orm.EventAuditLog(
            event_id=event_id,
            from_status=from_status,
            to_status=to_status,
            operator=redact_sensitive_text(operator) if operator else None,
            reason=redact_sensitive_text(reason)[:4096] if reason else None,
            created_at=_utc_now(),
        )
        session.add(row)
        await session.flush()
        index_payload = self._audit_index_payload(row)
        doc_id = str(row.id)
        # Fire-and-forget OpenSearch indexing (ISSUE-084).
        if self._opensearch is not None and self._opensearch.enabled:
            asyncio.create_task(self._index_document_to_opensearch(doc_id, index_payload))
        return doc_id

    async def get_logs_by_event(self, event_id: str) -> list[orm.EventAuditLog]:
        async with self._session_factory() as session:
            rows = await session.scalars(
                select(orm.EventAuditLog)
                .where(orm.EventAuditLog.event_id == event_id)
                .order_by(
                    orm.EventAuditLog.created_at.asc(),
                    orm.EventAuditLog.id.asc(),
                )
            )
            return list(rows)


__all__ = ["EventAuditLogService"]
