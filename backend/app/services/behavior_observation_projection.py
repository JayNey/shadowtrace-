"""SourceIngester-facing semantic projection hook (ISSUE-119 / #624)."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ValidationError
from app.models.behavior_observation import BehaviorObservation
from app.services.behavior_observation_service import BehaviorObservationService

logger = logging.getLogger(__name__)

OnPersistedCallback = Callable[[str], Awaitable[None]]


class BehaviorObservationProjection:
    """Post-persistence semantic projection — sole writer path from SourceIngester."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self._service = BehaviorObservationService(session_factory)

    @property
    def service(self) -> BehaviorObservationService:
        return self._service

    async def project_source_record(self, source_record_id: str) -> BehaviorObservation | None:
        return await self._service.project_source_object(source_record_id)

    async def on_source_record_persisted(self, source_record_id: str) -> bool:
        """Best-effort projection; failures are durable and observable."""
        try:
            await self.project_source_record(source_record_id)
            return True
        except ValidationError as exc:
            logger.warning(
                "BehaviorObservation projection non-retryable source_record_id=%s err=%s",
                source_record_id,
                exc,
            )
            source_tenant_id = await self._lookup_source_tenant_id(source_record_id)
            await self._service.record_projection_failure(
                source_record_id=source_record_id,
                source_tenant_id=source_tenant_id,
                error_category="projection_non_retryable",
                detail={
                    "type": type(exc).__name__,
                    "message": str(exc),
                },
                force_dead_letter=True,
            )
            return False
        except Exception as exc:  # noqa: BLE001 — degrade without rolling back source writes
            logger.warning(
                "BehaviorObservation projection failed source_record_id=%s err=%s",
                source_record_id,
                exc,
            )
            source_tenant_id = await self._lookup_source_tenant_id(source_record_id)
            await self._service.record_projection_failure(
                source_record_id=source_record_id,
                source_tenant_id=source_tenant_id,
                error_category="projection_failed",
                detail={
                    "type": type(exc).__name__,
                    "message": str(exc),
                },
            )
            return False

    async def _lookup_source_tenant_id(self, source_record_id: str) -> str:
        try:
            from app.db import models as orm

            async with self._session_factory() as session:
                row = await session.get(orm.SourceObject, source_record_id)
                if row is not None:
                    return row.source_tenant_id
        except Exception:  # noqa: BLE001 — keep failure record best-effort
            pass
        return "unknown"

    def persisted_callback(self) -> OnPersistedCallback:
        return self.on_source_record_persisted
