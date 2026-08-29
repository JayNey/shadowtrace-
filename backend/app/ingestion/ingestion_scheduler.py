"""Mock XDR ingestion scheduler — wraps ``SourceIngester.poll()`` (ISSUE-107 / #611).

Poll logic, watermark, and checkpoint semantics live in ``SourceIngester`` only.
This module adds scheduling guards, advisory locking, and optional Redis counters.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Literal

from pydantic import BaseModel, ConfigDict
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.factory import build_source_adapter, source_mode_is_supported
from app.adapters.source.base import BaseSourceAdapter
from app.core.config import Settings, get_settings
from app.core.redis_client import RedisClient
from app.ingestion.source_ingester import IngestionSummary, SourceIngester
from app.models.enums import SourceObjectKind
from app.services.event_service import EventService

logger = logging.getLogger(__name__)

INGESTION_POLL_LOCK_NAME = "ingestion_poll"
_ALL_SOURCE_KINDS = (
    SourceObjectKind.INCIDENT,
    SourceObjectKind.ALERT,
    SourceObjectKind.ASSET,
    SourceObjectKind.LOG,
)
_DEFAULT_BATCH_SIZE = 50
_INGESTION_STATS_PREFIX = "shadowtrace:ingestion:stats"


def ingestion_poll_advisory_lock_key() -> int:
    """Stable int64 PostgreSQL advisory lock key for ``ingestion_poll``."""
    digest = hashlib.sha256(INGESTION_POLL_LOCK_NAME.encode()).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=True)


class IngestionRunResult(BaseModel):
    """Outcome of a single scheduler ``run_once`` invocation."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["completed", "skipped", "error"] = "completed"
    reason: str | None = None
    error_message: str | None = None
    summary: IngestionSummary | None = None


class IngestionScheduler:
    """Run one guarded Mock XDR poll cycle."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        event_service: EventService,
        settings: Settings | None = None,
        redis_client: RedisClient | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._event_service = event_service
        self._settings = settings or get_settings()
        self._redis_client = redis_client

    async def run_once(self) -> IngestionRunResult:
        settings = self._settings
        if not settings.ingestion_scheduler_enabled:
            logger.debug("ingestion scheduler disabled; skipping poll")
            return IngestionRunResult(status="skipped", reason="scheduler_disabled")

        source_mode = (settings.source_mode or "").strip().lower()
        if not source_mode_is_supported(settings):
            logger.info(
                "ingestion scheduler skip: unsupported source_mode=%s",
                settings.source_mode,
            )
            return IngestionRunResult(status="skipped", reason=f"source_mode_{source_mode}")

        lock_key = ingestion_poll_advisory_lock_key()
        async with self._session_factory() as session:
            locked = await session.scalar(
                text("SELECT pg_try_advisory_lock(:key)").bindparams(key=lock_key)
            )
            if not locked:
                logger.info("ingestion scheduler skip: advisory lock not acquired")
                return IngestionRunResult(status="skipped", reason="lock_not_acquired")

            adapter: BaseSourceAdapter | None = None
            try:
                adapter = self._build_source_adapter(settings)
                ingester = SourceIngester(
                    self._event_service,
                    self._session_factory,
                    source_mode=source_mode,
                )
                summary = await ingester.poll(
                    adapter,
                    _ALL_SOURCE_KINDS,
                    batch_size=_DEFAULT_BATCH_SIZE,
                )
                await self._record_stats(summary)
                if summary.degraded:
                    logger.warning(
                        "ingestion poll completed with degraded connectors "
                        "(accepted=%d duplicate=%d rejected=%d)",
                        summary.accepted,
                        summary.duplicate,
                        summary.rejected,
                    )
                else:
                    logger.info(
                        "ingestion poll completed accepted=%d duplicate=%d rejected=%d",
                        summary.accepted,
                        summary.duplicate,
                        summary.rejected,
                    )
                return IngestionRunResult(status="completed", summary=summary)
            except Exception as exc:  # noqa: BLE001 — return structured error, keep watermark
                logger.exception("ingestion poll failed: %s", exc)
                return IngestionRunResult(
                    status="error",
                    reason=type(exc).__name__,
                    error_message=str(exc),
                )
            finally:
                if adapter is not None:
                    closer = getattr(adapter, "aclose", None)
                    if closer is not None:
                        await closer()
                await session.execute(
                    text("SELECT pg_advisory_unlock(:key)").bindparams(key=lock_key)
                )

    def _build_source_adapter(self, settings: Settings) -> BaseSourceAdapter:
        return build_source_adapter(settings)

    def _build_mock_adapter(self, settings: Settings) -> BaseSourceAdapter:
        """Backward-compatible alias; production path is ``_build_source_adapter``."""
        return self._build_source_adapter(settings)

    async def _record_stats(self, summary: IngestionSummary) -> None:
        """Best-effort counters in Redis (no TTL; operational metrics only)."""
        if self._redis_client is None:
            return
        try:
            if not await self._redis_client.ping():
                return
            redis = self._redis_client.get_client()
            if summary.accepted:
                await redis.incrby(f"{_INGESTION_STATS_PREFIX}:accepted", summary.accepted)
            if summary.duplicate:
                await redis.incrby(f"{_INGESTION_STATS_PREFIX}:duplicate", summary.duplicate)
            if summary.rejected:
                await redis.incrby(f"{_INGESTION_STATS_PREFIX}:rejected", summary.rejected)
        except Exception:  # noqa: BLE001 — stats are best-effort
            logger.debug("ingestion stats redis update failed", exc_info=True)


__all__ = [
    "INGESTION_POLL_LOCK_NAME",
    "IngestionRunResult",
    "IngestionScheduler",
    "ingestion_poll_advisory_lock_key",
]
