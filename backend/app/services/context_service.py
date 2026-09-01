"""EventContext Hash store with PostgreSQL journal + Redis cache (ISSUE-013)."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Any

from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.redis_client import RedisClient
from app.db import models as orm
from app.models.context import EventContext
from app.models.disposition import WritebackSummary
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    WritebackReadiness,
)
from app.models.security_event import EventSummary, SecurityEvent
from app.services.classification_source import derive_classification_source
from app.services.writeback_event_projection import (
    load_writeback_rows,
    project_writeback_envelope,
)

logger = logging.getLogger(__name__)

CTX_KEY_PREFIX = "shadowtrace:ctx:"
CTX_LOG_PREFIX = "shadowtrace:ctx_log:"
CLOSED_TTL_SECONDS = 24 * 60 * 60
DEGRADED_CACHE_TTL_SECONDS = 30.0
REDIS_WRITE_BACKOFFS = (0.1, 0.5, 2.0)
DEGRADED_CACHE_MAX_ENTRIES = 2048


# EventContext Hash field names (excludes companion ``{key}__version`` keys).
CONTEXT_FIELD_NAMES: frozenset[str] = frozenset(EventContext.model_fields.keys())


@dataclass(frozen=True, slots=True)
class InitResult:
    redis_ok: bool
    version: int
    initialized: bool = True


@dataclass(frozen=True, slots=True)
class SetResult:
    redis_ok: bool
    version: int


def ctx_key(event_id: str) -> str:
    return f"{CTX_KEY_PREFIX}{event_id}"


def ctx_log_key(event_id: str) -> str:
    return f"{CTX_LOG_PREFIX}{event_id}"


def version_field(key: str) -> str:
    return f"{key}__version"


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(k): _to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_jsonable(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _journal_value(value: Any) -> Any:
    """JSONB-safe representation of an EventContext field value."""
    return _to_jsonable(value)


async def append_context_journal_in_session(
    session: AsyncSession,
    event_id: str,
    field_name: str,
    value: Any,
) -> int:
    """Append one EventContext journal entry inside an existing DB transaction."""
    if field_name not in CONTEXT_FIELD_NAMES:
        raise KeyError(f"unknown EventContext field: {field_name!r}")
    stored = _journal_value(value)
    result = await session.execute(
        text(
            "INSERT INTO event_context_field_version "
            "(event_id, field_name, current_version) "
            "VALUES (:event_id, :field_name, 1) "
            "ON CONFLICT (event_id, field_name) DO UPDATE "
            "SET current_version = event_context_field_version.current_version + 1 "
            "RETURNING current_version"
        ),
        {"event_id": event_id, "field_name": field_name},
    )
    new_version = int(result.one()[0])
    session.add(
        orm.EventContextJournal(
            event_id=event_id,
            field_name=field_name,
            value=stored if isinstance(stored, dict) else {"_scalar": stored},
            version=new_version,
        )
    )
    await session.flush()
    return new_version


def unwrap_journal_value(value: Any) -> Any:
    if isinstance(value, dict) and set(value.keys()) == {"_scalar"}:
        return value["_scalar"]
    return value


async def append_list_context_journal_in_session(
    session: AsyncSession,
    event_id: str,
    field_name: str,
    item: Any,
) -> int:
    """Append one element to a list-shaped EventContext field (full list re-written)."""
    row = await session.scalar(
        select(orm.EventContextJournal.value)
        .where(
            orm.EventContextJournal.event_id == event_id,
            orm.EventContextJournal.field_name == field_name,
        )
        .order_by(orm.EventContextJournal.version.desc())
        .limit(1)
    )
    items: list[Any] = []
    if row is not None:
        current = unwrap_journal_value(row)
        if isinstance(current, list):
            items = list(current)
        elif current is not None:
            items = [current]
    items.append(_journal_value(item))
    return await append_context_journal_in_session(session, event_id, field_name, items)


def event_summary_from_security_event(row: orm.SecurityEvent) -> EventSummary:
    """Build the EventContext ``event`` field (EventSummary) from the ORM row."""
    policy = DispositionPolicy(row.disposition_policy)
    writeback_required = policy is DispositionPolicy.REQUIRED
    if not writeback_required:
        writeback_readiness = WritebackReadiness.NOT_REQUIRED
    elif not row.disposition_source_ref:
        writeback_readiness = WritebackReadiness.SOURCE_UNRESOLVED
    else:
        # Capability is not authoritative on security_event. Fail closed until
        # PolicyFilter evaluates the connector/adapter and writes Action readiness.
        writeback_readiness = WritebackReadiness.CAPABILITY_UNKNOWN
    snapshot = (
        dict(row.event_context_snapshot) if isinstance(row.event_context_snapshot, dict) else None
    )
    from app.services.risk_verdict_projection import risk_observability_from_snapshot

    evidence_limited, scoring_mode, verdict_reason_codes = risk_observability_from_snapshot(
        snapshot
    )
    return EventSummary(
        event_id=row.event_id,
        event_type=EventType(row.event_type),
        title=row.title,
        status=EventStatus(row.status),
        severity=Severity(row.severity),
        risk_score=row.risk_score,
        final_verdict=FinalVerdict(row.final_verdict),
        writeback_required=writeback_required,
        writeback_readiness=writeback_readiness,
        writeback_overall_status=None,
        pending_writeback_count=0,
        created_at=row.created_at,
        updated_at=row.updated_at,
        occurred_at=row.occurred_at,
        classification_source=derive_classification_source(
            degraded_flags=[str(f) for f in (row.degraded_flags or [])],
            event_context_snapshot=snapshot,
        ),
        evidence_limited=evidence_limited,
        scoring_mode=scoring_mode,
        verdict_reason_codes=verdict_reason_codes,
        disposition_policy=policy,
        external_unsynced=bool(row.external_unsynced),
        escalated=bool(row.escalated),
    )


def event_summary_from_domain(event: SecurityEvent) -> EventSummary:
    """Build EventSummary from the public SecurityEvent model (non-ORM paths)."""
    writeback_required = event.disposition_policy is DispositionPolicy.REQUIRED
    if not writeback_required:
        writeback_readiness = WritebackReadiness.NOT_REQUIRED
    elif event.disposition_source_ref is None:
        writeback_readiness = WritebackReadiness.SOURCE_UNRESOLVED
    else:
        writeback_readiness = WritebackReadiness.CAPABILITY_UNKNOWN
    from app.services.risk_verdict_projection import risk_observability_from_snapshot

    evidence_limited, scoring_mode, verdict_reason_codes = risk_observability_from_snapshot(
        event.event_context_snapshot if isinstance(event.event_context_snapshot, dict) else None
    )
    return EventSummary(
        event_id=event.event_id,
        event_type=event.event_type,
        title=event.title,
        status=event.status,
        severity=event.severity,
        risk_score=event.risk_score,
        final_verdict=event.final_verdict,
        writeback_required=writeback_required,
        writeback_readiness=writeback_readiness,
        writeback_overall_status=None,
        pending_writeback_count=0,
        created_at=event.created_at,
        updated_at=event.updated_at,
        occurred_at=event.occurred_at,
        classification_source=derive_classification_source(
            classification_override=None,
            degraded_flags=list(event.degraded_flags or []),
            event_context_snapshot=event.event_context_snapshot,
        )
        if event.classification_source is None
        else event.classification_source,
        evidence_limited=evidence_limited,
        scoring_mode=scoring_mode,
        verdict_reason_codes=verdict_reason_codes,
        disposition_policy=event.disposition_policy,
        external_unsynced=event.external_unsynced,
        escalated=event.escalated,
    )


def _default_context_dict() -> dict[str, Any]:
    """Field defaults without going through SecurityEvent-typed ``event`` dumps."""
    return {
        name: field.get_default(call_default_factory=True)
        for name, field in EventContext.model_fields.items()
    }


def _context_as_dict(ctx: EventContext) -> dict[str, Any]:
    """Shallow field dict; preserves EventSummary-shaped ``event`` without warnings."""
    out: dict[str, Any] = {}
    for name in CONTEXT_FIELD_NAMES:
        out[name] = getattr(ctx, name)
    return out


def _assemble_event_context(raw: dict[str, Any]) -> EventContext:
    """Build EventContext, always validating (ISSUE-094 §2: no ``model_construct``
    bypass). ``event`` is typed as ``EventSummary | None`` so the EventSummary-shaped
    dict persisted by the journal/Redis/snapshot paths validates directly."""
    payload = {k: v for k, v in raw.items() if k in CONTEXT_FIELD_NAMES}
    base = _default_context_dict()
    base.update(payload)
    return EventContext.model_validate(base)


class EventContextStore:
    """Versioned EventContext store: PostgreSQL is authority; Redis is the hot cache."""

    def __init__(
        self,
        redis: RedisClient,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        on_redis_recovery: Callable[[str], Awaitable[None]] | None = None,
    ) -> None:
        self._redis = redis
        self._session_factory = session_factory
        self._degraded_cache: OrderedDict[str, EventContext] = OrderedDict()
        self._degraded_cache_ts: OrderedDict[str, float] = OrderedDict()
        self._degraded_cache_lock = RLock()
        self._on_redis_recovery = on_redis_recovery

    def set_on_redis_recovery(
        self,
        callback: Callable[[str], Awaitable[None]],
    ) -> None:
        """Register a callback invoked when Redis writes succeed after rebuild.

        The callback receives ``event_id`` and is called at most once per
        successful ``rebuild_context`` Redis write. Exceptions are logged
        and swallowed — the callback is a best-effort side effect.
        """
        self._on_redis_recovery = callback

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def init_context(self, event_id: str, event: EventSummary) -> InitResult:
        """Atomically initialize the ``event`` field once, healing Redis on repeats."""
        event_value = _journal_value(event)
        async with self._session_factory() as session:
            async with session.begin():
                inserted = await session.execute(
                    text(
                        "INSERT INTO event_context_field_version "
                        "(event_id, field_name, current_version) "
                        "VALUES (:event_id, 'event', 1) "
                        "ON CONFLICT (event_id, field_name) DO NOTHING "
                        "RETURNING current_version"
                    ),
                    {"event_id": event_id},
                )
                row = inserted.first()
                initialized = row is not None
                if row is not None:
                    version = int(row[0])
                    await self._insert_journal(session, event_id, "event", event_value, version)
                else:
                    existing = await session.scalar(
                        select(orm.EventContextFieldVersion.current_version).where(
                            orm.EventContextFieldVersion.event_id == event_id,
                            orm.EventContextFieldVersion.field_name == "event",
                        )
                    )
                    if existing is None:
                        raise RuntimeError(
                            "event context version disappeared during initialization"
                        )
                    version = int(existing)

        redis_ok = await self._redis_set_fields(
            event_id,
            {"event": event_value, version_field("event"): version},
            log_entry=(
                {
                    "op": "init_context",
                    "field_name": "event",
                    "version": version,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
                if initialized
                else None
            ),
        )
        return InitResult(
            redis_ok=redis_ok,
            version=version,
            initialized=initialized,
        )

    async def get(self, event_id: str, key: str) -> Any:
        if key not in CONTEXT_FIELD_NAMES:
            raise KeyError(f"unknown EventContext field: {key!r}")
        redis_error = False
        redis_value: Any = None
        redis_hit = False
        redis_version: int | None = None
        try:
            client = self._redis.get_client()
            raw = await client.hget(ctx_key(event_id), key)
            if raw is not None:
                raw_version = await client.hget(ctx_key(event_id), version_field(key))
                redis_version = (
                    int(RedisClient.loads(raw_version)) if raw_version is not None else None
                )
                redis_value = RedisClient.loads(raw)
                redis_hit = True
        except Exception:  # noqa: BLE001 - Redis is an optional cache path
            logger.debug(
                "Redis context read failed event_id=%s key=%s",
                event_id,
                key,
                exc_info=True,
            )
            redis_error = True

        # PostgreSQL/version checks are deliberately outside the Redis exception
        # boundary so SQLAlchemy, missing rows, and Pydantic errors propagate.
        if redis_hit and not redis_error:
            db_version = await self.get_field_version(event_id, key)
            if db_version is not None and redis_version == db_version:
                self._clear_degraded_cache(event_id)
                return redis_value
        if not redis_error:
            ctx = await self.rebuild_context(event_id)
            return getattr(ctx, key)
        cached = self._get_degraded_if_fresh(event_id)
        if cached is not None:
            return getattr(cached, key)

        ctx = await self.rebuild_context(event_id)
        return getattr(ctx, key)

    async def set(
        self,
        event_id: str,
        key: str,
        value: Any,
        version: int | None = None,  # noqa: ARG002 — reserved; DB UPSERT is authority
    ) -> SetResult:
        if key not in CONTEXT_FIELD_NAMES:
            raise KeyError(f"unknown EventContext field: {key!r}")
        if key == "analysis_only_complete":
            if not isinstance(value, bool):
                raise TypeError("analysis_only_complete must be a boolean")
            return await self.set_analysis_only_complete(event_id, value)

        stored = _journal_value(value)
        async with self._session_factory() as session:
            async with session.begin():
                new_version = await self._upsert_version(session, event_id, key)
                await self._insert_journal(session, event_id, key, stored, new_version)

        redis_ok = await self._redis_set_fields(
            event_id,
            {key: stored, version_field(key): new_version},
            log_entry={
                "op": "set",
                "field_name": key,
                "version": new_version,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )
        # Keep degraded memory view coherent when Redis is down.
        if not redis_ok and event_id in self._degraded_cache:
            current = self._degraded_cache[event_id]
            updated = EventContext.model_validate({**_context_as_dict(current), key: value})
            self._cache_degraded(event_id, updated)

        return SetResult(redis_ok=redis_ok, version=new_version)

    async def set_analysis_only_complete(
        self,
        event_id: str,
        complete: bool = True,
    ) -> SetResult:
        result = await self._set_analysis_only_complete(
            event_id,
            complete,
            expected_version=None,
        )
        assert result is not None  # no version precondition was supplied
        return result

    async def _set_analysis_only_complete(
        self,
        event_id: str,
        complete: bool,
        *,
        expected_version: int | None,
    ) -> SetResult | None:
        """Atomically persist the monotonic completion marker and ORM snapshot.

        The SecurityEvent row lock serializes all writes for this field. Once either
        the journal or snapshot records ``true``, a stale ``false`` request heals to
        ``true`` instead of allocating a downgrading journal version.
        """
        if not isinstance(complete, bool):
            raise TypeError("analysis_only_complete must be a boolean")

        from app.services.event_context_snapshot_projection import (
            merge_analysis_only_complete_into_snapshot,
        )

        async with self._session_factory() as session:
            async with session.begin():
                event_row = await session.get(
                    orm.SecurityEvent,
                    event_id,
                    with_for_update=True,
                )
                if event_row is None:
                    raise KeyError(f"security_event not found: {event_id}")

                version_row = await session.get(
                    orm.EventContextFieldVersion,
                    (event_id, "analysis_only_complete"),
                    with_for_update=True,
                )
                current_version = int(version_row.current_version) if version_row is not None else 0
                if expected_version is not None and current_version != expected_version:
                    return None
                current_value: Any = None
                if current_version > 0:
                    raw_current = await session.scalar(
                        select(orm.EventContextJournal.value).where(
                            orm.EventContextJournal.event_id == event_id,
                            orm.EventContextJournal.field_name == "analysis_only_complete",
                            orm.EventContextJournal.version == current_version,
                        )
                    )
                    current_value = self._unwrap_journal_value(raw_current)

                snapshot = (
                    dict(event_row.event_context_snapshot)
                    if isinstance(event_row.event_context_snapshot, dict)
                    else {}
                )
                effective = (
                    current_value is True
                    or snapshot.get("analysis_only_complete") is True
                    or complete
                )

                if current_value != effective:
                    current_version = await self._upsert_version(
                        session,
                        event_id,
                        "analysis_only_complete",
                    )
                    await self._insert_journal(
                        session,
                        event_id,
                        "analysis_only_complete",
                        effective,
                        current_version,
                    )

                event_row.event_context_snapshot = merge_analysis_only_complete_into_snapshot(
                    snapshot, effective
                )
                await session.flush()

        redis_ok = await self._redis_set_fields(
            event_id,
            {
                "analysis_only_complete": effective,
                version_field("analysis_only_complete"): current_version,
            },
            log_entry={
                "op": "set_analysis_only_complete",
                "field_name": "analysis_only_complete",
                "version": current_version,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )
        if not redis_ok and event_id in self._degraded_cache:
            current = self._degraded_cache[event_id]
            self._cache_degraded(
                event_id,
                EventContext.model_validate(
                    {
                        **_context_as_dict(current),
                        "analysis_only_complete": effective,
                    }
                ),
            )

        return SetResult(redis_ok=redis_ok, version=current_version)

    async def get_full_context(self, event_id: str) -> EventContext:
        redis_error = False
        redis_decoded: dict[str, Any] | None = None
        try:
            client = self._redis.get_client()
            raw_hash = await client.hgetall(ctx_key(event_id))
            if raw_hash:
                redis_decoded = self._decode_hash(raw_hash)
        except Exception:  # noqa: BLE001 - fall back to authoritative journal
            logger.debug("Redis context hash read failed event_id=%s", event_id, exc_info=True)
            redis_error = True

        if (
            redis_decoded is not None
            and not redis_error
            and any(k in CONTEXT_FIELD_NAMES for k in redis_decoded)
        ):
            db_versions = await self._load_current_field_versions(event_id)
            if not any(
                redis_decoded.get(version_field(field_name)) != db_version
                for field_name, db_version in db_versions.items()
            ):
                context = _assemble_event_context(redis_decoded)
                self._clear_degraded_cache(event_id)
                return context
        if not redis_error:
            return await self.rebuild_context(event_id)
        cached = self._get_degraded_if_fresh(event_id)
        if cached is not None:
            return cached
        return await self.rebuild_context(event_id)

    async def compare_and_set(
        self,
        event_id: str,
        key: str,
        expected_version: int,
        value: Any,
    ) -> bool:
        if key not in CONTEXT_FIELD_NAMES:
            raise KeyError(f"unknown EventContext field: {key!r}")
        if key == "analysis_only_complete":
            if value is not True:
                return False
            analysis_result = await self._set_analysis_only_complete(
                event_id,
                True,
                expected_version=expected_version,
            )
            return analysis_result is not None

        stored = _journal_value(value)
        async with self._session_factory() as session:
            async with session.begin():
                if expected_version == 0:
                    result = await session.execute(
                        text(
                            "INSERT INTO event_context_field_version "
                            "(event_id, field_name, current_version) "
                            "VALUES (:event_id, :field_name, 1) "
                            "ON CONFLICT (event_id, field_name) DO NOTHING "
                            "RETURNING current_version"
                        ),
                        {"event_id": event_id, "field_name": key},
                    )
                else:
                    result = await session.execute(
                        text(
                            "UPDATE event_context_field_version "
                            "SET current_version = current_version + 1 "
                            "WHERE event_id = :event_id AND field_name = :field_name "
                            "AND current_version = :expected "
                            "RETURNING current_version"
                        ),
                        {
                            "event_id": event_id,
                            "field_name": key,
                            "expected": expected_version,
                        },
                    )
                row = result.first()
                if row is None:
                    return False
                new_version = int(row[0])
                await self._insert_journal(session, event_id, key, stored, new_version)

        await self._redis_set_fields(
            event_id,
            {key: stored, version_field(key): new_version},
            log_entry={
                "op": "compare_and_set",
                "field_name": key,
                "version": new_version,
                "expected_version": expected_version,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )
        return True

    async def rebuild_context(self, event_id: str) -> EventContext:
        async with self._session_factory() as session:
            se = await session.get(orm.SecurityEvent, event_id)
            if se is None:
                raise KeyError(f"security_event not found: {event_id}")

            ctx: EventContext
            if EventStatus(se.status) is EventStatus.CLOSED and se.event_context_snapshot:
                ctx = _assemble_event_context(dict(se.event_context_snapshot))
                # ISSUE-266: journal may hold analysis_only_complete=true after a
                # post-freeze write; never downgrade snapshot truth once true.
                journal_ctx = await self._rebuild_from_journal(session, event_id)
                if journal_ctx.analysis_only_complete and not ctx.analysis_only_complete:
                    ctx = EventContext.model_validate(
                        {
                            **_context_as_dict(ctx),
                            "analysis_only_complete": True,
                        }
                    )
            else:
                ctx = await self._rebuild_from_journal(session, event_id)

            # Always overlay authoritative mirrors from security_event.
            summary = event_summary_from_security_event(se)
            flags = list(se.degraded_flags or [])
            writeback = await self._merge_writeback_summary(session, se)
            merged = _context_as_dict(ctx)
            merged.update(
                {
                    "event": summary,
                    "degraded_flags": [str(f) for f in flags],
                    "replan_count": int(se.replan_count or 0),
                    "writeback_summary": writeback,
                }
            )
            ctx = EventContext.model_validate(merged)

            versions = await self._load_field_versions(session, event_id)

        self._clear_degraded_cache(event_id)
        mapping = self._context_to_redis_mapping(ctx, versions)
        redis_ok = await self._redis_set_fields(event_id, mapping, log_entry=None, expire=False)
        if redis_ok and self._on_redis_recovery is not None:
            try:
                await self._on_redis_recovery(event_id)
            except Exception:  # noqa: BLE001 — best-effort side effect
                logger.warning(
                    "on_redis_recovery callback failed event_id=%s",
                    event_id,
                    exc_info=True,
                )
        if not redis_ok:
            self._cache_degraded(event_id, ctx)

        return ctx

    async def delete_cached_context(self, event_id: str) -> bool:
        """Delete Redis/in-process cache for an event merged into another event."""
        self._clear_degraded_cache(event_id)
        try:
            client = self._redis.get_client()
            await client.delete(
                ctx_key(event_id),
                ctx_log_key(event_id),
            )
            return True
        except Exception:  # noqa: BLE001
            logger.warning(
                "delete_cached_context failed event_id=%s",
                event_id,
                exc_info=True,
            )
            return False

    async def set_closed_ttl(self, event_id: str) -> bool:
        """Apply 24h TTL to the context Hash (and change log). Returns redis_ok."""
        try:
            client = self._redis.get_client()
            await client.expire(ctx_key(event_id), CLOSED_TTL_SECONDS)
            await client.expire(ctx_log_key(event_id), CLOSED_TTL_SECONDS)
            return True
        except Exception:  # noqa: BLE001
            logger.warning("set_closed_ttl failed event_id=%s", event_id, exc_info=True)
            return False

    async def refresh_closed_snapshot(self, event_id: str) -> EventContext:
        """Rebuild snapshot from journal + security_event mirrors; no Redis required."""
        async with self._session_factory() as session:
            async with session.begin():
                se = await session.get(
                    orm.SecurityEvent,
                    event_id,
                    with_for_update=True,
                )
                if se is None:
                    raise KeyError(f"security_event not found: {event_id}")

                ctx = await self._rebuild_from_journal(session, event_id)
                prior_snapshot = (
                    se.event_context_snapshot if isinstance(se.event_context_snapshot, dict) else {}
                )
                snapshot_complete = prior_snapshot.get("analysis_only_complete") is True
                overlay_report_quality = prior_snapshot.get("report_quality")
                persisted_report_quality = await session.scalar(
                    select(orm.Report.report_quality)
                    .where(orm.Report.event_id == event_id)
                    .limit(1)
                )
                if snapshot_complete and not ctx.analysis_only_complete:
                    version = await self._upsert_version(
                        session,
                        event_id,
                        "analysis_only_complete",
                    )
                    await self._insert_journal(
                        session,
                        event_id,
                        "analysis_only_complete",
                        True,
                        version,
                    )
                summary = event_summary_from_security_event(se)
                flags = list(se.degraded_flags or [])
                writeback = await self._merge_writeback_summary(session, se)
                merged = _context_as_dict(ctx)
                merged.update(
                    {
                        "event": summary,
                        "degraded_flags": [str(f) for f in flags],
                        "replan_count": int(se.replan_count or 0),
                        "writeback_summary": writeback,
                    }
                )
                if snapshot_complete:
                    merged["analysis_only_complete"] = True
                ctx = EventContext.model_validate(merged)
                snapshot = {k: _to_jsonable(v) for k, v in _context_as_dict(ctx).items()}
                snapshot["event"] = summary.model_dump(mode="json")
                snapshot["writeback_summary"] = (
                    writeback.model_dump(mode="json") if writeback is not None else None
                )
                quality_raw = (
                    persisted_report_quality
                    if persisted_report_quality not in (None, "")
                    else overlay_report_quality
                )
                if quality_raw not in (None, ""):
                    from app.services.event_context_snapshot_projection import (
                        merge_report_quality_into_snapshot,
                    )

                    try:
                        snapshot = merge_report_quality_into_snapshot(
                            snapshot,
                            str(quality_raw),
                        )
                    except ValueError:
                        logger.warning(
                            "closed snapshot skipped invalid report_quality event=%s value=%r",
                            event_id,
                            quality_raw,
                        )
                se.event_context_snapshot = snapshot
                versions = await self._load_field_versions(session, event_id)
                await session.flush()

        mapping = self._context_to_redis_mapping(ctx, versions)
        redis_ok = await self._redis_set_fields(
            event_id,
            mapping,
            log_entry=None,
            expire=False,
        )
        if redis_ok:
            self._clear_degraded_cache(event_id)
        else:
            self._cache_degraded(event_id, ctx)

        return ctx

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _clear_degraded_cache(self, event_id: str) -> None:
        with self._degraded_cache_lock:
            self._degraded_cache.pop(event_id, None)
            self._degraded_cache_ts.pop(event_id, None)

    def _cache_degraded(self, event_id: str, context: EventContext) -> None:
        """Store a bounded degraded-mode snapshot, evicting the oldest entry."""
        with self._degraded_cache_lock:
            if event_id in self._degraded_cache:
                self._degraded_cache.pop(event_id, None)
                self._degraded_cache_ts.pop(event_id, None)
            elif len(self._degraded_cache) >= DEGRADED_CACHE_MAX_ENTRIES:
                oldest, _ = self._degraded_cache_ts.popitem(last=False)
                self._degraded_cache.pop(oldest, None)
            self._degraded_cache[event_id] = context
            self._degraded_cache_ts[event_id] = time.monotonic()

    def _get_degraded_if_fresh(self, event_id: str) -> EventContext | None:
        with self._degraded_cache_lock:
            ts = self._degraded_cache_ts.get(event_id)
            cached = self._degraded_cache.get(event_id)
            if ts is None or cached is None:
                return None
            if time.monotonic() - ts > DEGRADED_CACHE_TTL_SECONDS:
                self._degraded_cache.pop(event_id, None)
                self._degraded_cache_ts.pop(event_id, None)
                return None
            self._degraded_cache.move_to_end(event_id)
            self._degraded_cache_ts.move_to_end(event_id)
            return cached

    @staticmethod
    async def _upsert_version(session: AsyncSession, event_id: str, field_name: str) -> int:
        result = await session.execute(
            text(
                "INSERT INTO event_context_field_version "
                "(event_id, field_name, current_version) "
                "VALUES (:event_id, :field_name, 1) "
                "ON CONFLICT (event_id, field_name) DO UPDATE "
                "SET current_version = event_context_field_version.current_version + 1 "
                "RETURNING current_version"
            ),
            {"event_id": event_id, "field_name": field_name},
        )
        row = result.one()
        return int(row[0])

    @staticmethod
    async def _insert_journal(
        session: AsyncSession,
        event_id: str,
        field_name: str,
        value: Any,
        version: int,
    ) -> None:
        session.add(
            orm.EventContextJournal(
                event_id=event_id,
                field_name=field_name,
                value=value if isinstance(value, dict) else {"_scalar": value},
                version=version,
            )
        )
        await session.flush()

    @staticmethod
    def _unwrap_journal_value(value: Any) -> Any:
        return unwrap_journal_value(value)

    async def _rebuild_from_journal(self, session: AsyncSession, event_id: str) -> EventContext:
        result = await session.execute(
            text(
                "SELECT DISTINCT ON (field_name) field_name, value "
                "FROM event_context_journal "
                "WHERE event_id = :event_id "
                "ORDER BY field_name, version DESC"
            ),
            {"event_id": event_id},
        )
        raw: dict[str, Any] = {}
        for field_name, value in result.all():
            if field_name in CONTEXT_FIELD_NAMES:
                raw[field_name] = self._unwrap_journal_value(value)
        return _assemble_event_context(raw)

    async def get_field_version(self, event_id: str, key: str) -> int | None:
        """Authoritative current version for a field, or None when unset.

        Reads ``event_context_field_version`` (the sole version source); callers
        must not treat the Redis ``{key}__version`` cache as authority.
        """
        async with self._session_factory() as session:
            row = await session.get(orm.EventContextFieldVersion, (event_id, key))
            return int(row.current_version) if row is not None else None

    async def get_versioned_field(self, event_id: str, key: str) -> tuple[Any, int]:
        """Read a field value and its authoritative version in one DB statement."""
        if key not in CONTEXT_FIELD_NAMES:
            raise KeyError(f"unknown EventContext field: {key!r}")
        async with self._session_factory() as session:
            result = await session.execute(
                text(
                    "SELECT journal.value, version.current_version "
                    "FROM event_context_field_version AS version "
                    "JOIN event_context_journal AS journal "
                    "ON journal.event_id = version.event_id "
                    "AND journal.field_name = version.field_name "
                    "AND journal.version = version.current_version "
                    "WHERE version.event_id = :event_id "
                    "AND version.field_name = :field_name"
                ),
                {"event_id": event_id, "field_name": key},
            )
            row = result.first()
        if row is None:
            return None, 0
        return self._unwrap_journal_value(row[0]), int(row[1])

    async def _load_current_field_versions(self, event_id: str) -> dict[str, int]:
        async with self._session_factory() as session:
            return await self._load_field_versions(session, event_id)

    @staticmethod
    async def _load_field_versions(session: AsyncSession, event_id: str) -> dict[str, int]:
        rows = await session.execute(
            select(
                orm.EventContextFieldVersion.field_name,
                orm.EventContextFieldVersion.current_version,
            ).where(orm.EventContextFieldVersion.event_id == event_id)
        )
        return {str(name): int(ver) for name, ver in rows.all()}

    def _context_to_redis_mapping(
        self, ctx: EventContext, versions: dict[str, int]
    ) -> dict[str, Any]:
        mapping: dict[str, Any] = {}
        for key in CONTEXT_FIELD_NAMES:
            mapping[key] = _to_jsonable(getattr(ctx, key))
            if key in versions:
                mapping[version_field(key)] = versions[key]
        return mapping

    def _decode_hash(self, raw_hash: dict[Any, Any]) -> dict[str, Any]:
        decoded: dict[str, Any] = {}
        for raw_key, raw_val in raw_hash.items():
            if isinstance(raw_key, (bytes, bytearray)):
                key = raw_key.decode("utf-8")
            else:
                key = str(raw_key)
            if key.endswith("__version"):
                ver = RedisClient.loads(raw_val)
                decoded[key] = int(ver) if not isinstance(ver, int) else ver
            else:
                decoded[key] = RedisClient.loads(raw_val)
        return decoded

    async def _redis_set_fields(
        self,
        event_id: str,
        fields: dict[str, Any],
        *,
        log_entry: dict[str, Any] | None,
        expire: bool = False,
    ) -> bool:
        """Write Hash fields with retry; append optional change-log entry."""
        key = ctx_key(event_id)
        encoded: dict[str | bytes, bytes] = {}
        for field, value in fields.items():
            encoded[field] = RedisClient.dumps(value)

        last_exc: Exception | None = None
        # One initial attempt plus up to len(backoffs) retries (0.1/0.5/2.0s).
        max_attempts = 1 + len(REDIS_WRITE_BACKOFFS)
        for attempt in range(max_attempts):
            try:
                client = self._redis.get_client()
                if encoded:
                    await client.hset(key, mapping=encoded)  # type: ignore[arg-type]
                if log_entry is not None:
                    await client.rpush(ctx_log_key(event_id), RedisClient.dumps(log_entry))
                if expire:
                    await client.expire(key, CLOSED_TTL_SECONDS)
                self._clear_degraded_cache(event_id)
                return True
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
            if attempt + 1 < max_attempts:
                await asyncio.sleep(REDIS_WRITE_BACKOFFS[attempt])

        logger.warning(
            "Redis context write failed after retries event_id=%s error_type=%s",
            event_id,
            type(last_exc).__name__ if last_exc is not None else "unknown",
        )
        return False

    async def _merge_writeback_summary(
        self,
        session: AsyncSession,
        se: orm.SecurityEvent,
    ) -> WritebackSummary | None:
        """Recompute the event-level WritebackSummary from Action + outbox rows.

        Always derived fresh from persisted Action.writeback_* fields and
        DispositionOutbox/Receipt rows — never carried forward from a stale
        prior summary (no ``model_construct`` bypass, no "existing" fallback)
        so every rebuild path (Redis miss, journal rebuild, CLOSED snapshot
        refresh) converges on the same, unique correct readiness/status.

        Membership and ranking come from ``project_writeback_envelope`` — the
        same projector GET ``/events/{id}`` uses. Entity side-effect outboxes
        (writeback_applicable=false) never enter the envelope.
        """
        policy = DispositionPolicy(se.disposition_policy)
        actions, outboxes, receipts_by_wb = await load_writeback_rows(session, se.event_id)
        envelope = project_writeback_envelope(policy, actions, outboxes, receipts_by_wb)

        return WritebackSummary(
            event_id=se.event_id,
            closure_cycle=envelope.closure_cycle,
            disposition_policy=policy,
            required_action_count=envelope.required_action_count,
            applicable_action_count=envelope.applicable_action_count,
            blocked_action_ids=list(envelope.blocked_action_ids),
            readiness_counts=dict(envelope.readiness_counts),
            aggregate_readiness=envelope.aggregate_readiness,
            writeback_counts=dict(envelope.writeback_counts),
            aggregate_status=envelope.aggregate_status,
            terminal_event_action_id=envelope.terminal_event_action_id,
            terminal_event_writeback_id=envelope.terminal_event_writeback_id,
            terminal_event_disposition=envelope.terminal_event_disposition,
            terminal_event_confirmed=envelope.terminal_event_confirmed,
            external_unsynced=bool(se.external_unsynced),
            updated_at=datetime.now(UTC),
        )
