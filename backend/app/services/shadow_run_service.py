"""Shadow run persistence — isolated namespace storage (ISSUE-135 / #641 Phase A)."""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.db.orm.shadow_run import (
    ShadowDecisionRecordORM,
    ShadowQueryArtifactORM,
    ShadowRunORM,
)
from app.models.decision_record import DecisionRecord
from app.models.shadow_run import (
    ShadowQueryArtifact,
    ShadowQueryArtifactKind,
    ShadowRun,
    ShadowRunProvenance,
    ShadowRunStatus,
)
from app.models.tool_call_grant import ToolCallMode
from app.services.tool_call_grant_resolver import build_namespace_key

logger = logging.getLogger(__name__)


def _content_hash(payload: dict[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ShadowRunService:
    """Durable shadow namespace runs — never mutates production ledgers."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        retention_hours: int = 168,
    ) -> None:
        self._session_factory = session_factory
        self._retention_hours = max(1, retention_hours)

    @classmethod
    def from_settings(
        cls,
        session_factory: async_sessionmaker[AsyncSession],
        settings: Settings,
    ) -> ShadowRunService:
        return cls(
            session_factory,
            retention_hours=settings.react_shadow_retention_hours,
        )

    async def create_run(
        self,
        *,
        event_id: str,
        tenant_id: str,
        principal: str,
        trigger: str,
        max_steps: int,
        max_tool_calls: int,
    ) -> ShadowRun:
        shadow_run_id = await self._new_shadow_run_id()
        namespace_key = build_namespace_key(
            ToolCallMode.SHADOW,
            event_id=event_id,
            shadow_run_id=shadow_run_id,
        )
        now = datetime.now(UTC)
        provenance = ShadowRunProvenance(trigger=trigger, principal=principal)
        run = ShadowRun(
            shadow_run_id=shadow_run_id,
            event_id=event_id,
            tenant_id=tenant_id,
            namespace_key=namespace_key,
            status=ShadowRunStatus.RUNNING,
            max_steps=max_steps,
            max_tool_calls=max_tool_calls,
            provenance=provenance,
            retention_expires_at=now + timedelta(hours=self._retention_hours),
            created_at=now,
        )
        async with self._session_factory() as session:
            async with session.begin():
                session.add(
                    ShadowRunORM(
                        shadow_run_id=run.shadow_run_id,
                        event_id=run.event_id,
                        tenant_id=run.tenant_id,
                        namespace_key=run.namespace_key,
                        status=run.status.value,
                        max_steps=run.max_steps,
                        step_count=0,
                        max_tool_calls=run.max_tool_calls,
                        tool_call_count=0,
                        provenance=run.provenance.model_dump(mode="json"),
                        result_summary={},
                        rejected_reasons=[],
                        retention_expires_at=run.retention_expires_at,
                        created_at=now,
                    )
                )
        return run

    async def persist_decision_record(
        self,
        run: ShadowRun,
        record: DecisionRecord,
    ) -> str:
        async with self._session_factory() as session:
            async with session.begin():
                existing = await session.scalar(
                    select(ShadowDecisionRecordORM).where(
                        ShadowDecisionRecordORM.idempotency_key == record.idempotency_key
                    )
                )
                if existing is not None:
                    return self._finalize_existing_record(existing, record)

                row = ShadowDecisionRecordORM(
                    record_id=record.record_id,
                    shadow_run_id=run.shadow_run_id,
                    event_id=run.event_id,
                    namespace_key=run.namespace_key,
                    idempotency_key=record.idempotency_key,
                    record_hash=record.record_hash,
                    payload=record.model_dump(mode="json"),
                    retention_expires_at=run.retention_expires_at,
                )
                try:
                    session.add(row)
                    await session.flush()
                except IntegrityError:
                    existing = await session.scalar(
                        select(ShadowDecisionRecordORM).where(
                            ShadowDecisionRecordORM.idempotency_key == record.idempotency_key
                        )
                    )
                    if existing is None:
                        raise
                    return self._finalize_existing_record(existing, record)
        return record.record_id

    @staticmethod
    def _finalize_existing_record(
        existing: ShadowDecisionRecordORM,
        record: DecisionRecord,
    ) -> str:
        if existing.record_hash != record.record_hash:
            logger.warning(
                "ShadowDecisionRecord idempotency replay hash mismatch key=%s existing=%s new=%s",
                record.idempotency_key,
                existing.record_hash,
                record.record_hash,
            )
        return existing.record_id

    async def persist_artifact(
        self,
        run: ShadowRun,
        *,
        kind: ShadowQueryArtifactKind,
        payload: dict[str, object],
        provenance: dict[str, object] | None = None,
    ) -> ShadowQueryArtifact:
        artifact_id = f"sha-{secrets.token_hex(4)}"
        content_hash = _content_hash(payload)
        artifact = ShadowQueryArtifact(
            artifact_id=artifact_id,
            shadow_run_id=run.shadow_run_id,
            kind=kind,
            content_hash=content_hash,
            payload=payload,
            provenance=dict(provenance or {}),
            retention_expires_at=run.retention_expires_at,
            created_at=datetime.now(UTC),
        )
        async with self._session_factory() as session:
            async with session.begin():
                session.add(
                    ShadowQueryArtifactORM(
                        artifact_id=artifact.artifact_id,
                        shadow_run_id=artifact.shadow_run_id,
                        kind=artifact.kind.value,
                        content_hash=artifact.content_hash,
                        payload=artifact.payload,
                        provenance=artifact.provenance,
                        retention_expires_at=artifact.retention_expires_at,
                    )
                )
        return artifact

    async def finalize_run(
        self,
        shadow_run_id: str,
        *,
        status: ShadowRunStatus,
        step_count: int,
        tool_call_count: int,
        result_summary: dict[str, object] | None = None,
        rejected_reasons: list[str] | None = None,
    ) -> ShadowRun | None:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(ShadowRunORM, shadow_run_id)
                if row is None:
                    return None
                row.status = status.value
                row.step_count = step_count
                row.tool_call_count = tool_call_count
                row.result_summary = dict(result_summary or {})
                row.rejected_reasons = list(rejected_reasons or [])
                row.completed_at = now
        return await self.get_run(shadow_run_id)

    async def get_run(self, shadow_run_id: str) -> ShadowRun | None:
        async with self._session_factory() as session:
            row = await session.get(ShadowRunORM, shadow_run_id)
        if row is None:
            return None
        return ShadowRun(
            shadow_run_id=row.shadow_run_id,
            event_id=row.event_id,
            tenant_id=row.tenant_id,
            namespace_key=row.namespace_key,
            status=ShadowRunStatus(row.status),
            max_steps=int(row.max_steps),
            step_count=int(row.step_count),
            max_tool_calls=int(row.max_tool_calls),
            tool_call_count=int(row.tool_call_count),
            provenance=ShadowRunProvenance.model_validate(row.provenance),
            result_summary=dict(row.result_summary or {}),
            rejected_reasons=list(row.rejected_reasons or []),
            retention_expires_at=row.retention_expires_at,
            created_at=row.created_at,
            completed_at=row.completed_at,
        )

    async def count_production_decision_records_for_event(self, event_id: str) -> int:
        from app.db import models as orm

        async with self._session_factory() as session:
            count = await session.scalar(
                select(func.count())
                .select_from(orm.DecisionRecord)
                .where(orm.DecisionRecord.event_id == event_id)
            )
        return int(count or 0)

    async def _new_shadow_run_id(self) -> str:
        async with self._session_factory() as session:
            for _ in range(8):
                shadow_run_id = f"sr-{secrets.token_hex(4)}"
                existing = await session.get(ShadowRunORM, shadow_run_id)
                if existing is None:
                    return shadow_run_id
        raise RuntimeError("failed to allocate shadow_run_id")


__all__ = ["ShadowRunService"]
