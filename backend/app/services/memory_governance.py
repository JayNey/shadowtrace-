"""Governed review, promotion, deduplication, and retention for memory candidates."""

from __future__ import annotations

import hashlib
import re
import secrets
import unicodedata
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import MemoryReviewConflictError, MemoryReviewNotFoundError
from app.db.orm.memory_review import MemoryReviewORM
from app.models.agent_io import FpRuleCandidate, ProfileUpdate
from app.models.case import FalsePositiveCase, HistoryCase
from app.models.memory import MemoryCandidate, MemoryReview
from app.services.case_kb_service import FP_KB_NAME, HISTORY_KB_NAME, CaseKBService
from app.services.profile_service import RISK_HISTORY_LIMIT, ProfileService

PROFILE_KB_NAME = "entity_profile"
LOW_CONFIDENCE_THRESHOLD = 0.5
PENDING_REVIEW_TTL_DAYS = 30

_KB_BY_TYPE = {
    "fp_rule": FP_KB_NAME,
    "history_case": HISTORY_KB_NAME,
    "profile": PROFILE_KB_NAME,
}


class MemoryGovernance:
    """Keep generated memory isolated until a human explicitly promotes it."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        case_kb_service: CaseKBService,
        profile_service: ProfileService,
        now: Callable[[], datetime] | None = None,
        profile_history_limit: int = RISK_HISTORY_LIMIT,
        low_confidence_threshold: float = LOW_CONFIDENCE_THRESHOLD,
        pending_ttl_days: int = PENDING_REVIEW_TTL_DAYS,
    ) -> None:
        if profile_history_limit < 1:
            raise ValueError("profile_history_limit must be positive")
        if not 0.0 <= low_confidence_threshold <= 1.0:
            raise ValueError("low_confidence_threshold must be between 0 and 1")
        if pending_ttl_days < 1:
            raise ValueError("pending_ttl_days must be positive")
        self._session_factory = session_factory
        self._case_kb = case_kb_service
        self._profiles = profile_service
        self._now = now or (lambda: datetime.now(UTC))
        self._profile_history_limit = profile_history_limit
        self._low_confidence_threshold = low_confidence_threshold
        self._pending_ttl = timedelta(days=pending_ttl_days)

    async def ingest_candidate(self, candidate: MemoryCandidate | Mapping[str, Any]) -> str:
        """Validate and durably enqueue a candidate without touching retrieval stores."""
        parsed = MemoryCandidate.model_validate(candidate)
        payload = _prepare_candidate(parsed)
        return await self._insert_pending(parsed, payload)

    async def persist_pending_fallback(
        self,
        candidate: MemoryCandidate | Mapping[str, Any],
    ) -> str:
        """Compensate for an enqueue-path failure with a direct pending-row insert."""
        parsed = MemoryCandidate.model_validate(candidate)
        payload = _prepare_candidate(parsed)
        payload["_review"] = {"enqueue_path": "fallback_after_retry"}
        return await self._insert_pending(parsed, payload)

    async def _insert_pending(
        self,
        candidate: MemoryCandidate,
        payload: dict[str, Any],
    ) -> str:
        async with self._session_factory() as session:
            async with session.begin():
                review_id = await _new_review_id(session)
                session.add(
                    MemoryReviewORM(
                        review_id=review_id,
                        kb_name=candidate.kb_name,
                        candidate_type=candidate.candidate_type,
                        payload=payload,
                        status="pending",
                        confidence=candidate.confidence,
                        created_at=self._now(),
                    )
                )
        return review_id

    async def dedupe(self, kb_name: str) -> int:
        """Demote exact replay duplicates, retaining the highest-confidence newest row."""
        async with self._session_factory() as session:
            async with session.begin():
                rows = list(
                    await session.scalars(
                        select(MemoryReviewORM)
                        .where(
                            MemoryReviewORM.kb_name == kb_name,
                            MemoryReviewORM.status == "pending",
                        )
                        .order_by(MemoryReviewORM.created_at.asc(), MemoryReviewORM.review_id.asc())
                        .with_for_update()
                    )
                )
                groups: dict[str, list[MemoryReviewORM]] = {}
                for row in rows:
                    groups.setdefault(_fingerprint(row), []).append(row)
                demoted = 0
                for candidates in groups.values():
                    if len(candidates) < 2:
                        continue
                    keeper = max(candidates, key=_review_rank)
                    for row in candidates:
                        if row is keeper:
                            continue
                        _mark_demoted(
                            row,
                            operator="memory_governance",
                            reason=f"duplicate_of:{keeper.review_id}",
                            decided_at=self._now(),
                        )
                        demoted += 1
                return demoted

    async def resolve_conflict(self, kb_name: str, key: str) -> None:
        """Keep the best pending candidate for a fingerprint and demote the rest."""
        async with self._session_factory() as session:
            async with session.begin():
                rows = list(
                    await session.scalars(
                        select(MemoryReviewORM)
                        .where(
                            MemoryReviewORM.kb_name == kb_name,
                            MemoryReviewORM.status.in_(("pending", "promoted")),
                        )
                        .order_by(MemoryReviewORM.created_at.asc(), MemoryReviewORM.review_id.asc())
                        .with_for_update()
                    )
                )
                matching = [row for row in rows if _fingerprint(row) == key]
                if not matching:
                    return
                promoted = [row for row in matching if row.status == "promoted"]
                keeper = max(promoted or matching, key=_review_rank)
                for row in matching:
                    if row is keeper or row.status != "pending":
                        continue
                    _mark_demoted(
                        row,
                        operator="memory_governance",
                        reason=f"conflict_winner:{keeper.review_id}",
                        decided_at=self._now(),
                    )

    async def promote(self, review_id: str, operator: str) -> None:
        """Atomically promote a candidate and its target-store representation."""
        decided_by = _required_text(operator, "operator")
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.scalar(
                    select(MemoryReviewORM)
                    .where(MemoryReviewORM.review_id == review_id)
                    .with_for_update()
                )
                if row is None:
                    raise MemoryReviewNotFoundError(
                        f"memory review {review_id} not found",
                        details={"review_id": review_id},
                    )
                if row.status == "promoted":
                    return
                if row.status != "pending":
                    raise MemoryReviewConflictError(
                        f"memory review {review_id} is already {row.status}",
                        details={"review_id": review_id, "status": row.status},
                    )
                row.status = "promoted"
                row.operator = decided_by
                row.decided_at = self._now()
                await self._promote_payload(row, decided_by, session)
                await session.flush()

    async def demote(self, review_id: str, operator: str, reason: str) -> None:
        """Reject a pending candidate while retaining an auditable queue record."""
        decided_by = _required_text(operator, "operator")
        decision_reason = _required_text(reason, "reason")
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.scalar(
                    select(MemoryReviewORM)
                    .where(MemoryReviewORM.review_id == review_id)
                    .with_for_update()
                )
                if row is None:
                    raise MemoryReviewNotFoundError(
                        f"memory review {review_id} not found",
                        details={"review_id": review_id},
                    )
                if row.status == "demoted":
                    return
                if row.status != "pending":
                    raise MemoryReviewConflictError(
                        f"memory review {review_id} is already {row.status}",
                        details={"review_id": review_id, "status": row.status},
                    )
                _mark_demoted(
                    row,
                    operator=decided_by,
                    reason=decision_reason,
                    decided_at=self._now(),
                )

    async def apply_retention(self, kb_name: str) -> int:
        """Demote expired low-confidence reviews and trim profile risk history."""
        cutoff = self._now() - self._pending_ttl
        affected = 0
        async with self._session_factory() as session:
            async with session.begin():
                rows = list(
                    await session.scalars(
                        select(MemoryReviewORM)
                        .where(
                            MemoryReviewORM.kb_name == kb_name,
                            MemoryReviewORM.status == "pending",
                            MemoryReviewORM.confidence < self._low_confidence_threshold,
                            MemoryReviewORM.created_at <= cutoff,
                        )
                        .order_by(MemoryReviewORM.created_at.asc())
                        .with_for_update()
                    )
                )
                for row in rows:
                    _mark_demoted(
                        row,
                        operator="memory_governance",
                        reason="pending_review_ttl_expired",
                        decided_at=self._now(),
                    )
                    affected += 1
        if kb_name == PROFILE_KB_NAME:
            affected += await self._profiles.apply_retention(self._profile_history_limit)
        return affected

    async def list_pending(self, kb_name: str | None = None) -> list[MemoryReview]:
        """List pending reviews oldest first, optionally restricted to one KB."""
        statement = select(MemoryReviewORM).where(MemoryReviewORM.status == "pending")
        if kb_name is not None:
            statement = statement.where(MemoryReviewORM.kb_name == kb_name)
        statement = statement.order_by(
            MemoryReviewORM.created_at.asc(), MemoryReviewORM.review_id.asc()
        )
        async with self._session_factory() as session:
            rows = list(await session.scalars(statement))
            return [MemoryReview.model_validate(row) for row in rows]

    def fingerprint(self, candidate: MemoryCandidate | Mapping[str, Any]) -> str:
        """Return the stable normalized key used by conflict resolution."""
        parsed = MemoryCandidate.model_validate(candidate)
        payload = _validated_payload(parsed.candidate_type, parsed.payload)
        return _fingerprint_values(parsed.candidate_type, payload)

    async def _promote_payload(
        self,
        row: MemoryReviewORM,
        operator: str,
        session: AsyncSession,
    ) -> None:
        payload = _candidate_payload(row.payload)
        if row.candidate_type == "history_case":
            await self._case_kb.upsert_history_case(
                HistoryCase.model_validate(payload),
                session=session,
            )
            return
        if row.candidate_type == "profile":
            await self._profiles.upsert(
                ProfileUpdate.model_validate(payload),
                session=session,
            )
            return

        candidate = FpRuleCandidate.model_validate(payload)
        digest = hashlib.sha256(_normalize_text(candidate.alert_signature).encode()).hexdigest()
        fp_case = FalsePositiveCase(
            case_id=f"case-{digest[:8]}",
            pattern_summary=candidate.rule_summary,
            alert_signature=candidate.alert_signature,
            entity_pattern=str(payload.get("entity_pattern") or "reviewed alert signature"),
            fp_reason=str(payload.get("fp_reason") or candidate.rule_summary),
            confirmed_by=operator,
            confirmed_at=self._now(),
        )
        await self._case_kb.upsert_fp_case(fp_case, session=session)


async def _new_review_id(session: AsyncSession) -> str:
    for _ in range(8):
        review_id = f"rev-{secrets.token_hex(4)}"
        if await session.get(MemoryReviewORM, review_id) is None:
            return review_id
    raise RuntimeError("unable to allocate unique memory review id")


def _validated_payload(candidate_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    clean = _candidate_payload(payload)
    if candidate_type == "fp_rule":
        return FpRuleCandidate.model_validate(clean).model_dump(mode="json")
    if candidate_type == "history_case":
        return HistoryCase.model_validate(clean).model_dump(mode="json")
    if candidate_type == "profile":
        return ProfileUpdate.model_validate(clean).model_dump(mode="json")
    raise ValueError(f"unsupported memory candidate type: {candidate_type}")


def _prepare_candidate(candidate: MemoryCandidate) -> dict[str, Any]:
    expected_kb = _KB_BY_TYPE[candidate.candidate_type]
    if candidate.kb_name != expected_kb:
        raise ValueError(
            f"candidate_type={candidate.candidate_type} requires kb_name={expected_kb}"
        )
    return _validated_payload(candidate.candidate_type, candidate.payload)


def _candidate_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "_review"}


def _fingerprint(row: MemoryReviewORM) -> str:
    return _fingerprint_values(row.candidate_type, _candidate_payload(row.payload))


def _fingerprint_values(candidate_type: str, payload: Mapping[str, Any]) -> str:
    if candidate_type == "fp_rule":
        identity = _normalize_text(str(payload.get("alert_signature", "")))
    elif candidate_type == "history_case":
        event_type = _normalize_text(str(payload.get("event_type", "")))
        entities = sorted(
            part
            for part in (
                _normalize_text(item) for item in str(payload.get("key_entities", "")).split(";")
            )
            if part
        )
        identity = f"{event_type}|{'|'.join(entities)}"
    elif candidate_type == "profile":
        identity = "|".join(
            [
                _normalize_text(str(payload.get("entity_type", ""))),
                _normalize_text(str(payload.get("entity_value", ""))),
            ]
        )
    else:
        raise ValueError(f"unsupported memory candidate type: {candidate_type}")
    digest = hashlib.sha256(identity.encode()).hexdigest()
    return f"{candidate_type}:{digest}"


def _review_rank(row: MemoryReviewORM) -> tuple[float, datetime, str]:
    created_at = row.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    return row.confidence, created_at, row.review_id


def _mark_demoted(
    row: MemoryReviewORM,
    *,
    operator: str,
    reason: str,
    decided_at: datetime,
) -> None:
    payload = _candidate_payload(row.payload)
    payload["_review"] = {"demote_reason": reason}
    row.payload = payload
    row.status = "demoted"
    row.operator = operator
    row.decided_at = decided_at


def _normalize_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return re.sub(r"\s+", " ", normalized).strip()


def _required_text(value: str, name: str) -> str:
    rendered = value.strip()
    if not rendered:
        raise ValueError(f"{name} is required")
    return rendered
