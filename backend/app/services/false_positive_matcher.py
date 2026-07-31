"""FalsePositiveMatcher: vector-based false-positive pre-filter (ISSUE-078 / ISSUE-114).

Matches alert snapshots against the ``fp_case_kb`` knowledge base to produce
an **advisory** recommendation (``investigate_with_flag`` / ``no_match``) that
is written to ``EventContext.false_positive_match`` via a post-triage hook.

Pre-evidence paths must never emit ``close_as_fp`` (ISSUE-114). Typed closure
requires post-evidence adjudication via :class:`PostEvidenceFpAdjudicator`.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.entities import (
    AccountEntity,
    DomainEntity,
    EntitySet,
    FileEntity,
    HostEntity,
    IPEntity,
    ProcessEntity,
)
from app.models.workflow import FP_LOW_THRESHOLD
from app.services.case_kb_service import CaseKBService
from app.services.working_memory import BoundWorkingMemory

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# FPMatchResult
# --------------------------------------------------------------------------- #


class FPMatchResult(BaseModel):
    """Result of matching an alert snapshot against the false-positive case KB.

    Fields match the ISSUE-078 unified naming:
    - ``matched``: True when max_score >= FP_LOW_THRESHOLD
    - ``recommendation``: investigate_with_flag / no_match (pre-evidence advisory only)
    """

    model_config = ConfigDict(extra="forbid")

    matched: bool
    max_score: float
    matched_case_id: str | None = None
    matched_pattern: str | None = None
    recommendation: str = Field(..., description="investigate_with_flag | no_match")


# --------------------------------------------------------------------------- #
# FalsePositiveMatcher
# --------------------------------------------------------------------------- #


class FalsePositiveMatcher:
    """Vector-based false-positive matcher using the fp_case_kb.

    Builds a rich alert text from the source_snapshot + entities, searches
    the fp_case_kb via :class:`CaseKBService`, and returns an
    :class:`FPMatchResult` with a recommendation based on the top-1 score.

    Degradation strategy: when the KB is unavailable or empty, returns
    ``no_match`` so the investigation proceeds normally with zero impact.
    """

    def __init__(self, case_kb_service: CaseKBService) -> None:
        self._case_kb = case_kb_service

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def match(
        self,
        source_snapshot: dict[str, Any],
        entities: EntitySet,
    ) -> FPMatchResult:
        """Match *source_snapshot* + *entities* against the fp_case_kb.

        Args:
            source_snapshot: Frozen normalized XDR source snapshot (file
                fallback uses the compatible ``raw_alert_snapshot`` field).
            entities: Entity set for text enrichment (regex-extracted for
                the pre-triage hook path; LLM-extracted for post-triage).

        Returns:
            FPMatchResult with recommendation based on top-1 score vs
            FP_HIGH_THRESHOLD / FP_LOW_THRESHOLD.
        """
        alert_text = _build_alert_text(source_snapshot, entities)

        try:
            results = await self._case_kb.search_fp_cases(alert_text, top_k=1)
        except Exception:
            logger.warning(
                "FalsePositiveMatcher: fp_case_kb search failed; returning no_match",
                exc_info=True,
            )
            return _no_match()

        if not results:
            return _no_match()

        top = results[0]
        score = float(top.score)
        recommendation = _recommendation_for(score)

        return FPMatchResult(
            matched=score >= FP_LOW_THRESHOLD,
            max_score=score,
            matched_case_id=(top.metadata.get("case_id") if recommendation != "no_match" else None),
            matched_pattern=(
                top.metadata.get("pattern_summary") if recommendation != "no_match" else None
            ),
            recommendation=recommendation,
        )


# --------------------------------------------------------------------------- #
# FalsePositiveMatcherHook — post-triage hook for TriageAgent
# --------------------------------------------------------------------------- #


class FalsePositiveMatcherHook:
    """Post-triage hook that runs the :class:`FalsePositiveMatcher` and writes
    the result to ``EventContext.false_positive_match``.

    Runs as a **post-triage** hook so it has access to the LLM-extracted
    (and hint-merged) entities in ``triage_result`` — fixing the ISSUE-078
    spec requirement that FP matching uses the final EntitySet, not just
    regex-extracted placeholder entities.

    Uses its own ``BoundWorkingMemory`` bound to the ``FalsePositiveMatcher``
    writer identity (via ``WRITER_ALIASES`` when legacy journal writers are present).
    Does NOT change EventStatus, call set_final_verdict, or write reports —
    those actions are owned by the orchestration layer.

    Degradation / skip-write strategy:

    * KB unavailable → logged, write skipped, investigation proceeds normally
    * ``no_match`` recommendation → write skipped (零影响 — no trace left)
    * Any unexpected exception in the hook body → caught, logged, write skipped;
      the TriageAgent / investigation pipeline is NOT crashed
    """

    def __init__(
        self,
        matcher: FalsePositiveMatcher,
        working_memory: BoundWorkingMemory,
    ) -> None:
        self._matcher = matcher
        self._wm = working_memory

    async def __call__(
        self,
        agent: Any,  # BaseAgent[TriageAgentInput, TriageResult]
        input: Any,  # TriageAgentInput
    ) -> None:
        try:
            await self._run(agent, input)
        except Exception:
            logger.warning(
                "FalsePositiveMatcherHook failed for event=%s; skip write, investigation continues",
                getattr(input, "event_id", "?"),
                exc_info=True,
            )
            # Hook failure must not crash the TriageAgent pipeline.
            # The investigation proceeds normally with zero impact.

    async def _run(self, agent: Any, input: Any) -> None:
        wm = self._wm
        if wm is None:
            return

        # Read source_snapshot through the agent's own memory (read is not
        # ownership-gated — any bound identity can read any field).
        agent_wm = getattr(agent, "working_memory", None)
        if agent_wm is None:
            return

        snapshot = await agent_wm.read(input.event_id, "source_snapshot")
        if not isinstance(snapshot, dict):
            return

        # Read the triage_result to get the LLM-extracted + hint-merged
        # EntitySet (ISSUE-078 spec: FP matching uses final entities).
        triage_result = await agent_wm.read(input.event_id, "triage_result")
        entities = _entities_from_triage_result(triage_result)

        result = await self._matcher.match(snapshot, entities)

        # Degradation / zero-impact: skip write when there is no match.
        # The investigation proceeds as if the hook never ran.
        if result.recommendation == "no_match":
            return

        fp_match: dict[str, Any] = {
            "matched": result.matched,
            "max_score": result.max_score,
            "matched_case_id": result.matched_case_id,
            "matched_pattern": result.matched_pattern,
            "recommendation": result.recommendation,
            "source": "FalsePositiveMatcher",
            "phase": "pre_evidence",
            "matched_at": datetime.now(UTC).isoformat(),
        }

        await wm.write(input.event_id, "false_positive_match", fp_match)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _build_alert_text(source_snapshot: dict[str, Any], entities: EntitySet) -> str:
    """Build a searchable alert text from snapshot + entities for vector retrieval.

    Combines alert_type, title, description, and entity features into a single
    pipe-delimited string. Scenario/fixture identifiers are excluded (ISSUE-114).
    """
    parts: list[str] = []

    # Alert type / event type.
    alert_type = source_snapshot.get("alert_type", "")
    if alert_type:
        parts.append(f"alert_type={alert_type}")

    # Title / subject.
    title = source_snapshot.get("title") or source_snapshot.get("subject", "")
    if title:
        parts.append(str(title))

    # Description.
    description = source_snapshot.get("description", "")
    if description:
        parts.append(str(description))

    # Severity from snapshot.
    severity = source_snapshot.get("severity", "")
    if severity:
        parts.append(f"severity={severity}")

    # Entity features from EntitySet.
    entity_parts = _entity_features(entities)
    if entity_parts:
        parts.append(entity_parts)

    # File fallback: raw_alert_snapshot fields.
    raw_snap = source_snapshot.get("raw_alert_snapshot")
    if isinstance(raw_snap, dict):
        raw_title = raw_snap.get("title", "")
        if raw_title:
            parts.append(str(raw_title))
        raw_desc = raw_snap.get("description", "")
        if raw_desc and raw_desc != description:
            parts.append(str(raw_desc))

    return " | ".join(parts) if parts else str(source_snapshot)


def _entity_features(entities: EntitySet) -> str:
    """Render entity features as a compact string for text matching."""
    features: list[str] = []

    for acct in entities.accounts:
        label = acct.username or acct.display_name or acct.entity_id
        features.append(f"account={label}")

    for host in entities.hosts:
        label = host.hostname or host.ip or host.entity_id
        features.append(f"host={label}")

    for ip in entities.ips:
        addr = ip.address or ip.entity_id
        scope = ip.scope if ip.scope != "unknown" else ""
        features.append(f"ip={addr}" + (f" scope={scope}" if scope else ""))

    for dom in entities.domains:
        label = dom.fqdn or dom.entity_id
        features.append(f"domain={label}")

    for proc in entities.processes:
        label = proc.name or proc.entity_id
        features.append(f"process={label}")

    for file in entities.files:
        label = file.name or file.path or file.entity_id
        features.append(f"file={label}")

    return "; ".join(features) if features else ""


def _entities_from_triage_result(triage_result: Any) -> EntitySet:
    """Extract an ``EntitySet`` from a serialized ``triage_result`` dict.

    The ``triage_result`` is stored as a JSON dict (``model_dump(mode="json")``).
    Returns an empty ``EntitySet`` when *triage_result* is not a dict or has no
    ``entities`` key, so the matcher still works with the snapshot text alone.
    """
    if not isinstance(triage_result, dict):
        return EntitySet()

    entities_raw = triage_result.get("entities")
    if not isinstance(entities_raw, dict):
        return EntitySet()

    return EntitySet(
        accounts=[
            AccountEntity(
                entity_id=e.get("entity_id", ""),
                entity_type="account",
                username=e.get("username", ""),
            )
            for e in (entities_raw.get("accounts") or [])
            if isinstance(e, dict)
        ],
        hosts=[
            HostEntity(
                entity_id=e.get("entity_id", ""),
                entity_type="host",
                hostname=e.get("hostname", ""),
            )
            for e in (entities_raw.get("hosts") or [])
            if isinstance(e, dict)
        ],
        ips=[
            IPEntity(
                entity_id=e.get("entity_id", ""),
                entity_type="ip",
                address=e.get("address", ""),
                scope=e.get("scope", "unknown"),
            )
            for e in (entities_raw.get("ips") or [])
            if isinstance(e, dict)
        ],
        domains=[
            DomainEntity(
                entity_id=e.get("entity_id", ""),
                entity_type="domain",
                fqdn=e.get("fqdn", ""),
            )
            for e in (entities_raw.get("domains") or [])
            if isinstance(e, dict)
        ],
        processes=[
            ProcessEntity(
                entity_id=e.get("entity_id", ""),
                entity_type="process",
                name=e.get("name", ""),
            )
            for e in (entities_raw.get("processes") or [])
            if isinstance(e, dict)
        ],
        files=[
            FileEntity(
                entity_id=e.get("entity_id", ""),
                entity_type="file",
                name=e.get("name", ""),
                path=e.get("path", ""),
            )
            for e in (entities_raw.get("files") or [])
            if isinstance(e, dict)
        ],
    )


def _recommendation_for(score: float) -> str:
    """Map a similarity score to a pre-evidence advisory recommendation."""
    if score >= FP_LOW_THRESHOLD:
        return "investigate_with_flag"
    return "no_match"


def _no_match() -> FPMatchResult:
    """Return a no-match result (degradation or empty KB)."""
    return FPMatchResult(
        matched=False,
        max_score=0.0,
        recommendation="no_match",
    )


def build_fp_close_reason(
    false_positive_match: dict[str, Any] | None,
    *,
    fp_adjudication: dict[str, Any] | None = None,
    default: str = "investigation:close",
) -> str:
    """Build an audit-friendly close reason from post-evidence FP adjudication."""
    adjudication = fp_adjudication if isinstance(fp_adjudication, dict) else None
    if adjudication is None and isinstance(false_positive_match, dict):
        if false_positive_match.get("phase") == "post_evidence":
            adjudication = false_positive_match

    if isinstance(adjudication, dict) and adjudication.get("recommendation") == "close_as_fp":
        parts = ["close_as_fp", "post_evidence"]
        window_id = adjudication.get("matched_window_id")
        if window_id:
            parts.append(f"window={window_id}")
        evidence_ids = adjudication.get("supporting_evidence_ids") or []
        if evidence_ids:
            parts.append(f"evidence={len(evidence_ids)}")
        return " ".join(parts)

    if isinstance(false_positive_match, dict):
        if false_positive_match.get("recommendation") == "close_as_fp":
            # Legacy callers may still pass close_as_fp — keep audit text stable.
            case_id = false_positive_match.get("matched_case_id")
            pattern = false_positive_match.get("matched_pattern") or false_positive_match.get(
                "matched_rule"
            )
            parts = ["close_as_fp"]
            if case_id:
                parts.append(f"matched {case_id}")
            elif pattern:
                parts.append("matched")
            if pattern:
                parts.append(str(pattern))
            return " ".join(parts)

    return default


__all__ = [
    "FPMatchResult",
    "FalsePositiveMatcher",
    "FalsePositiveMatcherHook",
    "_entities_from_triage_result",
    "build_fp_close_reason",
]
