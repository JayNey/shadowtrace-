"""Shared helpers for post-evidence FP adjudication persistence (ISSUE-114)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.models.agent_io import EvidenceOutput, TriageResult
from app.models.fp_adjudication import FpAdjudicationResult
from app.services.fp_adjudication_service import PostEvidenceFpAdjudicator
from app.services.working_memory import BoundWorkingMemory


async def run_post_evidence_fp_adjudication(
    *,
    event_id: str,
    evidence_output: EvidenceOutput,
    triage_result: TriageResult,
    source_snapshot: dict[str, Any] | None,
    occurred_at: datetime | None,
    working_memory: BoundWorkingMemory | None = None,
    adjudicator: PostEvidenceFpAdjudicator | None = None,
) -> FpAdjudicationResult:
    """Run typed FP adjudication and optionally persist to working memory."""
    service = adjudicator or PostEvidenceFpAdjudicator()
    result = service.adjudicate(
        event_id=event_id,
        evidence_output=evidence_output,
        triage_result=triage_result,
        source_snapshot=source_snapshot,
        occurred_at=occurred_at,
    )
    if working_memory is not None:
        await working_memory.write(
            event_id,
            "fp_adjudication",
            result.model_dump(mode="json"),
        )
    return result


__all__ = ["run_post_evidence_fp_adjudication"]
