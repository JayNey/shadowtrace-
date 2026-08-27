"""Shared helpers for post-evidence FP adjudication persistence (ISSUE-114)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.models.agent_io import EvidenceOutput, OrgContextMatch, TriageResult
from app.models.fp_adjudication import FpAdjudicationResult
from app.services.change_window_baseline_loader import resolve_tenant_id
from app.services.fp_adjudication_service import PostEvidenceFpAdjudicator
from app.services.org_context_matcher import load_org_context_matches
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
    org_context_matches: list[OrgContextMatch] | None = None,
    knowledge_store: Any | None = None,
    tenant_id: str | None = None,
) -> FpAdjudicationResult:
    """Run typed FP adjudication and optionally persist to working memory."""
    matches = list(org_context_matches or [])
    if not matches and knowledge_store is not None:
        resolved_tenant = tenant_id or resolve_tenant_id(source_snapshot) or ""
        if resolved_tenant:
            matches = await load_org_context_matches(
                knowledge_store,
                triage_result=triage_result,
                evidence_output=evidence_output,
                tenant_id=resolved_tenant,
                occurred_at=occurred_at,
            )
    service = adjudicator or PostEvidenceFpAdjudicator()
    result = service.adjudicate(
        event_id=event_id,
        evidence_output=evidence_output,
        triage_result=triage_result,
        source_snapshot=source_snapshot,
        occurred_at=occurred_at,
        org_context_matches=matches,
    )
    if working_memory is not None:
        await working_memory.write(
            event_id,
            "fp_adjudication",
            result.model_dump(mode="json"),
        )
    return result


__all__ = ["run_post_evidence_fp_adjudication"]
