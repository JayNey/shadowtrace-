"""Shared prompt packing helpers for specialist agent handoff (ISSUE-326 / #957)."""

from __future__ import annotations

import warnings
from typing import Any

from app.models.agent_io import EvidenceOutput, TriageResult

_DECISION_SUMMARY_LIMIT = 512
_REASONING_LIMIT = 500
_EVIDENCE_SAMPLE_LIMIT = 12
_EVIDENCE_DESCRIPTION_LIMIT = 200


def bounded_decision_summary(triage_result: TriageResult) -> str:
    return (triage_result.decision_summary or "")[:_DECISION_SUMMARY_LIMIT]


def bounded_triage_reasoning(triage_result: TriageResult) -> str:
    """Keep the deprecated reasoning key as a secondary input without restoring CoT."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return (triage_result.reasoning or "")[:_REASONING_LIMIT]


def evidence_prompt_block(evidence_output: EvidenceOutput) -> dict[str, Any]:
    """Serialize evidence for downstream agent prompts (aligned with risk/response)."""
    return {
        "overall_confidence": evidence_output.overall_confidence,
        "collection_status": evidence_output.collection_status.value,
        "success_sources": list(evidence_output.success_sources),
        "failed_sources": list(evidence_output.failed_sources),
        "evidence_count": len(evidence_output.evidence_list),
        "sample": [
            {
                "source": item.source.value,
                "evidence_type": item.evidence_type,
                "description": (item.description or "")[:_EVIDENCE_DESCRIPTION_LIMIT],
                "confidence": item.confidence,
                "mitre_technique": item.mitre_technique,
                "is_conflicting": item.is_conflicting,
            }
            for item in evidence_output.evidence_list[:_EVIDENCE_SAMPLE_LIMIT]
        ],
    }


__all__ = [
    "bounded_decision_summary",
    "bounded_triage_reasoning",
    "evidence_prompt_block",
]
