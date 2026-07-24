"""Risk scoring prompt builders (ISSUE-035)."""

from __future__ import annotations

import json
from typing import Any

from app.core.llm.base import LLMMessage
from app.models.agent_io import EvidenceOutput, TriageResult

FACTOR_NAMES: tuple[str, ...] = (
    "asset_impact",
    "behavior_anomaly",
    "evidence_confidence",
    "attack_stage",
    "data_sensitivity",
    "threat_intel",
)


def build_risk_messages(
    *,
    triage_result: TriageResult,
    evidence_output: EvidenceOutput,
    rag_summary: dict[str, Any] | None = None,
    storyline_summary: str | None = None,
) -> list[LLMMessage]:
    """Build JSON-mode messages that request per-dimension scores only (no CoT)."""
    system = (
        "You are ShadowTrace RiskAgent. Score residual cyber risk for one security "
        "event across six fixed dimensions. Reply with JSON only. Do not include "
        "hidden chain-of-thought. For each dimension provide score (0-100) and a "
        "short evidence-based reason (one sentence)."
    )
    payload = {
        "triage": {
            "event_type": triage_result.event_type.value,
            "severity": triage_result.severity.value,
            "ioc_list": list(triage_result.ioc_list),
            "reasoning": triage_result.reasoning,
        },
        "evidence": {
            "overall_confidence": evidence_output.overall_confidence,
            "collection_status": evidence_output.collection_status.value,
            "success_sources": list(evidence_output.success_sources),
            "failed_sources": list(evidence_output.failed_sources),
            "evidence_count": len(evidence_output.evidence_list),
            "sample": [
                {
                    "source": item.source.value,
                    "evidence_type": item.evidence_type,
                    "description": item.description[:200],
                    "confidence": item.confidence,
                    "mitre_technique": item.mitre_technique,
                    "is_conflicting": item.is_conflicting,
                }
                for item in evidence_output.evidence_list[:12]
            ],
        },
        "rag": rag_summary or {},
        "storyline_summary": storyline_summary or "",
        "required_factors": list(FACTOR_NAMES),
        "response_schema": {
            "factors": {
                "<factor_name>": {"score": "0-100", "reason": "short string"},
            },
            "raw_confidence": "0-1",
        },
    }
    user = (
        "Score the event. Return JSON shaped like:\n"
        '{"factors":{"asset_impact":{"score":80,"reason":"..."},'
        '"behavior_anomaly":{"score":70,"reason":"..."},'
        '"evidence_confidence":{"score":75,"reason":"..."},'
        '"attack_stage":{"score":85,"reason":"..."},'
        '"data_sensitivity":{"score":70,"reason":"..."},'
        '"threat_intel":{"score":80,"reason":"..."}},'
        '"raw_confidence":0.82}\n'
        f"Context:\n{json.dumps(payload, ensure_ascii=False)}"
    )
    return [
        LLMMessage(role="system", content=system),
        LLMMessage(role="user", content=user),
    ]
