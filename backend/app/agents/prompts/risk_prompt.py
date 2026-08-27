"""Risk scoring prompt builders (ISSUE-035 / ISSUE-251).

LLM selects a per-dimension rubric band; numeric scores are server-landed.
Legacy ``score`` fields still parse and map onto the nearest band.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.agents.prompts.prompt_blocks import (
    bounded_decision_summary,
    bounded_triage_reasoning,
    evidence_prompt_block,
)
from app.agents.risk_rubric import FACTOR_NAMES, rubric_catalog_for_prompt
from app.core.llm.base import LLMMessage
from app.models.agent_io import EvidenceOutput, TriageResult


class RiskFactorLLM(BaseModel):
    """One dimension choice from risk_score structured output."""

    model_config = ConfigDict(extra="ignore")

    rubric_id: str | None = None
    lean: str | None = None
    secondary_rubric_id: str | None = None
    score: float | None = None
    reason: str = ""

    @model_validator(mode="before")
    @classmethod
    def _accept_reasoning_alias(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        data = dict(value)
        if not data.get("reason") and data.get("reasoning") is not None:
            data["reason"] = data.get("reasoning")
        return data

    @field_validator("rubric_id", "secondary_rubric_id", "lean", mode="before")
    @classmethod
    def _blank_to_none(cls, value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @field_validator("score", mode="before")
    @classmethod
    def _coerce_score(cls, value: Any) -> float | None:
        if value is None or value == "":
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @field_validator("reason", mode="before")
    @classmethod
    def _coerce_reason(cls, value: Any) -> str:
        return "" if value is None else str(value)

    def has_choice(self) -> bool:
        return bool(self.rubric_id) or self.score is not None


class RiskScoreLLMResponse(BaseModel):
    """Slim wire model so JSON repair embeds a real schema (ISSUE-251)."""

    model_config = ConfigDict(extra="ignore")

    factors: dict[str, RiskFactorLLM] = Field(default_factory=dict)
    raw_confidence: float = 0.75
    evidence_limited: bool = False

    @field_validator("factors", mode="before")
    @classmethod
    def _coerce_factors(cls, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {}
        out: dict[str, Any] = {}
        for key, entry in value.items():
            if not isinstance(entry, dict):
                continue
            try:
                parsed = RiskFactorLLM.model_validate(entry)
            except Exception:
                continue
            if not parsed.has_choice():
                continue
            out[str(key)] = parsed
        return out

    @field_validator("raw_confidence", mode="before")
    @classmethod
    def _coerce_confidence(cls, value: Any) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.75

    @field_validator("evidence_limited", mode="before")
    @classmethod
    def _coerce_limited(cls, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes"}
        return bool(value)

    @model_validator(mode="after")
    def _require_all_factors(self) -> RiskScoreLLMResponse:
        missing = [name for name in FACTOR_NAMES if name not in self.factors]
        if missing:
            raise ValueError(f"risk_score missing required factors: {missing}")
        return self


def build_risk_messages(
    *,
    triage_result: TriageResult,
    evidence_output: EvidenceOutput,
    rag_summary: dict[str, Any] | None = None,
    graph_summary: dict[str, Any] | None = None,
    source_snapshot: dict[str, Any] | None = None,
) -> list[LLMMessage]:
    """Build JSON-mode messages that request per-dimension rubric bands (no CoT)."""
    system = (
        "You are ShadowTrace RiskAgent. Classify residual cyber risk for one "
        "security event across six fixed dimensions. Do not invent a 0-100 score. "
        "For each dimension pick one rubric_id from the provided catalog, optional "
        "lean (low|mid|high), and optional secondary_rubric_id only when the case "
        "sits between two adjacent bands. Return a single JSON object only "
        "(no markdown fences, no commentary) with shape:\n"
        '{"factors":{"asset_impact":{"rubric_id":"...","lean":"mid","reason":"..."},'
        '"behavior_anomaly":{"rubric_id":"...","lean":"mid","reason":"..."},'
        '"evidence_confidence":{"rubric_id":"...","lean":"mid","reason":"..."},'
        '"attack_stage":{"rubric_id":"...","lean":"mid","reason":"..."},'
        '"data_sensitivity":{"rubric_id":"...","lean":"mid","reason":"..."},'
        '"threat_intel":{"rubric_id":"...","lean":"mid","reason":"..."}},'
        '"raw_confidence":0.0,"evidence_limited":false}\n'
        "Each reason is one evidence-based sentence. Do not include chain-of-thought. "
        "Missing or failed evidence collection does NOT mean low threat — preserve "
        "source alert severity when evidence is sparse and set evidence_limited=true."
    )
    source_context: dict[str, Any] = {}
    if isinstance(source_snapshot, dict):
        normalized = source_snapshot.get("normalized")
        if isinstance(normalized, dict):
            source_context["normalized"] = normalized
        if source_snapshot.get("severity"):
            source_context["severity"] = source_snapshot.get("severity")
    payload = {
        "triage": {
            "event_type": triage_result.event_type.value,
            "severity": triage_result.severity.value,
            "ioc_list": list(triage_result.ioc_list),
            "decision_summary": bounded_decision_summary(triage_result),
            "reasoning": bounded_triage_reasoning(triage_result),
        },
        "source_snapshot": source_context,
        "evidence": evidence_prompt_block(evidence_output),
        "rag": rag_summary or {},
        "graph_summary": graph_summary or {},
        "required_factors": list(FACTOR_NAMES),
        "rubrics": rubric_catalog_for_prompt(),
        "lean_values": ["low", "mid", "high"],
    }
    user = (
        "Pick a rubric band per dimension and respond with JSON only.\n"
        f"Context:\n{json.dumps(payload, ensure_ascii=False)}"
    )
    return [
        LLMMessage(role="system", content=system),
        LLMMessage(role="user", content=user),
    ]


__all__ = [
    "FACTOR_NAMES",
    "RiskFactorLLM",
    "RiskScoreLLMResponse",
    "build_risk_messages",
]
