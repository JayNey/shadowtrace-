"""LLM output admissibility for RiskAgent merge path (ISSUE-102 Phase B / #675)."""

from __future__ import annotations

from app.core.llm.base import LLMResponse
from app.models.agent_io import LlmAdmissibility


def classify_llm_risk_response(response: LLMResponse) -> LlmAdmissibility:
    """Return whether parsed LLM risk scores may influence the merged assessment.

    ``degraded`` responses are structurally valid but must not alter deterministic
    gaps/confidence (rule-only contract applies).
    """
    if response.degraded_reason:
        return LlmAdmissibility.DEGRADED
    return LlmAdmissibility.VALID


__all__ = ["classify_llm_risk_response"]
