"""Triage vs risk scoring consistency checks (ISSUE-200).

When triage classifies weakly (OTHER / no-threat narrative) but downstream
risk scoring reaches confirmed-threat territory, operators need an auditable
signal without auto-downgrading the verdict (anti-miss).
"""

from __future__ import annotations

from app.agents.verdict_resolver import CONFIRMED_THREAT_RISK_THRESHOLD
from app.models.agent_io import TriageResult
from app.models.enums import EventType, FinalVerdict

TRIAGE_RISK_INCONSISTENCY_FLAG = "triage_risk_inconsistency"

# Re-export for callers that already import from this module (ISSUE-200).
HIGH_RISK_SCORE_THRESHOLD = CONFIRMED_THREAT_RISK_THRESHOLD

# Substrings observed in Mock golden / weak triage narratives.
_WEAK_TRIAGE_SUMMARY_PHRASES: tuple[str, ...] = (
    "no clear threat pattern",
    "no threat pattern detected",
    "likely not a threat",
    "no obvious threat",
)

INCONSISTENCY_DISCLOSURE_HEADER = (
    "分类与评分不一致：分诊阶段未识别明确威胁模式或事件类型为 OTHER，"
    "但风险评分达到确认威胁阈值；请结合证据链人工复核，勿仅依据分诊摘要结案。"
)


def triage_has_weak_classification_signal(triage: TriageResult) -> bool:
    """Return True when triage output signals low-confidence / no-pattern classification."""
    if triage.event_type is EventType.OTHER:
        return True
    summary = (triage.decision_summary or triage.reasoning or "").strip().lower()
    if not summary:
        return False
    return any(phrase in summary for phrase in _WEAK_TRIAGE_SUMMARY_PHRASES)


def should_flag_triage_risk_inconsistency(
    *,
    triage: TriageResult,
    risk_score: int,
    final_verdict: FinalVerdict,
) -> bool:
    """Detect weak triage + confirmed threat without mutating verdict."""
    if final_verdict is not FinalVerdict.CONFIRMED_THREAT:
        return False
    if int(risk_score) < HIGH_RISK_SCORE_THRESHOLD:
        return False
    return triage_has_weak_classification_signal(triage)


__all__ = [
    "HIGH_RISK_SCORE_THRESHOLD",
    "INCONSISTENCY_DISCLOSURE_HEADER",
    "TRIAGE_RISK_INCONSISTENCY_FLAG",
    "should_flag_triage_risk_inconsistency",
    "triage_has_weak_classification_signal",
]
