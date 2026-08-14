"""Triage vs risk scoring consistency checks (ISSUE-200 / ISSUE-330).

When triage classifies weakly (OTHER / no-threat narrative) but downstream
risk scoring reaches confirmed-threat territory, operators need an auditable
signal without auto-downgrading the verdict (anti-miss).

ISSUE-330: outward-facing severity (reports, audit scorecards, UI) must use
``risk_assessment.severity`` as the authoritative source.  Triage severity may
be disclosed explicitly when it diverges — never via silent ``or`` fallbacks.
"""

from __future__ import annotations

import re
from typing import Any

from app.agents.verdict_resolver import CONFIRMED_THREAT_RISK_THRESHOLD
from app.models.agent_io import RiskAssessment, TriageResult
from app.models.enums import EventType, FinalVerdict, Severity

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

_TRIAGE_DECISION_SUMMARY_PREFIX_RE = re.compile(
    r"^event_type=[^,]+,\s*severity=[^,]+,\s*need_investigation=(?:True|False|false|true)"
    r"(?:;\s*)?",
    re.IGNORECASE,
)


def triage_has_weak_classification_signal(triage: TriageResult) -> bool:
    """Return True when triage output signals low-confidence / no-pattern classification."""
    if triage.event_type is EventType.OTHER:
        return True
    summary = (triage.decision_summary or triage.reasoning or "").strip().lower()
    if not summary:
        return False
    return any(phrase in summary for phrase in _WEAK_TRIAGE_SUMMARY_PHRASES)


def _coerce_severity(value: Severity | str | None) -> Severity | None:
    if value is None:
        return None
    if isinstance(value, Severity):
        return value
    text = str(value).strip().lower()
    if not text:
        return None
    try:
        return Severity(text)
    except ValueError:
        return None


def strip_triage_machine_prefix(decision_summary: str) -> str:
    """Remove the machine-readable triage base prefix from ``decision_summary``."""
    stripped = (decision_summary or "").strip()
    if not stripped:
        return ""
    return _TRIAGE_DECISION_SUMMARY_PREFIX_RE.sub("", stripped, count=1).strip()


def resolve_outward_severity(
    *,
    risk_assessment: RiskAssessment | dict[str, Any] | None = None,
    event_severity: Severity | str | None = None,
) -> Severity | None:
    """Authoritative outward severity: risk assessment first, then event row.

    Never reads triage snapshots — triage severity is planning context only.
    """
    if isinstance(risk_assessment, RiskAssessment):
        return risk_assessment.severity
    if isinstance(risk_assessment, dict):
        coerced = _coerce_severity(risk_assessment.get("severity"))
        if coerced is not None:
            return coerced
    return _coerce_severity(event_severity)


def format_triage_decision_excerpt(
    triage: TriageResult | None,
    *,
    outward_severity: Severity,
    max_chars: int = 320,
) -> str | None:
    """Bounded triage excerpt for outward reports without silent severity mixing."""
    if triage is None:
        return None
    summary = (triage.decision_summary or "").strip()
    if not summary:
        return None
    notes = strip_triage_machine_prefix(summary)
    if triage.severity is outward_severity:
        if not notes:
            return None
        return f"分诊结论：{notes[:max_chars]}"
    parts = [f"分诊严重级别 {triage.severity.value}"]
    if notes:
        parts.append(notes)
    body = "；".join(parts)
    return f"分诊快照：{body[:max_chars]}"


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
    "format_triage_decision_excerpt",
    "resolve_outward_severity",
    "should_flag_triage_risk_inconsistency",
    "strip_triage_machine_prefix",
    "triage_has_weak_classification_signal",
]
