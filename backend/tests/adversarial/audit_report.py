"""Build human-readable adversarial audit reports."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from app.models.enums import EventStatus, EventType, FinalVerdict, Severity

AdversarialAuditMode = Literal["analysis_only", "full_loop"]

_ANALYSIS_SCORED_CHECKS = frozenset(
    {
        "event_type_acceptable",
        "severity_at_least_minimum",
        "risk_score_at_least_minimum",
        "verdict_matches_expected",
        "reached_reporting",
    }
)
_FULL_LOOP_SCORED_CHECKS = _ANALYSIS_SCORED_CHECKS | frozenset({"closed_reached"})


@dataclass(frozen=True, slots=True)
class AdversarialAuditChecks:
    """Evaluation against ``GROUND_TRUTH``.

    Analysis-only audit treats mismatches as informative scores.  Production
    full-loop tests add hard gates on terminal status, report, disposition
    targets, and zero shim usage (ISSUE-203).

    In ``full_loop`` mode, ``closed_reached`` is a scored dimension and
    ``verdict_for_human`` cannot be release-grade PASS until CLOSED (ISSUE-319).
    """

    ground_truth: dict[str, Any]
    event_type: str | None
    severity: str | None
    risk_score: int | None
    final_verdict: str | None
    entities_found: list[str]
    indicators_found: list[str]
    report_excerpt: str
    triage_summary: str
    evidence_collection_status: str | None
    status_sequence: list[str]
    audit_mode: AdversarialAuditMode = "analysis_only"

    def __post_init__(self) -> None:
        if self.audit_mode not in {"analysis_only", "full_loop"}:
            raise ValueError(
                f"audit_mode must be 'analysis_only' or 'full_loop', got {self.audit_mode!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        gt = self.ground_truth
        acceptable_types = set(gt.get("acceptable_event_types") or [])
        min_risk = int(gt.get("minimum_risk_score") or 0)
        expected_verdict = str(gt.get("expected_verdict") or "")
        min_severity = str(gt.get("minimum_severity") or "medium")
        required_entities = list(gt.get("must_identify_entities") or [])
        required_indicators = list(gt.get("must_identify_indicators") or [])

        severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        actual_severity_rank = severity_rank.get(str(self.severity or "").lower(), 0)
        min_severity_rank = severity_rank.get(min_severity.lower(), 2)

        entity_hits = [e for e in required_entities if e in self.entities_found]
        indicator_hits = [i for i in required_indicators if i in self.indicators_found]

        closed_reached = EventStatus.CLOSED.value in self.status_sequence
        checks = {
            "event_type_acceptable": (
                self.event_type in acceptable_types if self.event_type else False
            ),
            "severity_at_least_minimum": actual_severity_rank >= min_severity_rank,
            "risk_score_at_least_minimum": (self.risk_score or 0) >= min_risk,
            "verdict_matches_expected": self.final_verdict == expected_verdict,
            "entities_identified": entity_hits,
            "entities_missing": [e for e in required_entities if e not in entity_hits],
            "indicators_identified": indicator_hits,
            "indicators_missing": [i for i in required_indicators if i not in indicator_hits],
            "reached_reporting": EventStatus.REPORTING.value in self.status_sequence,
        }
        if self.audit_mode == "full_loop":
            checks["closed_reached"] = closed_reached

        scored_keys = (
            _FULL_LOOP_SCORED_CHECKS if self.audit_mode == "full_loop" else _ANALYSIS_SCORED_CHECKS
        )
        scored_passed = sum(
            1 for key, value in checks.items() if key in scored_keys and value is True
        )
        analysis_passed = sum(
            1 for key, value in checks.items() if key in _ANALYSIS_SCORED_CHECKS and value is True
        )
        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "audit_mode": self.audit_mode,
            "ground_truth": gt,
            "observed": {
                "event_type": self.event_type,
                "severity": self.severity,
                "risk_score": self.risk_score,
                "final_verdict": self.final_verdict,
                "status_sequence": self.status_sequence,
                "triage_summary": self.triage_summary,
                "evidence_collection_status": self.evidence_collection_status,
                "report_excerpt": self.report_excerpt,
                "entities_found": self.entities_found,
                "indicators_found": self.indicators_found,
            },
            "checks": checks,
            "score": {
                "passed": scored_passed,
                "scored_dimensions": scored_passed,
                "total_dimensions": len(scored_keys),
                "analysis_passed": analysis_passed,
                "analysis_total_dimensions": len(_ANALYSIS_SCORED_CHECKS),
            },
            "verdict_for_human": _human_verdict(checks, audit_mode=self.audit_mode),
        }

    def write_json(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return path


def _human_verdict(
    checks: dict[str, Any],
    *,
    audit_mode: AdversarialAuditMode = "analysis_only",
) -> str:
    if audit_mode == "full_loop" and not checks.get("closed_reached"):
        if checks.get("reached_reporting") and checks.get("risk_score_at_least_minimum"):
            # Keep the token "PASS" out of FAIL text so greps / `"PASS" in verdict` stay clean.
            return (
                "FAIL — analysis criteria met but full loop did not reach CLOSED; not release-grade"
            )
        return "FAIL — full loop did not reach CLOSED"
    if not checks.get("reached_reporting"):
        return "FAIL — investigation did not reach reporting or missed critical signals"
    if checks.get("verdict_matches_expected") and checks.get("risk_score_at_least_minimum"):
        if audit_mode == "full_loop":
            return "PASS — full loop reached CLOSED with expected verdict and adequate risk score"
        return "PASS — agent flagged expected verdict with adequate risk score"
    if checks.get("risk_score_at_least_minimum"):
        return "PARTIAL — high risk detected but verdict/type may differ; review report"
    return "WEAK — pipeline completed but under-scored or wrong verdict"


def collect_entity_tokens(payload: Any) -> list[str]:
    """Flatten nested context payloads into searchable tokens."""
    tokens: list[str] = []

    def _walk(value: Any) -> None:
        if isinstance(value, str):
            stripped = value.strip()
            if stripped:
                tokens.append(stripped)
        elif isinstance(value, dict):
            for item in value.values():
                _walk(item)
        elif isinstance(value, list):
            for item in value:
                _walk(item)

    _walk(payload)
    return tokens


def normalize_enum(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (EventType, FinalVerdict, Severity)):
        return value.value
    return str(value)
