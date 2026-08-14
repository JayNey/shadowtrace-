"""Build human-readable adversarial audit reports.

Dynamic ``adversarial_audit`` pytest modules are excluded by pyproject addopts;
run them with ``-m adversarial_audit -o addopts=``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from app.models.agent_io import CollectionStatus
from app.models.enums import EventStatus, EventType, FinalVerdict, Severity
from app.models.evidence import SKIP_GAP_REASONS, skipped_entity_description

AdversarialAuditMode = Literal["analysis_only", "full_loop"]

# ISSUE-065 / ISSUE-347: informative only — never folded into scored PASS dimensions.
OUTPUT_QUALITY_PASS_THRESHOLD = 0.75
_EVAL_ERROR_REASON_PREFIX = "eval_error_defaulted"

_ANALYSIS_SCORED_CHECKS = frozenset(
    {
        "event_type_acceptable",
        "severity_at_least_minimum",
        "risk_score_at_least_minimum",
        "verdict_matches_expected",
        "reached_reporting",
    }
)
_FULL_LOOP_SCORED_CHECKS = _ANALYSIS_SCORED_CHECKS | frozenset(
    {"closed_reached", "evidence_collection_ok"}
)

_GENERIC_QUERY_DNS_SKIP_DESCRIPTION = skipped_entity_description("query_dns")


@dataclass(frozen=True, slots=True)
class AdversarialAuditChecks:
    """Evaluation against ``GROUND_TRUTH``.

    Analysis-only audit treats mismatches as informative scores.  Production
    full-loop tests add hard gates on terminal status, report, disposition
    targets, and zero shim usage (ISSUE-203).

    In ``full_loop`` mode, ``closed_reached`` is a scored dimension and
    ``verdict_for_human`` cannot be release-grade PASS until CLOSED (ISSUE-319).

    ``evidence_collection_ok`` is scored in ``full_loop`` only (ISSUE-346).
    Analysis-only keeps it unscored but annotates PARTIAL when collection is
    incomplete (failure-or-footnote, not a silent PASS). Surfaces
    ``collection_status=failed`` and mandatory ``query_dns`` skips at the
    certification layer without coupling ``MIN_EVIDENCE_SOURCES`` into
    ``validate_closed_gate`` (ISSUE-312).

    ``output_quality`` lives in the ``unscored`` bucket (ISSUE-347): visibility
    only, never a scored dimension and never wired into ``validate_closed_gate``.
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
    triage_severity: str | None = None
    audit_mode: AdversarialAuditMode = "analysis_only"
    evidence_gaps: list[dict[str, Any]] | None = None
    quality_scores: list[dict[str, Any]] | None = None
    output_quality_blocking: bool = False

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
        evidence_ok, evidence_detail = evaluate_evidence_collection_ok(
            collection_status=self.evidence_collection_status,
            gaps=self.evidence_gaps,
        )
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
            "evidence_collection_ok": evidence_ok,
            "evidence_collection_detail": evidence_detail,
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
        payload: dict[str, Any] = {
            "generated_at": datetime.now(UTC).isoformat(),
            "audit_mode": self.audit_mode,
            "ground_truth": gt,
            "observed": {
                "event_type": self.event_type,
                "severity": self.severity,
                "triage_severity": self.triage_severity,
                "risk_score": self.risk_score,
                "final_verdict": self.final_verdict,
                "status_sequence": self.status_sequence,
                "triage_summary": self.triage_summary,
                "evidence_collection_status": self.evidence_collection_status,
                "evidence_gaps": list(self.evidence_gaps or []),
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
            "unscored": {
                "output_quality": build_output_quality_unscored(
                    self.quality_scores,
                    output_quality_blocking=self.output_quality_blocking,
                ),
            },
        }
        return payload

    def write_json(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return path


def evaluate_evidence_collection_ok(
    *,
    collection_status: str | None,
    gaps: list[dict[str, Any]] | None = None,
) -> tuple[bool, dict[str, Any]]:
    """Certification-layer evidence floor (ISSUE-346).

    Independent of ``validate_closed_gate`` / ``MIN_EVIDENCE_SOURCES`` (ISSUE-312).
    """
    status = (collection_status or "").strip().lower()
    gap_list = list(gaps or [])
    dns_skips = _query_dns_skip_gaps(gap_list)
    expected_skips = [gap for gap in dns_skips if _is_expected_query_dns_skip(gap)]
    mandatory_skips = [gap for gap in dns_skips if gap not in expected_skips]

    failure_reasons: list[str] = []
    if status == CollectionStatus.FAILED.value:
        failure_reasons.append("collection_status_failed")
    if mandatory_skips:
        failure_reasons.append("mandatory_query_dns_skipped")

    ok = not failure_reasons
    return ok, {
        "collection_status": status or None,
        "query_dns_skips": dns_skips,
        "expected_query_dns_skips": expected_skips,
        "mandatory_query_dns_skips": mandatory_skips,
        "failure_reasons": failure_reasons,
    }


def _query_dns_skip_gaps(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for gap in gaps:
        detail = gap.get("detail") if isinstance(gap.get("detail"), dict) else {}
        tool_name = str(detail.get("tool_name") or gap.get("tool_name") or "")
        if tool_name != "query_dns":
            continue
        reason = str(gap.get("reason") or "")
        if reason not in SKIP_GAP_REASONS:
            continue
        hits.append(
            {
                "reason": reason,
                "missing_source": gap.get("missing_source"),
                "detail": detail,
            }
        )
    return hits


def _is_expected_query_dns_skip(gap: dict[str, Any]) -> bool:
    """ISSUE-338: IP-only / no FQDN inputs should not fail the scorecard."""
    if gap.get("reason") != "source_skipped":
        return False
    detail = gap.get("detail") if isinstance(gap.get("detail"), dict) else {}
    description = str(detail.get("description") or "").strip()
    return description == _GENERIC_QUERY_DNS_SKIP_DESCRIPTION


def coerce_quality_scores(raw: Any) -> list[dict[str, Any]]:
    """Normalize WorkingMemory ``quality_scores`` payloads for audit reports."""
    if not isinstance(raw, list):
        return []
    return [entry for entry in raw if isinstance(entry, dict)]


def build_output_quality_unscored(
    quality_scores: list[dict[str, Any]] | None,
    *,
    output_quality_blocking: bool = False,
) -> dict[str, Any]:
    """Summarize OutputQuality scores for adversarial visibility (ISSUE-347).

    Lives in the ``unscored`` bucket: does not affect ``verdict_for_human`` or
    scored dimensions, and must not be wired into ``validate_closed_gate``.
    """
    agents: dict[str, Any] = {}
    eval_error_agents: list[str] = []
    passing = 0
    scores: list[float] = []

    for item in quality_scores or []:
        if not isinstance(item, dict):
            continue
        agent_name = str(item.get("agent_name") or "").strip()
        if not agent_name:
            continue
        raw_score = item.get("score", 0.0)
        try:
            score = round(float(raw_score), 4)
        except (TypeError, ValueError):
            score = 0.0
        verdict = str(item.get("verdict") or "")
        reasons = item.get("reasons") if isinstance(item.get("reasons"), list) else []
        eval_error = any(
            isinstance(reason, str) and reason.startswith(_EVAL_ERROR_REASON_PREFIX)
            for reason in reasons
        )
        if eval_error:
            eval_error_agents.append(agent_name)
        agents[agent_name] = {
            "score": score,
            "verdict": verdict,
            "metrics": item.get("metrics") if isinstance(item.get("metrics"), dict) else {},
            "evaluated_by": item.get("evaluated_by"),
            "eval_error": eval_error,
            "reasons": [str(reason) for reason in reasons[:5]],
        }
        scores.append(score)
        if verdict == "pass":
            passing += 1

    return {
        "present": bool(agents),
        "pass_threshold": OUTPUT_QUALITY_PASS_THRESHOLD,
        "blocking_profile": output_quality_blocking,
        "agents": agents,
        "summary": {
            "agents_evaluated": len(agents),
            "agents_passing": passing,
            "minimum_score": min(scores) if scores else None,
            "eval_error_agents": eval_error_agents,
        },
    }


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
    if audit_mode == "full_loop" and not checks.get("evidence_collection_ok", True):
        if checks.get("closed_reached") and checks.get("risk_score_at_least_minimum"):
            return (
                "FAIL — full loop reached CLOSED but evidence collection incomplete; "
                "not release-grade"
            )
        return "FAIL — evidence collection incomplete"
    if checks.get("verdict_matches_expected") and checks.get("risk_score_at_least_minimum"):
        if not checks.get("evidence_collection_ok", True):
            return (
                "PARTIAL — expected verdict but evidence collection incomplete "
                "(see evidence_collection_ok)"
            )
        if audit_mode == "full_loop":
            return "PASS — full loop reached CLOSED with expected verdict and adequate risk score"
        return "PASS — agent flagged expected verdict with adequate risk score"
    if checks.get("risk_score_at_least_minimum"):
        return "PARTIAL — high risk detected but verdict/type may differ; review report"
    return "WEAK — pipeline completed but under-scored or wrong verdict"


def normalize_enum(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (EventType, FinalVerdict, Severity)):
        return value.value
    return str(value)


def resolve_observed_severity(
    *,
    risk_ctx: dict[str, Any] | None,
    event_severity: Any,
    triage_ctx: dict[str, Any] | None = None,
) -> tuple[str | None, str | None]:
    """Outward severity for audit scorecards (ISSUE-330).

    Returns ``(outward_severity, triage_severity)``.  Outward severity prefers
    ``risk_assessment.severity``, then the event row.  Triage severity is returned
    separately for transparency and must never be used as a silent fallback.
    """
    outward: str | None = None
    if isinstance(risk_ctx, dict):
        outward = normalize_enum(risk_ctx.get("severity"))
    if outward is None:
        outward = normalize_enum(event_severity)
    triage_severity = (
        normalize_enum(triage_ctx.get("severity")) if isinstance(triage_ctx, dict) else None
    )
    return outward, triage_severity
