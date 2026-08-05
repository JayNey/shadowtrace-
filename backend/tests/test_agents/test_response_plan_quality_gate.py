"""Tests for response plan containment quality gate (ISSUE-198)."""

from __future__ import annotations

from dataclasses import dataclass

from app.agents.rules.response_plan_quality_gate import (
    CONTAINMENT_TOOLS,
    apply_containment_quality_gate,
    has_actionable_containment_targets,
    requires_threat_aligned_containment,
)
from app.models.agent_io import ResponsePlanGeneratedBy, RiskAssessment, ScoringMode
from app.models.entities import EntitySet, HostEntity, IPEntity
from app.models.enums import FinalVerdict, Severity


@dataclass
class _Candidate:
    tool_name: str
    target: str = ""


def _risk(*, score: int = 85, severity: Severity = Severity.HIGH) -> RiskAssessment:
    return RiskAssessment(
        risk_score=score,
        severity=severity,
        confidence=0.9,
        scoring_mode=ScoringMode.RULE_ONLY,
    )


def _entities_with_external_ip() -> EntitySet:
    return EntitySet(
        ips=[
            IPEntity(
                entity_id="ip-ext",
                address="198.51.100.44",
                scope="external",
            )
        ],
        hosts=[HostEntity(entity_id="host-1", hostname="victim-host-01")],
    )


def test_has_actionable_containment_targets_requires_known_entities() -> None:
    assert has_actionable_containment_targets(_entities_with_external_ip()) is True
    assert has_actionable_containment_targets(EntitySet()) is False


def test_requires_containment_for_confirmed_threat_with_entities() -> None:
    assert requires_threat_aligned_containment(
        severity=Severity.MEDIUM,
        risk_assessment=_risk(score=40, severity=Severity.MEDIUM),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=_entities_with_external_ip(),
        disposition_only=False,
    )


def test_requires_containment_false_for_false_positive() -> None:
    assert not requires_threat_aligned_containment(
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.FALSE_POSITIVE,
        entities=_entities_with_external_ip(),
        disposition_only=False,
    )


def test_apply_gate_falls_back_when_llm_leaves_only_ticket() -> None:
    llm_filtered = [
        _Candidate("create_ticket"),
    ]
    rule_filtered = [
        _Candidate("block_ip", "198.51.100.44"),
        _Candidate("create_ticket"),
    ]
    merged, generated_by, strategy = apply_containment_quality_gate(
        candidates=llm_filtered,
        rule_fallback_candidates=rule_filtered,
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM proposed candidate actions",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=_entities_with_external_ip(),
        disposition_only=False,
    )
    tool_names = {item.tool_name for item in merged}
    assert "block_ip" in tool_names
    assert generated_by is ResponsePlanGeneratedBy.TEMPLATE
    assert "containment_quality_gate" in strategy


def test_apply_gate_marks_unsatisfied_when_no_rule_containment() -> None:
    llm_filtered = [_Candidate("create_ticket")]
    merged, generated_by, strategy = apply_containment_quality_gate(
        candidates=llm_filtered,
        rule_fallback_candidates=[_Candidate("create_ticket")],
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM proposed candidate actions",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=_entities_with_external_ip(),
        disposition_only=False,
    )
    assert merged == llm_filtered
    assert generated_by is ResponsePlanGeneratedBy.TEMPLATE
    assert "containment_quality_gate_unsatisfied" in strategy


def test_apply_gate_noop_when_llm_already_has_containment() -> None:
    llm_filtered = [_Candidate("block_ip", "198.51.100.44")]
    rule_filtered = [_Candidate("isolate_host", "victim-host-01")]
    merged, generated_by, strategy = apply_containment_quality_gate(
        candidates=llm_filtered,
        rule_fallback_candidates=rule_filtered,
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM ok",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=_entities_with_external_ip(),
        disposition_only=False,
    )
    assert merged == llm_filtered
    assert generated_by is ResponsePlanGeneratedBy.LLM
    assert strategy == "LLM ok"


def test_containment_tools_cover_issue_scope() -> None:
    for tool in ("block_ip", "block_domain", "isolate_host", "disable_account"):
        assert tool in CONTAINMENT_TOOLS
