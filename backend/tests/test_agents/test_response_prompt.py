"""Response prompt packing tests (ISSUE-326 / #957)."""

from __future__ import annotations

import json

from app.agents.prompts.response_prompt import build_response_plan_messages
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    RiskAssessment,
    ScoringMode,
    TriageResult,
)
from app.models.enums import EventType, EvidenceSource, Severity
from app.models.evidence import Evidence


def _risk() -> RiskAssessment:
    return RiskAssessment(
        risk_score=72,
        severity=Severity.HIGH,
        confidence=0.8,
        risk_factors=[],
        scoring_mode=ScoringMode.RULE_ONLY,
    )


def test_response_user_payload_includes_decision_summary_when_reasoning_empty() -> None:
    triage = TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        reasoning="",
        decision_summary="Coordinated data exfiltration to external staging host.",
    )
    evidence = EvidenceOutput(
        evidence_list=[
            Evidence(
                evidence_id="ev-1",
                event_id="evt-test",
                source=EvidenceSource.NETWORK_FLOW,
                evidence_type="flow",
                description="Large HTTPS upload to 203.0.113.88",
                confidence=0.92,
            )
        ],
        collection_status=CollectionStatus.COMPLETED,
        overall_confidence=0.9,
        success_sources=["network_flow"],
        failed_sources=["endpoint_telemetry"],
    )
    messages = build_response_plan_messages(
        triage_result=triage,
        risk_assessment=_risk(),
        evidence_output=evidence,
        available_tools=["create_ticket"],
        entities_summary={},
    )
    payload = json.loads(messages[1].content.split("Context:\n", 1)[1])
    assert payload["decision_summary"] == "Coordinated data exfiltration to external staging host."
    assert payload["triage_reasoning"] == ""
    assert payload["evidence"]["success_sources"] == ["network_flow"]
    assert payload["evidence"]["failed_sources"] == ["endpoint_telemetry"]
    assert payload["evidence"]["sample"][0]["description"] == "Large HTTPS upload to 203.0.113.88"


def test_response_decision_summary_truncated_to_512_chars() -> None:
    long_summary = "x" * 600
    triage = TriageResult.model_construct(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=False,
        reasoning="",
        decision_summary=long_summary,
    )
    messages = build_response_plan_messages(
        triage_result=triage,
        risk_assessment=_risk(),
        evidence_output=None,
        available_tools=["create_ticket"],
        entities_summary={},
    )
    payload = json.loads(messages[1].content.split("Context:\n", 1)[1])
    assert len(payload["decision_summary"]) == 512
    assert payload["decision_summary"] == long_summary[:512]
