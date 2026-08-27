"""Risk prompt packing tests (ISSUE-326 / #957)."""

from __future__ import annotations

import json

from app.agents.prompts.risk_prompt import build_risk_messages
from app.models.agent_io import CollectionStatus, EvidenceOutput, TriageResult
from app.models.enums import EventType, EvidenceSource, Severity
from app.models.evidence import Evidence


def test_risk_payload_includes_decision_summary_when_reasoning_empty() -> None:
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
    messages = build_risk_messages(triage_result=triage, evidence_output=evidence)
    payload = json.loads(messages[1].content.split("Context:\n", 1)[1])
    triage_block = payload["triage"]
    assert (
        triage_block["decision_summary"]
        == "Coordinated data exfiltration to external staging host."
    )
    assert triage_block["reasoning"] == ""
    assert payload["evidence"]["success_sources"] == ["network_flow"]
    assert payload["evidence"]["failed_sources"] == ["endpoint_telemetry"]
    sample = payload["evidence"]["sample"][0]
    assert sample["description"] == "Large HTTPS upload to 203.0.113.88"
    assert sample["source"] == EvidenceSource.NETWORK_FLOW.value
    assert sample["evidence_type"] == "flow"
    assert sample["confidence"] == 0.92
    assert "rubrics" in payload
    assert set(payload["rubrics"]) == {
        "asset_impact",
        "behavior_anomaly",
        "evidence_confidence",
        "attack_stage",
        "data_sensitivity",
        "threat_intel",
    }
    assert len(payload["rubrics"]["attack_stage"]) == 5
    assert "rubric_id" in messages[0].content
    assert "Do not invent a 0-100 score" in messages[0].content


def test_risk_decision_summary_truncated_to_512_chars() -> None:
    long_summary = "y" * 600
    triage = TriageResult.model_construct(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=False,
        reasoning="legacy cot should not be primary",
        decision_summary=long_summary,
    )
    evidence = EvidenceOutput(
        evidence_list=[],
        collection_status=CollectionStatus.PARTIAL_DONE,
        overall_confidence=0.1,
    )
    messages = build_risk_messages(triage_result=triage, evidence_output=evidence)
    payload = json.loads(messages[1].content.split("Context:\n", 1)[1])
    assert len(payload["triage"]["decision_summary"]) == 512
    assert payload["triage"]["decision_summary"] == long_summary[:512]
    assert payload["triage"]["reasoning"] == "legacy cot should not be primary"[:500]


def test_risk_empty_decision_summary_and_reasoning() -> None:
    triage = TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=False,
        reasoning="",
        decision_summary="",
    )
    evidence = EvidenceOutput(
        evidence_list=[],
        collection_status=CollectionStatus.PARTIAL_DONE,
        overall_confidence=0.1,
    )
    messages = build_risk_messages(triage_result=triage, evidence_output=evidence)
    payload = json.loads(messages[1].content.split("Context:\n", 1)[1])
    assert payload["triage"]["decision_summary"] == ""
    assert payload["triage"]["reasoning"] == ""
    assert payload["evidence"]["sample"] == []


def test_risk_reasoning_none_coerced_to_empty_string() -> None:
    triage = TriageResult.model_construct(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=False,
        reasoning=None,
        decision_summary="kept",
    )
    evidence = EvidenceOutput(
        evidence_list=[],
        collection_status=CollectionStatus.PARTIAL_DONE,
        overall_confidence=0.1,
    )
    messages = build_risk_messages(triage_result=triage, evidence_output=evidence)
    payload = json.loads(messages[1].content.split("Context:\n", 1)[1])
    assert payload["triage"]["decision_summary"] == "kept"
    assert payload["triage"]["reasoning"] == ""
