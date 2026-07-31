"""Tests for regex entity extraction and semantic validation (ISSUE-100 / #603)."""

from __future__ import annotations

import time

import pytest

from app.agents.evidence_agent import EvidenceAgent
from app.agents.rules.entity_extraction_rules import extract_entities_regex
from app.agents.rules.entity_validation import validate_entity_set, validate_host_entity
from app.agents.triage_agent import TriageAgent
from app.core.llm.base import LLMResponse
from app.models.agent_io import TriageResult
from app.models.entities import EntitySet, HostEntity
from app.models.enums import EventType, Severity
from tests.test_agents.test_triage_agent import (
    _make_input,
    _MockBoundWorkingMemory,
    _MockLLMClient,
)

# --------------------------------------------------------------------------- #
# Positive hostname extraction
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("alert_text", "expected_host"),
    [
        ("Host DEV-WKS-012 compromised", "DEV-WKS-012"),
        ("PC-FIN-023 uploaded sensitive data", "PC-FIN-023"),
        ("Malicious process on db01 detected", "db01"),
        ("workstation ip-10-0-0-4 seen in logs", "ip-10-0-0-4"),
        ("endpoint ubuntu-prod-01 restarted", "ubuntu-prod-01"),
        ("activity on web-01-prod detected", "web-01-prod"),
    ],
)
def test_positive_hostname_extraction(alert_text: str, expected_host: str) -> None:
    extracted = extract_entities_regex(alert_text)
    assert expected_host in extracted.hostnames


def test_ransomware_like_title_produces_no_hostname() -> None:
    alert = "Malicious process spawned — ransomware-like behavior"
    extracted = extract_entities_regex(alert)
    assert extracted.hostnames == []
    validated = validate_entity_set(
        EntitySet(hosts=[HostEntity(entity_id="h1", hostname="ransomware-like")]),
        provenance="regex",
        alert_text=alert,
    )
    assert validated.entity_set.hosts == []


# --------------------------------------------------------------------------- #
# Negative natural-language samples (≥20)
# --------------------------------------------------------------------------- #

_NEGATIVE_PHRASES: tuple[str, ...] = (
    "Malicious process spawned — ransomware-like behavior",
    "persistent beacon detected on endpoint",
    "lateral movement observed across network",
    "suspicious activity observed in environment",
    "behavior detected on endpoint",
    "like pattern observed during scan",
    "stage chain attempt blocked",
    "unknown anomaly flagged by sensor",
    "malicious activity related to download",
    "suspicious process-based execution chain",
    "credential-based attack attempt detected",
    "data exfiltration-like behavior observed",
    "command-and-control-like traffic pattern",
    "file-less attack stage detected",
    "multi-stage ransomware-like campaign",
    "beacon-like communication detected",
    "policy violation related to upload",
    "anomaly chain detected by analytics",
    "suspicious lateral-movement pattern",
    "unknown threat-like indicator observed",
    "persistent-beacon style activity noted",
    "behavior-based detection triggered",
    "attack stage3 detected",
    "level2 alert triggered",
    "phase1 complete",
)


@pytest.mark.parametrize("phrase", _NEGATIVE_PHRASES)
def test_negative_samples_no_hostname_false_positives(phrase: str) -> None:
    extracted = extract_entities_regex(phrase)
    assert extracted.hostnames == []
    validated = validate_entity_set(
        EntitySet(
            hosts=[
                HostEntity(entity_id=f"h{i}", hostname=h)
                for i, h in enumerate(extracted.hostnames, 1)
            ]
        ),
        provenance="regex",
        alert_text=phrase,
    )
    assert validated.entity_set.hosts == []


@pytest.mark.parametrize("phrase", _NEGATIVE_PHRASES)
def test_negative_samples_reject_injected_llm_phrase_hostnames(phrase: str) -> None:
    for hostname in ("ransomware-like", "beacon-like", "lateral-movement"):
        result = validate_entity_set(
            EntitySet(hosts=[HostEntity(entity_id="h1", hostname=hostname)]),
            provenance="llm",
            alert_text=phrase,
        )
        assert result.entity_set.hosts == []


# --------------------------------------------------------------------------- #
# LLM + regex share validator
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("hostname", "provenance"),
    [
        ("ransomware-like", "regex"),
        ("ransomware-like", "llm"),
    ],
)
def test_llm_and_regex_reject_same_invalid_hostname(hostname: str, provenance: str) -> None:
    alert = "Malicious process spawned — ransomware-like behavior"
    entities = EntitySet(hosts=[HostEntity(entity_id="h1", hostname=hostname)])
    result = validate_entity_set(entities, provenance=provenance, alert_text=alert)  # type: ignore[arg-type]
    assert result.entity_set.hosts == []
    assert result.rejection_summary["total_rejected"] == 1


@pytest.mark.asyncio
async def test_llm_invalid_entities_fall_back_to_validated_regex() -> None:
    from app.agents.prompts.triage_prompt import TriageLLMResponse

    llm_entities = EntitySet(hosts=[HostEntity(entity_id="bad", hostname="ransomware-like")])
    llm_response = LLMResponse(
        content="",
        parsed=TriageLLMResponse(
            event_type=EventType.MALICIOUS_PROCESS,
            entities=llm_entities,
            reasoning="",
        ),
        model_name="mock",
    )
    wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
    agent = TriageAgent(llm_client=_MockLLMClient(response=llm_response), working_memory=wm)
    alert = "Malicious process spawned — ransomware-like behavior"
    extraction = await agent._extract_entities(alert, "evt-100")
    assert extraction.llm_entities == EntitySet()
    assert extraction.regex_entities.hosts == []
    assert extraction.text_degraded is True
    assert extraction.rejection_summary.get("total_rejected", 0) >= 1


# --------------------------------------------------------------------------- #
# EvidenceAgent skips rejected / missing host entities
# --------------------------------------------------------------------------- #


def test_evidence_skips_query_edr_when_no_host_entity() -> None:
    agent = EvidenceAgent(llm_client=None, tool_executor=None)
    triage = TriageResult(
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.HIGH,
        need_investigation=True,
        entities=EntitySet(),
    )
    params = agent._build_params(
        "query_edr_process",
        triage.entities,
        {"start": "2024-01-01T00:00:00Z", "end": "2024-01-02T00:00:00Z"},
    )
    assert params is None


def test_llm_rejects_phrase_hostname_when_alert_mentions_endpoint() -> None:
    alert = "persistent beacon detected on endpoint"
    for hostname in ("beacon-like", "persistent-beacon", "lateral-movement"):
        result = validate_entity_set(
            EntitySet(hosts=[HostEntity(entity_id="h1", hostname=hostname)]),
            provenance="llm",
            alert_text=alert,
        )
        assert result.entity_set.hosts == []


def test_llm_rejects_ransomware_like_even_when_dev_wks_in_alert() -> None:
    alert = "Malicious process spawned — ransomware-like behavior on DEV-WKS-012"
    result = validate_entity_set(
        EntitySet(
            hosts=[
                HostEntity(entity_id="bad", hostname="ransomware-like"),
                HostEntity(entity_id="good", hostname="DEV-WKS-012"),
            ]
        ),
        provenance="llm",
        alert_text=alert,
    )
    hostnames = {h.hostname for h in result.entity_set.hosts}
    assert "ransomware-like" not in hostnames
    assert "DEV-WKS-012" in hostnames


@pytest.mark.asyncio
async def test_triage_keeps_valid_host_when_llm_also_returns_phrase_hostname() -> None:
    from app.agents.prompts.triage_prompt import TriageLLMResponse

    llm_entities = EntitySet(
        hosts=[
            HostEntity(entity_id="bad", hostname="ransomware-like"),
            HostEntity(entity_id="good", hostname="DEV-WKS-012"),
        ]
    )
    llm_response = LLMResponse(
        content="",
        parsed=TriageLLMResponse(
            event_type=EventType.MALICIOUS_PROCESS,
            entities=llm_entities,
            reasoning="",
        ),
        model_name="mock",
    )
    wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
    agent = TriageAgent(llm_client=_MockLLMClient(response=llm_response), working_memory=wm)
    alert = "Malicious process spawned — ransomware-like behavior on DEV-WKS-012"
    result = await agent._run(_make_input(raw_event_summary=alert))
    hostnames = {h.hostname for h in result.entities.hosts}
    assert "ransomware-like" not in hostnames
    assert "DEV-WKS-012" in hostnames
    assert result.entity_rejection_summary.get("total_rejected", 0) >= 1


@pytest.mark.asyncio
async def test_triage_entity_rejection_summary_counts_llm_rejections() -> None:
    from app.agents.prompts.triage_prompt import TriageLLMResponse

    llm_entities = EntitySet(hosts=[HostEntity(entity_id="bad", hostname="ransomware-like")])
    llm_response = LLMResponse(
        content="",
        parsed=TriageLLMResponse(
            event_type=EventType.MALICIOUS_PROCESS,
            entities=llm_entities,
            reasoning="",
        ),
        model_name="mock",
    )
    wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
    agent = TriageAgent(llm_client=_MockLLMClient(response=llm_response), working_memory=wm)
    alert = "Malicious process spawned — ransomware-like behavior"
    result = await agent._run(_make_input(raw_event_summary=alert))
    assert result.entity_rejection_summary.get("total_rejected", 0) >= 1
    assert "phrase_without_host_context" in result.entity_rejection_summary.get(
        "rejection_counts", {}
    )


def test_decision_basis_includes_entity_rejection_summary() -> None:
    from app.services.agent_trace_service import TraceProjection

    result = TriageResult(
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.HIGH,
        need_investigation=True,
        entity_rejection_summary={
            "rejection_counts": {"phrase_without_host_context": 1},
            "total_rejected": 1,
        },
    )
    basis = TraceProjection.decision_basis(result.model_dump(mode="json"))
    assert basis["entity_rejection_summary"]["total_rejected"] == 1


@pytest.mark.asyncio
async def test_triage_ransomware_title_no_edr_host_id() -> None:
    llm_response = LLMResponse(content="", parsed=None, model_name="mock")
    wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
    agent = TriageAgent(llm_client=_MockLLMClient(response=llm_response), working_memory=wm)
    alert = "Malicious process spawned — ransomware-like behavior"
    result = await agent._run(_make_input(raw_event_summary=alert))
    assert not result.entities.hosts
    evidence = EvidenceAgent(llm_client=None, tool_executor=None)
    params = evidence._build_params(
        "query_edr_process",
        result.entities,
        {"start": "2024-01-01T00:00:00Z", "end": "2024-01-02T00:00:00Z"},
    )
    assert params is None


# --------------------------------------------------------------------------- #
# Performance / regex safety (no fragile millisecond gate)
# --------------------------------------------------------------------------- #


def test_validator_completes_on_4kb_alert_without_catastrophic_cost() -> None:
    base = "Malicious process spawned — ransomware-like behavior. "
    alert = (base * 200)[:4096]
    assert len(alert) >= 4000

    started = time.perf_counter()
    for _ in range(50):
        extracted = extract_entities_regex(alert)
        validate_entity_set(
            EntitySet(
                hosts=[
                    HostEntity(entity_id=f"h{i}", hostname=h)
                    for i, h in enumerate(extracted.hostnames, 1)
                ]
            ),
            provenance="regex",
            alert_text=alert,
        )
    elapsed = time.perf_counter() - started
    # CI-stable: 50 passes over 4KB should finish quickly; avoid fixed per-call ms threshold.
    assert elapsed < 2.0


@pytest.mark.parametrize(
    "phrase",
    [
        "attack stage3 detected",
        "level2 alert triggered",
        "phase1 complete",
    ],
)
def test_alert_short_tokens_never_extracted_as_hostnames(phrase: str) -> None:
    assert extract_entities_regex(phrase).hostnames == []


def test_vm_contextual_low_confidence_hostname_accepted() -> None:
    extracted = extract_entities_regex("vm myserver compromised")
    assert "myserver" in extracted.hostnames


@pytest.mark.asyncio
async def test_triage_reasoning_splits_source_and_text_rejections() -> None:
    from app.models.entities import AccountEntity

    wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
    agent = TriageAgent(
        llm_client=_MockLLMClient(
            response=LLMResponse(content="", parsed=None, model_name="mock"),
        ),
        working_memory=wm,
    )
    hint = EntitySet(
        accounts=[AccountEntity(entity_id="bad", username="not a valid user!")],
    )
    alert = "Malicious process spawned — ransomware-like behavior"
    result = await agent._run(_make_input(raw_event_summary=alert, hint_entities=hint))
    assert "invalid source entity candidate(s)" in result.decision_summary
    assert result.entity_rejection_summary.get("total_rejected", 0) >= 1


def test_validate_host_entity_api() -> None:
    ok, reason = validate_host_entity(
        "DEV-WKS-012",
        provenance="regex",
        alert_text="Host DEV-WKS-012 compromised",
    )
    assert ok is True
    assert reason == ""

    ok, reason = validate_host_entity(
        "ransomware-like",
        provenance="regex",
        alert_text="Malicious process spawned — ransomware-like behavior",
    )
    assert ok is False
    assert reason == "phrase_without_host_context"
