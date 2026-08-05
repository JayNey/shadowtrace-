"""Agent-level scenario_id routing tests (ISSUE-199)."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from app.agents.report_agent import ReportAgent
from app.agents.report_section_builder import SECTION_KEYS
from app.agents.response_agent import ResponseAgent
from app.agents.risk_agent import RiskAgent
from app.agents.triage_agent import TriageAgent
from app.core.llm.base import LLMMessage, LLMResponse
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    ReportAgentInput,
    ResponseAgentInput,
    RiskAgentInput,
    RiskAssessment,
    ScoringMode,
    TriageAgentInput,
    TriageResult,
)
from app.models.entities import EntitySet
from app.models.enums import EventType, FinalVerdict, Severity
from app.models.report import ReportSection


class _ScenarioCapturingLLM:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def chat(
        self,
        messages: list[LLMMessage],
        *,
        event_id: str,
        agent_name: str,
        prompt_key: str,
        scenario_id: str | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        del messages, kwargs
        self.calls.append(
            {
                "event_id": event_id,
                "agent_name": agent_name,
                "prompt_key": prompt_key,
                "scenario_id": scenario_id,
            }
        )
        if prompt_key == "triage_extract":
            content = (
                '{"entities":{"accounts":[],"hosts":[],"ips":[],"domains":[],'
                '"processes":[],"files":[]},"decision_summary":"ok"}'
            )
        elif prompt_key == "response_plan":
            content = json.dumps(
                {
                    "actions": [
                        {
                            "tool_name": "create_ticket",
                            "target_type": "ticket",
                            "target": "ticket",
                            "parameters": {},
                            "reason": "track",
                        }
                    ],
                    "strategy_summary": "test plan",
                }
            )
        elif prompt_key == "report_generate":
            content = json.dumps(
                {
                    "title": "Test report",
                    "summary": "Summary",
                    "sections": {key: f"{key} body" for key in SECTION_KEYS},
                }
            )
        else:
            content = (
                '{"factors":{"asset_impact":{"score":70,"reason":"test"},'
                '"behavior_anomaly":{"score":70,"reason":"test"},'
                '"evidence_confidence":{"score":70,"reason":"test"},'
                '"attack_stage":{"score":70,"reason":"test"},'
                '"data_sensitivity":{"score":70,"reason":"test"},'
                '"threat_intel":{"score":70,"reason":"test"}},'
                '"raw_confidence":0.8}'
            )
        return LLMResponse(
            content=content,
            model_name="mock",
            prompt_tokens=1,
            completion_tokens=1,
            total_tokens=2,
            latency_ms=1,
            fallback_level=2,
        )


class _FakeWorkingMemory:
    def __init__(self, values: dict[tuple[str, str], Any]) -> None:
        self.values = values

    async def read(self, event_id: str, key: str) -> Any:
        return self.values.get((event_id, key))

    async def write(self, event_id: str, key: str, value: Any) -> None:
        self.values[(event_id, key)] = value

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        del event_id, note


def _bound_wm(values: dict[tuple[str, str], Any]) -> Any:
    store = _FakeWorkingMemory(values)

    class _Bound:
        async def read(self, event_id: str, key: str) -> Any:
            return await store.read(event_id, key)

        async def write(self, event_id: str, key: str, value: Any) -> None:
            await store.write(event_id, key, value)

        async def append_scratchpad(self, event_id: str, note: str) -> None:
            await store.append_scratchpad(event_id, note)

    bound = _Bound()
    bound.for_writer = lambda _name: bound  # type: ignore[attr-defined]
    return bound


def _risk() -> RiskAssessment:
    return RiskAssessment(
        risk_score=80,
        severity=Severity.HIGH,
        confidence=0.9,
        scoring_mode=ScoringMode.RULE_ONLY,
    )


@pytest.mark.asyncio
async def test_triage_agent_passes_event_scenario_not_insider_default() -> None:
    llm = _ScenarioCapturingLLM()
    wm = _FakeWorkingMemory(
        {
            (
                "evt-host",
                "source_snapshot",
            ): {"normalized": {"scenario": "host_compromise"}},
        }
    )

    class _BoundWM:
        async def read(self, event_id: str, key: str) -> Any:
            return await wm.read(event_id, key)

        async def write(self, event_id: str, key: str, value: Any) -> None:
            await wm.write(event_id, key, value)

        async def append_scratchpad(self, event_id: str, note: str) -> None:
            await wm.append_scratchpad(event_id, note)

    agent = TriageAgent(llm_client=llm, working_memory=_BoundWM())
    await agent._run(
        TriageAgentInput(
            event_id="evt-host",
            raw_event_summary="Suspicious lateral activity on host srv-01",
            hint_entities=EntitySet(),
        )
    )

    assert llm.calls
    assert llm.calls[0]["scenario_id"] == "host_compromise"
    assert llm.calls[0]["scenario_id"] != "insider_data_exfiltration"


@pytest.mark.asyncio
async def test_risk_agent_passes_event_scenario_from_source_snapshot() -> None:
    llm = _ScenarioCapturingLLM()
    agent = RiskAgent(llm_client=llm, working_memory=_bound_wm({}))
    await agent._score_with_llm(
        RiskAgentInput(
            event_id="evt-other",
            triage_result=TriageResult(
                event_type=EventType.OTHER,
                severity=Severity.MEDIUM,
                need_investigation=True,
                entities=EntitySet(),
            ),
            evidence_output=EvidenceOutput(
                evidence_list=[],
                overall_confidence=0.5,
                collection_status=CollectionStatus.COMPLETED,
            ),
        ),
        source_snapshot={"normalized": {"scenario": "host_compromise"}},
    )

    assert llm.calls[0]["scenario_id"] == "host_compromise"
    assert llm.calls[0]["scenario_id"] != "insider_data_exfiltration"


@pytest.mark.asyncio
async def test_risk_agent_without_context_uses_none_scenario_id() -> None:
    llm = _ScenarioCapturingLLM()
    agent = RiskAgent(llm_client=llm, working_memory=_bound_wm({}))
    await agent._score_with_llm(
        RiskAgentInput(
            event_id="evt-other",
            triage_result=TriageResult(
                event_type=EventType.OTHER,
                severity=Severity.MEDIUM,
                need_investigation=True,
                entities=EntitySet(),
            ),
            evidence_output=EvidenceOutput(
                evidence_list=[],
                overall_confidence=0.5,
                collection_status=CollectionStatus.COMPLETED,
            ),
        ),
        source_snapshot=None,
    )

    assert llm.calls[0]["scenario_id"] is None
    assert llm.calls[0]["scenario_id"] != "insider_data_exfiltration"


@pytest.mark.asyncio
async def test_response_agent_passes_event_scenario_from_source_snapshot() -> None:
    llm = _ScenarioCapturingLLM()
    event_id = "evt-response-scenario"
    wm = _FakeWorkingMemory(
        {
            (event_id, "source_snapshot"): {"normalized": {"scenario": "host_compromise"}},
        }
    )
    agent = ResponseAgent(llm_client=llm, working_memory=wm)
    await agent._generate_with_llm(
        input=ResponseAgentInput(
            event_id=event_id,
            risk_assessment=_risk(),
            evidence_output=EvidenceOutput(
                evidence_list=[],
                collection_status=CollectionStatus.COMPLETED,
                overall_confidence=0.8,
            ),
        ),
        triage=TriageResult(
            event_type=EventType.DATA_EXFILTRATION,
            severity=Severity.HIGH,
            need_investigation=True,
            entities=EntitySet(),
        ),
        entities=EntitySet(),
    )

    assert llm.calls[0]["prompt_key"] == "response_plan"
    assert llm.calls[0]["scenario_id"] == "host_compromise"
    assert llm.calls[0]["scenario_id"] != "insider_data_exfiltration"


@pytest.mark.asyncio
async def test_response_agent_falls_back_to_event_raw_alert_snapshot() -> None:
    llm = _ScenarioCapturingLLM()
    event_id = "evt-response-raw-alert"

    class _EventService:
        async def get_event(self, _event_id: str) -> Any:
            return SimpleNamespace(
                raw_alert_snapshot={"scenario": "malicious_process"},
            )

    agent = ResponseAgent(
        llm_client=llm,
        working_memory=_FakeWorkingMemory({}),
        event_service=_EventService(),
    )
    await agent._generate_with_llm(
        input=ResponseAgentInput(
            event_id=event_id,
            risk_assessment=_risk(),
        ),
        triage=TriageResult(
            event_type=EventType.MALICIOUS_PROCESS,
            severity=Severity.HIGH,
            need_investigation=True,
            entities=EntitySet(),
        ),
        entities=EntitySet(),
    )

    assert llm.calls[0]["scenario_id"] == "malicious_process"


@pytest.mark.asyncio
async def test_report_agent_passes_event_scenario_from_source_snapshot() -> None:
    llm = _ScenarioCapturingLLM()
    agent = ReportAgent(llm_client=llm)
    await agent._generate_with_llm(
        input=ReportAgentInput(
            event_id="evt-report-scenario",
            evidence_output=EvidenceOutput(
                evidence_list=[],
                collection_status=CollectionStatus.COMPLETED,
                overall_confidence=0.8,
            ),
            risk_assessment=_risk(),
        ),
        triage=TriageResult(
            event_type=EventType.OTHER,
            severity=Severity.HIGH,
            need_investigation=True,
            entities=EntitySet(),
        ),
        draft_sections=[ReportSection(key="overview", title="Overview", content="draft")],
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        rag=None,
        source_snapshot={"normalized": {"scenario": "host_compromise"}},
    )

    assert llm.calls[0]["prompt_key"] == "report_generate"
    assert llm.calls[0]["scenario_id"] == "host_compromise"
    assert llm.calls[0]["scenario_id"] != "insider_data_exfiltration"
