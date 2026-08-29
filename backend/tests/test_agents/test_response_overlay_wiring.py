"""Layer 8a: overlay copy is held by ResponseAgent and shared with Filter/materialize."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from app.adapters.sangfor.capability_manifest import (
    build_sangfor_capability_manifest,
    response_agent_overrides_for_kind,
)
from app.adapters.sangfor.capability_overlay import (
    SANGFOR_ADAPTER_KIND,
    SangforDevice,
    SangforOverlayConfig,
    apply_capability_overlay,
)
from app.agents.response_agent import (
    ActionCandidate,
    ResponseAgent,
    ResponsePolicyFilter,
    build_mock_capability_manifest,
)
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    ResponseAgentInput,
    RiskAssessment,
    RiskFactor,
    ScoringMode,
    TriageResult,
)
from app.models.entities import AccountEntity, EntitySet, HostEntity, IPEntity
from app.models.enums import (
    ActionStatus,
    DispositionPolicy,
    EventType,
    ExecutionOwner,
    FinalVerdict,
    Severity,
    SourceObjectKind,
    WritebackReadiness,
)
from app.models.source import SourceReference
from app.tools.specs import baseline_tool_index

_RESPONSE_AGENT_SRC = (
    Path(__file__).resolve().parents[2] / "app" / "agents" / "response_agent.py"
)


class _FakeWorkingMemory:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], Any] = {}

    async def read(self, event_id: str, key: str) -> Any:
        return self.values.get((event_id, key))

    async def write(self, event_id: str, key: str, value: Any) -> None:
        self.values[(event_id, key)] = value

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        return None


class _FakeEventService:
    def __init__(self) -> None:
        self.disposition_policy = DispositionPolicy.REQUIRED
        self.final_verdict = FinalVerdict.NONE

    async def get_event(self, event_id: str) -> Any:
        return SimpleNamespace(
            event_id=event_id,
            disposition_policy=self.disposition_policy,
            final_verdict=self.final_verdict,
            creation_source_ref=SourceReference(
                source_kind=SourceObjectKind.INCIDENT,
                source_product="mock_xdr",
                source_tenant_id="tenant-1",
                connector_id="conn-mock",
                source_object_id="INC-001",
            ),
        )


class _FailingLLM:
    async def chat(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("llm unavailable")


def _ref() -> SourceReference:
    return SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-1",
        connector_id="conn-mock",
        source_object_id="INC-001",
        ingested_at=datetime.now(UTC),
    )


def _entities() -> EntitySet:
    return EntitySet(
        accounts=[
            AccountEntity(entity_id="acct-1", username="svc-backup", source_refs=[_ref()]),
        ],
        hosts=[HostEntity(entity_id="host-1", hostname="PC-FIN-023", source_refs=[_ref()])],
        ips=[
            IPEntity(
                entity_id="ip-ext",
                address="203.0.113.50",
                scope="external",
                source_refs=[_ref()],
            ),
        ],
    )


def _risk() -> RiskAssessment:
    return RiskAssessment(
        risk_score=85,
        severity=Severity.HIGH,
        confidence=0.88,
        risk_factors=[
            RiskFactor(
                factor_name="asset_impact",
                weight=0.2,
                raw_score=85.0,
                weighted_score=17.0,
                reasoning="test",
            )
        ],
        scoring_mode=ScoringMode.LLM_AND_RULE,
        evidence_limited=False,
    )


def _triage() -> TriageResult:
    return TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        entities=_entities(),
        reasoning="test triage",
    )


def _seed_wm(wm: _FakeWorkingMemory, event_id: str) -> None:
    triage = _triage()
    wm.values[(event_id, "triage_result")] = triage.model_dump(mode="json")
    wm.values[(event_id, "execution_plan")] = {
        "plan_id": "pln-test",
        "event_id": event_id,
        "revision": 0,
        "steps": [],
    }
    wm.values[(event_id, "event")] = {
        "event_id": event_id,
        "disposition_policy": DispositionPolicy.REQUIRED.value,
        "creation_source_ref": _ref().model_dump(mode="json"),
    }
    wm.values[(event_id, "disposition_only_intent")] = False


def _agent_input(event_id: str) -> ResponseAgentInput:
    return ResponseAgentInput(
        event_id=event_id,
        risk_assessment=_risk(),
        evidence_output=EvidenceOutput(
            evidence_list=[],
            collection_status=CollectionStatus.COMPLETED,
            overall_confidence=0.9,
        ),
    )


def _sangfor_overlay():
    return apply_capability_overlay(
        baseline_tool_index(),
        SangforOverlayConfig(
            adapter_kind=SANGFOR_ADAPTER_KIND,
            devices=(SangforDevice(device_type="AF", device_id="af-1"),),
        ),
    )


def test_response_agent_source_has_no_vendor_literals() -> None:
    text = _RESPONSE_AGENT_SRC.read_text(encoding="utf-8")
    lowered = text.lower()
    assert "sangfor" not in lowered
    assert "dealstatus" not in lowered
    assert "/api/xdr/" not in lowered


def test_default_filter_keeps_mock_dual_owners() -> None:
    filt = ResponsePolicyFilter(
        manifest=build_mock_capability_manifest(),
        entities=_entities(),
        disposition_policy=DispositionPolicy.REQUIRED,
        source_locator=None,
    )
    assert filt.resolve_execution_owner("isolate_host") is ExecutionOwner.XDR_MANAGED
    assert filt.resolve_execution_owner("disable_account") is ExecutionOwner.XDR_MANAGED
    baseline = baseline_tool_index()
    assert ExecutionOwner.DIRECT_TOOL in baseline["isolate_host"].supported_execution_owners
    assert ExecutionOwner.DIRECT_TOOL in baseline["disable_account"].supported_execution_owners


def test_overlay_filter_clears_isolate_owner_but_keeps_candidate() -> None:
    overlay = _sangfor_overlay()
    filt = ResponsePolicyFilter(
        manifest=build_sangfor_capability_manifest(),
        entities=_entities(),
        disposition_policy=DispositionPolicy.REQUIRED,
        source_locator=None,
        tool_index=overlay,
    )
    assert filt.resolve_execution_owner("isolate_host") is None
    assert filt.resolve_execution_owner("disable_account") is None
    isolate_meta = overlay["isolate_host"]
    assert isolate_meta.executable is True
    kept = filt.filter_candidates(
        [
            ActionCandidate(
                tool_name="isolate_host",
                target_type="host",
                target="PC-FIN-023",
                parameters={},
                reason="need isolation",
            ),
            ActionCandidate(
                tool_name="disable_account",
                target_type="account",
                target="svc-backup",
                parameters={},
                reason="need disable",
            ),
        ]
    )
    names = {item.tool_name for item in kept}
    assert names == {"isolate_host", "disable_account"}


@pytest.mark.asyncio
async def test_mock_execute_still_materializes_isolate_and_disable() -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id)
    agent = ResponseAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=_FakeEventService(),
        capability_manifest=build_mock_capability_manifest(),
    )
    plan = await agent.execute(_agent_input(event_id))
    names = {action.tool_name for action in plan.actions}
    assert "isolate_host" in names
    assert "disable_account" in names
    isolate = next(action for action in plan.actions if action.tool_name == "isolate_host")
    disable = next(action for action in plan.actions if action.tool_name == "disable_account")
    assert isolate.execution_owner is ExecutionOwner.XDR_MANAGED
    assert disable.execution_owner is ExecutionOwner.XDR_MANAGED
    assert isolate.provider_name == "mock_xdr"


@pytest.mark.asyncio
async def test_run_passes_agent_tool_index_into_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id)
    overlay = _sangfor_overlay()
    agent = ResponseAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=_FakeEventService(),
        capability_manifest=build_sangfor_capability_manifest(),
        tool_index=overlay,
    )
    captured: dict[str, Any] = {}
    orig_init = ResponsePolicyFilter.__init__

    def _spy(self, *args: Any, **kwargs: Any) -> None:
        captured["tool_index"] = kwargs.get("tool_index")
        orig_init(self, *args, **kwargs)

    monkeypatch.setattr(ResponsePolicyFilter, "__init__", _spy)
    await agent.execute(_agent_input(event_id))
    assert captured["tool_index"] is agent._tool_index
    assert captured["tool_index"] is overlay


@pytest.mark.asyncio
async def test_materialize_does_not_recall_baseline_tool_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id)
    agent = ResponseAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=_FakeEventService(),
        capability_manifest=build_mock_capability_manifest(),
    )

    def _boom() -> dict[str, Any]:
        raise AssertionError("execute path must not call baseline_tool_index()")

    monkeypatch.setattr("app.agents.response_agent.baseline_tool_index", _boom)
    plan = await agent.execute(_agent_input(event_id))
    names = {action.tool_name for action in plan.actions}
    assert "isolate_host" in names
    assert "disable_account" in names


@pytest.mark.asyncio
async def test_sangfor_overlay_persists_ownerless_isolate_and_disable() -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id)
    overlay = _sangfor_overlay()
    agent = ResponseAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=_FakeEventService(),
        capability_manifest=build_sangfor_capability_manifest(),
        tool_index=overlay,
    )
    plan = await agent.execute(_agent_input(event_id))
    names = {action.tool_name for action in plan.actions}
    assert "isolate_host" in names
    assert "disable_account" in names
    isolate = next(action for action in plan.actions if action.tool_name == "isolate_host")
    disable = next(action for action in plan.actions if action.tool_name == "disable_account")
    for gap in (isolate, disable):
        assert gap.execution_owner is None
        assert gap.writeback_applicable is False
        assert gap.writeback_readiness is WritebackReadiness.NOT_REQUIRED
        assert gap.status is not ActionStatus.REJECTED
        assert gap.provider_name != "mock_xdr"
        assert gap.provider_name == "sangfor_xdr"
    assert agent.capability_manifest.provider_name == "sangfor_xdr"


def test_kind_mock_overrides_do_not_change_agent_defaults() -> None:
    assert response_agent_overrides_for_kind("mock") == {}
    agent = ResponseAgent(capability_manifest=build_mock_capability_manifest())
    assert agent.capability_manifest.provider_name == "mock_xdr"
    assert agent._tool_index["isolate_host"].supported_execution_owners
