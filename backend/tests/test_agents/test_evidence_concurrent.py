"""EvidenceAgent concurrent collection + ConflictDetector tests (ISSUE-034)."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from app.agents.conflict_detector import (
    CONFLICT_PENALTY_FACTOR,
    RULE_ASSET_ISOLATED_BUT_EDR_ACTIVE,
    RULE_IAM_ABSENT_BUT_EDR_ACTIVE,
    RULE_NETWORK_SILENT_BUT_DLP_UPLOAD,
    ConflictDetector,
)
from app.agents.evidence_agent import (
    EvidenceAgent,
    InMemoryEvidenceRepository,
)
from app.models.agent_io import EvidenceAgentInput, TriageResult
from app.models.entities import (
    AccountEntity,
    DomainEntity,
    EntitySet,
    HostEntity,
    IPEntity,
)
from app.models.enums import EventType, EvidenceSource, Severity
from app.models.evidence import Evidence
from app.models.ids import new_evidence_id
from app.models.tool_meta import ToolResult, ToolResultStatus
from app.services.evidence_projection import (
    EvidenceProjection,
    bind_evidence_projection,
    bind_evidence_query_scope,
)
from tests.test_tools.tool_system_fixtures import DEFAULT_SCOPE, WINDOW, new_sfx

pytestmark = pytest.mark.asyncio


class _EventScopeService:
    def __init__(self, scope: Any = DEFAULT_SCOPE) -> None:
        self.scope = scope

    async def get_evidence_query_scope(self, event_id: str) -> Any:
        return self.scope


class _FakeWorkingMemory:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], Any] = {}
        self.scratchpad: dict[str, list[str]] = {}

    async def read(self, event_id: str, key: str) -> Any:
        return self.values.get((event_id, key))

    async def write(self, event_id: str, key: str, value: Any) -> None:
        self.values[(event_id, key)] = value

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        self.scratchpad.setdefault(event_id, []).append(note)


class _DelayedExecutor:
    """Wraps a real executor and adds per-tool artificial delay."""

    def __init__(self, inner: Any, delays: dict[str, float]) -> None:
        self._inner = inner
        self._delays = delays

    async def call(
        self,
        tool_name: str,
        params: dict[str, Any],
        event_id: str,
        **kwargs: Any,
    ) -> ToolResult:
        delay = float(self._delays.get(tool_name, 0.0))
        if delay > 0:
            await asyncio.sleep(delay)
        result = await self._inner.call(tool_name, params, event_id, **kwargs)
        if isinstance(result, ToolResult):
            return result.model_copy(
                update={"execution_time_ms": int(delay * 1000) + int(result.execution_time_ms or 0)}
            )
        return ToolResult.model_validate(result)


class _HangingExecutor:
    """Completes selected tools; hangs forever on others (until cancelled)."""

    def __init__(self, inner: Any, hang_tools: set[str]) -> None:
        self._inner = inner
        self._hang_tools = hang_tools

    async def call(
        self,
        tool_name: str,
        params: dict[str, Any],
        event_id: str,
        **kwargs: Any,
    ) -> ToolResult:
        if tool_name in self._hang_tools:
            await asyncio.sleep(3600)
            return ToolResult(
                call_id=f"call-hang-{new_sfx()}",
                tool_name=tool_name,
                provider_name="test",
                status=ToolResultStatus.TIMEOUT,
                execution_time_ms=3600000,
            )
        return await self._inner.call(tool_name, params, event_id, **kwargs)


def _main_scenario_triage() -> TriageResult:
    return TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        entities=EntitySet(
            accounts=[AccountEntity(entity_id="ent-acc-1", username="zhangsan")],
            hosts=[
                HostEntity(
                    entity_id="ent-host-1",
                    hostname="PC-FIN-023",
                    ip="10.20.30.23",
                )
            ],
            ips=[
                IPEntity(
                    entity_id="ent-ip-int",
                    address="10.20.30.23",
                    scope="internal",
                ),
                IPEntity(
                    entity_id="ent-ip-ext",
                    address="203.0.113.88",
                    scope="external",
                ),
            ],
            domains=[
                DomainEntity(
                    entity_id="ent-dom-1",
                    fqdn="unknown-upload-example.com",
                )
            ],
        ),
        ioc_list=["203.0.113.88", "unknown-upload-example.com"],
        reasoning="insider data exfiltration main scenario",
    )


def _evd(
    *,
    source: EvidenceSource,
    evidence_type: str,
    confidence: float,
    event_id: str,
    raw_data: dict[str, Any],
    related: list[str] | None = None,
    is_conflicting: bool = False,
) -> Evidence:
    return Evidence(
        evidence_id=new_evidence_id(),
        event_id=event_id,
        source=source,
        evidence_type=evidence_type,
        description="fixture",
        confidence=confidence,
        timestamp=datetime(2024, 6, 15, 9, 0, 0, tzinfo=UTC),
        related_entities=related or [],
        raw_data=raw_data,
        is_conflicting=is_conflicting,
    )


def _build_agent(
    *,
    tool_executor: Any,
    evidence_mode: str,
    global_timeout_s: float = 30.0,
    wm: _FakeWorkingMemory | None = None,
    repo: InMemoryEvidenceRepository | None = None,
) -> tuple[EvidenceAgent, _FakeWorkingMemory, InMemoryEvidenceRepository]:
    memory = wm or _FakeWorkingMemory()
    store = repo or InMemoryEvidenceRepository()
    agent = EvidenceAgent(
        tool_executor=tool_executor,
        working_memory=memory,
        evidence_repository=store,
        event_service=_EventScopeService(),
        default_time_range=dict(WINDOW),
        evidence_mode=evidence_mode,
        global_timeout_s=global_timeout_s,
        query_timeout_s=10.0,
    )
    return agent, memory, store


async def test_concurrent_matches_sequential_results(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
) -> None:
    """并发与顺序模式在同一 fixture 上产出一致的证据集合。"""
    event_id = f"evt-evd-mode-{new_sfx()}"
    triage = _main_scenario_triage()

    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            seq_agent, _, _ = _build_agent(
                tool_executor=tool_executor,
                evidence_mode="sequential",
            )
            seq_out = await seq_agent.execute(
                EvidenceAgentInput(event_id=event_id + "-seq", triage_result=triage)
            )

            conc_agent, _, _ = _build_agent(
                tool_executor=tool_executor,
                evidence_mode="concurrent",
            )
            conc_out = await conc_agent.execute(
                EvidenceAgentInput(event_id=event_id + "-conc", triage_result=triage)
            )

    def fingerprint(items: list[Evidence]) -> set[tuple[str, str, str | None]]:
        return {
            (
                item.source.value,
                item.evidence_type,
                item.timestamp.isoformat() if item.timestamp else None,
            )
            for item in items
        }

    assert fingerprint(seq_out.evidence_list) == fingerprint(conc_out.evidence_list)
    assert set(seq_out.success_sources) == set(conc_out.success_sources)
    assert seq_out.collection_status == conc_out.collection_status


async def test_concurrent_wall_time_within_slowest_plus_two_seconds(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
) -> None:
    """并发 7 路总耗时不超过最慢单路 + 2 秒。"""
    delays = {
        "query_account_login": 0.15,
        "query_edr_process": 0.20,
        "query_file_access": 0.18,
        "query_network_flow": 0.25,
        "query_dns": 0.12,
        "query_asset_info": 0.10,
        "query_threat_intel": 0.22,
    }
    slowest = max(delays.values())
    delayed = _DelayedExecutor(tool_executor, delays)
    agent, _, _ = _build_agent(tool_executor=delayed, evidence_mode="concurrent")

    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            started = time.perf_counter()
            output = await agent.execute(
                EvidenceAgentInput(
                    event_id=f"evt-evd-speed-{new_sfx()}",
                    triage_result=_main_scenario_triage(),
                )
            )
            elapsed = time.perf_counter() - started

    # CI runs pytest with --cov; coverage instrumentation adds wall-time overhead.
    try:
        from coverage import Coverage

        slack_s = 5.0 if Coverage.current() is not None else 2.0
    except Exception:
        slack_s = 2.0
    assert len(output.success_sources) >= 5
    assert elapsed <= slowest + slack_s
    assert agent.last_collection_elapsed_s is not None
    assert agent.last_collection_elapsed_s <= slowest + slack_s


async def test_global_timeout_keeps_completed_results(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
) -> None:
    """全局超时后保留已完成查询，未完成记入 failed_sources。"""
    hang_tools = {"query_threat_intel", "query_dns"}
    hanging = _HangingExecutor(tool_executor, hang_tools)
    agent, _, repo = _build_agent(
        tool_executor=hanging,
        evidence_mode="concurrent",
        global_timeout_s=0.4,
    )
    event_id = f"evt-evd-timeout-{new_sfx()}"

    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            output = await agent.execute(
                EvidenceAgentInput(
                    event_id=event_id,
                    triage_result=_main_scenario_triage(),
                )
            )

    assert output.evidence_list  # completed sources retained
    assert "threat_intel" in output.failed_sources or "dns" in output.failed_sources
    assert any(gap.reason == "global_timeout" for gap in output.gaps)
    stored = await repo.list_by_event(event_id)
    assert {row.evidence_id for row in stored} == {
        item.evidence_id for item in output.evidence_list
    }


async def test_main_scenario_triggers_iam_absent_high_conflict(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
) -> None:
    """主场景矛盾数据触发 iam_absent_but_edr_active（high）并降权。"""
    event_id = f"evt-evd-conflict-{new_sfx()}"
    agent, _, repo = _build_agent(
        tool_executor=tool_executor,
        evidence_mode="concurrent",
    )

    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            output = await agent.execute(
                EvidenceAgentInput(
                    event_id=event_id,
                    triage_result=_main_scenario_triage(),
                )
            )

    high = [
        c
        for c in output.conflicts
        if c.detail.get("rule_name") == RULE_IAM_ABSENT_BUT_EDR_ACTIVE
        and c.detail.get("severity") == "high"
    ]
    assert high, f"expected iam conflict, got {output.conflicts!r}"
    penalized_ids = set(high[0].evidence_ids)
    assert penalized_ids

    for item in output.evidence_list:
        if item.evidence_id in penalized_ids:
            assert item.is_conflicting is True

    stored = await repo.list_by_event(event_id)
    stored_by_id = {row.evidence_id: row for row in stored}
    for evidence_id in penalized_ids:
        row = stored_by_id[evidence_id]
        mem = next(item for item in output.evidence_list if item.evidence_id == evidence_id)
        assert row.is_conflicting is True
        assert abs(row.confidence - mem.confidence) < 1e-9


async def test_conflict_detector_three_rules_and_penalty() -> None:
    """三条规则均可触发；惩罚因子 0.7；confidence 计算基于降权后证据。"""
    event_id = f"evt-rules-{uuid4().hex[:8]}"
    detector = ConflictDetector()

    iam_absent = _evd(
        source=EvidenceSource.IDENTITY,
        evidence_type="login_lookup",
        confidence=0.80,
        event_id=event_id,
        raw_data={"account": "zhangsan", "result": "no_record"},
        related=["zhangsan"],
        is_conflicting=True,
    )
    edr = _evd(
        source=EvidenceSource.ENDPOINT,
        evidence_type="process_create",
        confidence=0.90,
        event_id=event_id,
        raw_data={
            "account": "zhangsan",
            "hostname": "PC-FIN-023",
            "process": "powershell.exe",
            "action": "process_create",
        },
        related=["zhangsan", "PC-FIN-023"],
    )
    silent_net = _evd(
        source=EvidenceSource.NETWORK_FLOW,
        evidence_type="no_flow",
        confidence=0.70,
        event_id=event_id,
        raw_data={"result": "silent", "src_ip": "10.20.30.23"},
    )
    upload = _evd(
        source=EvidenceSource.DATA_SECURITY,
        evidence_type="upload",
        confidence=0.85,
        event_id=event_id,
        raw_data={"action": "upload", "file_name": "finance_report.zip"},
    )
    isolated = _evd(
        source=EvidenceSource.ASSET,
        evidence_type="asset_info",
        confidence=0.75,
        event_id=event_id,
        raw_data={
            "hostname": "PC-FIN-023",
            "ip": "10.20.30.23",
            "agent_status": "isolated",
        },
        related=["PC-FIN-023"],
    )

    evidence = [iam_absent, edr, silent_net, upload, isolated]
    conflicts = detector.detect(evidence)
    rules = {c.detail.get("rule_name") for c in conflicts}
    assert RULE_IAM_ABSENT_BUT_EDR_ACTIVE in rules
    assert RULE_NETWORK_SILENT_BUT_DLP_UPLOAD in rules
    assert RULE_ASSET_ISOLATED_BUT_EDR_ACTIVE in rules

    penalized, _ = detector.detect_and_penalize(evidence)
    by_id = {item.evidence_id: item for item in penalized}
    assert abs(by_id[iam_absent.evidence_id].confidence - 0.80 * CONFLICT_PENALTY_FACTOR) < 1e-9
    assert by_id[iam_absent.evidence_id].is_conflicting is True
    assert abs(by_id[edr.evidence_id].confidence - 0.90 * CONFLICT_PENALTY_FACTOR) < 1e-9

    # overall_confidence uses penalized list
    status_conf = EvidenceAgent._overall_confidence(
        penalized,
        EvidenceAgent._collection_status(5),
    )
    assert 0.0 <= status_conf <= 1.0


async def test_evidence_table_conflict_fields_match_memory(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
) -> None:
    """evidence 仓库 is_conflicting / confidence 与内存态一致。"""
    event_id = f"evt-evd-db-sync-{new_sfx()}"
    agent, _, repo = _build_agent(
        tool_executor=tool_executor,
        evidence_mode="concurrent",
    )
    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            output = await agent.execute(
                EvidenceAgentInput(
                    event_id=event_id,
                    triage_result=_main_scenario_triage(),
                )
            )

    stored = await repo.list_by_event(event_id)
    assert len(stored) == len(output.evidence_list)
    mem_by_id = {item.evidence_id: item for item in output.evidence_list}
    for row in stored:
        mem = mem_by_id[row.evidence_id]
        assert row.is_conflicting is mem.is_conflicting
        assert abs(row.confidence - mem.confidence) < 1e-9
