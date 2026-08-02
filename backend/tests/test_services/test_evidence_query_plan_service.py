"""ISSUE-115 evidence query plan resolution tests."""

from __future__ import annotations

from app.agents.evidence_agent import EVIDENCE_QUERY_ORDER
from app.models.agent_io import ExecutionPlan, PlanBudget, PlanStep, TriageResult
from app.models.entities import (
    AccountEntity,
    DomainEntity,
    EntitySet,
    HostEntity,
    IPEntity,
)
from app.models.enums import EventType, Severity
from app.services.evidence_projection import EvidenceQueryScope
from app.services.evidence_query_plan_service import (
    SEVEN_EVIDENCE_TOOLS,
    apply_query_budget,
    build_query_dedupe_key,
    resolve_event_type_floor,
    resolve_evidence_query_plan,
    resolve_mandatory_baseline,
    sanitize_planned_tools,
    snapshot_cutoff_from_source,
)


def _rich_triage() -> TriageResult:
    return TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        entities=EntitySet(
            accounts=[AccountEntity(entity_id="a1", username="alice")],
            hosts=[HostEntity(entity_id="h1", hostname="host-1", ip="10.0.0.5")],
            ips=[
                IPEntity(entity_id="i1", address="10.0.0.5", scope="internal"),
                IPEntity(entity_id="i2", address="203.0.113.1", scope="external"),
            ],
            domains=[DomainEntity(entity_id="d1", fqdn="evil.example")],
        ),
        ioc_list=["203.0.113.1"],
        reasoning="test",
    )


def test_mandatory_baseline_is_entity_and_event_aware() -> None:
    mandatory = resolve_mandatory_baseline(_rich_triage())
    assert "query_account_login" in mandatory
    assert "query_edr_process" in mandatory
    assert "query_network_flow" in mandatory
    assert "query_threat_intel" in mandatory


def test_sanitize_rejects_response_and_disposition_tools() -> None:
    clean, rejected = sanitize_planned_tools(
        ["query_dns", "block_ip", "update_source_event_disposition", "not_a_tool"]
    )
    assert clean == ["query_dns"]
    assert "block_ip" in rejected
    assert "update_source_event_disposition" in rejected


def test_valid_plan_merges_mandatory_without_dropping() -> None:
    triage = _rich_triage()
    plan = resolve_evidence_query_plan(
        triage,
        planned_tools=["query_dns"],
    )
    assert "query_dns" in plan.tools
    assert set(plan.mandatory_tools).issubset(set(plan.tools))
    assert not plan.used_safety_baseline


def test_empty_plan_falls_back_to_seven_source_baseline() -> None:
    triage = _rich_triage()
    plan = resolve_evidence_query_plan(triage, planned_tools=[])
    assert plan.tools == list(SEVEN_EVIDENCE_TOOLS)
    assert plan.used_safety_baseline
    assert "plan_missing_or_invalid" in plan.degraded_reasons


def test_adversarial_non_query_plan_falls_back_without_reducing_mandatory() -> None:
    triage = _rich_triage()
    mandatory = resolve_mandatory_baseline(triage)
    plan = resolve_evidence_query_plan(
        triage,
        planned_tools=["block_ip", "rollback_isolate_host"],
    )
    assert plan.used_safety_baseline
    assert set(mandatory).issubset(set(plan.tools))


def test_budget_trim_keeps_mandatory_first() -> None:
    ordered = list(EVIDENCE_QUERY_ORDER)
    mandatory = frozenset({"query_account_login", "query_network_flow", "query_threat_intel"})
    floor = frozenset({"query_network_flow", "query_threat_intel"})
    kept, trimmed, budget_exceeded = apply_query_budget(
        ordered,
        mandatory_tools=mandatory,
        floor_tools=floor,
        max_tool_calls=4,
    )
    assert len(kept) == 4
    assert mandatory.issubset(set(kept))
    assert floor.issubset(set(kept))
    assert len(trimmed) == len(ordered) - 4
    assert budget_exceeded is False


def test_budget_never_drops_mandatory_when_cap_tight() -> None:
    triage = _rich_triage()
    mandatory = resolve_mandatory_baseline(triage)
    plan = resolve_evidence_query_plan(
        triage,
        execution_plan=ExecutionPlan(
            plan_id="pln-tight",
            event_id="evt-tight",
            steps=[
                PlanStep(
                    step_order=1,
                    step_goal="collect",
                    assigned_agent="evidence_agent",
                    required_tools=list(SEVEN_EVIDENCE_TOOLS),
                    success_criteria="ok",
                )
            ],
            budget=PlanBudget(max_tool_calls=2),
            revision=0,
        ),
    )
    assert set(mandatory).issubset(set(plan.tools))
    assert len(plan.tools) >= len(mandatory)
    assert "budget_exceeded_mandatory_preserved" in plan.degraded_reasons
    assert "mandatory_trimmed" not in " ".join(plan.degraded_reasons)


def test_invalid_execution_plan_dict_falls_back_to_baseline() -> None:
    triage = _rich_triage()
    mandatory = resolve_mandatory_baseline(triage)
    plan = resolve_evidence_query_plan(
        triage,
        execution_plan={"steps": "not-a-list", "plan_id": "bad"},
    )
    assert plan.used_safety_baseline
    assert "plan_missing_or_invalid" in plan.degraded_reasons
    assert set(mandatory).issubset(set(plan.tools))
    assert plan.tools == list(SEVEN_EVIDENCE_TOOLS)


def test_budget_trim_preserves_event_type_floor_first() -> None:
    triage = TriageResult(
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.HIGH,
        need_investigation=True,
        entities=EntitySet(
            hosts=[HostEntity(entity_id="h1", hostname="host-1", ip="10.0.0.5")],
        ),
        reasoning="test",
    )
    floor = resolve_event_type_floor(triage)
    plan = resolve_evidence_query_plan(
        triage,
        execution_plan=ExecutionPlan(
            plan_id="pln-floor",
            event_id="evt-floor",
            steps=[
                PlanStep(
                    step_order=1,
                    step_goal="collect",
                    assigned_agent="evidence_agent",
                    required_tools=list(SEVEN_EVIDENCE_TOOLS),
                    success_criteria="ok",
                )
            ],
            budget=PlanBudget(max_tool_calls=3),
            revision=0,
        ),
    )
    assert len(plan.tools) == 3
    assert floor.issubset(set(plan.tools))
    assert "budget_trimmed_optional_queries" in plan.degraded_reasons
    assert "budget_exceeded_mandatory_preserved" not in plan.degraded_reasons


def test_manifest_disabled_tool_rejected_at_runtime() -> None:
    triage = _rich_triage()
    allowlisted = frozenset(tool for tool in SEVEN_EVIDENCE_TOOLS if tool != "query_dns")
    plan = resolve_evidence_query_plan(
        triage,
        planned_tools=["query_dns", "query_asset_info"],
        allowlisted=allowlisted,
    )
    assert "query_dns" not in plan.tools
    assert "query_dns" in plan.rejected_tools
    assert "manifest_disabled_tools" in plan.degraded_reasons


def test_dedupe_key_changes_with_scope_and_window() -> None:
    params = {"account": "alice", "time_range": {"start": "a", "end": "b"}}
    scope_a = EvidenceQueryScope(source_tenant_id="t1", connector_ids=frozenset({"c1"}))
    scope_b = EvidenceQueryScope(source_tenant_id="t2", connector_ids=frozenset({"c2"}))
    key_a = build_query_dedupe_key("query_account_login", params, params["time_range"], scope_a)
    key_b = build_query_dedupe_key("query_account_login", params, params["time_range"], scope_b)
    assert key_a != key_b


def test_dedupe_key_includes_snapshot_cutoff() -> None:
    params = {"account": "alice"}
    window = {"start": "a", "end": "b"}
    without = build_query_dedupe_key("query_account_login", params, window, None)
    with_cutoff = build_query_dedupe_key(
        "query_account_login",
        params,
        window,
        None,
        snapshot_cutoff="snap-001",
    )
    assert without != with_cutoff


def test_snapshot_cutoff_from_source_prefers_snapshot_id() -> None:
    assert snapshot_cutoff_from_source({"snapshot_id": "snap-abc"}) == "snap-abc"
    assert snapshot_cutoff_from_source({"frozen_at_event_id": "evt-1"}) == "evt-1"
    assert snapshot_cutoff_from_source(None) == ""


def test_execution_plan_budget_caps_optional_tools() -> None:
    triage = _rich_triage()
    mandatory = resolve_mandatory_baseline(triage)
    execution_plan = ExecutionPlan(
        plan_id="pln-test",
        event_id="evt-test",
        steps=[
            PlanStep(
                step_order=1,
                step_goal="collect",
                assigned_agent="evidence_agent",
                required_tools=list(SEVEN_EVIDENCE_TOOLS),
                success_criteria="ok",
            )
        ],
        budget=PlanBudget(max_tool_calls=3),
        revision=0,
    )
    plan = resolve_evidence_query_plan(
        triage,
        execution_plan=execution_plan,
    )
    assert set(mandatory).issubset(set(plan.tools))
    assert len(plan.tools) >= len(mandatory)
    assert "budget_exceeded_mandatory_preserved" in plan.degraded_reasons


def test_deterministic_tool_order_for_same_inputs() -> None:
    triage = _rich_triage()
    first = resolve_evidence_query_plan(triage, planned_tools=["query_dns", "query_asset_info"])
    second = resolve_evidence_query_plan(triage, planned_tools=["query_asset_info", "query_dns"])
    assert first.tools == second.tools
