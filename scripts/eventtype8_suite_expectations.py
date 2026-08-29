"""Two-column EventType-8 gold-path expectations (A=mock_xdr, B=sangfor_xdr).

Contract: docs/eval-8-eventtype-gold-paths-plan.md §2–§4.
Do not mix columns in one assert. Do not treat SCENARIO_EXPECTATIONS.allowed_actions
as the pass gate. Persist fields are the real ones: context_snapshot / rag_output;
fp_similarity.matched_case_id + max_score; OrgContextMatch.match_type (no is_exact).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from dynamic_eval_profiles import EVENTTYPE8_SCENARIOS

EvalColumn = Literal["mock_xdr", "sangfor_xdr"]

# Aligns with RiskAgent fp_similarity.max_score gate (backend/app/agents/risk_agent.py).
FP_MAX_SCORE_THRESHOLD = 0.7
FP_MATCHED_CASE_ID = "case-00000001"

TOOLS_WITHOUT_SANGFOR_CREATE_URI = (
    "isolate_host",
    "disable_account",
    "block_process",
)


@dataclass(frozen=True)
class PersistHit:
    """A required persist hit. Source is API snapshot or EventContext rag_output."""

    source: Literal["context_snapshot", "rag_output"]
    path: str
    equals: str | None = None
    min_score: float | None = None
    match_type: str | None = None
    nonempty_list: bool = False


@dataclass(frozen=True)
class ColumnExpectation:
    """Per-scenario, per-column quality + execution expectation."""

    required_job_success: tuple[str, ...]
    owner_may_be_none: tuple[str, ...]
    forbid_entity_job_success: tuple[str, ...]
    persist_hits: tuple[PersistHit, ...]
    require_writeback_confirmed: bool
    fp_full_loop_gate: bool = False
    skip_entity_response: bool = False


def _fp_hits() -> tuple[PersistHit, ...]:
    return (
        PersistHit(
            source="rag_output",
            path="fp_similarity.matched_case_id",
            equals=FP_MATCHED_CASE_ID,
        ),
        PersistHit(
            source="rag_output",
            path="fp_similarity.max_score",
            min_score=FP_MAX_SCORE_THRESHOLD,
        ),
    )


def _mock(
    *,
    required_job_success: tuple[str, ...] = (),
    forbid_entity_job_success: tuple[str, ...] = (),
    persist_hits: tuple[PersistHit, ...] = (),
    require_writeback_confirmed: bool = False,
    fp_full_loop_gate: bool = False,
    skip_entity_response: bool = False,
) -> ColumnExpectation:
    return ColumnExpectation(
        required_job_success=required_job_success,
        owner_may_be_none=(),
        forbid_entity_job_success=forbid_entity_job_success,
        persist_hits=persist_hits,
        require_writeback_confirmed=require_writeback_confirmed,
        fp_full_loop_gate=fp_full_loop_gate,
        skip_entity_response=skip_entity_response,
    )


def _sangfor(
    *,
    required_job_success: tuple[str, ...] = (),
    owner_may_be_none: tuple[str, ...] = (),
    forbid_entity_job_success: tuple[str, ...] = (),
    persist_hits: tuple[PersistHit, ...] = (),
    require_writeback_confirmed: bool = False,
    fp_full_loop_gate: bool = False,
    skip_entity_response: bool = False,
) -> ColumnExpectation:
    return ColumnExpectation(
        required_job_success=required_job_success,
        owner_may_be_none=owner_may_be_none,
        forbid_entity_job_success=forbid_entity_job_success,
        persist_hits=persist_hits,
        require_writeback_confirmed=require_writeback_confirmed,
        fp_full_loop_gate=fp_full_loop_gate,
        skip_entity_response=skip_entity_response,
    )


SUITE_EXPECTATIONS: dict[str, dict[EvalColumn, ColumnExpectation]] = {
    "account_anomaly_fp": {
        "mock_xdr": _mock(
            persist_hits=_fp_hits(),
            forbid_entity_job_success=("isolate_host",),
            fp_full_loop_gate=True,
            skip_entity_response=True,
        ),
        "sangfor_xdr": _sangfor(
            persist_hits=_fp_hits(),
            forbid_entity_job_success=("isolate_host",),
            owner_may_be_none=TOOLS_WITHOUT_SANGFOR_CREATE_URI,
            fp_full_loop_gate=True,
            skip_entity_response=True,
        ),
    },
    "suspicious_domain_access": {
        "mock_xdr": _mock(required_job_success=("block_domain",)),
        "sangfor_xdr": _sangfor(
            # AF inventory is a live config fact — unconfigured sites keep owner None.
            owner_may_be_none=("isolate_host", "disable_account", "block_process"),
            required_job_success=(),
        ),
    },
    "insider_data_exfiltration": {
        "mock_xdr": _mock(
            required_job_success=("isolate_host",),
            require_writeback_confirmed=True,
        ),
        "sangfor_xdr": _sangfor(
            owner_may_be_none=TOOLS_WITHOUT_SANGFOR_CREATE_URI,
            require_writeback_confirmed=True,
        ),
    },
    "host_compromise": {
        "mock_xdr": _mock(
            required_job_success=("scan_host_for_virus",),
            # Canonical Mock still allows isolate SUCCESS (quality must not drop).
        ),
        "sangfor_xdr": _sangfor(
            owner_may_be_none=("isolate_host", "disable_account", "block_process"),
        ),
    },
    "insider_privilege_abuse": {
        "mock_xdr": _mock(
            required_job_success=("disable_account",),
            persist_hits=(
                PersistHit(
                    source="rag_output",
                    path="org_context_matches",
                    match_type="exact",
                    nonempty_list=True,
                ),
            ),
        ),
        "sangfor_xdr": _sangfor(
            owner_may_be_none=TOOLS_WITHOUT_SANGFOR_CREATE_URI,
            persist_hits=(
                PersistHit(
                    source="rag_output",
                    path="org_context_matches",
                    match_type="exact",
                    nonempty_list=True,
                ),
            ),
        ),
    },
    "malicious_process": {
        "mock_xdr": _mock(
            required_job_success=("block_process", "query_edr_process"),
            persist_hits=(
                PersistHit(
                    source="rag_output",
                    path="playbook_refs",
                    nonempty_list=True,
                ),
            ),
        ),
        "sangfor_xdr": _sangfor(
            owner_may_be_none=("block_process", "isolate_host", "disable_account"),
            persist_hits=(
                PersistHit(
                    source="rag_output",
                    path="playbook_refs",
                    nonempty_list=True,
                ),
            ),
        ),
    },
    "lateral_movement": {
        "mock_xdr": _mock(
            required_job_success=("block_ip",),
            persist_hits=(
                PersistHit(
                    source="context_snapshot",
                    path="graph_output",
                    nonempty_list=False,
                ),
                PersistHit(
                    source="rag_output",
                    path="attack_techniques",
                    nonempty_list=True,
                ),
            ),
        ),
        "sangfor_xdr": _sangfor(
            owner_may_be_none=TOOLS_WITHOUT_SANGFOR_CREATE_URI,
            persist_hits=(
                PersistHit(
                    source="rag_output",
                    path="attack_techniques",
                    nonempty_list=True,
                ),
            ),
        ),
    },
    "other_unclassified": {
        "mock_xdr": _mock(
            skip_entity_response=True,
            forbid_entity_job_success=("isolate_host", "block_ip", "block_domain"),
            persist_hits=(
                PersistHit(
                    source="rag_output",
                    path="similar_cases",
                    nonempty_list=True,
                ),
            ),
        ),
        "sangfor_xdr": _sangfor(
            skip_entity_response=True,
            forbid_entity_job_success=("isolate_host", "block_ip", "block_domain"),
            owner_may_be_none=TOOLS_WITHOUT_SANGFOR_CREATE_URI,
            persist_hits=(
                PersistHit(
                    source="rag_output",
                    path="similar_cases",
                    nonempty_list=True,
                ),
            ),
        ),
    },
}


# Copied from backend/app/services/org_context_matcher.py so host eval
# does not import the backend package. match_type=="exact" in the table
# means this exact-family, not a nonexistent is_exact field.
ORG_CONTEXT_EXACT_MATCH_TYPES = frozenset(
    {
        "domain_exact",
        "domain_suffix",
        "restricted_domain",
        "cidr",
        "ip_exact",
        "account_exact",
        "host_exact",
        "window",
        "exact",
    }
)

_MOCK_LLM_MODEL_MARKERS = ("mock-model", "mockllm", "mock_llm")
_QUERY_TOOL_PREFIX = "query_"
_JOB_SUCCESS = "success"
_EFFECT_VERIFIED = "verified"
_LLM_CALL_TYPE = "llm_call"
_MOCK_TOOL_PROVIDER = "mock_tool_provider"
_PROVIDER_FIELDS = ("provider_name", "provider", "job_provider", "adapter_kind")


def _dig(obj: object, path: str) -> object:
    cur: object = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def is_exact_family_match_type(match_type: str) -> bool:
    return str(match_type or "") in ORG_CONTEXT_EXACT_MATCH_TYPES


def _graph_has_structure(graph: object) -> bool:
    if not isinstance(graph, dict):
        return False
    edges = graph.get("edges")
    if isinstance(edges, list) and len(edges) > 0:
        return True
    summary = graph.get("summary")
    if isinstance(summary, dict):
        features = summary.get("features")
        if isinstance(features, list) and len(features) > 0:
            return True
    return False


def eval_persist_hit(
    hit: PersistHit,
    *,
    snapshot: dict | None,
    rag_output: dict | None,
    graph_output: dict | None,
) -> None:
    if hit.source == "rag_output":
        root: object = rag_output or {}
        if hit.path == "org_context_matches" and not (
            isinstance(root, dict) and isinstance(root.get("org_context_matches"), list)
        ):
            root = snapshot or {}
        value = _dig(root, hit.path)
    elif hit.path == "graph_output":
        value = graph_output
    else:
        value = _dig(snapshot or {}, hit.path)

    label = f"{hit.source}.{hit.path}"
    if hit.equals is not None:
        if str(value or "") != str(hit.equals):
            raise RuntimeError(
                f"eventtype8 persist {label} expected {hit.equals!r}, got {value!r}"
            )
        return
    if hit.min_score is not None:
        try:
            score = float(value)  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                f"eventtype8 persist {label} is not a score: {value!r}"
            ) from exc
        if score < hit.min_score:
            raise RuntimeError(
                f"eventtype8 persist {label}={score} below min_score={hit.min_score}"
            )
        return
    if hit.match_type is not None:
        if not isinstance(value, list) or not value:
            raise RuntimeError(
                f"eventtype8 persist {label} must be a nonempty list for match_type, "
                f"got {value!r}"
            )
        exact_hits = [
            item
            for item in value
            if isinstance(item, dict)
            and is_exact_family_match_type(str(item.get("match_type") or ""))
        ]
        if not exact_hits:
            raise RuntimeError(
                f"eventtype8 persist {label} has no exact-family match_type "
                f"(wanted {hit.match_type!r} family), items={value!r}"
            )
        return
    if hit.path == "graph_output":
        if not _graph_has_structure(value):
            raise RuntimeError(
                f"eventtype8 persist graph_output needs edges or summary.features, "
                f"got {value!r}"
            )
        return
    if hit.nonempty_list:
        if not isinstance(value, list) or len(value) == 0:
            raise RuntimeError(
                f"eventtype8 persist {label} must be a nonempty list, got {value!r}"
            )


def _is_query_tool(tool_name: str) -> bool:
    return tool_name.startswith(_QUERY_TOOL_PREFIX)


def assert_required_job_success(
    tool_name: str,
    *,
    actions: list[dict],
    tool_calls: list[dict],
) -> None:
    """A-column: Job SUCCESS with execution_owner set. Query tools may use tool-calls."""
    matching_actions = [a for a in actions if str(a.get("tool_name") or "") == tool_name]
    if _is_query_tool(tool_name):
        call_ok = any(
            str(c.get("tool_name") or "") == tool_name
            and str(c.get("status") or "") == _JOB_SUCCESS
            for c in tool_calls
        )
        action_ok = any(
            str(a.get("status") or "") == _JOB_SUCCESS for a in matching_actions
        )
        if not (call_ok or action_ok):
            raise RuntimeError(
                f"eventtype8 A-column requires {tool_name} tool-call or action SUCCESS"
            )
        return

    success_owned = [
        a
        for a in matching_actions
        if str(a.get("status") or "") == _JOB_SUCCESS and a.get("execution_owner")
    ]
    if not success_owned:
        owned_none = [
            a
            for a in matching_actions
            if str(a.get("status") or "") == _JOB_SUCCESS and not a.get("execution_owner")
        ]
        if owned_none:
            raise RuntimeError(
                f"eventtype8 A-column forbids owner=None SUCCESS for {tool_name}"
            )
        raise RuntimeError(
            f"eventtype8 A-column requires {tool_name} Action status=success "
            f"with execution_owner set"
        )
    verified = [
        a
        for a in success_owned
        if str(a.get("effect_verification_status") or "") == _EFFECT_VERIFIED
    ]
    if not verified:
        raise RuntimeError(
            f"eventtype8 A-column requires {tool_name} effect_verification_status=verified"
        )


def assert_forbid_entity_job_success(tool_name: str, *, actions: list[dict]) -> None:
    for action in actions:
        if str(action.get("tool_name") or "") != tool_name:
            continue
        if str(action.get("status") or "") == _JOB_SUCCESS:
            raise RuntimeError(
                f"eventtype8 forbids {tool_name} Action SUCCESS "
                f"(action_id={action.get('action_id')!r})"
            )


def assert_real_llm_calls(entries: list[dict], *, event_id: str) -> None:
    ok_models: list[str] = []
    for entry in entries:
        if str(entry.get("entry_type") or "") != _LLM_CALL_TYPE:
            continue
        detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else {}
        model = str(detail.get("model_name") or "")
        status = str(detail.get("status") or "").lower()
        lowered = model.lower()
        if status != "success":
            continue
        if any(marker in lowered for marker in _MOCK_LLM_MODEL_MARKERS):
            raise RuntimeError(
                f"eventtype8 suite refuses MockLLM model_name={model!r} for {event_id}"
            )
        if model.strip():
            ok_models.append(model)
    if not ok_models:
        raise RuntimeError(
            f"eventtype8 suite requires a successful llm_call_log row for {event_id} "
            "(model_name must not be a MockLLM placeholder)"
        )


def assert_eventtype8_mock_column(
    scenario: str,
    *,
    snapshot: dict | None,
    rag_output: dict | None,
    graph_output: dict | None,
    actions: list[dict],
    tool_calls: list[dict],
    llm_trace_entries: list[dict],
    event_id: str,
) -> dict[str, object]:
    """A-column (mock_xdr) persist + Job SUCCESS+Verify. Demo path must not call this."""
    expectation = column_expectation(scenario, "mock_xdr")
    assert_real_llm_calls(llm_trace_entries, event_id=event_id)
    for hit in expectation.persist_hits:
        eval_persist_hit(
            hit,
            snapshot=snapshot,
            rag_output=rag_output if isinstance(rag_output, dict) else None,
            graph_output=graph_output if isinstance(graph_output, dict) else None,
        )
    for tool_name in expectation.required_job_success:
        assert_required_job_success(
            tool_name,
            actions=actions,
            tool_calls=tool_calls,
        )
    for tool_name in expectation.forbid_entity_job_success:
        assert_forbid_entity_job_success(tool_name, actions=actions)
    return {
        "scenario": scenario,
        "column": "mock_xdr",
        "required_job_success": list(expectation.required_job_success),
        "persist_hits": [hit.path for hit in expectation.persist_hits],
    }


def assert_no_mock_tool_provider(
    *,
    actions: list[dict],
    tool_calls: list[dict],
) -> None:
    """B-column: live query/disposition must not carry Canonical Mock stamps."""
    for row in (*actions, *tool_calls):
        blob = " ".join(str(row.get(key) or "") for key in _PROVIDER_FIELDS)
        if _MOCK_TOOL_PROVIDER in blob.lower():
            raise RuntimeError(
                "eventtype8 B-column forbids mock_tool_provider on query/disposition, "
                f"got {row!r}"
            )


def assert_eventtype8_sangfor_column(
    scenario: str,
    *,
    snapshot: dict | None,
    rag_output: dict | None,
    graph_output: dict | None,
    actions: list[dict],
    tool_calls: list[dict],
    llm_trace_entries: list[dict],
    event_id: str,
) -> dict[str, object]:
    """B-column (sangfor_xdr). Independent of the mock assert.

    Isolate/disable/kill-process without a vendor create URI may have
    ``owner=None`` and must not be required Job SUCCESS. ``mock_tool_provider``
    on query or disposition fails the column.
    """
    expectation = column_expectation(scenario, "sangfor_xdr")
    assert_real_llm_calls(llm_trace_entries, event_id=event_id)
    assert_no_mock_tool_provider(actions=actions, tool_calls=tool_calls)
    for hit in expectation.persist_hits:
        eval_persist_hit(
            hit,
            snapshot=snapshot,
            rag_output=rag_output if isinstance(rag_output, dict) else None,
            graph_output=graph_output if isinstance(graph_output, dict) else None,
        )
    for tool_name in expectation.required_job_success:
        assert_required_job_success(
            tool_name,
            actions=actions,
            tool_calls=tool_calls,
        )
    for tool_name in expectation.forbid_entity_job_success:
        assert_forbid_entity_job_success(tool_name, actions=actions)
    return {
        "scenario": scenario,
        "column": "sangfor_xdr",
        "required_job_success": list(expectation.required_job_success),
        "owner_may_be_none": list(expectation.owner_may_be_none),
        "persist_hits": [hit.path for hit in expectation.persist_hits],
    }


def column_expectation(scenario: str, column: EvalColumn) -> ColumnExpectation:
    if column not in {"mock_xdr", "sangfor_xdr"}:
        raise KeyError(f"unknown eval column: {column!r}")
    try:
        columns = SUITE_EXPECTATIONS[scenario]
    except KeyError as exc:
        raise KeyError(f"unknown eventtype8 scenario: {scenario!r}") from exc
    return columns[column]


def assert_suite_covers_eventtype8() -> None:
    missing = [s for s in EVENTTYPE8_SCENARIOS if s not in SUITE_EXPECTATIONS]
    extra = [s for s in SUITE_EXPECTATIONS if s not in EVENTTYPE8_SCENARIOS]
    if missing or extra:
        raise AssertionError(
            f"SUITE_EXPECTATIONS must match EVENTTYPE8_SCENARIOS; "
            f"missing={missing} extra={extra}"
        )
    for scenario, columns in SUITE_EXPECTATIONS.items():
        if set(columns) != {"mock_xdr", "sangfor_xdr"}:
            raise AssertionError(
                f"{scenario} must define both mock_xdr and sangfor_xdr columns, "
                f"got {sorted(columns)}"
            )


__all__ = [
    "ColumnExpectation",
    "EvalColumn",
    "FP_MATCHED_CASE_ID",
    "FP_MAX_SCORE_THRESHOLD",
    "ORG_CONTEXT_EXACT_MATCH_TYPES",
    "PersistHit",
    "SUITE_EXPECTATIONS",
    "TOOLS_WITHOUT_SANGFOR_CREATE_URI",
    "assert_eventtype8_mock_column",
    "assert_eventtype8_sangfor_column",
    "assert_forbid_entity_job_success",
    "assert_no_mock_tool_provider",
    "assert_real_llm_calls",
    "assert_required_job_success",
    "assert_suite_covers_eventtype8",
    "column_expectation",
    "eval_persist_hit",
    "is_exact_family_match_type",
]
