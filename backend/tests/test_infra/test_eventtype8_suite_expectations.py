"""EventType-8 two-column expectation unit tests (no real LLM)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = REPO_ROOT / "scripts"


def _load_module(name: str, path: Path):
    scripts_dir = str(SCRIPTS)
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def expect_mod():
    return _load_module(
        "eventtype8_suite_expectations_under_test",
        SCRIPTS / "eventtype8_suite_expectations.py",
    )


def test_suite_covers_all_eventtype8_scenarios(expect_mod) -> None:
    expect_mod.assert_suite_covers_eventtype8()
    assert len(expect_mod.SUITE_EXPECTATIONS) == 8


def test_insider_columns_differ_on_isolate_success_vs_owner_none(expect_mod) -> None:
    mock_col = expect_mod.column_expectation("insider_data_exfiltration", "mock_xdr")
    sangfor_col = expect_mod.column_expectation("insider_data_exfiltration", "sangfor_xdr")
    assert "isolate_host" in mock_col.required_job_success
    assert mock_col.owner_may_be_none == ()
    assert "isolate_host" in sangfor_col.owner_may_be_none
    assert "isolate_host" not in sangfor_col.required_job_success


def test_fp_persist_uses_matched_case_id_and_score_not_nonempty(expect_mod) -> None:
    mock_col = expect_mod.column_expectation("account_anomaly_fp", "mock_xdr")
    paths = {hit.path: hit for hit in mock_col.persist_hits}
    assert "fp_similarity.matched_case_id" in paths
    assert paths["fp_similarity.matched_case_id"].equals == expect_mod.FP_MATCHED_CASE_ID
    assert paths["fp_similarity.max_score"].min_score == expect_mod.FP_MAX_SCORE_THRESHOLD
    assert mock_col.fp_full_loop_gate is True
    assert mock_col.skip_entity_response is True


def test_other_unclassified_skips_entity_jobs_and_requires_similar_cases(expect_mod) -> None:
    mock_col = expect_mod.column_expectation("other_unclassified", "mock_xdr")
    assert mock_col.skip_entity_response is True
    assert mock_col.required_job_success == ()
    assert "isolate_host" in mock_col.forbid_entity_job_success
    assert "block_ip" in mock_col.forbid_entity_job_success
    paths = {hit.path: hit for hit in mock_col.persist_hits}
    assert paths["similar_cases"].nonempty_list is True


def test_org_persist_uses_match_type_exact(expect_mod) -> None:
    mock_col = expect_mod.column_expectation("insider_privilege_abuse", "mock_xdr")
    org_hits = [hit for hit in mock_col.persist_hits if hit.path == "org_context_matches"]
    assert org_hits
    assert org_hits[0].match_type == "exact"
    assert "disable_account" in mock_col.required_job_success
    sangfor_col = expect_mod.column_expectation("insider_privilege_abuse", "sangfor_xdr")
    assert "disable_account" in sangfor_col.owner_may_be_none


def test_host_compromise_a_requires_scan_b_allows_owner_none(expect_mod) -> None:
    mock_col = expect_mod.column_expectation("host_compromise", "mock_xdr")
    sangfor_col = expect_mod.column_expectation("host_compromise", "sangfor_xdr")
    assert "scan_host_for_virus" in mock_col.required_job_success
    assert "isolate_host" in sangfor_col.owner_may_be_none
    assert mock_col.required_job_success != sangfor_col.required_job_success


def test_column_expectation_rejects_unknown_column(expect_mod) -> None:
    with pytest.raises(KeyError, match="unknown eval column"):
        expect_mod.column_expectation("insider_data_exfiltration", "live")  # type: ignore[arg-type]


_LLM_OK = [
    {
        "entry_type": "llm_call",
        "detail": {"model_name": "qwen-plus", "status": "success"},
    }
]


def _isolate_success(*, owner: str | None = "direct_tool") -> list[dict]:
    return [
        {
            "action_id": "act-iso",
            "tool_name": "isolate_host",
            "status": "success",
            "execution_owner": owner,
            "effect_verification_status": "verified",
        }
    ]


def test_mock_column_isolate_success_passes(expect_mod) -> None:
    result = expect_mod.assert_eventtype8_mock_column(
        "insider_data_exfiltration",
        snapshot={},
        rag_output={},
        graph_output=None,
        actions=_isolate_success(),
        tool_calls=[],
        llm_trace_entries=_LLM_OK,
        event_id="evt-iso",
    )
    assert result["column"] == "mock_xdr"
    assert "isolate_host" in result["required_job_success"]


def test_mock_column_owner_none_fails(expect_mod) -> None:
    with pytest.raises(RuntimeError, match="owner=None"):
        expect_mod.assert_eventtype8_mock_column(
            "insider_data_exfiltration",
            snapshot={},
            rag_output={},
            graph_output=None,
            actions=_isolate_success(owner=None),
            tool_calls=[],
            llm_trace_entries=_LLM_OK,
            event_id="evt-iso",
        )


def test_mock_column_unverified_effect_fails(expect_mod) -> None:
    with pytest.raises(RuntimeError, match="effect_verification_status"):
        expect_mod.assert_eventtype8_mock_column(
            "insider_data_exfiltration",
            snapshot={},
            rag_output={},
            graph_output=None,
            actions=[
                {
                    "tool_name": "isolate_host",
                    "status": "success",
                    "execution_owner": "direct_tool",
                    "effect_verification_status": None,
                }
            ],
            tool_calls=[],
            llm_trace_entries=_LLM_OK,
            event_id="evt-iso",
        )


def test_fp_persist_matched_case_id_and_score(expect_mod) -> None:
    expect_mod.assert_eventtype8_mock_column(
        "account_anomaly_fp",
        snapshot={},
        rag_output={
            "fp_similarity": {
                "matched_case_id": expect_mod.FP_MATCHED_CASE_ID,
                "max_score": 0.91,
            }
        },
        graph_output=None,
        actions=[],
        tool_calls=[],
        llm_trace_entries=_LLM_OK,
        event_id="evt-fp",
    )


def test_fp_forbid_isolate_success(expect_mod) -> None:
    with pytest.raises(RuntimeError, match="forbids isolate_host"):
        expect_mod.assert_eventtype8_mock_column(
            "account_anomaly_fp",
            snapshot={},
            rag_output={
                "fp_similarity": {
                    "matched_case_id": expect_mod.FP_MATCHED_CASE_ID,
                    "max_score": 0.91,
                }
            },
            graph_output=None,
            actions=_isolate_success(),
            tool_calls=[],
            llm_trace_entries=_LLM_OK,
            event_id="evt-fp",
        )


def test_org_exact_family_account_exact_passes(expect_mod) -> None:
    expect_mod.eval_persist_hit(
        expect_mod.column_expectation("insider_privilege_abuse", "mock_xdr").persist_hits[0],
        snapshot={
            "org_context_matches": [{"match_type": "account_exact", "entity": "svc-admin-abuse"}]
        },
        rag_output={},
        graph_output=None,
    )


def test_graph_output_requires_edges_or_features(expect_mod) -> None:
    hit = expect_mod.column_expectation("lateral_movement", "mock_xdr").persist_hits[0]
    with pytest.raises(RuntimeError, match="edges or summary.features"):
        expect_mod.eval_persist_hit(
            hit,
            snapshot={},
            rag_output={},
            graph_output={"edges": []},
        )
    expect_mod.eval_persist_hit(
        hit,
        snapshot={},
        rag_output={},
        graph_output={"edges": [{"src": "JUMP-HOST-001", "dst": "SRV-CORE-002"}]},
    )


def test_real_llm_calls_reject_mock_model(expect_mod) -> None:
    with pytest.raises(RuntimeError, match="MockLLM"):
        expect_mod.assert_real_llm_calls(
            [
                {
                    "entry_type": "llm_call",
                    "detail": {"model_name": "mock-model", "status": "success"},
                }
            ],
            event_id="evt-x",
        )


def test_sangfor_column_allows_owner_none_and_does_not_require_isolate(
    expect_mod,
) -> None:
    result = expect_mod.assert_eventtype8_sangfor_column(
        "insider_data_exfiltration",
        snapshot={},
        rag_output={},
        graph_output=None,
        actions=_isolate_success(owner=None),
        tool_calls=[],
        llm_trace_entries=_LLM_OK,
        event_id="evt-iso-b",
    )
    assert result["column"] == "sangfor_xdr"
    assert "isolate_host" in result["owner_may_be_none"]
    assert "isolate_host" not in result["required_job_success"]
    empty = expect_mod.assert_eventtype8_sangfor_column(
        "insider_data_exfiltration",
        snapshot={},
        rag_output={},
        graph_output=None,
        actions=[],
        tool_calls=[],
        llm_trace_entries=_LLM_OK,
        event_id="evt-iso-b-empty",
    )
    assert empty["required_job_success"] == []


def test_sangfor_column_rejects_mock_tool_provider_on_disposition(expect_mod) -> None:
    with pytest.raises(RuntimeError, match="mock_tool_provider"):
        expect_mod.assert_eventtype8_sangfor_column(
            "insider_data_exfiltration",
            snapshot={},
            rag_output={},
            graph_output=None,
            actions=[
                {
                    "action_id": "act-iso",
                    "tool_name": "isolate_host",
                    "status": "success",
                    "execution_owner": None,
                    "provider_name": "mock_tool_provider",
                }
            ],
            tool_calls=[],
            llm_trace_entries=_LLM_OK,
            event_id="evt-iso-mock",
        )


def test_sangfor_column_rejects_mock_tool_provider_on_query(expect_mod) -> None:
    with pytest.raises(RuntimeError, match="mock_tool_provider"):
        expect_mod.assert_eventtype8_sangfor_column(
            "malicious_process",
            snapshot={},
            rag_output={"playbook_refs": [{"playbook_id": "pb-mp"}]},
            graph_output=None,
            actions=[],
            tool_calls=[
                {
                    "tool_name": "query_edr_process",
                    "status": "success",
                    "provider_name": "mock_tool_provider",
                }
            ],
            llm_trace_entries=_LLM_OK,
            event_id="evt-query-mock",
        )


def test_sangfor_and_mock_asserts_are_not_the_same_function(expect_mod) -> None:
    assert (
        expect_mod.assert_eventtype8_sangfor_column
        is not expect_mod.assert_eventtype8_mock_column
    )
    sangfor = expect_mod.column_expectation("host_compromise", "sangfor_xdr")
    mock = expect_mod.column_expectation("host_compromise", "mock_xdr")
    assert "scan_host_for_virus" in mock.required_job_success
    assert "scan_host_for_virus" not in sangfor.required_job_success
    assert "isolate_host" in sangfor.owner_may_be_none
