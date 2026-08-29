"""Unit tests for mock-embedding keyword query reduction."""

from __future__ import annotations

from app.rag.keyword_aliases import (
    expand_keyword_query,
    extra_keyword_queries,
    keyword_queries_for_kb,
    keyword_query_for_kb,
)


def test_exact_chinese_exfil_maps_to_exfiltration() -> None:
    assert expand_keyword_query("数据外泄") == "exfiltration"


def test_verbose_attack_query_becomes_short_fts() -> None:
    query = (
        "Event type: data_exfiltration. Alert severity: critical. "
        "Behavior evidence: 7z.exe a finance_report.zip"
    )
    queries = keyword_queries_for_kb("attack_kb", query)
    assert "exfiltration" in queries
    assert "archive" in queries
    assert keyword_query_for_kb("attack_kb", query) == "exfiltration"


def test_demo_iocs_are_not_hardcoded_aliases() -> None:
    from app.rag import keyword_aliases as module

    blob = " ".join(needle for needle, _expansion in module._CONTAINS_ALIASES)
    assert "unknown-upload-example.com" not in blob
    assert "brand-new-cdn-example.net" not in blob
    assert "finance_report" not in blob
    assert "ops-change-bot" not in blob
    assert "JUMP-HOST-001" not in blob
    assert "svc-admin-abuse" not in blob
    assert "WKS-GEN-099" not in blob


def test_host_compromise_maps_to_credential_dumping_not_valid_accounts() -> None:
    query = "Event type: host_compromise. Alert severity: high."
    queries = keyword_queries_for_kb("attack_kb", query)
    assert "credential dumping" in queries
    assert "scripting" in queries
    assert all("valid accounts" not in item for item in queries)


def test_history_query_uses_host_entity_not_stopwords() -> None:
    query = (
        "Historical case with event type data_exfiltration. "
        "Entities: Host:PC-FIN-023, Account:zhangsan, Process:7z.exe"
    )
    reduced = keyword_query_for_kb("history_case_kb", query)
    assert "PC-FIN-023" in reduced
    assert "Event" not in reduced
    assert "type" not in reduced.split()


def test_fp_ops_bot_query_is_and_safe() -> None:
    alert = (
        "Bulk login by ops account during change window: ops-change-bot "
        "executed automated password rotation from PC-OPS-JUMP-01"
    )
    reduced = keyword_query_for_kb("fp_case_kb", alert)
    assert "ops-change-bot" in reduced
    assert "Bulk" not in reduced
    assert "False" not in reduced


def test_playbook_query_uses_event_type_slug() -> None:
    query = "SOAR playbook for event type data_exfiltration, severity high."
    assert keyword_query_for_kb("playbook_kb", query) == "data_exfiltration"


def test_playbook_query_hits_malicious_process_slug() -> None:
    query = "SOAR playbook for event type malicious_process, severity high."
    assert keyword_query_for_kb("playbook_kb", query) == "malicious_process"


def test_history_query_hits_unclassified_host() -> None:
    query = (
        "Historical case with event type other. "
        "Entities: Host:WKS-GEN-099, Account:general-user-099"
    )
    reduced = keyword_query_for_kb("history_case_kb", query)
    assert "WKS-GEN-099" in reduced


def test_attack_lateral_query_keeps_rdp_fixture_tokens() -> None:
    query = "Event type: lateral_movement. RDP pivot mstsc.exe from JUMP-HOST-001."
    queries = keyword_queries_for_kb("attack_kb", query)
    blob = " ".join(queries).lower()
    assert "lateral movement" in blob


def test_playbook_without_event_type_skips_keyword() -> None:
    assert keyword_queries_for_kb("playbook_kb", "generic SOAR response notes") == []


def test_structured_query_skips_rewrite() -> None:
    from app.rag.query_rewrite_policy import should_skip_query_rewrite

    assert should_skip_query_rewrite("Event type: data_exfiltration. Host:pc-1") is True
    assert should_skip_query_rewrite("Historical case with event type insider_threat.") is True
    assert should_skip_query_rewrite("login") is False


def test_insider_phrase_extra_queries() -> None:
    extras = extra_keyword_queries("内鬼外泄 7z.exe")
    assert extras
    assert any("insider" in item or "archive" in item for item in extras)


def test_fp_labeled_account_host_and_is_first_keyword_road() -> None:
    query = (
        "False positive pattern for event type account_anomaly, severity low. "
        "Account:ops-change-bot Host:PC-OPS-JUMP-01 Process:net.exe"
    )
    roads = keyword_queries_for_kb("fp_case_kb", query, limit=2)
    assert any("ops-change-bot" in item and "PC-OPS-JUMP-01" in item for item in roads)
    assert "ops-change-bot" in roads[0]
    assert "PC-OPS-JUMP-01" in roads[0]
    assert "net.exe" not in roads[0]
