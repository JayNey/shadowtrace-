"""Seed JSON alignment for gold-path RAG (no Postgres)."""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
ATTACK_FILE = REPO_ROOT / "data" / "knowledge" / "attack_techniques.json"
HISTORY_FILE = REPO_ROOT / "data" / "knowledge" / "history_cases.json"
FP_FILE = REPO_ROOT / "data" / "knowledge" / "fp_cases.json"
_PLAYBOOKS_JSON = REPO_ROOT / "data" / "knowledge" / "playbooks.json"


def test_emotet_history_case_no_longer_reuses_gold_path_host() -> None:
    rows = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    by_id = {row["case_id"]: row for row in rows}
    emotet = by_id["case-10000003"]
    gold = by_id["case-10000017"]
    emotet_blob = f"{emotet['summary']} {emotet['key_entities']}"
    assert "PC-FIN-023" not in emotet_blob
    assert "zhangsan" not in emotet_blob
    assert "PC-FIN-023" in gold["key_entities"]
    assert "7z.exe" in gold["key_entities"]
    assert "unknown-upload-example.com" in gold["key_entities"]
    assert gold["event_type"] == "data_exfiltration"


def test_attack_seed_has_gold_path_aliases() -> None:
    payload = json.loads(ATTACK_FILE.read_text(encoding="utf-8"))
    by_id = {row["technique_id"]: row for row in payload["techniques"]}
    assert "内鬼" in (by_id["T1078"].get("aliases") or [])
    assert "7z" in " ".join(by_id["T1560.001"].get("keywords") or []).lower()
    assert "数据外泄" in (by_id["T1567"].get("aliases") or [])
    assert "可疑域名" in (by_id["T1566"].get("aliases") or [])


def test_fp_seed_has_fileshare_and_cdn_negatives() -> None:
    rows = json.loads(FP_FILE.read_text(encoding="utf-8"))
    by_id = {row["case_id"]: row for row in rows}
    assert "files.corp.internal" in by_id["case-0000000d"]["entity_pattern"]
    assert "PC-FIN-011" in by_id["case-0000000d"]["entity_pattern"]
    assert "cdn.corp.internal" in by_id["case-0000000e"]["entity_pattern"]
    assert "cdn-publisher-01" in by_id["case-0000000e"]["entity_pattern"]
    assert "PC-CDN-LAB-02" in by_id["case-0000000e"]["entity_pattern"]
    assert "ops-change-bot" in by_id["case-00000001"]["entity_pattern"]


_FP_FROZEN_EVENT_TYPE = {
    "case-00000001": "account_anomaly",
    "case-00000002": "data_exfiltration",
    "case-00000003": "other",
    "case-00000004": "other",
    "case-00000005": "other",
    "case-00000006": "other",
    "case-00000007": "other",
    "case-00000008": "other",
    "case-00000009": "other",
    "case-0000000a": "malicious_process",
    "case-0000000b": "other",
    "case-0000000c": "malicious_process",
    "case-0000000d": "data_exfiltration",
    "case-0000000e": "other",
}

_FP_BANNED_GLOBS = (
    "PC-FIN-*",
    "office-user-*",
    "PC-OFFICE-*",
    "finance-*",
)

_FP_TRUE_POSITIVE_BAN = (
    "PC-FIN-023",
    "zhangsan",
    "unknown-upload-example.com",
    "brand-new-cdn-example.net",
    "svc-admin-abuse",
    "SRV-ADMIN-003",
    "WKS-HOST-007",
    "svc-beacon-007",
    "beacon.exe",
    "beacon-example.test",
    "DEV-WKS-012",
    "dev-user-012",
    "ransomware_stage.exe",
    "JUMP-HOST-001",
    "ops-jump-001",
    "SRV-CORE-002",
    "mstsc.exe",
    "net.exe",
    "office-user-014",
    "PC-OFFICE-014",
    "general-user-099",
)


def _fp_searchable_blob(row: dict) -> str:
    return " ".join(
        str(row.get(key) or "")
        for key in ("pattern_summary", "alert_signature", "entity_pattern", "fp_reason")
    )


def test_fp_seed_p1a_frozen_event_types_and_ban_tokens() -> None:
    from app.models.case import FalsePositiveCase, fp_case_metadata, fp_case_to_text

    rows = json.loads(FP_FILE.read_text(encoding="utf-8"))
    assert len(rows) == 14
    by_id = {row["case_id"]: row for row in rows}
    assert set(by_id) == set(_FP_FROZEN_EVENT_TYPE)
    typed = [row["event_type"] for row in rows]
    assert typed.count("account_anomaly") == 1
    assert "suspicious_domain" not in typed
    for case_id, event_type in _FP_FROZEN_EVENT_TYPE.items():
        assert by_id[case_id]["event_type"] == event_type
        parsed = FalsePositiveCase.model_validate(by_id[case_id])
        assert parsed.event_type.value == event_type
        assert fp_case_metadata(parsed)["event_type"] == event_type
        assert event_type in fp_case_to_text(parsed)

    zero_d = _fp_searchable_blob(by_id["case-0000000d"])
    assert "PC-FIN-011" in zero_d
    assert "files.corp.internal" in zero_d
    zero_e = _fp_searchable_blob(by_id["case-0000000e"])
    assert "office-user-014" not in zero_e
    assert "brand-new-cdn-example.net" not in zero_e
    assert "cdn.corp.internal" in zero_e

    zero_b = _fp_searchable_blob(by_id["case-0000000b"])
    assert "monthend-export-bot" in zero_b
    assert "FIN-APP-02" in zero_b
    assert by_id["case-0000000b"]["event_type"] == "other"

    corpus = " ".join(_fp_searchable_blob(row) for row in rows)
    for token in _FP_TRUE_POSITIVE_BAN:
        assert token not in corpus
    for glob in _FP_BANNED_GLOBS:
        assert glob not in corpus


def test_fp_seed_p1b_backup_and_scanner_aliases() -> None:
    rows = json.loads(FP_FILE.read_text(encoding="utf-8"))
    by_id = {row["case_id"]: row for row in rows}
    assert len(rows) == 14

    backup = _fp_searchable_blob(by_id["case-00000002"])
    assert "svc-backup" in backup
    assert "backup-svc" in backup
    assert "BACKUP-SRV-03" in backup
    assert "files.corp.internal" in backup

    scanner = _fp_searchable_blob(by_id["case-00000003"])
    assert "SCANNER-01" in scanner
    assert "scanner-svc" in scanner
    assert "vuln-scanner-01" in scanner
    assert "10.20.0.15" in scanner


def test_history_seed_aligns_other_unclassified_host() -> None:
    rows = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    by_id = {row["case_id"]: row for row in rows}
    other = by_id["case-10000021"]
    assert other["event_type"] == "other"
    assert "unclassified" in other["summary"]
    assert "insufficient context" in other["summary"]
    assert "WKS-GEN-099" in other["summary"]
    assert "general-user-099" in other["summary"]
    assert "unclassified" in other["key_entities"]
    assert "insufficient context" in other["key_entities"]
    assert "WKS-GEN-099" in other["key_entities"]
    assert "general-user-099" in other["key_entities"]
    gen_hits = [
        row
        for row in rows
        if row.get("event_type") == "other"
        and "WKS-GEN-099" in row.get("key_entities", "")
    ]
    assert [row["case_id"] for row in gen_hits] == ["case-10000021"]


def test_history_seed_fixture_true_positives_and_frozen_counts() -> None:
    rows = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    by_id = {row["case_id"]: row for row in rows}

    usb = by_id["case-10000007"]
    assert usb["event_type"] == "insider_threat"
    assert "U 盘" in usb["summary"]
    assert "svc-admin-abuse" not in usb["summary"]
    assert "resigning_dev" in usb["key_entities"]

    host = by_id["case-10000022"]
    assert host["event_type"] == "host_compromise"
    assert host["case_label"] == "true_positive"
    for token in (
        "WKS-HOST-007",
        "svc-beacon-007",
        "beacon.exe",
        "beacon-example.test",
        "isolate",
        "scan",
    ):
        assert token in host["summary"]
        assert token in host["key_entities"]

    mp = by_id["case-10000023"]
    assert mp["event_type"] == "malicious_process"
    for token in ("DEV-WKS-012", "ransomware_stage.exe", "block_process"):
        assert token in mp["summary"]
        assert token in mp["key_entities"]

    insider = by_id["case-10000024"]
    assert insider["event_type"] == "insider_threat"
    for token in ("svc-admin-abuse", "SRV-ADMIN-003", "net.exe", "disable_account"):
        assert token in insider["summary"]
        assert token in insider["key_entities"]

    lateral = by_id["case-10000025"]
    assert lateral["event_type"] == "lateral_movement"
    for token in (
        "JUMP-HOST-001",
        "SRV-CORE-002",
        "mstsc.exe",
        "ops-jump-001",
        "lateral movement",
    ):
        assert token in lateral["summary"]
        assert token in lateral["key_entities"]

    assert sum(1 for row in rows if row.get("event_type") == "account_anomaly") == 3
    assert sum(1 for row in rows if row.get("event_type") == "data_exfiltration") == 4
    assert "case-10000026" not in by_id


def test_attack_t1021_keywords_align_lateral_fixture() -> None:
    from app.rag.keyword_aliases import keyword_queries_for_kb

    payload = json.loads(ATTACK_FILE.read_text(encoding="utf-8"))
    by_id = {row["technique_id"]: row for row in payload["techniques"]}
    keywords = " ".join(by_id["T1021"].get("keywords") or [])
    assert "JUMP-HOST-001" in keywords
    assert "RDP" in keywords
    assert "mstsc.exe" in keywords
    assert "lateral" in keywords.lower()
    queries = keyword_queries_for_kb(
        "attack_kb",
        "Event type: lateral_movement. RDP pivot mstsc.exe from JUMP-HOST-001.",
    )
    blob = " ".join(queries).lower()
    seed = keywords.lower()
    assert "lateral movement" in blob
    assert "lateral movement" in seed or "lateral" in seed


def test_attack_seed_p2_count_and_fixture_keywords() -> None:
    payload = json.loads(ATTACK_FILE.read_text(encoding="utf-8"))
    techniques = payload["techniques"]
    assert len(techniques) == 79
    ids = [row["technique_id"] for row in techniques]
    assert "T1021.001" not in ids
    assert "T1570" not in ids
    by_id = {row["technique_id"]: row for row in techniques}

    t1071 = " ".join(by_id["T1071"].get("keywords") or [])
    assert "beacon.exe" in t1071
    assert "beacon-example.test" in t1071

    t1021 = " ".join(by_id["T1021"].get("keywords") or [])
    assert "JUMP-HOST-001" in t1021
    assert "mstsc.exe" in t1021

    t1078_detection = by_id["T1078"].get("detection") or ""
    assert "zhangsan" in t1078_detection
    assert "PC-FIN-023" in t1078_detection
    t1078_blob = " ".join(
        [
            " ".join(by_id["T1078"].get("keywords") or []),
            " ".join(by_id["T1078"].get("aliases") or []),
            by_id["T1078"].get("description") or "",
            t1078_detection,
        ]
    )
    assert "ops-change-bot" not in t1078_blob

    ops_ids = [
        row["technique_id"]
        for row in techniques
        if "ops-change-bot" in json.dumps(row, ensure_ascii=False)
    ]
    assert ops_ids == ["T1110"]

    t1059_kw = " ".join(by_id["T1059"].get("keywords") or [])
    t1218_kw = " ".join(by_id["T1218"].get("keywords") or [])
    assert "ransomware_stage.exe" in t1059_kw
    assert "ransomware_stage.exe" in t1218_kw
    assert "beacon.exe" not in t1059_kw
    assert "net.exe" in " ".join(by_id["T1134"].get("keywords") or [])

    t1047_kw = " ".join(by_id["T1047"].get("keywords") or [])
    assert "WMI" in t1047_kw
    assert "lateral" in t1047_kw.lower()
    assert "JUMP-HOST-001" not in t1047_kw
    assert "mstsc.exe" not in t1047_kw

    for row in techniques:
        aliases = " ".join(row.get("aliases") or [])
        if "beacon.exe" in aliases:
            assert "ransomware_stage.exe" not in aliases
        if "ransomware_stage.exe" in aliases:
            assert "beacon.exe" not in aliases

    beacon_ids = [
        row["technique_id"]
        for row in techniques
        if "beacon.exe" in " ".join(row.get("keywords") or [])
    ]
    assert beacon_ids == ["T1071"]
    ransomware_ids = [
        row["technique_id"]
        for row in techniques
        if "ransomware_stage.exe" in " ".join(row.get("keywords") or [])
    ]
    assert set(ransomware_ids) == {"T1059", "T1218"}
    net_ids = [
        row["technique_id"]
        for row in techniques
        if "net.exe" in " ".join(row.get("keywords") or [])
    ]
    assert net_ids == ["T1134"]


def test_playbook_seed_malicious_process_has_block_and_query() -> None:
    playbooks = json.loads(_PLAYBOOKS_JSON.read_text(encoding="utf-8"))
    rows = playbooks.get("playbooks") or []
    mp = [row for row in rows if row.get("event_type") == "malicious_process"]
    assert mp
    tools = {step.get("tool_name") for row in mp for step in row.get("steps") or []}
    assert "block_process" in tools
    assert "query_edr_process" in tools


def test_playbook_seed_insider_high_containment_applies_at_medium() -> None:
    """Privilege-abuse eval can land medium after RiskAgent; still must bind disable_account."""
    playbooks = json.loads(_PLAYBOOKS_JSON.read_text(encoding="utf-8"))
    rows = playbooks.get("playbooks") or []
    high = next(row for row in rows if row.get("playbook_id") == "pb-3c4d5e6f")
    assert high["event_type"] == "insider_threat"
    assert high["min_severity"] == "medium"
    first = (high.get("steps") or [])[0]
    assert first.get("tool_name") == "disable_account"


def test_playbook_seed_lateral_containment_starts_with_block_ip() -> None:
    playbooks = json.loads(_PLAYBOOKS_JSON.read_text(encoding="utf-8"))
    rows = playbooks.get("playbooks") or []
    containment = next(row for row in rows if row.get("playbook_id") == "pb-2a3b4c5d")
    assert containment["event_type"] == "lateral_movement"
    assert containment["min_severity"] == "medium"
    first = (containment.get("steps") or [])[0]
    assert first.get("tool_name") == "block_ip"


def test_playbook_seed_p0_anchors_unchanged_count_and_gold_refs() -> None:
    playbooks = json.loads(_PLAYBOOKS_JSON.read_text(encoding="utf-8"))
    rows = playbooks.get("playbooks") or []
    assert len(rows) == 13
    domain = [row for row in rows if row.get("event_type") == "suspicious_domain"]
    assert len(domain) == 1
    assert domain[0]["playbook_id"] == "pb-c8d9e0f1"
    assert domain[0]["min_severity"] == "medium"
    assert (domain[0].get("steps") or [])[0].get("tool_name") == "block_domain"
    host = [row for row in rows if row.get("event_type") == "host_compromise"]
    assert [row["playbook_id"] for row in host] == ["pb-1c2d3e4f"]
    insider = next(row for row in rows if row.get("playbook_id") == "pb-3c4d5e6f")
    assert insider["min_severity"] == "medium"
    lateral = next(row for row in rows if row.get("playbook_id") == "pb-2a3b4c5d")
    assert lateral["min_severity"] == "medium"


def test_org_seed_p0_person_status_and_frozen_allow() -> None:
    from app.knowledge.org_context_seed import mock_org_context_records

    records = mock_org_context_records()
    by_id = {row.record_id: row for row in records}
    for record_id in (
        "org-person-zhangsan",
        "org-person-office-user-014",
        "org-person-general-user-099",
    ):
        row = by_id[record_id]
        assert row.kind == "person_status"
        assert "≠" in row.content
    abuse = by_id["org-acct-svc-admin-abuse"]
    assert abuse.kind == "account_role"
    assert abuse.accounts == ("svc-admin-abuse",)
    admin_src = by_id["org-src-srv-admin-003"]
    assert admin_src.kind == "allowed_source"
    assert admin_src.hosts == ("SRV-ADMIN-003",)
    backup = by_id["org-window-nightly-backup"]
    assert backup.window_start == "02:00"
    assert backup.window_end == "04:00"
    jump_allow = [
        row
        for row in records
        if row.kind == "allowed_source" and "JUMP-HOST-001" in row.hosts
    ]
    assert jump_allow == []
    window = by_id["org-window-ops-change"]
    assert window.kind == "time_window"
    assert window.window_start == "08:00"
    assert window.window_end == "12:00"
    assert window.accounts == ("ops-change-bot",)
    assert window.hosts == ("PC-OPS-JUMP-01",)
    jump_explain = by_id["org-data-jump-host-not-approved"]
    assert jump_explain.kind == "data_handling"
    assert jump_explain.hosts == ()
    assert jump_explain.accounts == ()
    beacon = by_id["org-data-beacon-c2-unapproved"]
    assert beacon.domains == ("beacon-example.test",)
    ransomware = by_id["org-data-ransomware-stage-not-approved"]
    assert "ransomware_stage.exe" in ransomware.content
