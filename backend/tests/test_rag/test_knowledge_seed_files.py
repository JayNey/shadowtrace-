"""Seed JSON alignment for gold-path RAG (no Postgres)."""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
ATTACK_FILE = REPO_ROOT / "data" / "knowledge" / "attack_techniques.json"
HISTORY_FILE = REPO_ROOT / "data" / "knowledge" / "history_cases.json"
FP_FILE = REPO_ROOT / "data" / "knowledge" / "fp_cases.json"


def test_emotet_history_case_no_longer_reuses_gold_path_host() -> None:
    rows = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    by_id = {row["case_id"]: row for row in rows}
    emotet = by_id["case-10000003"]
    gold = by_id["case-10000017"]
    assert "PC-FIN-023" not in emotet["key_entities"]
    assert "zhangsan" not in emotet["key_entities"]
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
    assert "cdn.corp.internal" in by_id["case-0000000e"]["entity_pattern"]
    assert "ops-change-bot" in by_id["case-00000001"]["entity_pattern"]


def test_history_seed_aligns_other_unclassified_host() -> None:
    rows = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    hits = [row for row in rows if row.get("event_type") == "other" and "WKS-GEN-099" in row.get("key_entities", "")]
    assert hits, "history_case_kb must include WKS-GEN-099 for other_unclassified"
    assert any("general-user-099" in row["key_entities"] for row in hits)


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


def test_playbook_seed_malicious_process_has_block_and_query() -> None:
    playbooks = json.loads((REPO_ROOT / "data" / "knowledge" / "playbooks.json").read_text(encoding="utf-8"))
    rows = playbooks.get("playbooks") or []
    mp = [row for row in rows if row.get("event_type") == "malicious_process"]
    assert mp
    tools = {step.get("tool_name") for row in mp for step in row.get("steps") or []}
    assert "block_process" in tools
    assert "query_edr_process" in tools


def test_playbook_seed_insider_high_containment_applies_at_medium() -> None:
    """Privilege-abuse eval can land medium after RiskAgent; still must bind disable_account."""
    playbooks = json.loads((REPO_ROOT / "data" / "knowledge" / "playbooks.json").read_text(encoding="utf-8"))
    rows = playbooks.get("playbooks") or []
    high = next(row for row in rows if row.get("playbook_id") == "pb-3c4d5e6f")
    assert high["event_type"] == "insider_threat"
    assert high["min_severity"] == "medium"
    first = (high.get("steps") or [])[0]
    assert first.get("tool_name") == "disable_account"


def test_playbook_seed_lateral_containment_starts_with_block_ip() -> None:
    playbooks = json.loads((REPO_ROOT / "data" / "knowledge" / "playbooks.json").read_text(encoding="utf-8"))
    rows = playbooks.get("playbooks") or []
    containment = next(row for row in rows if row.get("playbook_id") == "pb-2a3b4c5d")
    assert containment["event_type"] == "lateral_movement"
    assert containment["min_severity"] == "medium"
    first = (containment.get("steps") or [])[0]
    assert first.get("tool_name") == "block_ip"
