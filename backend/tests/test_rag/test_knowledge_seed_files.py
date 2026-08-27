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
