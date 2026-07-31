"""Contract drift gate tests (ISSUE-112)."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS = _REPO_ROOT / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from contract_export_lib import (  # noqa: E402
    compare_contract_trees,
    export_all_contracts,
)


def _load_check_module():
    spec = importlib.util.spec_from_file_location(
        "check_contract_drift",
        _SCRIPTS / "check_contract_drift.py",
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_fresh_export_is_deterministic() -> None:
    with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
        root_a = Path(tmp_a) / "contracts"
        root_b = Path(tmp_b) / "contracts"
        export_all_contracts(root_a)
        export_all_contracts(root_b)
        assert compare_contract_trees(root_a, root_b) == []


def test_compare_detects_stale_committed_file() -> None:
    with tempfile.TemporaryDirectory() as expected_tmp, tempfile.TemporaryDirectory() as actual_tmp:
        expected = Path(expected_tmp)
        actual = Path(actual_tmp)
        (expected / "schemas").mkdir()
        (actual / "schemas").mkdir()
        (expected / "schemas" / "StaleModel.json").write_text("{}\n", encoding="utf-8")
        (actual / "schemas" / "SecurityEvent.json").write_text("{}\n", encoding="utf-8")

        diffs = compare_contract_trees(expected, actual)
        kinds = {item.kind for item in diffs}
        assert "stale_committed" in kinds
        assert "missing_committed" in kinds


def test_check_contract_drift_passes_on_current_repo() -> None:
    mod = _load_check_module()
    assert mod.main() == 0


def test_check_contract_drift_fails_when_openapi_differs() -> None:
    mod = _load_check_module()
    with tempfile.TemporaryDirectory() as tmp:
        fake_root = Path(tmp) / "contracts"
        fake_root.mkdir()
        (fake_root / "openapi").mkdir()
        (fake_root / "openapi" / "openapi.json").write_text('{"changed": true}\n', encoding="utf-8")

        original = mod.COMMITTED_CONTRACTS_ROOT
        try:
            mod.COMMITTED_CONTRACTS_ROOT = fake_root
            assert mod.main() == 1
        finally:
            mod.COMMITTED_CONTRACTS_ROOT = original


def test_export_env_pins_event_chat_route() -> None:
    from app.contracts.export_env import CONTRACT_EXPORT_ENV, apply_contract_export_env
    from app.main import app

    apply_contract_export_env()
    assert CONTRACT_EXPORT_ENV["EVENT_CHAT_ENABLED"] == "true"
    schema = app.openapi()
    assert "/api/v1/events/{event_id}/chat" in schema["paths"]
