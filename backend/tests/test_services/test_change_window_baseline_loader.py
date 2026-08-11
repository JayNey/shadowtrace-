"""ISSUE-313 change-window baseline loader tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.config import Settings
from app.services.change_window_baseline_loader import (
    load_change_window_baseline,
    probe_change_window_baseline,
    resolve_change_window_baseline_path,
)


def _write_baseline(path: Path, *, tenant_id: str = "tenant-demo") -> None:
    payload = {
        "schema_version": 1,
        "tenants": [
            {
                "tenant_id": tenant_id,
                "change_windows": [
                    {
                        "window_id": "cw-test",
                        "authorized_accounts": ["ops-change-bot"],
                        "authorized_actions": ["login"],
                        "authorized_asset_groups": ["ops"],
                        "valid_from": "2024-06-15T08:00:00+00:00",
                        "valid_until": "2024-06-15T12:00:00+00:00",
                    }
                ],
            }
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_resolve_path_uses_explicit_argument(tmp_path: Path) -> None:
    target = tmp_path / "custom" / "change_windows.json"
    _write_baseline(target)
    assert resolve_change_window_baseline_path(str(target)) == target


def test_resolve_path_uses_settings_override(tmp_path: Path) -> None:
    target = tmp_path / "settings" / "change_windows.json"
    _write_baseline(target)
    settings = Settings(CHANGE_WINDOW_BASELINE_PATH=str(target))
    assert resolve_change_window_baseline_path(settings=settings) == target


def test_resolve_path_walks_up_from_module_to_repo_data() -> None:
    resolved = resolve_change_window_baseline_path()
    assert resolved.name == "change_windows.json"
    assert "organization" in resolved.parts
    assert resolved.is_file()


def test_container_layout_path_is_used_when_file_exists(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    container_path = tmp_path / "app" / "data" / "organization" / "change_windows.json"
    _write_baseline(container_path)

    import app.services.change_window_baseline_loader as loader

    monkeypatch.setattr(loader, "_CONTAINER_BASELINE_PATH", container_path)
    monkeypatch.setattr(loader, "_walk_up_for_baseline", lambda _start: None)
    assert resolve_change_window_baseline_path() == container_path


def test_probe_reports_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    settings = Settings(CHANGE_WINDOW_BASELINE_PATH=str(missing))
    probe = probe_change_window_baseline(settings)
    assert probe["status"] == "unavailable"
    assert probe["resolved_path"] == str(missing)
    assert "file_missing" in probe["reasons"]


def test_probe_ready_when_tenant_present(tmp_path: Path) -> None:
    target = tmp_path / "change_windows.json"
    _write_baseline(target)
    settings = Settings(CHANGE_WINDOW_BASELINE_PATH=str(target))
    probe = probe_change_window_baseline(settings)
    assert probe["status"] == "ready"
    assert "tenant-demo" in probe["tenant_ids"]


def test_load_indexes_tenant(tmp_path: Path) -> None:
    load_change_window_baseline.cache_clear()
    target = tmp_path / "change_windows.json"
    _write_baseline(target)
    indexed = load_change_window_baseline(str(target))
    assert "tenant-demo" in indexed
    assert indexed["tenant-demo"].change_windows[0].window_id == "cw-test"
