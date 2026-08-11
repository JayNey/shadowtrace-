"""ISSUE-313 change-window baseline loader tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.config import Settings
from app.services.change_window_baseline_loader import (
    assert_demo_eval_baseline_available,
    clear_change_window_baseline_cache,
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
    clear_change_window_baseline_cache()
    target = tmp_path / "change_windows.json"
    _write_baseline(target)
    indexed = load_change_window_baseline(str(target))
    assert "tenant-demo" in indexed
    assert indexed["tenant-demo"].change_windows[0].window_id == "cw-test"


def test_probe_degraded_when_tenant_windows_empty(tmp_path: Path) -> None:
    target = tmp_path / "empty_windows.json"
    target.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "tenants": [{"tenant_id": "tenant-demo", "change_windows": []}],
            }
        ),
        encoding="utf-8",
    )
    settings = Settings(CHANGE_WINDOW_BASELINE_PATH=str(target))
    probe = probe_change_window_baseline(settings)
    assert probe["status"] == "degraded"
    assert any(str(r).startswith("empty_change_windows:") for r in probe["reasons"])


def test_probe_reports_invalid_json(tmp_path: Path) -> None:
    target = tmp_path / "bad.json"
    target.write_text("{not-json", encoding="utf-8")
    settings = Settings(CHANGE_WINDOW_BASELINE_PATH=str(target))
    probe = probe_change_window_baseline(settings)
    assert probe["status"] == "unavailable"
    assert "json_invalid" in probe["reasons"]


def test_assert_demo_eval_baseline_available_raises_when_tenant_missing(tmp_path: Path) -> None:
    clear_change_window_baseline_cache()
    missing = tmp_path / "missing.json"
    settings = Settings(CHANGE_WINDOW_BASELINE_PATH=str(missing))
    with pytest.raises(RuntimeError, match="resolved_path="):
        assert_demo_eval_baseline_available(settings)


def test_assert_demo_eval_baseline_available_passes_when_ready(tmp_path: Path) -> None:
    clear_change_window_baseline_cache()
    target = tmp_path / "ok.json"
    _write_baseline(target)
    settings = Settings(CHANGE_WINDOW_BASELINE_PATH=str(target))
    assert_demo_eval_baseline_available(settings)


def test_assert_demo_raises_on_empty_tenant_demo_windows(tmp_path: Path) -> None:
    clear_change_window_baseline_cache()
    target = tmp_path / "empty.json"
    target.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "tenants": [{"tenant_id": "tenant-demo", "change_windows": []}],
            }
        ),
        encoding="utf-8",
    )
    settings = Settings(CHANGE_WINDOW_BASELINE_PATH=str(target))
    with pytest.raises(RuntimeError, match="resolved_path="):
        assert_demo_eval_baseline_available(settings)


def test_assert_demo_uses_settings_path_when_settings_none(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """settings=None must still honor CHANGE_WINDOW_BASELINE_PATH (ISSUE-313)."""
    clear_change_window_baseline_cache()
    good = tmp_path / "good.json"
    empty = tmp_path / "empty.json"
    _write_baseline(good)
    empty.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "tenants": [{"tenant_id": "tenant-demo", "change_windows": []}],
            }
        ),
        encoding="utf-8",
    )

    import app.services.change_window_baseline_loader as loader

    # Walk-up / container would find "good"; env points at empty → assert must fail.
    monkeypatch.setattr(loader, "_CONTAINER_BASELINE_PATH", good)
    monkeypatch.setattr(loader, "_walk_up_for_baseline", lambda _start: good)
    monkeypatch.setenv("CHANGE_WINDOW_BASELINE_PATH", str(empty))
    from app.core.config import get_settings

    get_settings.cache_clear()
    with pytest.raises(RuntimeError, match=str(empty)):
        assert_demo_eval_baseline_available(None)


def test_probe_reports_unreadable_file_without_raising(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "locked.json"
    target.write_text("{}", encoding="utf-8")
    settings = Settings(CHANGE_WINDOW_BASELINE_PATH=str(target))

    def _boom(*_args, **_kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "read_text", _boom)
    probe = probe_change_window_baseline(settings)
    assert probe["status"] == "unavailable"
    assert "file_unreadable" in probe["reasons"]


def test_probe_ready_when_only_non_required_tenant_empty(tmp_path: Path) -> None:
    target = tmp_path / "mixed.json"
    target.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "tenants": [
                    {
                        "tenant_id": "tenant-demo",
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
                    },
                    {"tenant_id": "tenant-other", "change_windows": []},
                ],
            }
        ),
        encoding="utf-8",
    )
    settings = Settings(
        CHANGE_WINDOW_BASELINE_PATH=str(target),
        CHANGE_WINDOW_BASELINE_REQUIRED="true",
        CHANGE_WINDOW_BASELINE_REQUIRED_TENANTS="tenant-demo",
    )
    probe = probe_change_window_baseline(settings)
    assert probe["status"] == "ready"
    assert any("empty_change_windows" in str(r) for r in probe["reasons"])


def test_load_change_window_baseline_reflects_settings_path_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_change_window_baseline_cache()
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    _write_baseline(first, tenant_id="tenant-demo")
    payload = {
        "schema_version": 1,
        "tenants": [
            {
                "tenant_id": "tenant-other",
                "change_windows": [
                    {
                        "window_id": "cw-other",
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
    second.write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setenv("CHANGE_WINDOW_BASELINE_PATH", str(first))
    from app.core.config import get_settings

    get_settings.cache_clear()
    indexed_first = load_change_window_baseline()
    assert "tenant-demo" in indexed_first

    monkeypatch.setenv("CHANGE_WINDOW_BASELINE_PATH", str(second))
    get_settings.cache_clear()
    indexed_second = load_change_window_baseline()
    assert "tenant-other" in indexed_second
    assert "tenant-demo" not in indexed_second
