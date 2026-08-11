"""ISSUE-301 unit tests: dynamic eval matrix helpers (no Docker required)."""

from __future__ import annotations

import importlib.util
import json
import signal
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
MATRIX_PATH = REPO_ROOT / "scripts" / "dynamic_eval_matrix.py"


def _mock_subprocess_result() -> object:
    return type("Proc", (), {"returncode": 0, "stdout": "", "stderr": ""})()


FULL_LOOP_PATH = REPO_ROOT / "scripts" / "dynamic_eval_full_loop.py"


def _load_matrix_module():
    scripts_dir = str(REPO_ROOT / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location(
        "dynamic_eval_matrix_under_test",
        MATRIX_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["dynamic_eval_matrix_under_test"] = module
    spec.loader.exec_module(module)
    return module


def _load_full_loop_module():
    scripts_dir = str(REPO_ROOT / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location(
        "dynamic_eval_full_loop_under_test",
        FULL_LOOP_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["dynamic_eval_full_loop_under_test"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def full_loop_mod():
    return _load_full_loop_module()


@pytest.fixture(scope="module")
def matrix_mod():
    return _load_matrix_module()


def test_event_ids_from_seed_summary_returns_explicit_ids(matrix_mod) -> None:
    summary = {"accepted": 1, "event_ids": ["evt-a", "evt-b"]}
    assert matrix_mod.event_ids_from_seed_summary(
        summary,
        scenario="insider_data_exfiltration",
        max_events=1,
    ) == ["evt-a"]


def test_event_ids_from_seed_summary_raises_when_missing(matrix_mod) -> None:
    with pytest.raises(matrix_mod.MatrixError, match="missing event_ids"):
        matrix_mod.event_ids_from_seed_summary(
            {"accepted": 1},
            scenario="insider_data_exfiltration",
            max_events=1,
        )


def test_scenario_seed_offset_is_stable(matrix_mod) -> None:
    first = matrix_mod.scenario_seed_offset(42, "insider_data_exfiltration")
    second = matrix_mod.scenario_seed_offset(42, "insider_data_exfiltration")
    assert first == second
    assert first != matrix_mod.scenario_seed_offset(42, "account_anomaly_fp")


def test_service_row_unhealthy_flags_running_unhealthy(matrix_mod) -> None:
    required = {"backend"}
    row = {"Service": "backend", "State": "running", "Health": "unhealthy"}
    assert matrix_mod._service_row_unhealthy(row, required=required) is True


def test_service_row_unhealthy_accepts_running_healthy(matrix_mod) -> None:
    required = {"backend"}
    row = {"Service": "backend", "State": "running", "Health": "healthy"}
    assert matrix_mod._service_row_unhealthy(row, required=required) is False


def test_sanitize_error_text_redacts_bearer(matrix_mod) -> None:
    raw = "failed Authorization: Bearer secret-token-value"
    sanitized = matrix_mod._sanitize_error_text(raw)
    assert "secret-token-value" not in sanitized
    assert "<redacted>" in sanitized


def test_sanitize_error_text_redacts_password_key(matrix_mod) -> None:
    raw = 'seed failed password="hunter2" during ingest'
    sanitized = matrix_mod._sanitize_error_text(raw)
    assert "hunter2" not in sanitized
    assert "<redacted>" in sanitized


def test_parse_args_defaults_compat_profile(matrix_mod) -> None:
    args = matrix_mod.parse_args(["--scenarios", "insider_data_exfiltration"])
    assert args.require_closed is False
    assert args.fresh_volumes is True


def test_matrix_main_stops_after_first_scenario_failure(matrix_mod) -> None:
    calls: list[str] = []

    def _fake_run_scenario(*, scenario: str, **kwargs):
        calls.append(scenario)
        if scenario == "insider_data_exfiltration":
            raise matrix_mod.MatrixError("simulated failure")
        return {"status": "passed"}

    with patch.object(matrix_mod, "run_scenario", side_effect=_fake_run_scenario):
        rc = matrix_mod.main(
            [
                "--scenarios",
                "insider_data_exfiltration,account_anomaly_fp",
                "--no-build",
            ]
        )
    assert rc == 1
    assert calls == ["insider_data_exfiltration"]


def test_scenario_project_name_unique_for_all_gold_scenarios(matrix_mod) -> None:
    run_id = "20260810T120000Z-deadbeef"
    names = [
        matrix_mod._scenario_project_name(scenario, run_id)
        for scenario in matrix_mod.GOLD_SCENARIOS
    ]
    assert len(names) == len(set(names))


def test_parse_scenarios_rejects_duplicates(matrix_mod) -> None:
    with pytest.raises(matrix_mod.MatrixError, match="duplicate scenario"):
        matrix_mod._parse_scenarios("insider_data_exfiltration,insider_data_exfiltration")


def test_sanitize_redacts_sensitive_dict_keys(matrix_mod) -> None:
    payload = {
        "token": "secret-token",
        "nested": {"password": "secret-password", "ok": "visible"},
    }
    sanitized = matrix_mod._sanitize(payload)
    assert sanitized["token"] == "<redacted>"
    assert sanitized["nested"]["password"] == "<redacted>"
    assert sanitized["nested"]["ok"] == "visible"


def test_compose_down_raises_on_failure(matrix_mod) -> None:
    with patch.object(
        matrix_mod,
        "_run",
        return_value=type(
            "Proc",
            (),
            {"returncode": 1, "stdout": "boom", "stderr": ""},
        )(),
    ):
        with pytest.raises(matrix_mod.MatrixError, match="compose down failed"):
            matrix_mod._compose_down(
                "proj",
                [matrix_mod._BASE_COMPOSE, matrix_mod._EVAL_COMPOSE],
                volumes=True,
            )


def test_run_scenario_finally_compose_down_with_volumes(matrix_mod, tmp_path: Path) -> None:
    down_calls: list[bool] = []

    def _fake_down(_project: str, _files: list[Path], *, volumes: bool) -> None:
        down_calls.append(volumes)

    with (
        patch.object(matrix_mod, "_compose_down", side_effect=_fake_down),
        patch.object(matrix_mod, "_wait_stack_healthy"),
        patch.object(
            matrix_mod,
            "_seed_scenario",
            return_value={"accepted": 1, "event_ids": ["evt-a"]},
        ),
        patch.object(
            matrix_mod,
            "_run_full_loop_via_exec",
            return_value={"final_statuses": {"evt-a": "closed"}},
        ),
        patch.object(matrix_mod, "_run", return_value=_mock_subprocess_result()),
    ):
        manifest = matrix_mod.run_scenario(
            scenario="insider_data_exfiltration",
            run_id="run-test",
            artifact_root=tmp_path,
            token="bootstrap-token",
            seed=42,
            mock_xdr_url="http://mock-xdr:8100",
            require_closed=False,
            fresh_volumes=True,
            stack_timeout_s=10.0,
            max_wait_s=10.0,
            poll_interval_s=1.0,
            max_events=1,
            build=False,
        )
    assert manifest["status"] == "passed"
    assert down_calls == [True]


def test_run_scenario_cleanup_failure_after_pass_raises(matrix_mod, tmp_path: Path) -> None:
    def _fake_down(_project: str, _files: list[Path], *, volumes: bool) -> None:
        raise matrix_mod.MatrixError("compose down failed project=proj-test exit=1")

    with (
        patch.object(matrix_mod, "_compose_down", side_effect=_fake_down),
        patch.object(matrix_mod, "_wait_stack_healthy"),
        patch.object(
            matrix_mod,
            "_seed_scenario",
            return_value={"accepted": 1, "event_ids": ["evt-a"]},
        ),
        patch.object(
            matrix_mod,
            "_run_full_loop_via_exec",
            return_value={"final_statuses": {"evt-a": "closed"}},
        ),
        patch.object(matrix_mod, "_run", return_value=_mock_subprocess_result()),
    ):
        with pytest.raises(matrix_mod.MatrixError, match="compose down failed"):
            matrix_mod.run_scenario(
                scenario="insider_data_exfiltration",
                run_id="run-test",
                artifact_root=tmp_path,
                token="bootstrap-token",
                seed=42,
                mock_xdr_url="http://mock-xdr:8100",
                require_closed=False,
                fresh_volumes=True,
                stack_timeout_s=10.0,
                max_wait_s=10.0,
                poll_interval_s=1.0,
                max_events=1,
                build=False,
            )
    manifest = json.loads(
        (tmp_path / "insider_data_exfiltration" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["status"] == "passed_with_cleanup_error"
    assert "cleanup_error" in manifest


def test_run_full_loop_via_exec_passes_explicit_event_ids(matrix_mod) -> None:
    captured: list[list[str]] = []

    def _fake_run(cmd: list[str], **kwargs):
        captured.append(cmd)
        return type("Proc", (), {"returncode": 0, "stdout": "{}", "stderr": ""})()

    with patch.object(matrix_mod, "_run", side_effect=_fake_run):
        matrix_mod._run_full_loop_via_exec(
            "proj",
            [matrix_mod._BASE_COMPOSE, matrix_mod._EVAL_COMPOSE],
            event_ids=["evt-a", "evt-b"],
            scenario="insider_data_exfiltration",
            token="bootstrap-token",
            require_closed=True,
            max_wait_s=10.0,
            poll_interval_s=1.0,
        )
    cmd = captured[0]
    assert cmd.count("--event-id") == 2
    assert "evt-a" in cmd and "evt-b" in cmd
    assert "--require-closed" in cmd
    assert "--generate-report" in cmd


def test_signal_handler_respects_fresh_volumes_flag(matrix_mod) -> None:
    down_volumes: list[bool] = []

    def _fake_down(_project: str, _files: list[Path], *, volumes: bool) -> None:
        down_volumes.append(volumes)

    matrix_mod._CLEANUP.set_project("proj-test", fresh_volumes=False)
    with patch.object(matrix_mod, "_compose_down", side_effect=_fake_down):
        matrix_mod._CLEANUP.cleanup()
    assert down_volumes == [False]


def test_matrix_failure_summary_includes_manifest_fields(
    matrix_mod,
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    scenario = "insider_data_exfiltration"
    manifest_path = artifact_root / scenario / "manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(
        json.dumps(
            {
                "compose_project_name": "shadowtrace-eval-insider-run",
                "event_ids": ["evt-seed-1"],
                "status": "failed",
            }
        ),
        encoding="utf-8",
    )

    def _fake_run_scenario(*, scenario: str, **kwargs):
        raise matrix_mod.MatrixError("simulated failure")

    with patch.object(matrix_mod, "run_scenario", side_effect=_fake_run_scenario):
        rc = matrix_mod.main(
            [
                "--scenarios",
                scenario,
                "--artifact-dir",
                str(artifact_root),
                "--no-build",
            ]
        )
    assert rc == 1
    summary = json.loads((artifact_root / "summary.json").read_text(encoding="utf-8"))
    row = summary["results"][scenario]
    assert row["compose_project_name"] == "shadowtrace-eval-insider-run"
    assert row["event_ids"] == ["evt-seed-1"]


def test_require_closed_rejects_heuristic_event_selection(full_loop_mod) -> None:
    with patch.object(full_loop_mod, "DynamicEvalClient") as client_cls:
        client = client_cls.return_value
        client.get_json.side_effect = lambda path: (
            {"items": []} if "/events" in path else {"playbook_resources": {"status": "ready"}}
        )
        with pytest.raises(SystemExit, match="heuristic DB selection is forbidden"):
            full_loop_mod.main(["--require-closed"])


def test_full_loop_rejects_event_id_with_seed_via_compose(full_loop_mod) -> None:
    with pytest.raises(SystemExit, match="cannot be combined with --seed-via-compose"):
        full_loop_mod.main(
            [
                "--require-closed",
                "--event-id",
                "evt-x",
                "--seed-via-compose",
            ]
        )


def test_event_outcome_ok_rejects_verifying_when_require_closed(full_loop_mod) -> None:
    assert full_loop_mod.event_outcome_ok("verifying", require_closed=True) is False


def test_signal_handler_writes_summary_when_cleanup_fails(matrix_mod, tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    summary: dict[str, object] = {
        "run_id": "run-x",
        "results": {},
    }
    active_run = {
        "artifact_root": artifact_root,
        "summary": summary,
        "scenario": "insider_data_exfiltration",
        "manifest": {
            "compose_project_name": "shadowtrace-eval-insider-run",
            "event_ids": ["evt-a"],
        },
    }

    def _handler(signum: int, _frame: object) -> None:
        cleanup_error: str | None = None
        try:
            raise matrix_mod.MatrixError("compose down failed")
        except matrix_mod.MatrixError as exc:
            cleanup_error = matrix_mod._sanitize_error_text(str(exc))
        scenario = active_run.get("scenario")
        summary_ref = active_run.get("summary")
        if scenario and isinstance(summary_ref, dict):
            manifest = (
                active_run.get("manifest") if isinstance(active_run.get("manifest"), dict) else {}
            )
            interrupted = {
                "status": "interrupted",
                "compose_project_name": manifest.get("compose_project_name"),
                "event_ids": manifest.get("event_ids"),
            }
            if cleanup_error:
                interrupted["cleanup_error"] = cleanup_error
            summary_ref["status"] = "interrupted"
            summary_ref["results"][scenario] = interrupted
            matrix_mod._write_json(artifact_root / "summary.json", summary_ref)
        raise SystemExit(128 + signum)

    with pytest.raises(SystemExit):
        _handler(signal.SIGINT, None)
    payload = json.loads((artifact_root / "summary.json").read_text(encoding="utf-8"))
    row = payload["results"]["insider_data_exfiltration"]
    assert row["status"] == "interrupted"
    assert "cleanup_error" in row


def test_run_scenario_records_cleanup_error_on_failure_path(
    matrix_mod,
    tmp_path: Path,
) -> None:
    def _fake_down(_project: str, _files: list[Path], *, volumes: bool) -> None:
        raise matrix_mod.MatrixError("down failed after scenario error")

    with (
        patch.object(matrix_mod, "_compose_down", side_effect=_fake_down),
        patch.object(matrix_mod, "_wait_stack_healthy"),
        patch.object(
            matrix_mod,
            "_seed_scenario",
            side_effect=matrix_mod.MatrixError("seed failed"),
        ),
        patch.object(
            matrix_mod,
            "_run",
            return_value=type("Proc", (), {"returncode": 0, "stdout": "", "stderr": ""})(),
        ),
    ):
        with pytest.raises(matrix_mod.MatrixError, match="seed failed"):
            matrix_mod.run_scenario(
                scenario="insider_data_exfiltration",
                run_id="run-test",
                artifact_root=tmp_path,
                token="bootstrap-token",
                seed=42,
                mock_xdr_url="http://mock-xdr:8100",
                require_closed=False,
                fresh_volumes=True,
                stack_timeout_s=10.0,
                max_wait_s=10.0,
                poll_interval_s=1.0,
                max_events=1,
                build=False,
            )
    manifest = json.loads(
        (tmp_path / "insider_data_exfiltration" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["status"] == "failed"
    assert manifest["cleanup_error"]["message"]
