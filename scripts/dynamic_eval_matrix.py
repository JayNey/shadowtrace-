#!/usr/bin/env python3
"""Official dynamic-eval matrix orchestrator (ISSUE-301).

Runs gold-path scenarios serially with **fresh Compose project + volumes** per
scenario so Mock XDR state is never shared across in-flight runs.

Industrial guarantees
---------------------
- Unique ``COMPOSE_PROJECT_NAME`` per scenario (never reuses fixed project).
- ``try/finally`` → ``docker compose down -v --remove-orphans`` even on failure/SIGINT.
- No host port probing: ``infra/docker-compose.eval.yml`` unpublishes ports; seed
  and harness use ``docker compose exec backend`` against ``http://127.0.0.1:8000``.
- Seed returns explicit ``event_ids``; full-loop harness receives ``--event-id``
  flags (no "latest event" guessing on a shared DB).
- ``--require-closed`` enables strict CLOSED + report + writeback gate profile.
- Default compat profile (without ``--require-closed``) keeps ISSUE-256 semantics.

Usage::

    python3 scripts/dynamic_eval_matrix.py \\
        --scenarios insider_data_exfiltration,account_anomaly_fp,suspicious_domain_access \\
        --fresh-volumes \\
        --require-closed

    make eval-full-loop-matrix
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
import zlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

_SCRIPTS_DIR = Path(__file__).resolve().parent
_ROOT_DIR = _SCRIPTS_DIR.parent
_EVAL_COMPOSE = _ROOT_DIR / "infra" / "docker-compose.eval.yml"
_BASE_COMPOSE = _ROOT_DIR / "infra" / "docker-compose.yml"

if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from dynamic_eval_full_loop import (  # noqa: E402
    GOLD_SCENARIOS,
    parse_seed_stdout,
)
from dynamic_eval_profiles import (  # noqa: E402
    ScenarioEvalProfile,
    profile_for_scenario,
)

_DEFAULT_SCENARIOS = ",".join(GOLD_SCENARIOS)
_SENSITIVE_KEYS = frozenset(
    {
        "token",
        "authorization",
        "password",
        "secret",
        "api_key",
        "access_token",
        "refresh_token",
        "DEV_AUTH_TOKENS",
    }
)


class MatrixError(RuntimeError):
    """Matrix orchestration failure."""

    def __init__(self, message: str) -> None:
        super().__init__(_sanitize_error_text(message))


def _sanitize_error_text(text: str, *, max_len: int = 4096) -> str:
    """Redact/truncate subprocess output before it lands in artifacts."""
    redacted = re.sub(
        r"(Bearer\s+)[^\s'\"]+",
        r"\1<redacted>",
        text,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(
        r"(Authorization['\"]?\s*[:=]\s*['\"]?)[^'\"\s]+",
        r"\1<redacted>",
        redacted,
        flags=re.IGNORECASE,
    )
    for key in _SENSITIVE_KEYS:
        pattern = rf"({re.escape(key)}['\"]?\s*[:=]\s*['\"]?)([^'\"\s,}}]+)"
        redacted = re.sub(pattern, r"\1<redacted>", redacted, flags=re.IGNORECASE)
    if len(redacted) > max_len:
        return redacted[:max_len] + "…<truncated>"
    return redacted


def scenario_seed_offset(base_seed: int, scenario: str) -> int:
    """Stable per-scenario seed offset (does not depend on PYTHONHASHSEED)."""
    return int(base_seed) + (zlib.adler32(scenario.encode("utf-8")) % 10_000)


def event_ids_from_seed_summary(
    seed_summary: dict[str, Any],
    *,
    scenario: str,
    max_events: int,
) -> list[str]:
    """Read explicit event IDs emitted by seed_mock_xdr_and_ingest."""
    raw = seed_summary.get("event_ids")
    if not isinstance(raw, list):
        raise MatrixError(
            f"seed summary missing event_ids for scenario={scenario}: {seed_summary!r}"
        )
    event_ids = [str(item) for item in raw if item]
    if not event_ids:
        raise MatrixError(
            f"seed returned empty event_ids for scenario={scenario}: {seed_summary!r}"
        )
    return event_ids[: max(1, max_events)]


def _service_row_unhealthy(row: dict[str, Any], *, required: set[str]) -> bool:
    service = str(row.get("Service") or "")
    if service not in required:
        return False
    state = str(row.get("State") or "").lower()
    if state != "running":
        return True
    health = str(row.get("Health") or "").lower()
    if health and health not in {"healthy"}:
        return True
    return False


class _CleanupRegistry:
    """Track active compose project for SIGINT/SIGTERM cleanup."""

    def __init__(self) -> None:
        self._project: str | None = None
        self._fresh_volumes: bool = True
        self._compose_files: list[Path] = [_BASE_COMPOSE, _EVAL_COMPOSE]

    def set_project(
        self,
        project: str | None,
        *,
        fresh_volumes: bool = True,
    ) -> None:
        self._project = project
        if project is not None:
            self._fresh_volumes = fresh_volumes

    def cleanup(self) -> None:
        project = self._project
        if not project:
            return
        print(f"[dynamic-eval-matrix] cleanup project={project}", file=sys.stderr)
        _compose_down(project, self._compose_files, volumes=self._fresh_volumes)


_CLEANUP = _CleanupRegistry()


def _git_commit() -> str:
    try:
        return (
            subprocess.check_output(
                ["git", "-C", str(_ROOT_DIR), "rev-parse", "HEAD"],
                text=True,
            ).strip()
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def _compose_cmd(
    project: str,
    compose_files: list[Path],
    *args: str,
) -> list[str]:
    cmd = ["docker", "compose", "--project-name", project]
    for compose_file in compose_files:
        cmd.extend(["-f", str(compose_file)])
    cmd.extend(args)
    return cmd


def _run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    capture: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd or _ROOT_DIR,
        capture_output=capture,
        text=True,
        check=check,
    )


def _compose_down(
    project: str,
    compose_files: list[Path],
    *,
    volumes: bool,
) -> None:
    cmd = _compose_cmd(project, compose_files, "down", "--remove-orphans")
    if volumes:
        cmd.append("-v")
    proc = _run(cmd, capture=True, check=False)
    if proc.returncode != 0:
        detail = _sanitize_error_text((proc.stderr or proc.stdout or "").strip())
        raise MatrixError(
            f"compose down failed project={project} exit={proc.returncode}"
            + (f": {detail}" if detail else "")
        )


def _scenario_project_name(scenario: str, run_id: str) -> str:
    safe = "".join(ch if ch.isalnum() else "-" for ch in scenario.lower())
    return f"shadowtrace-eval-{safe}-{run_id}"


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            key_l = str(key).lower()
            if key_l in _SENSITIVE_KEYS or key_l.endswith("_token"):
                out[key] = "<redacted>"
            else:
                out[key] = _sanitize(item)
        return out
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, str) and len(value) > 4096:
        return value[:4096] + "…<truncated>"
    return value


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_sanitize(payload), ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )


def _append_cleanup_error_to_manifest(
    scenario_dir: Path,
    *,
    cleanup_error: MatrixError,
    manifest_sink: dict[str, Any] | None,
) -> None:
    payload = {
        "type": type(cleanup_error).__name__,
        "message": _sanitize_error_text(str(cleanup_error)),
    }
    manifest_path = scenario_dir / "manifest.json"
    manifest: dict[str, Any]
    if manifest_path.is_file():
        try:
            loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest = loaded if isinstance(loaded, dict) else {}
        except (OSError, json.JSONDecodeError):
            manifest = {}
    else:
        manifest = {}
    manifest["cleanup_error"] = payload
    if manifest.get("status") == "passed":
        manifest["status"] = "passed_with_cleanup_error"
    _write_json(manifest_path, manifest)
    if manifest_sink is not None:
        manifest_sink["cleanup_error"] = payload


def _wait_stack_healthy(project: str, compose_files: list[Path], timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        proc = _run(
            _compose_cmd(
                project,
                compose_files,
                "ps",
                "--format",
                "json",
            ),
            capture=True,
            check=False,
        )
        if proc.returncode != 0:
            time.sleep(3.0)
            continue
        rows: list[dict[str, Any]] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                rows.append(parsed)
        if not rows:
            time.sleep(3.0)
            continue
        required = {"postgres", "redis", "mock-xdr", "backend", "worker"}
        seen = {str(row.get("Service") or "") for row in rows}
        unhealthy = [row for row in rows if _service_row_unhealthy(row, required=required)]
        if required.issubset(seen) and not unhealthy:
            return
        time.sleep(3.0)
    raise MatrixError(
        f"stack for project={project} did not become healthy within {timeout_s}s"
    )


def _seed_scenario(
    project: str,
    compose_files: list[Path],
    *,
    scenario: str,
    seed: int,
    mock_xdr_url: str,
    instance: int = 0,
) -> dict[str, Any]:
    cmd = _compose_cmd(
        project,
        compose_files,
        "exec",
        "-T",
        "backend",
        "python3",
        "scripts/seed_mock_xdr_and_ingest.py",
        "--scenario",
        scenario,
        "--mock-xdr-url",
        mock_xdr_url,
        "--seed",
        str(seed),
        "--instance",
        str(instance),
    )
    print(f"[dynamic-eval-matrix] seed scenario={scenario} project={project}")
    proc = _run(cmd, capture=True, check=False)
    if proc.returncode != 0:
        raise MatrixError(
            "seed_mock_xdr_and_ingest failed "
            f"(exit={proc.returncode}):\n{_sanitize_error_text(proc.stdout)}\n"
            f"{_sanitize_error_text(proc.stderr)}"
        )
    summary = parse_seed_stdout(proc.stdout)
    accepted = summary.get("accepted")
    if not isinstance(accepted, int) or accepted < 1:
        raise MatrixError(
            f"seed returned no accepted events for scenario={scenario}: {summary!r}"
        )
    return summary


def _run_full_loop_via_exec(
    project: str,
    compose_files: list[Path],
    *,
    event_ids: list[str],
    scenario: str,
    token: str,
    require_closed: bool,
    analysis_only: bool = False,
    semantic_profile: str | None = None,
    max_wait_s: float,
    poll_interval_s: float,
    gate_label: str = "full_loop",
) -> dict[str, Any]:
    cmd = _compose_cmd(
        project,
        compose_files,
        "exec",
        "-T",
        "backend",
        "python3",
        "scripts/dynamic_eval_full_loop.py",
        "--base-url",
        "http://127.0.0.1:8000",
        "--token",
        token,
        "--scenario",
        scenario,
        "--max-events",
        str(len(event_ids)),
        "--poll-interval-s",
        str(poll_interval_s),
        "--max-wait-s",
        str(max_wait_s),
        "--json",
    )
    for event_id in event_ids:
        cmd.extend(["--event-id", event_id])
    if analysis_only:
        cmd.append("--analysis-only")
        if semantic_profile:
            cmd.extend(["--semantic-profile", semantic_profile])
    elif require_closed:
        cmd.append("--require-closed")
        cmd.append("--generate-report")

    print(
        f"[dynamic-eval-matrix] {gate_label} scenario={scenario} "
        f"event_ids={event_ids} analysis_only={analysis_only} "
        f"require_closed={require_closed}"
    )
    proc = _run(cmd, capture=True, check=False)
    stdout = proc.stdout.strip()
    if proc.returncode != 0:
        raise MatrixError(
            "dynamic_eval_full_loop failed "
            f"(exit={proc.returncode}):\n{_sanitize_error_text(stdout)}\n"
            f"{_sanitize_error_text(proc.stderr)}"
        )
    try:
        result = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise MatrixError(
            "full_loop did not emit JSON on stdout: "
            f"{_sanitize_error_text(stdout)!r}\n"
            f"stderr={_sanitize_error_text(proc.stderr)!r}"
        ) from exc
    if not isinstance(result, dict):
        raise MatrixError(f"unexpected full_loop result type: {type(result)!r}")
    return result


def _run_scenario_gate(
    project: str,
    compose_files: list[Path],
    *,
    event_ids: list[str],
    scenario: str,
    token: str,
    profile: ScenarioEvalProfile,
    gate: str,
    max_wait_s: float,
    poll_interval_s: float,
) -> dict[str, Any]:
    if gate == "semantic":
        if profile.semantic == "full_loop_strict":
            return _run_full_loop_via_exec(
                project,
                compose_files,
                event_ids=event_ids,
                scenario=scenario,
                token=token,
                require_closed=True,
                max_wait_s=max_wait_s,
                poll_interval_s=poll_interval_s,
                gate_label="semantic_full_loop_strict",
            )
        return _run_full_loop_via_exec(
            project,
            compose_files,
            event_ids=event_ids,
            scenario=scenario,
            token=token,
            require_closed=False,
            analysis_only=True,
            semantic_profile=profile.semantic,
            max_wait_s=max_wait_s,
            poll_interval_s=poll_interval_s,
            gate_label=f"semantic_{profile.semantic}",
        )
    if gate == "pressure" and profile.pressure != "none":
        return _run_full_loop_via_exec(
            project,
            compose_files,
            event_ids=event_ids,
            scenario=scenario,
            token=token,
            require_closed=profile.pressure == "full_loop_strict",
            max_wait_s=max_wait_s,
            poll_interval_s=poll_interval_s,
            gate_label=f"pressure_{profile.pressure}",
        )
    raise MatrixError(f"unsupported gate={gate!r} for scenario={scenario!r}")


def run_scenario(
    *,
    scenario: str,
    run_id: str,
    artifact_root: Path,
    token: str,
    seed: int,
    mock_xdr_url: str,
    require_closed: bool,
    profile_by_scenario: bool,
    fresh_volumes: bool,
    stack_timeout_s: float,
    max_wait_s: float,
    poll_interval_s: float,
    max_events: int,
    build: bool,
    manifest_sink: dict[str, Any] | None = None,
) -> dict[str, Any]:
    project = _scenario_project_name(scenario, run_id)
    compose_files = [_BASE_COMPOSE, _EVAL_COMPOSE]
    scenario_dir = artifact_root / scenario
    scenario_profile = profile_for_scenario(scenario) if profile_by_scenario else None
    manifest: dict[str, Any] = {
        "scenario": scenario,
        "compose_project_name": project,
        "git_commit": _git_commit(),
        "started_at": datetime.now(tz=UTC).isoformat(),
        "fresh_volumes": fresh_volumes,
        "require_closed": require_closed,
        "profile_by_scenario": profile_by_scenario,
        "profile": (
            scenario_profile.semantic
            if scenario_profile is not None
            else ("strict" if require_closed else "compat")
        ),
    }
    if manifest_sink is not None:
        manifest_sink.clear()
        manifest_sink.update(manifest)

    _CLEANUP.set_project(project, fresh_volumes=fresh_volumes)
    started = time.monotonic()
    try:
        up_cmd = _compose_cmd(
            project,
            compose_files,
            "up",
            "-d",
            "--wait",
            "--wait-timeout",
            str(int(stack_timeout_s)),
            "--profile",
            "worker",
        )
        if build:
            up_cmd.insert(up_cmd.index("up") + 1, "--build")
        print(f"[dynamic-eval-matrix] up project={project} scenario={scenario}")
        proc = _run(up_cmd, capture=True, check=False)
        if proc.returncode != 0:
            raise MatrixError(
                f"compose up failed (exit={proc.returncode}):\n"
                f"{_sanitize_error_text(proc.stdout)}\n"
                f"{_sanitize_error_text(proc.stderr)}"
            )
        _wait_stack_healthy(project, compose_files, stack_timeout_s)

        seed_summary = _seed_scenario(
            project,
            compose_files,
            scenario=scenario,
            seed=seed,
            mock_xdr_url=mock_xdr_url,
            instance=0,
        )
        event_ids = event_ids_from_seed_summary(
            seed_summary,
            scenario=scenario,
            max_events=max_events,
        )
        semantic_event_ids = [event_ids[0]]
        pressure_event_ids = [eid for eid in event_ids if eid not in semantic_event_ids][:1]
        pressure_seed_summary: dict[str, Any] | None = None
        manifest["seed_summary"] = seed_summary
        manifest["event_ids"] = list(event_ids)
        manifest["semantic_event_ids"] = semantic_event_ids
        manifest["pressure_event_ids"] = list(pressure_event_ids)
        if manifest_sink is not None:
            manifest_sink.update(manifest)

        if profile_by_scenario and scenario_profile is not None:
            semantic_result = _run_scenario_gate(
                project,
                compose_files,
                event_ids=semantic_event_ids,
                scenario=scenario,
                token=token,
                profile=scenario_profile,
                gate="semantic",
                max_wait_s=max_wait_s,
                poll_interval_s=poll_interval_s,
            )
            manifest["semantic_result"] = semantic_result
            pressure_result: dict[str, Any] | None = None
            pressure_error: dict[str, Any] | None = None
            if scenario_profile.pressure != "none":
                if not pressure_event_ids:
                    # Reseed AFTER semantic gate so analysis-only still sees instance=0 mock data.
                    pressure_seed_summary = _seed_scenario(
                        project,
                        compose_files,
                        scenario=scenario,
                        seed=seed,
                        mock_xdr_url=mock_xdr_url,
                        instance=1,
                    )
                    pressure_ids = event_ids_from_seed_summary(
                        pressure_seed_summary,
                        scenario=scenario,
                        max_events=1,
                    )
                    pressure_event_ids = [
                        eid for eid in pressure_ids if eid not in semantic_event_ids
                    ]
                    if not pressure_event_ids:
                        raise MatrixError(
                            "pressure gate could not obtain a distinct event_id after "
                            f"instance=1 reseed for scenario={scenario}: "
                            f"semantic={semantic_event_ids!r} pressure_seed={pressure_ids!r}"
                        )
                    event_ids = list(dict.fromkeys([*event_ids, *pressure_event_ids]))
                    manifest["pressure_seed_summary"] = pressure_seed_summary
                    manifest["event_ids"] = event_ids
                    manifest["pressure_event_ids"] = pressure_event_ids
                    if manifest_sink is not None:
                        manifest_sink.update(manifest)
                if set(pressure_event_ids) & set(semantic_event_ids):
                    raise MatrixError(
                        "pressure gate event_ids must be distinct from semantic gate "
                        f"event_ids for scenario={scenario}: "
                        f"semantic={semantic_event_ids!r} pressure={pressure_event_ids!r}"
                    )
                try:
                    pressure_result = _run_scenario_gate(
                        project,
                        compose_files,
                        event_ids=pressure_event_ids,
                        scenario=scenario,
                        token=token,
                        profile=scenario_profile,
                        gate="pressure",
                        max_wait_s=max_wait_s,
                        poll_interval_s=poll_interval_s,
                    )
                except MatrixError as exc:
                    pressure_error = {
                        "type": type(exc).__name__,
                        "message": _sanitize_error_text(str(exc)),
                    }
                    manifest["pressure_result"] = pressure_result
                    manifest["pressure_error"] = pressure_error
                    manifest["result"] = semantic_result
                    if scenario_profile.pressure_blocks_pass:
                        manifest["status"] = "failed"
                        raise
                else:
                    manifest["pressure_result"] = pressure_result
            manifest["result"] = semantic_result
            manifest["status"] = (
                "passed"
                if pressure_error is None or not scenario_profile.pressure_blocks_pass
                else "failed"
            )
        else:
            loop_result = _run_full_loop_via_exec(
                project,
                compose_files,
                event_ids=event_ids,
                scenario=scenario,
                token=token,
                require_closed=require_closed,
                max_wait_s=max_wait_s,
                poll_interval_s=poll_interval_s,
            )
            manifest["result"] = loop_result
            manifest["status"] = "passed"
        manifest["elapsed_s"] = round(time.monotonic() - started, 2)
        _write_json(scenario_dir / "manifest.json", manifest)
        final = (manifest.get("result") or {}).get("final_statuses")
        print(
            f"[dynamic-eval-matrix] PASS scenario={scenario} "
            f"elapsed_s={manifest['elapsed_s']} final={final}"
        )
        return manifest
    except Exception as exc:
        manifest["status"] = "failed"
        manifest["error"] = {
            "type": type(exc).__name__,
            "message": _sanitize_error_text(str(exc)),
        }
        manifest["elapsed_s"] = round(time.monotonic() - started, 2)
        _write_json(scenario_dir / "manifest.json", manifest)
        if manifest_sink is not None:
            manifest_sink.update(manifest)
        raise
    finally:
        down_error: MatrixError | None = None
        try:
            _compose_down(project, compose_files, volumes=fresh_volumes)
        except MatrixError as exc:
            down_error = exc
        _CLEANUP.set_project(None)
        if down_error is not None:
            _append_cleanup_error_to_manifest(
                scenario_dir,
                cleanup_error=down_error,
                manifest_sink=manifest_sink,
            )
            if sys.exc_info()[0] is not None:
                print(
                    f"[dynamic-eval-matrix] ERROR cleanup failed: {down_error}",
                    file=sys.stderr,
                )
            else:
                raise down_error


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ISSUE-301 official dynamic-eval matrix (fresh stack per scenario)"
    )
    parser.add_argument(
        "--scenarios",
        default=_DEFAULT_SCENARIOS,
        help=f"Comma-separated scenario ids (default: {_DEFAULT_SCENARIOS})",
    )
    parser.add_argument(
        "--artifact-dir",
        default=None,
        help="Root artifact directory (default: artifacts/dynamic-eval-matrix/<run-id>)",
    )
    parser.add_argument(
        "--fresh-volumes",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Remove volumes on scenario teardown (default: true)",
    )
    parser.add_argument(
        "--require-closed",
        action="store_true",
        help="Strict CLOSED profile (reject reporting/contained/verifying)",
    )
    parser.add_argument(
        "--profile-by-scenario",
        action="store_true",
        help=(
            "ISSUE-313: run per-scenario semantic + optional pressure gates "
            "(insider strict full-loop; FP/domain analysis-only semantic + "
            "compat full-loop pressure)"
        ),
    )
    parser.add_argument("--token", default="bootstrap-token")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--mock-xdr-url",
        default="http://mock-xdr:8100",
        help="Mock XDR URL as seen from backend container",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=1,
        help="Max events per scenario (default 1)",
    )
    parser.add_argument(
        "--stack-timeout-s",
        type=float,
        default=240.0,
        help="Compose up / health wait timeout per scenario",
    )
    parser.add_argument(
        "--max-wait-s",
        type=float,
        default=float(os.environ.get("DYNAMIC_EVAL_MAX_WAIT_S", "240")),
    )
    parser.add_argument("--poll-interval-s", type=float, default=2.0)
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="Skip compose --build on scenario up",
    )
    return parser.parse_args(argv)


def _parse_scenarios(raw: str) -> list[str]:
    scenarios = [part.strip() for part in raw.split(",") if part.strip()]
    if not scenarios:
        raise MatrixError("at least one scenario is required")
    seen: set[str] = set()
    for scenario in scenarios:
        if scenario in seen:
            raise MatrixError(f"duplicate scenario in --scenarios: {scenario!r}")
        seen.add(scenario)
    unknown = [s for s in scenarios if s not in GOLD_SCENARIOS]
    if unknown:
        raise MatrixError(
            f"unknown scenario(s): {unknown}; allowed={list(GOLD_SCENARIOS)}"
        )
    return scenarios


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.max_wait_s >= 30 * 60:
        raise SystemExit(
            "Refusing max-wait-s >= 30 minutes — use scripted approve, not timeout."
        )

    if args.require_closed and args.profile_by_scenario:
        raise SystemExit("--require-closed cannot be combined with --profile-by-scenario")

    run_id = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8]
    artifact_root = Path(
        args.artifact_dir or (_ROOT_DIR / "artifacts" / "dynamic-eval-matrix" / run_id)
    )
    scenarios = _parse_scenarios(str(args.scenarios))

    active_run: dict[str, Any] = {
        "artifact_root": artifact_root,
        "summary": None,
        "scenario": None,
        "manifest": None,
    }

    def _signal_handler(signum: int, _frame: Any) -> None:
        print(
            f"[dynamic-eval-matrix] signal {signum} — running cleanup",
            file=sys.stderr,
        )
        cleanup_error: str | None = None
        try:
            _CLEANUP.cleanup()
        except MatrixError as exc:
            cleanup_error = _sanitize_error_text(str(exc))
            print(
                f"[dynamic-eval-matrix] ERROR cleanup failed: {cleanup_error}",
                file=sys.stderr,
            )
        scenario = active_run.get("scenario")
        summary_ref = active_run.get("summary")
        if scenario and isinstance(summary_ref, dict):
            manifest = active_run.get("manifest") if isinstance(active_run.get("manifest"), dict) else {}
            interrupted = {
                "status": "interrupted",
                "compose_project_name": manifest.get("compose_project_name"),
                "event_ids": manifest.get("event_ids"),
            }
            if cleanup_error:
                interrupted["cleanup_error"] = cleanup_error
            summary_ref["status"] = "interrupted"
            summary_ref["results"][scenario] = interrupted
            _write_json(artifact_root / "summary.json", summary_ref)
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    summary: dict[str, Any] = {
        "run_id": run_id,
        "git_commit": _git_commit(),
        "scenarios": scenarios,
        "artifact_root": str(artifact_root),
        "fresh_volumes": bool(args.fresh_volumes),
        "require_closed": bool(args.require_closed),
        "profile_by_scenario": bool(args.profile_by_scenario),
        "results": {},
    }
    active_run["summary"] = summary

    print(
        f"[dynamic-eval-matrix] run_id={run_id} scenarios={scenarios} "
        f"profile={'by_scenario' if args.profile_by_scenario else ('strict' if args.require_closed else 'compat')} "
        f"artifact_root={artifact_root}"
    )

    for scenario in scenarios:
        per_seed = scenario_seed_offset(int(args.seed), scenario)
        active_run["scenario"] = scenario
        active_run["manifest"] = {
            "compose_project_name": _scenario_project_name(scenario, run_id),
        }
        try:
            manifest = run_scenario(
                scenario=scenario,
                run_id=run_id,
                artifact_root=artifact_root,
                token=str(args.token),
                seed=per_seed,
                mock_xdr_url=str(args.mock_xdr_url),
                require_closed=bool(args.require_closed),
                profile_by_scenario=bool(args.profile_by_scenario),
                fresh_volumes=bool(args.fresh_volumes),
                stack_timeout_s=float(args.stack_timeout_s),
                max_wait_s=float(args.max_wait_s),
                poll_interval_s=float(args.poll_interval_s),
                max_events=int(args.max_events),
                build=not bool(args.no_build),
                manifest_sink=active_run["manifest"],
            )
            summary["results"][scenario] = {
                "status": manifest.get("status"),
                "event_ids": manifest.get("event_ids"),
                "compose_project_name": manifest.get("compose_project_name"),
                "final_statuses": (manifest.get("result") or {}).get("final_statuses"),
                "semantic_profile": manifest.get("profile"),
            }
            if manifest.get("pressure_error"):
                summary["results"][scenario]["pressure_error"] = manifest["pressure_error"]
            if manifest.get("pressure_result"):
                summary["results"][scenario]["pressure_final_statuses"] = (
                    manifest["pressure_result"].get("final_statuses")
                )
            if manifest.get("cleanup_error"):
                summary["results"][scenario]["cleanup_error"] = manifest["cleanup_error"]
            active_run["manifest"] = manifest
        except Exception as exc:
            failed_manifest_path = artifact_root / scenario / "manifest.json"
            compose_project_name = active_run["manifest"].get("compose_project_name")
            event_ids = None
            if failed_manifest_path.is_file():
                try:
                    failed_manifest = json.loads(
                        failed_manifest_path.read_text(encoding="utf-8")
                    )
                    if isinstance(failed_manifest, dict):
                        compose_project_name = failed_manifest.get(
                            "compose_project_name", compose_project_name
                        )
                        event_ids = failed_manifest.get("event_ids")
                except (OSError, json.JSONDecodeError):
                    pass
            summary["results"][scenario] = {
                "status": "failed",
                "error": _sanitize_error_text(str(exc)),
                "compose_project_name": compose_project_name,
                "event_ids": event_ids,
            }
            failed_manifest = artifact_root / scenario / "manifest.json"
            if failed_manifest.is_file():
                try:
                    manifest_data = json.loads(failed_manifest.read_text(encoding="utf-8"))
                    cleanup_error = manifest_data.get("cleanup_error")
                    if cleanup_error:
                        summary["results"][scenario]["cleanup_error"] = cleanup_error
                except (OSError, json.JSONDecodeError):
                    pass
            summary["status"] = "failed"
            _write_json(artifact_root / "summary.json", summary)
            print(f"[dynamic-eval-matrix] FAIL scenario={scenario}: {exc}", file=sys.stderr)
            return 1
        finally:
            active_run["scenario"] = None
            active_run["manifest"] = None

    summary["status"] = "passed"
    _write_json(artifact_root / "summary.json", summary)
    print(f"[dynamic-eval-matrix] ALL PASSED run_id={run_id}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except MatrixError as exc:
        print(f"[dynamic-eval-matrix] ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
