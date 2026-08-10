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
        self._compose_files: list[Path] = [_BASE_COMPOSE, _EVAL_COMPOSE]

    def set_project(self, project: str | None) -> None:
        self._project = project

    def cleanup(self) -> None:
        project = self._project
        if not project:
            return
        print(f"[dynamic-eval-matrix] cleanup project={project}", file=sys.stderr)
        _compose_down(project, self._compose_files, volumes=True)


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
        print(
            f"[dynamic-eval-matrix] WARN compose down failed "
            f"project={project} exit={proc.returncode}",
            file=sys.stderr,
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
    max_wait_s: float,
    poll_interval_s: float,
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
    if require_closed:
        cmd.append("--require-closed")

    print(
        f"[dynamic-eval-matrix] full_loop scenario={scenario} "
        f"event_ids={event_ids} require_closed={require_closed}"
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
            f"full_loop did not emit JSON on stdout: {stdout!r}\nstderr={proc.stderr!r}"
        ) from exc
    if not isinstance(result, dict):
        raise MatrixError(f"unexpected full_loop result type: {type(result)!r}")
    return result


def run_scenario(
    *,
    scenario: str,
    run_id: str,
    artifact_root: Path,
    token: str,
    seed: int,
    mock_xdr_url: str,
    require_closed: bool,
    fresh_volumes: bool,
    stack_timeout_s: float,
    max_wait_s: float,
    poll_interval_s: float,
    max_events: int,
    build: bool,
) -> dict[str, Any]:
    project = _scenario_project_name(scenario, run_id)
    compose_files = [_BASE_COMPOSE, _EVAL_COMPOSE]
    scenario_dir = artifact_root / scenario
    manifest: dict[str, Any] = {
        "scenario": scenario,
        "compose_project_name": project,
        "git_commit": _git_commit(),
        "started_at": datetime.now(tz=UTC).isoformat(),
        "fresh_volumes": fresh_volumes,
        "require_closed": require_closed,
        "profile": "strict" if require_closed else "compat",
    }

    _CLEANUP.set_project(project)
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
                f"{proc.stdout}\n{proc.stderr}"
            )
        _wait_stack_healthy(project, compose_files, stack_timeout_s)

        seed_summary = _seed_scenario(
            project,
            compose_files,
            scenario=scenario,
            seed=seed,
            mock_xdr_url=mock_xdr_url,
        )
        event_ids = event_ids_from_seed_summary(
            seed_summary,
            scenario=scenario,
            max_events=max_events,
        )
        manifest["seed_summary"] = seed_summary
        manifest["event_ids"] = event_ids

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
        manifest["elapsed_s"] = round(time.monotonic() - started, 2)
        manifest["status"] = "passed"
        _write_json(scenario_dir / "manifest.json", manifest)
        print(
            f"[dynamic-eval-matrix] PASS scenario={scenario} "
            f"elapsed_s={manifest['elapsed_s']} final={loop_result.get('final_statuses')}"
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
        raise
    finally:
        _compose_down(project, compose_files, volumes=fresh_volumes)
        _CLEANUP.set_project(None)


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

    run_id = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8]
    artifact_root = Path(
        args.artifact_dir or (_ROOT_DIR / "artifacts" / "dynamic-eval-matrix" / run_id)
    )
    scenarios = _parse_scenarios(str(args.scenarios))

    def _signal_handler(signum: int, _frame: Any) -> None:
        print(
            f"[dynamic-eval-matrix] signal {signum} — running cleanup",
            file=sys.stderr,
        )
        _CLEANUP.cleanup()
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
        "results": {},
    }

    print(
        f"[dynamic-eval-matrix] run_id={run_id} scenarios={scenarios} "
        f"profile={'strict' if args.require_closed else 'compat'} "
        f"artifact_root={artifact_root}"
    )

    for scenario in scenarios:
        per_seed = scenario_seed_offset(int(args.seed), scenario)
        try:
            manifest = run_scenario(
                scenario=scenario,
                run_id=run_id,
                artifact_root=artifact_root,
                token=str(args.token),
                seed=per_seed,
                mock_xdr_url=str(args.mock_xdr_url),
                require_closed=bool(args.require_closed),
                fresh_volumes=bool(args.fresh_volumes),
                stack_timeout_s=float(args.stack_timeout_s),
                max_wait_s=float(args.max_wait_s),
                poll_interval_s=float(args.poll_interval_s),
                max_events=int(args.max_events),
                build=not bool(args.no_build),
            )
            summary["results"][scenario] = {
                "status": manifest.get("status"),
                "event_ids": manifest.get("event_ids"),
                "compose_project_name": manifest.get("compose_project_name"),
                "final_statuses": (manifest.get("result") or {}).get("final_statuses"),
            }
        except Exception as exc:
            summary["results"][scenario] = {
                "status": "failed",
                "error": _sanitize_error_text(str(exc)),
            }
            summary["status"] = "failed"
            _write_json(artifact_root / "summary.json", summary)
            print(f"[dynamic-eval-matrix] FAIL scenario={scenario}: {exc}", file=sys.stderr)
            return 1

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
