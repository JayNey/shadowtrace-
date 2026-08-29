"""Shared contract export and drift comparison helpers (ISSUE-112)."""

from __future__ import annotations

import filecmp
import json
import subprocess
import sys
import textwrap
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_BACKEND = _REPO_ROOT / "backend"
_SCRIPTS = _REPO_ROOT / "scripts"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from app.contracts.export_env import apply_contract_export_env  # noqa: E402

COMMITTED_CONTRACTS_ROOT = _REPO_ROOT / "contracts"
CANONICAL_SOCKETIO_SCHEMA = (
    _BACKEND / "app" / "contracts" / "socketio" / "events.schema.json"
)


@dataclass(frozen=True, slots=True)
class ContractDiff:
    """One drift finding between committed and freshly exported contracts."""

    kind: str
    relpath: str
    detail: str = ""


def _json_equal(path_a: Path, path_b: Path) -> bool:
    data_a = json.loads(path_a.read_text(encoding="utf-8"))
    data_b = json.loads(path_b.read_text(encoding="utf-8"))
    return data_a == data_b


def _iter_contract_files(root: Path) -> set[str]:
    files: set[str] = set()
    if not root.is_dir():
        return files
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.name == ".gitkeep":
            continue
        relpath = path.relative_to(root).as_posix()
        # Vendor packs are hand-maintained (check_sangfor_catalog_drift) and are
        # not produced by export_all_contracts. Do not treat them as stale.
        if relpath == "vendor" or relpath.startswith("vendor/"):
            continue
        files.add(relpath)
    return files


def compare_contract_trees(expected_root: Path, actual_root: Path) -> list[ContractDiff]:
    """Recursively compare two contract trees; detect missing, stale, and changed files."""
    diffs: list[ContractDiff] = []
    expected_files = _iter_contract_files(expected_root)
    actual_files = _iter_contract_files(actual_root)

    for relpath in sorted(expected_files - actual_files):
        diffs.append(
            ContractDiff(
                "stale_committed",
                relpath,
                "committed file is absent from fresh export",
            )
        )

    for relpath in sorted(actual_files - expected_files):
        diffs.append(
            ContractDiff(
                "missing_committed",
                relpath,
                "fresh export produced a file missing from committed contracts",
            )
        )

    for relpath in sorted(expected_files & actual_files):
        left = expected_root / relpath
        right = actual_root / relpath
        if left.suffix == ".json" and right.suffix == ".json":
            if not _json_equal(left, right):
                diffs.append(ContractDiff("content_mismatch", relpath, "JSON content differs"))
            continue
        if not filecmp.cmp(left, right, shallow=False):
            diffs.append(ContractDiff("content_mismatch", relpath, "file content differs"))

    return diffs


def _prune_stale_json_files(out_dir: Path, keep_stems: Iterable[str]) -> None:
    keep = set(keep_stems)
    if not out_dir.is_dir():
        return
    for path in out_dir.glob("*.json"):
        if path.stem not in keep:
            path.unlink()


def _export_openapi_inprocess(out_path: Path) -> Path:
    """Export OpenAPI in the current interpreter (internal; use ``export_openapi``)."""
    apply_contract_export_env()
    from app.main import app

    out_path.parent.mkdir(parents=True, exist_ok=True)
    schema = app.openapi()
    out_path.write_text(json.dumps(schema, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out_path


def export_openapi(out_path: Path) -> Path:
    """Export OpenAPI in a fresh subprocess so ``CONTRACT_EXPORT_ENV`` always applies.

    ``app.api.v1.api_router`` is built at first import time; exporting inside a pytest
    process that already imported ``app.api.v1`` would otherwise freeze feature flags
    such as ``EVENT_CHAT_ENABLED`` and produce nondeterministic drift results.
    """
    resolved = out_path.resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    snippet = textwrap.dedent(
        f"""
        import sys
        from pathlib import Path

        sys.path.insert(0, {str(_BACKEND)!r})
        sys.path.insert(0, {str(_SCRIPTS)!r})
        from contract_export_lib import _export_openapi_inprocess

        _export_openapi_inprocess(Path({str(resolved)!r}))
        """
    ).strip()
    subprocess.run(
        [sys.executable, "-c", snippet],
        cwd=_BACKEND,
        check=True,
    )
    return resolved


def export_core_schemas(out_dir: Path) -> list[Path]:
    from app.models import MODEL_REGISTRY

    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, model in sorted(MODEL_REGISTRY.items()):
        # ISSUE-265: serialization mode is the single canonical export (computed
        # fields such as InvestigationReport.degraded appear in committed artifacts).
        schema = model.model_json_schema(mode="serialization")
        path = out_dir / f"{name}.json"
        path.write_text(json.dumps(schema, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        written.append(path)
    _prune_stale_json_files(out_dir, MODEL_REGISTRY.keys())
    return written


def export_tool_schemas(out_dir: Path) -> list[Path]:
    from app.tools.specs import BASELINE_TOOL_NAMES, export_baseline_tool_schemas

    written = export_baseline_tool_schemas(out_dir)
    _prune_stale_json_files(out_dir, BASELINE_TOOL_NAMES)
    return written


def export_socketio_schema(out_path: Path) -> Path:
    from app.core.event_bus import SOCKET_MESSAGE_TYPES

    if not CANONICAL_SOCKETIO_SCHEMA.is_file():
        raise FileNotFoundError(f"canonical socket schema missing: {CANONICAL_SOCKETIO_SCHEMA}")

    doc = json.loads(CANONICAL_SOCKETIO_SCHEMA.read_text(encoding="utf-8"))
    envelope = doc.get("definitions", {}).get("SocketEventEnvelope", {})
    enum_values = envelope.get("properties", {}).get("type", {}).get("enum", [])
    schema_types = set(enum_values)
    code_types = set(SOCKET_MESSAGE_TYPES)
    if schema_types != code_types:
        missing_in_schema = sorted(code_types - schema_types)
        stale_in_schema = sorted(schema_types - code_types)
        raise ValueError(
            "SOCKET_MESSAGE_TYPES diverges from canonical socket schema enum: "
            f"missing_in_schema={missing_in_schema}, stale_in_schema={stale_in_schema}"
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out_path


def export_all_contracts(out_root: Path) -> None:
    """Export OpenAPI, core schemas, tool schemas, and Socket.IO schema into ``out_root``."""
    apply_contract_export_env()
    export_openapi(out_root / "openapi" / "openapi.json")
    export_core_schemas(out_root / "schemas")
    export_tool_schemas(out_root / "schemas" / "tools")
    export_socketio_schema(out_root / "socketio" / "events.schema.json")


def format_contract_diffs(diffs: list[ContractDiff]) -> str:
    lines = ["Contract drift detected:"]
    for item in diffs:
        suffix = f" ({item.detail})" if item.detail else ""
        lines.append(f"  - [{item.kind}] {item.relpath}{suffix}")
    lines.append("")
    lines.append("Update committed contracts with: make update-contracts")
    return "\n".join(lines)
