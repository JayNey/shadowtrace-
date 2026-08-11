"""Load Mock org change-window baseline from structured data (ISSUE-114 / ISSUE-313)."""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from app.models.fp_adjudication import ChangeWindowBaseline, OrgChangeWindowBaseline
from app.services.tenant_resolution import resolve_tenant_id

logger = logging.getLogger(__name__)

LoadedStatus = Literal["ready", "degraded", "unavailable"]

_CONTAINER_BASELINE_PATH = Path("/app/data/organization/change_windows.json")
_RELATIVE_BASELINE_SUFFIX = Path("data/organization/change_windows.json")
_DEMO_EVAL_REQUIRED_TENANT = "tenant-demo"


def _walk_up_for_baseline(start: Path) -> Path | None:
    current = start.resolve()
    for _ in range(12):
        candidate = current / _RELATIVE_BASELINE_SUFFIX
        if candidate.is_file():
            return candidate
        if current.parent == current:
            break
        current = current.parent
    return None


def _coerce_settings(settings: Any | None) -> Any | None:
    """Prefer explicit settings; otherwise mirror ``load()`` and pull ``get_settings()``."""
    if settings is not None:
        return settings
    try:
        from app.core.config import get_settings

        return get_settings()
    except Exception:
        return None


def resolve_change_window_baseline_path(
    path: str | None = None,
    *,
    settings: Any | None = None,
) -> Path:
    """Resolve the on-disk change-window baseline JSON path.

    Resolution order (ISSUE-313):
    1. Explicit *path* argument
    2. ``Settings.change_window_baseline_path`` when set
    3. Canonical container layout ``/app/data/organization/change_windows.json``
    4. Walk up from this module for ``data/organization/change_windows.json``
    5. Fall back to the container default (for error messages when missing)
    """
    if path is not None and str(path).strip():
        return Path(str(path).strip())

    configured = ""
    if settings is not None:
        configured = str(getattr(settings, "change_window_baseline_path", "") or "").strip()
    if configured:
        return Path(configured)

    if _CONTAINER_BASELINE_PATH.is_file():
        return _CONTAINER_BASELINE_PATH

    discovered = _walk_up_for_baseline(Path(__file__).resolve().parent)
    if discovered is not None:
        return discovered

    return _CONTAINER_BASELINE_PATH


def _required_tenant_ids(settings: Any | None) -> list[str]:
    if settings is None:
        return []
    raw = str(getattr(settings, "change_window_baseline_required_tenants", "") or "").strip()
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def _parse_baseline_file(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    reasons: list[str] = []
    if not path.is_file():
        return None, ["file_missing"]
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None, ["json_invalid"]
    except OSError:
        return None, ["file_unreadable"]
    except UnicodeDecodeError:
        return None, ["file_unreadable"]
    if not isinstance(raw, dict):
        return None, ["schema_root_not_object"]
    tenants_raw = raw.get("tenants")
    if not isinstance(tenants_raw, list):
        return None, ["schema_tenants_missing"]
    return raw, reasons


def _index_baseline(raw: dict[str, Any]) -> tuple[dict[str, OrgChangeWindowBaseline], int]:
    indexed: dict[str, OrgChangeWindowBaseline] = {}
    invalid_window_entries = 0
    for entry in raw.get("tenants") or []:
        if not isinstance(entry, dict):
            continue
        tenant_id = entry.get("tenant_id")
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            continue
        windows: list[ChangeWindowBaseline] = []
        for window in entry.get("change_windows") or []:
            if not isinstance(window, dict):
                invalid_window_entries += 1
                continue
            try:
                windows.append(ChangeWindowBaseline.model_validate(window))
            except Exception:
                invalid_window_entries += 1
                logger.debug("skip invalid change window entry", exc_info=True)
        indexed[tenant_id] = OrgChangeWindowBaseline(
            schema_version=int(raw.get("schema_version") or 1),
            tenant_id=tenant_id,
            change_windows=windows,
        )
    return indexed, invalid_window_entries


def probe_change_window_baseline(settings: Any | None = None) -> dict[str, Any]:
    """Structured readiness probe for health checks and eval preflight."""
    settings = _coerce_settings(settings)
    path = resolve_change_window_baseline_path(settings=settings)
    raw, reasons = _parse_baseline_file(path)
    if raw is None:
        status: LoadedStatus = "unavailable"
        return {
            "status": status,
            "resolved_path": str(path),
            "tenant_ids": [],
            "required_tenant_ids": _required_tenant_ids(settings),
            "reasons": reasons,
        }

    indexed, invalid_window_entries = _index_baseline(raw)
    tenant_ids = sorted(indexed.keys())
    required = _required_tenant_ids(settings)
    empty_window_tenants = [
        tenant_id for tenant_id, org in indexed.items() if not org.change_windows
    ]
    missing_required = [
        tenant_id
        for tenant_id in required
        if tenant_id not in indexed or not indexed[tenant_id].change_windows
    ]
    # Empty windows on non-required tenants must not fail-closed health when a
    # required-tenant list is configured (ISSUE-313 review).
    status_empty_tenants = (
        [tenant_id for tenant_id in empty_window_tenants if tenant_id in required]
        if required
        else list(empty_window_tenants)
    )
    if empty_window_tenants:
        reasons.append(f"empty_change_windows:{','.join(empty_window_tenants)}")
    if missing_required:
        reasons.append(f"missing_required_tenants:{','.join(missing_required)}")
    if not tenant_ids:
        reasons.append("no_tenant_entries")
    if invalid_window_entries:
        reasons.append(f"invalid_window_entries:{invalid_window_entries}")

    status_blocking = (
        bool(missing_required) or bool(status_empty_tenants) or not tenant_ids
    )
    required_flag = bool(getattr(settings, "change_window_baseline_required", False))
    if missing_required and required_flag:
        status = "unavailable"
    elif status_blocking:
        status = "degraded"
    elif invalid_window_entries:
        status = "degraded"
    else:
        # Non-required empty windows remain in reasons but do not block ready.
        status = "ready"

    return {
        "status": status,
        "resolved_path": str(path),
        "tenant_ids": tenant_ids,
        "required_tenant_ids": required,
        "reasons": reasons,
    }


def assert_demo_eval_baseline_available(settings: Any | None = None) -> None:
    """Fail-closed preflight for demo eval scenarios that depend on tenant-demo."""
    settings = _coerce_settings(settings)
    probe = probe_change_window_baseline(settings)
    path = str(probe["resolved_path"])
    indexed = load_change_window_baseline(path)
    tenant = indexed.get(_DEMO_EVAL_REQUIRED_TENANT)
    if tenant is None or not tenant.change_windows:
        reasons = list(probe.get("reasons") or [])
        detail = ", ".join(str(item) for item in reasons) if reasons else "baseline unavailable"
        raise RuntimeError(
            f"change-window baseline preflight failed: resolved_path={path!r} "
            f"missing tenant {_DEMO_EVAL_REQUIRED_TENANT!r} ({detail})"
        )


@lru_cache(maxsize=8)
def _load_change_window_baseline_at(resolved_path: str) -> dict[str, OrgChangeWindowBaseline]:
    path = Path(resolved_path)
    raw, _reasons = _parse_baseline_file(path)
    if raw is None:
        logger.warning("change-window baseline missing or invalid at %s", path)
        return {}
    indexed, _invalid = _index_baseline(raw)
    return indexed


def load_change_window_baseline(path: str | None = None) -> dict[str, OrgChangeWindowBaseline]:
    """Load tenant-indexed change-window baselines from *path* or settings default."""
    settings = None
    if path is None:
        settings = _coerce_settings(None)
    resolved = resolve_change_window_baseline_path(path, settings=settings)
    return _load_change_window_baseline_at(str(resolved))


def clear_change_window_baseline_cache() -> None:
    """Drop cached baseline parses (settings/path changes in tests)."""
    _load_change_window_baseline_at.cache_clear()


__all__ = [
    "assert_demo_eval_baseline_available",
    "clear_change_window_baseline_cache",
    "load_change_window_baseline",
    "probe_change_window_baseline",
    "resolve_change_window_baseline_path",
    "resolve_tenant_id",
]
