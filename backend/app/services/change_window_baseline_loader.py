"""Load Mock org change-window baseline from structured data (ISSUE-114)."""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.models.fp_adjudication import ChangeWindowBaseline, OrgChangeWindowBaseline

logger = logging.getLogger(__name__)

_DEFAULT_BASELINE_PATH = (
    Path(__file__).resolve().parents[3] / "data" / "organization" / "change_windows.json"
)


@lru_cache(maxsize=4)
def load_change_window_baseline(path: str | None = None) -> dict[str, OrgChangeWindowBaseline]:
    """Load tenant-indexed change-window baselines from *path*."""
    baseline_path = Path(path) if path is not None else _DEFAULT_BASELINE_PATH
    try:
        raw = json.loads(baseline_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        logger.warning("change-window baseline missing at %s", baseline_path)
        return {}
    except json.JSONDecodeError:
        logger.warning("change-window baseline JSON invalid at %s", baseline_path)
        return {}

    tenants_raw = raw.get("tenants")
    if not isinstance(tenants_raw, list):
        return {}

    indexed: dict[str, OrgChangeWindowBaseline] = {}
    for entry in tenants_raw:
        if not isinstance(entry, dict):
            continue
        tenant_id = entry.get("tenant_id")
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            continue
        windows: list[ChangeWindowBaseline] = []
        for window in entry.get("change_windows") or []:
            if not isinstance(window, dict):
                continue
            try:
                windows.append(ChangeWindowBaseline.model_validate(window))
            except Exception:
                logger.debug("skip invalid change window entry", exc_info=True)
        indexed[tenant_id] = OrgChangeWindowBaseline(
            schema_version=int(raw.get("schema_version") or 1),
            tenant_id=tenant_id,
            change_windows=windows,
        )
    return indexed


def resolve_tenant_id(source_snapshot: dict[str, Any] | None) -> str | None:
    """Resolve tenant id from immutable source snapshot; None when absent."""
    if not isinstance(source_snapshot, dict):
        return None

    def _normalize(value: object) -> str | None:
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    for key in ("source_tenant_id", "tenant_id"):
        tenant = _normalize(source_snapshot.get(key))
        if tenant is not None:
            return tenant

    creation_ref = source_snapshot.get("creation_source_ref")
    if isinstance(creation_ref, dict):
        for key in ("source_tenant_id", "tenant_id"):
            tenant = _normalize(creation_ref.get(key))
            if tenant is not None:
                return tenant

    snapshots = source_snapshot.get("source_reference_snapshots")
    if isinstance(snapshots, list):
        for item in snapshots:
            if not isinstance(item, dict):
                continue
            for key in ("source_tenant_id", "tenant_id"):
                tenant = _normalize(item.get(key))
                if tenant is not None:
                    return tenant

    return None


__all__ = ["load_change_window_baseline", "resolve_tenant_id"]
