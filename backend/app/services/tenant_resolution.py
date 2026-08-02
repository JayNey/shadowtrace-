"""Tenant id resolution from source snapshots (ISSUE-138)."""

from __future__ import annotations

from typing import Any


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


__all__ = ["resolve_tenant_id"]
