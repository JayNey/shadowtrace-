"""Deterministic id/hash builders for PolicyRelease (ISSUE-129 / #635)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from app.models.attack_control_mapping import MappingApprovalState
from app.models.policy_release import (
    POLICY_CORPUS_ID,
    POLICY_RELEASE_SCHEMA_VERSION,
    PolicyControl,
    PolicyMappingBundleEntry,
)
from app.services.knowledge_release_resolver import (
    canonical_json_bytes,
    compute_bundle_content_hash,
)


@dataclass(frozen=True, slots=True)
class PolicyBundleValidationResult:
    ok: bool
    content_hash: str
    controls: tuple[PolicyControl, ...]
    mappings: tuple[PolicyMappingBundleEntry, ...]
    object_count: int
    mapping_count: int
    errors: tuple[str, ...]


def compute_policy_control_hash(control: PolicyControl | dict[str, Any]) -> str:
    payload = control.model_dump(mode="json") if isinstance(control, PolicyControl) else control
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def build_policy_idempotency_key(*, content_hash: str, release_version: str) -> str:
    return f"{POLICY_CORPUS_ID}:{content_hash}:{release_version}"


def build_policy_release_id(content_hash: str, release_version: str) -> str:
    from app.services.knowledge_release_resolver import build_release_id

    # Namespace by corpus so release_id never collides with other KnowledgeRelease rows.
    material = f"{POLICY_CORPUS_ID}:{content_hash}:{release_version}"
    digest = hashlib.sha256(material.encode()).hexdigest()
    return build_release_id(digest)


def validate_policy_bundle(data: dict[str, Any]) -> PolicyBundleValidationResult:
    errors: list[str] = []
    raw_controls = data.get("controls")
    if not isinstance(raw_controls, list) or not raw_controls:
        return PolicyBundleValidationResult(
            ok=False,
            content_hash="",
            controls=(),
            mappings=(),
            object_count=0,
            mapping_count=0,
            errors=("controls must be a non-empty list",),
        )

    controls: list[PolicyControl] = []
    seen_control_ids: set[str] = set()
    control_ids: set[str] = set()
    for idx, raw in enumerate(raw_controls):
        if not isinstance(raw, dict):
            errors.append(f"controls[{idx}] must be an object")
            continue
        try:
            control = PolicyControl.model_validate(raw)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"controls[{idx}] invalid: {exc}")
            continue
        if control.control_id in seen_control_ids:
            errors.append(f"duplicate control_id {control.control_id}")
            continue
        seen_control_ids.add(control.control_id)
        control_ids.add(control.control_id)
        controls.append(control)

    mappings: list[PolicyMappingBundleEntry] = []
    seen_mapping_ids: set[str] = set()
    raw_mappings = data.get("mappings", [])
    if raw_mappings is None:
        raw_mappings = []
    if not isinstance(raw_mappings, list):
        errors.append("mappings must be a list when provided")
        raw_mappings = []

    for idx, raw in enumerate(raw_mappings):
        if not isinstance(raw, dict):
            errors.append(f"mappings[{idx}] must be an object")
            continue
        try:
            mapping = PolicyMappingBundleEntry.model_validate(raw)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"mappings[{idx}] invalid: {exc}")
            continue
        if mapping.mapping_id in seen_mapping_ids:
            errors.append(f"duplicate mapping_id {mapping.mapping_id}")
            continue
        if mapping.control_id not in control_ids:
            errors.append(f"mappings[{idx}] references unknown control_id {mapping.control_id}")
            continue
        control = next(c for c in controls if c.control_id == mapping.control_id)
        if mapping.framework_id != control.framework_id:
            errors.append(
                f"mappings[{idx}] framework_id {mapping.framework_id!r} "
                f"does not match control framework_id {control.framework_id!r}"
            )
            continue
        seen_mapping_ids.add(mapping.mapping_id)
        mappings.append(mapping)

    if errors:
        return PolicyBundleValidationResult(
            ok=False,
            content_hash="",
            controls=tuple(controls),
            mappings=tuple(mappings),
            object_count=len(controls),
            mapping_count=len(mappings),
            errors=tuple(errors),
        )

    content_hash = compute_bundle_content_hash(data)
    return PolicyBundleValidationResult(
        ok=True,
        content_hash=content_hash,
        controls=tuple(controls),
        mappings=tuple(mappings),
        object_count=len(controls),
        mapping_count=len(mappings),
        errors=(),
    )


def default_policy_provenance(source_path: str) -> dict[str, str]:
    return {
        "source_path": source_path,
        "imported_by": "policy_bundle_importer",
        "import_kind": "policy_control_bundle",
    }


def is_production_mapping(state: MappingApprovalState) -> bool:
    return state is MappingApprovalState.APPROVED


__all__ = [
    "POLICY_RELEASE_SCHEMA_VERSION",
    "PolicyBundleValidationResult",
    "build_policy_idempotency_key",
    "build_policy_release_id",
    "compute_policy_control_hash",
    "default_policy_provenance",
    "is_production_mapping",
    "validate_policy_bundle",
]
