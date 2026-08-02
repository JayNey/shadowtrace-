"""STIX 2.1 bundle validation for staged knowledge import (ISSUE-128 / #634)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.knowledge_release_resolver import compute_bundle_content_hash

_ALLOWED_OBJECT_TYPES = frozenset({"attack-pattern", "relationship"})
_SPEC_VERSION = "2.1"
_MITRE_SOURCE = "mitre-attack"


@dataclass(frozen=True, slots=True)
class StixBundleValidationResult:
    content_hash: str
    object_count: int
    relationship_count: int
    attack_pattern_count: int
    external_ids: tuple[str, ...]
    objects: tuple[dict[str, Any], ...]
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return not self.errors


def validate_stix_bundle(bundle: dict[str, Any]) -> StixBundleValidationResult:
    """Validate bundle structure, types, referential integrity, and external_id uniqueness."""
    errors: list[str] = []

    if bundle.get("type") != "bundle":
        errors.append("bundle.type must be 'bundle'")
    if bundle.get("spec_version") != _SPEC_VERSION:
        errors.append(f"bundle.spec_version must be '{_SPEC_VERSION}'")

    raw_objects = bundle.get("objects")
    if not isinstance(raw_objects, list) or not raw_objects:
        errors.append("bundle.objects must be a non-empty list")
        return StixBundleValidationResult(
            content_hash=compute_bundle_content_hash(bundle),
            object_count=0,
            relationship_count=0,
            attack_pattern_count=0,
            external_ids=(),
            objects=(),
            errors=tuple(errors),
        )

    objects: list[dict[str, Any]] = []
    for index, item in enumerate(raw_objects):
        if not isinstance(item, dict):
            errors.append(f"objects[{index}] must be an object")
            continue
        objects.append(item)

    id_index: dict[str, dict[str, Any]] = {}
    external_ids: list[str] = []
    attack_pattern_count = 0
    relationship_count = 0

    for index, obj in enumerate(objects):
        stix_type = obj.get("type")
        stix_id = obj.get("id")
        if not isinstance(stix_type, str) or not stix_type:
            errors.append(f"objects[{index}].type must be a non-empty string")
            continue
        if stix_type not in _ALLOWED_OBJECT_TYPES:
            errors.append(f"objects[{index}].type '{stix_type}' is not allowed")
            continue
        if not isinstance(stix_id, str) or not stix_id:
            errors.append(f"objects[{index}].id must be a non-empty string")
            continue
        if stix_id in id_index:
            errors.append(f"duplicate stix id: {stix_id}")
        else:
            id_index[stix_id] = obj

        if stix_type == "attack-pattern":
            attack_pattern_count += 1
            ext_id = _extract_mitre_external_id(obj)
            if ext_id is None:
                errors.append(f"attack-pattern {stix_id} missing mitre-attack external_id")
            elif ext_id in external_ids:
                errors.append(f"duplicate external_id within bundle: {ext_id}")
            else:
                external_ids.append(ext_id)
        elif stix_type == "relationship":
            relationship_count += 1

    for index, obj in enumerate(objects):
        if obj.get("type") != "relationship":
            continue
        source_ref = obj.get("source_ref")
        target_ref = obj.get("target_ref")
        rel_type = obj.get("relationship_type")
        if not isinstance(source_ref, str) or source_ref not in id_index:
            errors.append(f"relationship objects[{index}] has invalid source_ref")
        if not isinstance(target_ref, str) or target_ref not in id_index:
            errors.append(f"relationship objects[{index}] has invalid target_ref")
        if not isinstance(rel_type, str) or not rel_type.strip():
            errors.append(f"relationship objects[{index}] missing relationship_type")

    declared_count = bundle.get("x_shadowtrace_object_count")
    if declared_count is not None and int(declared_count) != len(objects):
        errors.append("x_shadowtrace_object_count does not match objects length")

    content_hash = compute_bundle_content_hash(bundle)
    return StixBundleValidationResult(
        content_hash=content_hash,
        object_count=len(objects),
        relationship_count=relationship_count,
        attack_pattern_count=attack_pattern_count,
        external_ids=tuple(external_ids),
        objects=tuple(objects),
        errors=tuple(errors),
    )


def _extract_mitre_external_id(obj: dict[str, Any]) -> str | None:
    refs = obj.get("external_references")
    if not isinstance(refs, list):
        return None
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        if ref.get("source_name") != _MITRE_SOURCE:
            continue
        external_id = ref.get("external_id")
        if isinstance(external_id, str) and external_id.startswith("T"):
            return external_id
    return None


__all__ = ["StixBundleValidationResult", "validate_stix_bundle"]
