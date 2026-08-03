"""Production comparison fixture loading (ISSUE-126 / #631 Phase B)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import orjson

from app.core.errors import ValidationError
from app.models.detection_production_comparison import (
    DetectionProductionBindingManifest,
    DetectionProductionCaseBinding,
)


@dataclass(frozen=True, slots=True)
class DetectionProductionDatasetManifest:
    dataset_id: str
    dataset_version: str
    shadow_dataset_id: str
    shadow_dataset_version: str
    schema_version: str
    content_hash: str


def _canonical_manifest_bytes(manifest: DetectionProductionBindingManifest) -> bytes:
    payload = manifest.model_dump(mode="json")
    payload.pop("content_hash", None)
    return orjson.dumps(payload, option=orjson.OPT_SORT_KEYS)


def compute_binding_manifest_hash(manifest: DetectionProductionBindingManifest) -> str:
    return hashlib.sha256(_canonical_manifest_bytes(manifest)).hexdigest()


def load_production_dataset_manifest(dataset_dir: Path) -> DetectionProductionDatasetManifest:
    path = dataset_dir / "manifest.json"
    if not path.is_file():
        raise FileNotFoundError(f"missing production dataset manifest: {path}")
    raw = orjson.loads(path.read_bytes())
    return DetectionProductionDatasetManifest(
        dataset_id=str(raw["dataset_id"]),
        dataset_version=str(raw["dataset_version"]),
        shadow_dataset_id=str(raw["shadow_dataset_id"]),
        shadow_dataset_version=str(raw["shadow_dataset_version"]),
        schema_version=str(raw.get("schema_version", "1.0")),
        content_hash=str(raw.get("content_hash", "")),
    )


def load_production_binding_manifest(dataset_dir: Path) -> DetectionProductionBindingManifest:
    dataset_manifest = load_production_dataset_manifest(dataset_dir)
    path = dataset_dir / "case_bindings.json"
    if not path.is_file():
        raise FileNotFoundError(f"missing production case bindings: {path}")
    raw = orjson.loads(path.read_bytes())
    bindings = [DetectionProductionCaseBinding.model_validate(item) for item in raw["bindings"]]
    manifest = DetectionProductionBindingManifest(
        schema_version=str(raw.get("schema_version", "1.0")),
        shadow_dataset_id=str(raw["shadow_dataset_id"]),
        shadow_dataset_version=str(raw["shadow_dataset_version"]),
        bindings=bindings,
    )
    binding_hash = compute_binding_manifest_hash(manifest)
    if dataset_manifest.shadow_dataset_id != manifest.shadow_dataset_id:
        raise ValidationError(
            "production dataset manifest shadow_dataset_id mismatch",
            details={
                "manifest": dataset_manifest.shadow_dataset_id,
                "bindings": manifest.shadow_dataset_id,
            },
        )
    if dataset_manifest.shadow_dataset_version != manifest.shadow_dataset_version:
        raise ValidationError(
            "production dataset manifest shadow_dataset_version mismatch",
            details={
                "manifest": dataset_manifest.shadow_dataset_version,
                "bindings": manifest.shadow_dataset_version,
            },
        )
    if dataset_manifest.content_hash and dataset_manifest.content_hash != binding_hash:
        raise ValidationError(
            "production dataset manifest content_hash mismatch",
            details={
                "manifest": dataset_manifest.content_hash,
                "bindings": binding_hash,
            },
        )
    return manifest.model_copy(update={"content_hash": binding_hash})


def binding_by_case_id(
    manifest: DetectionProductionBindingManifest,
) -> dict[str, DetectionProductionCaseBinding]:
    return {binding.case_id: binding for binding in manifest.bindings}


__all__ = [
    "DetectionProductionDatasetManifest",
    "binding_by_case_id",
    "compute_binding_manifest_hash",
    "load_production_binding_manifest",
    "load_production_dataset_manifest",
]
