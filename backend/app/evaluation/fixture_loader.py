"""Fixture loader for canonical evaluation truth datasets (ISSUE-113 Phase A).

Test/evaluation harness only — never import from runtime Agent or API paths.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.models.evaluation_truth import (
    BenignSliceExpectation,
    EvaluationCaseTruth,
    EvaluationDatasetManifest,
    LabelProvenance,
    OperationalTruthMapping,
    SliceType,
    ThreatSliceExpectation,
    TruthObservationRef,
    UnevaluableSliceExpectation,
)
from app.services.evaluation_truth_service import (
    EvaluationTruthService,
    build_evaluation_case_truth,
    compute_dataset_manifest_hash,
)

_SLICE_BUILDERS = {
    SliceType.THREAT.value: ThreatSliceExpectation.model_validate,
    SliceType.BENIGN.value: BenignSliceExpectation.model_validate,
    SliceType.UNEVALUABLE.value: UnevaluableSliceExpectation.model_validate,
}


def _parse_observation_refs(raw: Any) -> list[TruthObservationRef]:
    if not isinstance(raw, list):
        return []
    refs: list[TruthObservationRef] = []
    for item in raw:
        if isinstance(item, dict):
            refs.append(TruthObservationRef.model_validate(item))
    return refs


def _parse_operational_mapping(raw: Any) -> OperationalTruthMapping | None:
    if not isinstance(raw, dict):
        return None
    return OperationalTruthMapping.model_validate(raw)


def build_truth_from_fixture_case(
    case_payload: dict[str, Any],
    *,
    tenant_id: str,
    dataset_id: str,
    dataset_version: str,
) -> EvaluationCaseTruth:
    """Build an ``EvaluationCaseTruth`` from a fixture JSON object."""
    case_id = str(case_payload.get("case_id", "")).strip()
    if not case_id:
        raise ValueError("fixture case must include case_id")

    slice_raw = case_payload.get("slice_expectation")
    if not isinstance(slice_raw, dict):
        raise ValueError(f"case {case_id}: slice_expectation must be an object")
    slice_type = str(slice_raw.get("slice_type", "")).strip()
    builder = _SLICE_BUILDERS.get(slice_type)
    if builder is None:
        raise ValueError(f"case {case_id}: unsupported slice_type {slice_type!r}")

    provenance_raw = case_payload.get("label_provenance")
    if not isinstance(provenance_raw, dict):
        raise ValueError(f"case {case_id}: label_provenance must be an object")
    provenance = LabelProvenance.model_validate(provenance_raw)

    return build_evaluation_case_truth(
        tenant_id=tenant_id,
        source_tenant_id=case_payload.get("source_tenant_id"),
        source_product=case_payload.get("source_product"),
        connector_id=case_payload.get("connector_id"),
        dataset_id=dataset_id,
        dataset_version=dataset_version,
        case_id=case_id,
        case_version=int(case_payload.get("case_version", 1)),
        observation_refs=_parse_observation_refs(case_payload.get("observation_refs")),
        slice_expectation=builder(slice_raw),
        label_provenance=provenance,
        operational_mapping=_parse_operational_mapping(case_payload.get("operational_mapping")),
        retention_policy=str(case_payload.get("retention_policy", "evaluation_standard")),
    )


def load_fixture_manifest(dataset_dir: Path) -> dict[str, Any]:
    manifest_path = dataset_dir / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"missing manifest.json in {dataset_dir}")
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{manifest_path} must contain a JSON object")
    return payload


def load_fixture_cases(dataset_dir: Path) -> list[dict[str, Any]]:
    cases_dir = dataset_dir / "cases"
    if not cases_dir.is_dir():
        raise FileNotFoundError(f"missing cases/ directory in {dataset_dir}")
    cases: list[dict[str, Any]] = []
    for path in sorted(cases_dir.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"{path} must contain a JSON object")
        cases.append(payload)
    return cases


async def load_fixture_dataset(
    service: EvaluationTruthService,
    dataset_dir: Path,
    *,
    tenant_id: str | None = None,
) -> tuple[list[EvaluationCaseTruth], EvaluationDatasetManifest]:
    """Load and persist all cases from a fixture dataset directory."""
    manifest = load_fixture_manifest(dataset_dir)
    dataset_id = str(manifest.get("dataset_id", "")).strip()
    dataset_version = str(manifest.get("dataset_version", "")).strip()
    if not dataset_id or not dataset_version:
        raise ValueError("manifest must include dataset_id and dataset_version")

    resolved_tenant = tenant_id or str(manifest.get("tenant_id", "")).strip()
    if not resolved_tenant:
        raise ValueError("tenant_id must be provided or declared in manifest")

    persisted: list[EvaluationCaseTruth] = []
    for case_payload in load_fixture_cases(dataset_dir):
        truth = build_truth_from_fixture_case(
            case_payload,
            tenant_id=resolved_tenant,
            dataset_id=dataset_id,
            dataset_version=dataset_version,
        )
        persisted.append(await service.persist(truth))

    service_manifest = await service.get_dataset_manifest(
        tenant_id=resolved_tenant,
        dataset_id=dataset_id,
        dataset_version=dataset_version,
    )
    expected_hash = manifest.get("content_hash")
    if isinstance(expected_hash, str) and expected_hash.strip():
        if expected_hash.strip() != service_manifest.content_hash:
            raise ValueError(
                "dataset content_hash mismatch: expected "
                f"{expected_hash}, got {service_manifest.content_hash}"
            )

    local_hash = compute_dataset_manifest_hash(sorted(truth.content_hash for truth in persisted))
    if local_hash != service_manifest.content_hash:
        raise ValueError(
            "fixture loader manifest hash diverged from EvaluationTruthService: "
            f"{local_hash} != {service_manifest.content_hash}"
        )

    return persisted, service_manifest


__all__ = [
    "build_truth_from_fixture_case",
    "load_fixture_cases",
    "load_fixture_dataset",
    "load_fixture_manifest",
]
