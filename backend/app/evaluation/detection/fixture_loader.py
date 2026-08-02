"""Detection evaluation fixture context (ISSUE-126 / #631 Phase A)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.models.detection_rule import DetectionRuleDefinition


@dataclass(frozen=True, slots=True)
class DetectionObservationFixture:
    observation_id: str
    source_tenant_id: str
    detection_scope_id: str
    observed_at: datetime
    action: str | None
    category: str | None
    entity_type: str
    entity_id: str
    connector_id: str
    source_object_id: str
    detection_score: float = 55.0
    content_hash: str = "c" * 64
    observation_hash: str = "d" * 64


@dataclass(frozen=True, slots=True)
class DetectionScopeSeed:
    integration_instance_id: str
    connector_id: str
    source_product: str = "mock_xdr"


@dataclass(frozen=True, slots=True)
class DetectionTenantIsolationProbe:
    probe_id: str
    probe_tenant_id: str


@dataclass(frozen=True, slots=True)
class DetectionReplayFixture:
    """Per-case shadow replay inputs — not ground truth."""

    source_tenant_id: str
    cutoff_at: datetime
    scope_seed: DetectionScopeSeed
    package_id: str
    package_version: int
    rules: tuple[DetectionRuleDefinition, ...]
    observations: tuple[DetectionObservationFixture, ...]
    expected_rule_ids: tuple[str, ...] = ()
    tenant_isolation_probe: DetectionTenantIsolationProbe | None = None
    max_observations_scanned: int | None = None
    skip_shadow_execute: bool = False
    force_runtime_error: bool = False


@dataclass
class DetectionFixtureIndex:
    """Case-id keyed replay fixtures loaded alongside canonical truth."""

    by_case_id: dict[str, DetectionReplayFixture] = field(default_factory=dict)


def _parse_observation(raw: dict[str, Any], *, source_tenant_id: str, scope_id: str) -> DetectionObservationFixture:
    observed_at = datetime.fromisoformat(str(raw["observed_at"]))
    entity = raw.get("entity") or {}
    return DetectionObservationFixture(
        observation_id=str(raw["observation_id"]),
        source_tenant_id=source_tenant_id,
        detection_scope_id=scope_id,
        observed_at=observed_at,
        action=raw.get("action"),
        category=raw.get("category"),
        entity_type=str(entity.get("entity_type", "ip")),
        entity_id=str(entity.get("entity_id", "10.0.0.1")),
        connector_id=str(raw.get("connector_id", "conn-fixture")),
        source_object_id=str(raw.get("source_object_id", raw["observation_id"])),
        detection_score=float(raw.get("detection_score", 55.0)),
        content_hash=str(raw.get("content_hash", "c" * 64)),
        observation_hash=str(raw.get("observation_hash", "d" * 64)),
    )


def parse_detection_replay_fixture(case_payload: dict[str, Any]) -> DetectionReplayFixture | None:
    replay_raw = case_payload.get("detection_replay")
    if not isinstance(replay_raw, dict):
        return None

    source_tenant_id = str(replay_raw["source_tenant_id"]).strip()
    cutoff_at = datetime.fromisoformat(str(replay_raw["cutoff_at"]))
    scope_raw = replay_raw.get("scope_seed") or {}
    scope_seed = DetectionScopeSeed(
        integration_instance_id=str(scope_raw.get("integration_instance_id", "inst-fixture")),
        connector_id=str(scope_raw.get("connector_id", "conn-fixture")),
        source_product=str(scope_raw.get("source_product", "mock_xdr")),
    )
    rules_raw = replay_raw.get("rules") or []
    rules = tuple(DetectionRuleDefinition.model_validate(item) for item in rules_raw)
    observations_raw = replay_raw.get("observations") or []
    scope_placeholder = str(replay_raw.get("detection_scope_id", "scope-placeholder"))
    observations = tuple(
        _parse_observation(item, source_tenant_id=source_tenant_id, scope_id=scope_placeholder)
        for item in observations_raw
        if isinstance(item, dict)
    )
    expected_rule_ids = tuple(str(item) for item in (replay_raw.get("expected_rule_ids") or []))
    probe_raw = replay_raw.get("tenant_isolation_probe")
    probe: DetectionTenantIsolationProbe | None = None
    if isinstance(probe_raw, dict):
        probe = DetectionTenantIsolationProbe(
            probe_id=str(probe_raw.get("probe_id", "tenant-probe")),
            probe_tenant_id=str(probe_raw["probe_tenant_id"]),
        )
    max_scan = replay_raw.get("max_observations_scanned")
    return DetectionReplayFixture(
        source_tenant_id=source_tenant_id,
        cutoff_at=cutoff_at,
        scope_seed=scope_seed,
        package_id=str(replay_raw["package_id"]),
        package_version=int(replay_raw.get("package_version", 1)),
        rules=rules,
        observations=observations,
        expected_rule_ids=expected_rule_ids,
        tenant_isolation_probe=probe,
        max_observations_scanned=int(max_scan) if max_scan is not None else None,
        skip_shadow_execute=bool(replay_raw.get("skip_shadow_execute", False)),
        force_runtime_error=bool(replay_raw.get("force_runtime_error", False)),
    )


def load_detection_fixture_index(dataset_dir) -> DetectionFixtureIndex:
    from app.evaluation.fixture_loader import load_fixture_cases

    index = DetectionFixtureIndex()
    for case_payload in load_fixture_cases(dataset_dir):
        case_id = str(case_payload.get("case_id", "")).strip()
        replay = parse_detection_replay_fixture(case_payload)
        if case_id and replay is not None:
            index.by_case_id[case_id] = replay
    return index


__all__ = [
    "DetectionFixtureIndex",
    "DetectionObservationFixture",
    "DetectionReplayFixture",
    "DetectionScopeSeed",
    "DetectionTenantIsolationProbe",
    "load_detection_fixture_index",
    "parse_detection_replay_fixture",
]
