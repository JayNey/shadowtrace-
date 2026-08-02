"""Server-owned Detection Rule resolver (ISSUE-121 / #626)."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import orjson

from app.core.errors import ValidationError
from app.detection.operators import default_operator_registry
from app.detection.scoring.release import MOCK_ACCOUNT_MAD_RELEASE, MOCK_ACCOUNT_MAD_RELEASE_ID
from app.detection.sequences.releases import (
    GEO_SENSITIVE_SEQUENCE_V1,
    IDENTITY_EXFIL_SEQUENCE_V1,
    sequence_match_threshold,
)
from app.models.detection_rule import (
    CANDIDATE_DETECTION_SCHEMA_VERSION,
    DETECTION_RULE_SCHEMA_VERSION,
    PHASE_A_OPERATORS,
    CandidateDetection,
    CandidateDetectionProvenance,
    DetectionRuleDefinition,
    DetectionRulePackage,
    DetectionRulePackageProvenance,
    DetectionRuleRuntimeState,
    MissingDataPolicy,
    RuleOperatorKind,
)
from app.models.feature_snapshot import FEATURE_CONTRACT_VERSION, FeatureWindowKind

_ALLOWED_GROUP_FIELDS = frozenset({"entity_type", "entity_id", "category", "action"})
_ALLOWED_REQUIRED_FIELDS = frozenset(
    {"action", "category", "entity_type", "entity_id", "detection_score", "observation_count"}
)
_ALLOWED_VALUE_FIELDS = frozenset(
    {"observation_count", "avg_detection_score", "max_detection_score"}
)
_ALLOWED_MATCH_CRITERIA_KEYS = frozenset(
    {
        "action",
        "category",
        "entity_type",
        "entity_id",
        "model_release_id",
        "model_release_hash",
        "baseline_content_hash",
        "sequence_id",
        "sequence_hash",
        "sequence_steps",
        "max_step_gap_seconds",
    }
)
_ALLOWED_SEQUENCE_STEP_KEYS = frozenset({"action", "category", "entity_type", "entity_id"})


def _canonical_bytes(value: Any) -> bytes:
    return orjson.dumps(value, option=orjson.OPT_SORT_KEYS)


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _operator_value(operator: RuleOperatorKind | str) -> str:
    if isinstance(operator, RuleOperatorKind):
        return operator.value
    return str(operator)


def _validate_window_kind(window_kind: str) -> None:
    try:
        FeatureWindowKind(window_kind)
    except ValueError as exc:
        raise ValidationError(
            f"unsupported window kind: {window_kind}",
            details={"window_kind": window_kind},
        ) from exc


def compile_rule_definition(rule: DetectionRuleDefinition) -> DetectionRuleDefinition:
    """Schema validation + fail-closed compile step for one rule."""
    operator_value = _operator_value(rule.operator)
    if operator_value not in PHASE_A_OPERATORS:
        raise ValidationError(
            f"unsupported operator: {operator_value}",
            details={"operator": operator_value},
        )
    default_operator_registry().get(operator_value)

    _validate_window_kind(rule.window_kind)

    if rule.feature_contract_version != FEATURE_CONTRACT_VERSION:
        raise ValidationError(
            "unsupported feature contract version",
            details={"feature_contract_version": rule.feature_contract_version},
        )

    for field_name in rule.group_key_fields:
        if field_name not in _ALLOWED_GROUP_FIELDS:
            raise ValidationError(
                f"unsupported group key field: {field_name}",
                details={"field_name": field_name},
            )

    for field_name in rule.required_fields:
        if field_name not in _ALLOWED_REQUIRED_FIELDS:
            raise ValidationError(
                f"unsupported required field: {field_name}",
                details={"field_name": field_name},
            )

    if operator_value in {
        RuleOperatorKind.EVENT_MATCH.value,
        RuleOperatorKind.EVENT_COUNT.value,
        RuleOperatorKind.EVENT_SEQUENCE.value,
        RuleOperatorKind.STATISTICAL_ANOMALY.value,
    }:
        if rule.missing_data_policy is MissingDataPolicy.TREAT_AS_ZERO:
            raise ValidationError(
                "treat_as_zero missing_data_policy is not supported for "
                "observation/scorer operators",
                details={"rule_id": rule.rule_id, "operator": operator_value},
            )
        if (
            operator_value != RuleOperatorKind.STATISTICAL_ANOMALY.value
            and "observation_count" in rule.required_fields
        ):
            raise ValidationError(
                "observation_count required_field is not valid for observation operators",
                details={"rule_id": rule.rule_id, "operator": operator_value},
            )

    if operator_value == RuleOperatorKind.EVENT_MATCH.value and not rule.match_criteria:
        raise ValidationError(
            "event_match requires non-empty match_criteria",
            details={"rule_id": rule.rule_id},
        )

    for key in rule.match_criteria:
        if key not in _ALLOWED_MATCH_CRITERIA_KEYS:
            raise ValidationError(
                f"unsupported match_criteria key: {key}",
                details={"rule_id": rule.rule_id, "key": key},
            )

    if operator_value == RuleOperatorKind.VALUE_COUNT.value:
        if not rule.value_field:
            raise ValidationError(
                "value_count requires value_field",
                details={"rule_id": rule.rule_id},
            )
        if rule.value_field not in _ALLOWED_VALUE_FIELDS:
            raise ValidationError(
                f"unsupported value_field: {rule.value_field}",
                details={"value_field": rule.value_field},
            )

    if operator_value == RuleOperatorKind.STATISTICAL_ANOMALY.value:
        if rule.threshold <= 0:
            raise ValidationError(
                "statistical_anomaly requires positive robust_z threshold",
                details={"rule_id": rule.rule_id, "threshold": rule.threshold},
            )
        if rule.value_field is not None:
            raise ValidationError(
                "statistical_anomaly must not set value_field",
                details={"rule_id": rule.rule_id},
            )
        release_id = rule.match_criteria.get("model_release_id")
        if not isinstance(release_id, str) or not release_id:
            raise ValidationError(
                "statistical_anomaly requires model_release_id in match_criteria",
                details={"rule_id": rule.rule_id},
            )
        if release_id != MOCK_ACCOUNT_MAD_RELEASE_ID:
            raise ValidationError(
                "unsupported anomaly scorer release",
                details={"rule_id": rule.rule_id, "model_release_id": release_id},
            )
        release_hash = rule.match_criteria.get("model_release_hash")
        if isinstance(release_hash, str) and release_hash:
            if release_hash != MOCK_ACCOUNT_MAD_RELEASE.release_hash:
                raise ValidationError(
                    "anomaly scorer release hash mismatch",
                    details={
                        "rule_id": rule.rule_id,
                        "model_release_id": release_id,
                        "expected_release_hash": release_hash,
                    },
                )

    if operator_value == RuleOperatorKind.EVENT_SEQUENCE.value:
        if rule.threshold <= 0:
            raise ValidationError(
                "event_sequence requires positive threshold",
                details={"rule_id": rule.rule_id, "threshold": rule.threshold},
            )
        if rule.value_field is not None:
            raise ValidationError(
                "event_sequence must not set value_field",
                details={"rule_id": rule.rule_id},
            )
        sequence_id = rule.match_criteria.get("sequence_id")
        if not isinstance(sequence_id, str) or not sequence_id:
            raise ValidationError(
                "event_sequence requires sequence_id in match_criteria",
                details={"rule_id": rule.rule_id},
            )
        known_sequences = {
            IDENTITY_EXFIL_SEQUENCE_V1.sequence_id: IDENTITY_EXFIL_SEQUENCE_V1,
            GEO_SENSITIVE_SEQUENCE_V1.sequence_id: GEO_SENSITIVE_SEQUENCE_V1,
        }
        release = known_sequences.get(sequence_id)
        if release is None:
            raise ValidationError(
                "unsupported sequence package",
                details={"rule_id": rule.rule_id, "sequence_id": sequence_id},
            )
        sequence_hash = rule.match_criteria.get("sequence_hash")
        if not isinstance(sequence_hash, str) or not sequence_hash:
            raise ValidationError(
                "event_sequence requires sequence_hash in match_criteria",
                details={"rule_id": rule.rule_id, "sequence_id": sequence_id},
            )
        if sequence_hash != release.sequence_hash:
            raise ValidationError(
                "sequence package hash mismatch",
                details={
                    "rule_id": rule.rule_id,
                    "sequence_id": sequence_id,
                    "expected_sequence_hash": sequence_hash,
                },
            )
        raw_steps = rule.match_criteria.get("sequence_steps")
        if not isinstance(raw_steps, list) or len(raw_steps) < 2:
            raise ValidationError(
                "event_sequence requires at least two sequence_steps",
                details={"rule_id": rule.rule_id, "sequence_id": sequence_id},
            )
        for index, step in enumerate(raw_steps):
            if not isinstance(step, dict) or not step:
                raise ValidationError(
                    "sequence step must be a non-empty object",
                    details={"rule_id": rule.rule_id, "step_index": index},
                )
            for key in step:
                if key not in _ALLOWED_SEQUENCE_STEP_KEYS:
                    raise ValidationError(
                        f"unsupported sequence step key: {key}",
                        details={"rule_id": rule.rule_id, "step_index": index, "key": key},
                    )
        expected_steps = [dict(step) for step in release.sequence_steps]
        if raw_steps != expected_steps:
            raise ValidationError(
                "sequence_steps must match frozen sequence release",
                details={
                    "rule_id": rule.rule_id,
                    "sequence_id": sequence_id,
                },
            )
        max_gap = rule.match_criteria.get("max_step_gap_seconds")
        if not isinstance(max_gap, int) or max_gap <= 0:
            raise ValidationError(
                "max_step_gap_seconds must be a positive integer",
                details={"rule_id": rule.rule_id, "max_step_gap_seconds": max_gap},
            )
        if max_gap != release.max_step_gap_seconds:
            raise ValidationError(
                "max_step_gap_seconds must match frozen sequence release",
                details={
                    "rule_id": rule.rule_id,
                    "sequence_id": sequence_id,
                    "expected_max_step_gap_seconds": release.max_step_gap_seconds,
                },
            )
        expected_threshold = sequence_match_threshold(release)
        if rule.threshold != expected_threshold:
            raise ValidationError(
                "event_sequence threshold must equal frozen sequence step count",
                details={
                    "rule_id": rule.rule_id,
                    "sequence_id": sequence_id,
                    "expected_threshold": expected_threshold,
                    "threshold": rule.threshold,
                },
            )

    return rule


def compile_rule_package(
    *,
    source_tenant_id: str,
    package_version: int,
    runtime_state: DetectionRuleRuntimeState,
    rules: list[DetectionRuleDefinition],
    provenance: DetectionRulePackageProvenance,
    supersedes_package_id: str | None = None,
    package_id: str | None = None,
) -> DetectionRulePackage:
    if package_version < 1:
        raise ValidationError("package_version must be >= 1")
    if not rules:
        raise ValidationError("rule package must contain at least one rule")

    compiled_rules = [compile_rule_definition(rule) for rule in rules]
    seen_rule_ids: set[str] = set()
    for rule in compiled_rules:
        if rule.rule_id in seen_rule_ids:
            raise ValidationError(
                "duplicate rule_id in package",
                details={"rule_id": rule.rule_id},
            )
        seen_rule_ids.add(rule.rule_id)

    provenance_for_hash = provenance.model_dump(mode="json", exclude={"compiled_at"})
    body = {
        "source_tenant_id": source_tenant_id,
        "package_version": package_version,
        "rules": [rule.model_dump(mode="json") for rule in compiled_rules],
        "provenance": provenance_for_hash,
        "schema_version": DETECTION_RULE_SCHEMA_VERSION,
    }
    content_hash = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    resolved_package_id = package_id or build_package_id(content_hash=content_hash)
    idempotency_key = build_package_idempotency_key(
        source_tenant_id=source_tenant_id,
        package_version=package_version,
        content_hash=content_hash,
    )
    return DetectionRulePackage(
        package_id=resolved_package_id,
        source_tenant_id=source_tenant_id,
        package_version=package_version,
        runtime_state=runtime_state,
        rules=compiled_rules,
        provenance=provenance,
        content_hash=content_hash,
        idempotency_key=idempotency_key,
        supersedes_package_id=supersedes_package_id,
    )


def build_package_id(*, content_hash: str) -> str:
    digest = hashlib.sha256(content_hash.encode()).hexdigest()[:12]
    return f"drpkg-{digest}"


def build_package_idempotency_key(
    *,
    source_tenant_id: str,
    package_version: int,
    content_hash: str,
) -> str:
    return f"{source_tenant_id}:drpkg:v{package_version}:{content_hash}"


def build_candidate_detection_id(*, identity_hash: str) -> str:
    digest = hashlib.sha256(f"{identity_hash}|candidate".encode()).hexdigest()[:12]
    return f"dcand-{digest}"


def build_candidate_idempotency_key(
    *,
    source_tenant_id: str,
    package_id: str,
    rule_id: str,
    rule_version: int,
    cutoff_at: datetime,
    group_key: dict[str, str],
    ordered_observation_refs: list[dict[str, int | str]] | None = None,
) -> str:
    cutoff_iso = ensure_utc(cutoff_at).isoformat()
    group_material = "|".join(f"{key}={group_key[key]}" for key in sorted(group_key))
    base = (
        f"{source_tenant_id}:{package_id}:{rule_id}:v{rule_version}:{cutoff_iso}:{group_material}"
    )
    if ordered_observation_refs:
        ref_material = "|".join(
            f"{item['observation_id']}@{item['source_revision']}"
            for item in ordered_observation_refs
        )
        return f"{base}:{ref_material}"
    return base


def _sequence_observation_refs(
    provenance: CandidateDetectionProvenance,
) -> list[dict[str, int | str]] | None:
    if not provenance.sequence_step_matches:
        return None
    refs: list[dict[str, int | str]] = []
    for record in provenance.sequence_step_matches:
        obs_id = record.get("observation_id")
        revision = record.get("source_revision")
        if isinstance(obs_id, str) and isinstance(revision, int):
            refs.append({"observation_id": obs_id, "source_revision": revision})
    return refs or None


def _candidate_identity_body(
    *,
    source_tenant_id: str,
    detection_scope_id: str,
    package: DetectionRulePackage,
    rule: DetectionRuleDefinition,
    cutoff_at: datetime,
    group_key: dict[str, str],
    ordered_observation_refs: list[dict[str, int | str]] | None = None,
) -> dict[str, Any]:
    """Stable identity material — excludes mutable evidence except sequence refs."""
    body: dict[str, Any] = {
        "source_tenant_id": source_tenant_id,
        "detection_scope_id": detection_scope_id,
        "package_id": package.package_id,
        "package_version": package.package_version,
        "rule_id": rule.rule_id,
        "rule_version": rule.rule_version,
        "operator": rule.operator.value,
        "group_key": group_key,
        "cutoff_at": ensure_utc(cutoff_at).isoformat(),
        "window_kind": rule.window_kind,
        "severity": rule.severity,
        "shadow_only": True,
        "schema_version": CANDIDATE_DETECTION_SCHEMA_VERSION,
    }
    if ordered_observation_refs is not None:
        body["ordered_observation_refs"] = ordered_observation_refs
    return body


def build_candidate_detection(
    *,
    source_tenant_id: str,
    detection_scope_id: str,
    package: DetectionRulePackage,
    rule: DetectionRuleDefinition,
    cutoff_at: datetime,
    group_key: dict[str, str],
    matched_value: float,
    provenance: CandidateDetectionProvenance,
) -> CandidateDetection:
    ordered_observation_refs: list[dict[str, int | str]] | None = None
    if rule.operator is RuleOperatorKind.EVENT_SEQUENCE:
        ordered_observation_refs = _sequence_observation_refs(provenance)
    identity_body = _candidate_identity_body(
        source_tenant_id=source_tenant_id,
        detection_scope_id=detection_scope_id,
        package=package,
        rule=rule,
        cutoff_at=cutoff_at,
        group_key=group_key,
        ordered_observation_refs=ordered_observation_refs,
    )
    identity_hash = hashlib.sha256(_canonical_bytes(identity_body)).hexdigest()
    body = {
        **identity_body,
        "matched_value": matched_value,
        "provenance": provenance.model_dump(mode="json"),
    }
    content_hash = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    return CandidateDetection(
        candidate_detection_id=build_candidate_detection_id(identity_hash=identity_hash),
        source_tenant_id=source_tenant_id,
        detection_scope_id=detection_scope_id,
        package_id=package.package_id,
        package_version=package.package_version,
        rule_id=rule.rule_id,
        rule_version=rule.rule_version,
        operator=rule.operator,
        group_key=group_key,
        cutoff_at=ensure_utc(cutoff_at),
        window_kind=rule.window_kind,
        matched_value=matched_value,
        severity=rule.severity,
        shadow_only=True,
        provenance=provenance,
        content_hash=content_hash,
        idempotency_key=build_candidate_idempotency_key(
            source_tenant_id=source_tenant_id,
            package_id=package.package_id,
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            cutoff_at=cutoff_at,
            group_key=group_key,
            ordered_observation_refs=ordered_observation_refs,
        ),
    )


def build_runtime_error_id(
    *,
    source_tenant_id: str,
    package_id: str,
    rule_id: str | None,
    error_category: str,
    cutoff_at: datetime,
) -> str:
    cutoff_iso = ensure_utc(cutoff_at).isoformat()
    material = (
        f"{source_tenant_id}|{package_id}|{rule_id or '_package_'}|{error_category}|{cutoff_iso}"
    )
    digest = hashlib.sha256(material.encode()).hexdigest()[:12]
    return f"drerr-{digest}"


def allowed_runtime_transition(
    current: DetectionRuleRuntimeState,
    target: DetectionRuleRuntimeState,
) -> bool:
    transitions: dict[DetectionRuleRuntimeState, set[DetectionRuleRuntimeState]] = {
        DetectionRuleRuntimeState.DRAFT: {DetectionRuleRuntimeState.VALIDATED},
        DetectionRuleRuntimeState.VALIDATED: {
            DetectionRuleRuntimeState.SHADOW_ACTIVE,
            DetectionRuleRuntimeState.DISABLED,
        },
        DetectionRuleRuntimeState.SHADOW_ACTIVE: {DetectionRuleRuntimeState.DISABLED},
        DetectionRuleRuntimeState.DISABLED: set(),
    }
    return target in transitions.get(current, set())
