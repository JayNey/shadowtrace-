"""Policy release resolver and bundle validation tests (ISSUE-129 / #635)."""

from __future__ import annotations

import json
from pathlib import Path

from app.models.attack_control_mapping import MappingApprovalState
from app.services.policy_release_resolver import validate_policy_bundle

REPO_ROOT = Path(__file__).resolve().parents[3]
DATA_FILE = REPO_ROOT / "data" / "knowledge" / "policy_controls.json"


def test_validate_policy_controls_fixture() -> None:
    bundle = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    result = validate_policy_bundle(bundle)
    assert result.ok is True
    assert result.object_count == 2
    assert result.mapping_count == 2
    assert len(result.content_hash) == 64


def test_validate_policy_bundle_rejects_empty_controls() -> None:
    result = validate_policy_bundle({"controls": [], "mappings": []})
    assert result.ok is False
    assert "non-empty" in result.errors[0]


def test_validate_policy_bundle_rejects_unknown_mapping_control() -> None:
    bundle = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    bundle["mappings"].append(
        {
            "mapping_id": "map-bad",
            "technique_id": "T9999",
            "control_id": "ctrl-deadbeef",
            "framework_id": "nist_csf",
            "approval_state": "candidate",
            "mapping_version": "1.0",
            "provenance": "test",
        }
    )
    result = validate_policy_bundle(bundle)
    assert result.ok is False
    assert any("unknown control_id" in err for err in result.errors)


def test_validate_policy_bundle_rejects_mapping_framework_mismatch() -> None:
    bundle = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    control_id = bundle["controls"][0]["control_id"]
    bundle["mappings"].append(
        {
            "mapping_id": "map-framework-mismatch",
            "technique_id": "T9999",
            "control_id": control_id,
            "framework_id": "iso27001",
            "approval_state": "approved",
            "mapping_version": "1.0",
            "provenance": "test",
        }
    )
    result = validate_policy_bundle(bundle)
    assert result.ok is False
    assert any("framework_id" in err and "does not match" in err for err in result.errors)


def test_fixture_contains_candidate_and_approved_mappings() -> None:
    bundle = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    result = validate_policy_bundle(bundle)
    states = {mapping.approval_state for mapping in result.mappings}
    assert MappingApprovalState.APPROVED in states
    assert MappingApprovalState.CANDIDATE in states
