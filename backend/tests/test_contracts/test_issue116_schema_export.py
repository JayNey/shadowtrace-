"""ISSUE-116 contract schema export tests (#621)."""

from __future__ import annotations

from app.models import MODEL_REGISTRY
from app.models.agent_io import (
    AttackStoryline,
    GraphSummary,
    GraphSummaryFeature,
    StorylineClaimRef,
    StorylineGroundingStatus,
)


def test_issue116_contract_models_are_registered() -> None:
    expected = {
        "GraphSummary",
        "GraphSummaryFeature",
        "StorylineClaimRef",
        "AttackStoryline",
    }
    assert expected <= set(MODEL_REGISTRY.keys())


def test_graph_summary_schema_exports_evidence_bound_fields() -> None:
    schema = GraphSummaryFeature.model_json_schema(mode="serialization")
    props = schema.get("properties", {})
    assert "feature_kind" in props
    assert "evidence_ids" in props
    assert "score_hint" in props
    assert "attack_path" in props["feature_kind"]["enum"]


def test_storyline_claim_ref_schema_exports_navigation_fields() -> None:
    schema = StorylineClaimRef.model_json_schema(mode="serialization")
    props = schema.get("properties", {})
    for field in ("claim_id", "proposition_kind", "evidence_ids", "ordinal"):
        assert field in props


def test_attack_storyline_schema_exports_grounding_status_enum() -> None:
    schema = AttackStoryline.model_json_schema(mode="serialization")
    props = schema.get("properties", {})
    assert "claim_refs" in props
    assert "grounding_status" in props
    grounding = props["grounding_status"]
    enum_values = set(grounding.get("enum") or grounding["$ref"])
    if "$ref" in grounding:
        defs = schema.get("$defs", {})
        ref_name = grounding["$ref"].split("/")[-1]
        enum_values = set(defs[ref_name]["enum"])
    assert StorylineGroundingStatus.EVIDENCE_GROUNDED.value in enum_values
    assert StorylineGroundingStatus.LEGACY_EVIDENCE_GROUNDED.value in enum_values
    assert StorylineGroundingStatus.CLAIM_REFS_UNAVAILABLE.value in enum_values


def test_graph_summary_schema_roundtrip() -> None:
    summary = GraphSummary(
        features=[
            GraphSummaryFeature(
                feature_id="relation_connected_to",
                feature_kind="attack_stage",
                score_hint=70.0,
                evidence_ids=["evd-00000001"],
                provenance="graph_edge",
            )
        ],
        degraded_reason="neo4j_disabled",
    )
    restored = GraphSummary.model_validate(summary.model_dump(mode="json"))
    assert restored.features[0].evidence_ids == ["evd-00000001"]
    assert restored.degraded_reason == "neo4j_disabled"
