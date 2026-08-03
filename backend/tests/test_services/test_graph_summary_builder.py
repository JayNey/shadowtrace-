"""GraphSummary builder tests (ISSUE-116 / #621)."""

from __future__ import annotations

from datetime import UTC, datetime

from app.models.agent_io import GraphEdge, GraphNode, GraphOutput, GraphRelationType
from app.services.graph_summary_builder import build_graph_summary


def _now() -> datetime:
    return datetime(2026, 1, 1, tzinfo=UTC)


def test_build_graph_summary_includes_evidence_bound_features() -> None:
    output = GraphOutput(
        nodes=[
            GraphNode(
                node_id="node-a",
                event_id="evt-001",
                entity_type="account",
                entity_value="svc",
            ),
            GraphNode(
                node_id="node-b",
                event_id="evt-001",
                entity_type="ip",
                entity_value="203.0.113.9",
            ),
        ],
        edges=[
            GraphEdge(
                edge_id="edge-1",
                event_id="evt-001",
                source_node_id="node-a",
                target_node_id="node-b",
                relation_type=GraphRelationType.CONNECTED_TO,
                evidence_id="evd-00000001",
                occurred_at=_now(),
            )
        ],
        central_entities=["node-a"],
        attack_path_candidates=[["node-a", "node-b"]],
    )

    summary = build_graph_summary(output)

    assert summary.degraded is False
    assert summary.features
    assert all(feature.evidence_ids for feature in summary.features)
    kinds = {feature.feature_kind for feature in summary.features}
    assert "attack_path" in kinds
    assert "central_entity" in kinds


def test_build_graph_summary_propagates_degraded_reason() -> None:
    output = GraphOutput(
        degraded=True,
        degraded_reason="neo4j_disabled",
    )

    summary = build_graph_summary(output)

    assert summary.degraded is True
    assert summary.degraded_reason == "neo4j_disabled"


def test_build_graph_summary_omits_features_without_evidence_ids() -> None:
    output = GraphOutput(
        nodes=[
            GraphNode(
                node_id="node-a",
                event_id="evt-001",
                entity_type="account",
                entity_value="svc",
            ),
            GraphNode(
                node_id="node-b",
                event_id="evt-001",
                entity_type="ip",
                entity_value="203.0.113.9",
            ),
        ],
        edges=[],
        central_entities=["node-a"],
        attack_path_candidates=[["node-a", "node-b"]],
    )

    summary = build_graph_summary(output)

    assert summary.features == []
