"""Build evidence-bound GraphSummary from GraphOutput (ISSUE-116 / #621)."""

from __future__ import annotations

from collections import defaultdict

from app.graph.path_rank import PathRankSignals, kapr_score_hint, relation_stage
from app.models.agent_io import GraphOutput, GraphRelationType, GraphSummary, GraphSummaryFeature


def build_graph_summary(
    output: GraphOutput,
    *,
    signals: PathRankSignals | None = None,
) -> GraphSummary:
    """Derive deterministic, evidence-referenced features for pre-risk scoring."""
    features: list[GraphSummaryFeature] = []

    for index, path in enumerate(output.attack_path_candidates):
        path_nodes = set(path)
        evidence_ids = _evidence_ids_for_nodes(output, path_nodes)
        if not evidence_ids:
            continue
        features.append(
            GraphSummaryFeature(
                feature_id=f"attack_path_{index}",
                feature_kind="attack_path",
                score_hint=kapr_score_hint(path, output.edges, signals),
                evidence_ids=evidence_ids,
                provenance="graph_path",
            )
        )

    for index, entity in enumerate(output.central_entities[:3]):
        evidence_ids = _evidence_ids_for_entity(output, entity)
        if not evidence_ids:
            continue
        features.append(
            GraphSummaryFeature(
                feature_id=f"central_entity_{index}",
                feature_kind="central_entity",
                score_hint=60.0,
                evidence_ids=evidence_ids,
                provenance="graph_centrality",
            )
        )

    by_relation: dict[str, list[str]] = defaultdict(list)
    for edge in output.edges:
        relation = (
            edge.relation_type.value
            if hasattr(edge.relation_type, "value")
            else str(edge.relation_type)
        )
        if edge.evidence_id:
            by_relation[relation].append(edge.evidence_id)

    for relation, evidence_ids in by_relation.items():
        deduped = list(dict.fromkeys(evidence_ids))
        hint = relation_stage(relation)
        features.append(
            GraphSummaryFeature(
                feature_id=f"relation_{relation}",
                feature_kind=(
                    "attack_stage"
                    if relation
                    in {
                        GraphRelationType.CONNECTED_TO.value,
                        GraphRelationType.UPLOADED_TO.value,
                    }
                    else "lateral_movement"
                ),
                score_hint=hint,
                evidence_ids=deduped[:16],
                provenance="graph_edge",
            )
        )

    return GraphSummary(
        features=features,
        degraded=output.degraded,
        degraded_reason=output.degraded_reason,
    )


def _evidence_ids_for_nodes(output: GraphOutput, node_ids: set[str]) -> list[str]:
    ids: list[str] = []
    for edge in output.edges:
        if edge.source_node_id in node_ids and edge.target_node_id in node_ids:
            if edge.evidence_id:
                ids.append(edge.evidence_id)
    return list(dict.fromkeys(ids))


def _evidence_ids_for_entity(output: GraphOutput, entity_node_id: str) -> list[str]:
    ids: list[str] = []
    for edge in output.edges:
        if entity_node_id in {edge.source_node_id, edge.target_node_id} and edge.evidence_id:
            ids.append(edge.evidence_id)
    return list(dict.fromkeys(ids))[:16]


__all__ = ["build_graph_summary"]
