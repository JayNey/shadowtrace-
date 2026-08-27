"""KAPR identity, kill-chain ranking, and GraphSummary score_hint tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.graph.path_rank import (
    PathRankSignals,
    kapr_score,
    kapr_score_hint,
    path_progress,
    progress_gain,
    rank_attack_paths,
    relation_stage,
    signals_from_evidence,
    transition_weight,
)
from app.models.agent_io import GraphEdge, GraphNode, GraphOutput, GraphRelationType
from app.models.enums import EvidenceSource
from app.models.evidence import Evidence
from app.services.graph_summary_builder import build_graph_summary


def _edge(
    *,
    edge_id: str,
    source: str,
    target: str,
    relation: GraphRelationType,
    evidence_id: str,
) -> GraphEdge:
    return GraphEdge(
        edge_id=edge_id,
        event_id="evt-kapr",
        source_node_id=source,
        target_node_id=target,
        relation_type=relation,
        evidence_id=evidence_id,
        occurred_at=datetime(2024, 6, 15, 9, 0, tzinfo=UTC),
    )


def test_indistinguishable_scores_match_longest_first() -> None:
    edges = [
        _edge(
            edge_id="e1",
            source="n1",
            target="n2",
            relation=GraphRelationType.LOGGED_IN_FROM,
            evidence_id="evd-1",
        ),
        _edge(
            edge_id="e2",
            source="n2",
            target="n3",
            relation=GraphRelationType.LOGGED_IN_FROM,
            evidence_id="evd-2",
        ),
        _edge(
            edge_id="e3",
            source="n3",
            target="n4",
            relation=GraphRelationType.LOGGED_IN_FROM,
            evidence_id="evd-3",
        ),
    ]
    short = ["n1", "n2"]
    mid = ["n1", "n2", "n3"]
    long = ["n1", "n2", "n3", "n4"]
    scores = [kapr_score(path, edges) for path in (short, mid, long)]
    assert scores[0] == pytest.approx(scores[1])
    assert scores[1] == pytest.approx(scores[2])
    ranked = rank_attack_paths([short, long, mid], edges)
    assert ranked == sorted([short, long, mid], key=lambda item: (-len(item), str(item)))


def test_short_exfil_path_outranks_long_login_chain() -> None:
    edges = [
        _edge(
            edge_id="e-login-1",
            source="n1",
            target="n2",
            relation=GraphRelationType.LOGGED_IN_FROM,
            evidence_id="evd-a",
        ),
        _edge(
            edge_id="e-login-2",
            source="n2",
            target="n3",
            relation=GraphRelationType.LOGGED_IN_FROM,
            evidence_id="evd-b",
        ),
        _edge(
            edge_id="e-login-3",
            source="n3",
            target="n4",
            relation=GraphRelationType.LOGGED_IN_FROM,
            evidence_id="evd-c",
        ),
        _edge(
            edge_id="e-upload",
            source="n2",
            target="n5",
            relation=GraphRelationType.UPLOADED_TO,
            evidence_id="evd-d",
        ),
    ]
    login_chain = ["n1", "n2", "n3", "n4"]
    exfil = ["n1", "n2", "n5"]
    login_s = relation_stage(GraphRelationType.LOGGED_IN_FROM.value)
    exfil_s = relation_stage(GraphRelationType.UPLOADED_TO.value)
    assert path_progress(login_chain, edges) == pytest.approx(0.0)
    assert kapr_score(login_chain, edges) == pytest.approx(login_s)
    assert kapr_score(exfil, edges) == pytest.approx(
        ((login_s + exfil_s) / 2.0) * progress_gain(path_progress(exfil, edges))
    )
    ranked = rank_attack_paths([login_chain, exfil], edges)
    assert ranked[0] == exfil
    assert ranked[1] == login_chain


def test_repeated_tactic_progress_is_zero() -> None:
    edges = [
        _edge(
            edge_id="e1",
            source="n1",
            target="n2",
            relation=GraphRelationType.LOGGED_IN_FROM,
            evidence_id="evd-1",
        ),
        _edge(
            edge_id="e2",
            source="n2",
            target="n3",
            relation=GraphRelationType.LOGGED_IN_TO,
            evidence_id="evd-2",
        ),
    ]
    path = ["n1", "n2", "n3"]
    assert path_progress(path, edges) == pytest.approx(0.0)
    assert transition_weight("initial-access", "initial-access") == pytest.approx(0.0)


def test_backward_transition_scores_below_forward() -> None:
    edges = [
        _edge(
            edge_id="e-fwd-1",
            source="f1",
            target="f2",
            relation=GraphRelationType.LOGGED_IN_FROM,
            evidence_id="evd-f1",
        ),
        _edge(
            edge_id="e-fwd-2",
            source="f2",
            target="f3",
            relation=GraphRelationType.UPLOADED_TO,
            evidence_id="evd-f2",
        ),
        _edge(
            edge_id="e-back-1",
            source="b1",
            target="b2",
            relation=GraphRelationType.UPLOADED_TO,
            evidence_id="evd-b1",
        ),
        _edge(
            edge_id="e-back-2",
            source="b2",
            target="b3",
            relation=GraphRelationType.LOGGED_IN_FROM,
            evidence_id="evd-b2",
        ),
    ]
    forward = ["f1", "f2", "f3"]
    backward = ["b1", "b2", "b3"]
    assert path_progress(forward, edges) > 0.0
    assert path_progress(backward, edges) < 0.0
    assert kapr_score(forward, edges) > kapr_score(backward, edges)


def test_find_attack_paths_uses_kapr_order() -> None:
    from app.services.graph_projection import find_attack_paths

    nodes = [
        GraphNode(node_id=f"n{i}", event_id="evt-kapr", entity_type="host", entity_value=f"h{i}")
        for i in range(1, 6)
    ]
    edges = [
        _edge(
            edge_id="e-login-1",
            source="n1",
            target="n2",
            relation=GraphRelationType.LOGGED_IN_FROM,
            evidence_id="evd-a",
        ),
        _edge(
            edge_id="e-login-2",
            source="n2",
            target="n3",
            relation=GraphRelationType.LOGGED_IN_FROM,
            evidence_id="evd-b",
        ),
        _edge(
            edge_id="e-login-3",
            source="n3",
            target="n4",
            relation=GraphRelationType.LOGGED_IN_FROM,
            evidence_id="evd-c",
        ),
        _edge(
            edge_id="e-upload",
            source="n2",
            target="n5",
            relation=GraphRelationType.UPLOADED_TO,
            evidence_id="evd-d",
        ),
    ]
    paths = find_attack_paths(nodes, edges, max_paths=3)
    assert paths
    assert paths[0] == ["n1", "n2", "n5"]


def test_mitre_t1567_lifts_otherwise_identical_path() -> None:
    edges = [
        _edge(
            edge_id="e-login",
            source="a",
            target="b",
            relation=GraphRelationType.LOGGED_IN_FROM,
            evidence_id="evd-login",
        ),
        _edge(
            edge_id="e-plain",
            source="b",
            target="c",
            relation=GraphRelationType.CONNECTED_TO,
            evidence_id="evd-plain",
        ),
        _edge(
            edge_id="e-mitre",
            source="b",
            target="d",
            relation=GraphRelationType.CONNECTED_TO,
            evidence_id="evd-mitre",
        ),
    ]
    signals = PathRankSignals(mitre_by_evidence_id={"evd-mitre": "T1567.002"})
    plain = ["a", "b", "c"]
    mitre = ["a", "b", "d"]
    assert kapr_score(mitre, edges, signals) > kapr_score(plain, edges, signals)
    ranked = rank_attack_paths([plain, mitre], edges, signals)
    assert ranked[0] == mitre


def test_signals_from_evidence_and_confidence_mean() -> None:
    evidence = [
        Evidence(
            evidence_id="evd-hi",
            event_id="evt-kapr",
            source=EvidenceSource.NETWORK_FLOW,
            evidence_type="upload",
            description="upload",
            confidence=0.9,
        ),
        Evidence(
            evidence_id="evd-lo",
            event_id="evt-kapr",
            source=EvidenceSource.IDENTITY,
            evidence_type="login",
            description="login",
            confidence=0.2,
        ),
    ]
    signals = signals_from_evidence(evidence)
    assert signals.confidence_by_evidence_id["evd-hi"] == pytest.approx(0.9)
    assert "evd-hi" not in signals.mitre_by_evidence_id
    edges = [
        _edge(
            edge_id="e1",
            source="n1",
            target="n2",
            relation=GraphRelationType.LOGGED_IN_FROM,
            evidence_id="evd-lo",
        ),
        _edge(
            edge_id="e2",
            source="n2",
            target="n3",
            relation=GraphRelationType.UPLOADED_TO,
            evidence_id="evd-hi",
        ),
    ]
    path = ["n1", "n2", "n3"]
    raw = kapr_score(path, edges, signals)
    without = kapr_score(path, edges)
    assert raw < without
    assert raw == pytest.approx(without * ((0.2 + 0.9) / 2))


def test_graph_summary_path_hint_uses_kapr_not_length() -> None:
    output = GraphOutput(
        nodes=[
            GraphNode(
                node_id="n1",
                event_id="evt-kapr",
                entity_type="account",
                entity_value="svc",
            ),
            GraphNode(
                node_id="n2",
                event_id="evt-kapr",
                entity_type="ip",
                entity_value="203.0.113.9",
            ),
        ],
        edges=[
            _edge(
                edge_id="e1",
                source="n1",
                target="n2",
                relation=GraphRelationType.CONNECTED_TO,
                evidence_id="evd-1",
            )
        ],
        central_entities=["n1"],
        attack_path_candidates=[["n1", "n2"]],
    )
    summary = build_graph_summary(output)
    path_feature = next(item for item in summary.features if item.feature_kind == "attack_path")
    assert path_feature.score_hint == pytest.approx(kapr_score_hint(["n1", "n2"], output.edges))
    assert path_feature.score_hint != pytest.approx(35.0 + 12.0 * 2)
