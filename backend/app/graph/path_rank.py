"""Kill-chain Aligned Path Ranking (KAPR).

Time-monotonic DFS still generates candidates. KAPR only reorders them.

    KAPR(P) = mean_i s(e_i) * g(progress(P)) * mean_c(P)

s(e) is the MITRE tactic ordinal of an edge (technique tactics, else relation
fallback), scaled to [0, 100]. progress(P) sums kill-chain transition weights
w(T_i, T_{i+1}). g saturates with log1p so long climbs do not explode.

Identity: when every candidate path has the same KAPR score, ranking falls
back to ``(-len(path), str(path))`` — the previous longest-first order.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.models.agent_io import GraphRelationType
from app.models.evidence import Evidence

# MITRE Enterprise kill-chain order (same names as stix_bundle_builder).
ATTACK_TACTIC_ORDER: tuple[str, ...] = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)

_MAX_TACTIC_ORDINAL = len(ATTACK_TACTIC_ORDER) - 1
_TACTIC_ORDINAL: dict[str, int] = {name: index for index, name in enumerate(ATTACK_TACTIC_ORDER)}

RELATION_TACTIC: dict[str, str] = {
    GraphRelationType.LOGGED_IN_FROM.value: "initial-access",
    GraphRelationType.LOGGED_IN_TO.value: "initial-access",
    GraphRelationType.EXECUTED.value: "execution",
    GraphRelationType.REQUESTED.value: "discovery",
    GraphRelationType.RESOLVED.value: "discovery",
    GraphRelationType.ACCESSED.value: "collection",
    GraphRelationType.CONNECTED_TO.value: "command-and-control",
    GraphRelationType.UPLOADED_TO.value: "exfiltration",
}

DEFAULT_TACTIC = "discovery"

# Latest listed tactic when attack_techniques.json cannot be read.
_FALLBACK_TECHNIQUE_TACTICS: dict[str, str] = {
    "T1566": "initial-access",
    "T1078": "privilege-escalation",
    "T1059": "execution",
    "T1027": "defense-evasion",
    "T1005": "collection",
    "T1560": "collection",
    "T1041": "exfiltration",
    "T1567": "exfiltration",
    "T1486": "impact",
}

_REGRESSION_WEIGHT = 0.5
_PROGRESS_REF = float(_TACTIC_ORDINAL["exfiltration"] - _TACTIC_ORDINAL["initial-access"])
_HINT_SCALE = 100.0
_SCORE_EPS = 1e-9

_ATTACK_TECHNIQUES_PATH = (
    Path(__file__).resolve().parents[3] / "data" / "knowledge" / "attack_techniques.json"
)


@dataclass(frozen=True, slots=True)
class PathRankSignals:
    """Side table from evidence. GraphEdge has no confidence field."""

    confidence_by_evidence_id: Mapping[str, float] = field(default_factory=dict)
    mitre_by_evidence_id: Mapping[str, str] = field(default_factory=dict)


def signals_from_evidence(evidence_list: Sequence[Evidence]) -> PathRankSignals:
    confidence: dict[str, float] = {}
    mitre: dict[str, str] = {}
    for item in evidence_list:
        evidence_id = (item.evidence_id or "").strip()
        if not evidence_id:
            continue
        confidence[evidence_id] = max(0.0, min(1.0, float(item.confidence)))
        technique = (item.mitre_technique or "").strip()
        if technique:
            mitre[evidence_id] = technique
    return PathRankSignals(
        confidence_by_evidence_id=confidence,
        mitre_by_evidence_id=mitre,
    )


def normalize_tactic(name: str) -> str:
    return (name or "").strip().lower().replace("_", "-").replace(" ", "-")


def tactic_ordinal(tactic: str) -> int:
    return _TACTIC_ORDINAL.get(normalize_tactic(tactic), _TACTIC_ORDINAL[DEFAULT_TACTIC])


def tactic_stage(tactic: str) -> float:
    """Kill-chain stage in [0, 100] from a MITRE tactic name."""
    return 100.0 * tactic_ordinal(tactic) / _MAX_TACTIC_ORDINAL


def relation_stage(relation: str) -> float:
    return tactic_stage(RELATION_TACTIC.get(relation, DEFAULT_TACTIC))


def edge_tactic(edge: Any, signals: PathRankSignals | None = None) -> str:
    """Latest ATT&CK tactic for one edge (technique, else relation fallback)."""
    evidence_id = str(getattr(edge, "evidence_id", "") or "")
    if signals is not None and evidence_id:
        technique = signals.mitre_by_evidence_id.get(evidence_id, "")
        mapped = _technique_latest_tactic(technique)
        if mapped is not None:
            return mapped
    return RELATION_TACTIC.get(_relation_value(edge), DEFAULT_TACTIC)


def edge_stage(edge: Any, signals: PathRankSignals | None = None) -> float:
    """Kill-chain stage in [0, 100] for one directed edge."""
    return tactic_stage(edge_tactic(edge, signals))


def transition_weight(from_tactic: str, to_tactic: str) -> float:
    """w(T_i, T_j): forward span, 0 on repeat, penalized regression."""
    delta = tactic_ordinal(to_tactic) - tactic_ordinal(from_tactic)
    if delta > 0:
        return float(delta)
    if delta == 0:
        return 0.0
    return _REGRESSION_WEIGHT * float(delta)


def progress_gain(progress: float) -> float:
    """g(progress) with log saturation. Non-positive progress does not boost."""
    if _PROGRESS_REF <= 0:
        return 1.0
    return 1.0 + math.log1p(max(0.0, progress)) / math.log1p(_PROGRESS_REF)


def path_progress(
    path: Sequence[str],
    edges: Sequence[Any],
    signals: PathRankSignals | None = None,
) -> float:
    tactics = [edge_tactic(edge, signals) for edge in _path_edges(path, edges, signals)]
    if len(tactics) < 2:
        return 0.0
    return sum(
        transition_weight(tactics[index - 1], tactics[index]) for index in range(1, len(tactics))
    )


def kapr_score(
    path: Sequence[str],
    edges: Sequence[Any],
    signals: PathRankSignals | None = None,
) -> float:
    """Raw KAPR score (may exceed 100). Empty / single-node paths score 0."""
    stages = _path_edge_stages(path, edges, signals)
    if not stages:
        return 0.0
    mean_s = sum(stages) / len(stages)
    mean_c = _mean_confidence(path, edges, signals)
    return mean_s * progress_gain(path_progress(path, edges, signals)) * mean_c


def kapr_score_hint(
    path: Sequence[str],
    edges: Sequence[Any],
    signals: PathRankSignals | None = None,
) -> float:
    """Monotone squash of KAPR into GraphSummaryFeature.score_hint range."""
    raw = kapr_score(path, edges, signals)
    return max(0.0, min(100.0, 100.0 * math.tanh(raw / _HINT_SCALE)))


def rank_attack_paths(
    paths: Sequence[Sequence[str]],
    edges: Sequence[Any],
    signals: PathRankSignals | None = None,
) -> list[list[str]]:
    """Order paths by KAPR; indistinguishable scores use longest-first."""
    materialized = [list(path) for path in paths]
    if not materialized:
        return []
    scores = [kapr_score(path, edges, signals) for path in materialized]
    if _all_close(scores):
        return sorted(materialized, key=lambda item: (-len(item), str(item)))
    ranked = sorted(
        zip(scores, materialized, strict=True),
        key=lambda item: (-item[0], -len(item[1]), str(item[1])),
    )
    return [path for _, path in ranked]


def _path_edges(
    path: Sequence[str],
    edges: Sequence[Any],
    signals: PathRankSignals | None = None,
) -> list[Any]:
    chosen: list[Any] = []
    for source, target in zip(path, path[1:], strict=False):
        matching = [
            edge
            for edge in edges
            if getattr(edge, "source_node_id", None) == source
            and getattr(edge, "target_node_id", None) == target
        ]
        if not matching:
            continue
        chosen.append(max(matching, key=lambda edge: edge_stage(edge, signals)))
    return chosen


def _path_edge_stages(
    path: Sequence[str],
    edges: Sequence[Any],
    signals: PathRankSignals | None,
) -> list[float]:
    return [edge_stage(edge, signals) for edge in _path_edges(path, edges, signals)]


def _mean_confidence(
    path: Sequence[str],
    edges: Sequence[Any],
    signals: PathRankSignals | None,
) -> float:
    if signals is None or not signals.confidence_by_evidence_id:
        return 1.0
    values: list[float] = []
    for edge in _path_edges(path, edges, signals):
        evidence_id = str(getattr(edge, "evidence_id", "") or "")
        if evidence_id in signals.confidence_by_evidence_id:
            values.append(float(signals.confidence_by_evidence_id[evidence_id]))
    if not values:
        return 1.0
    return sum(values) / len(values)


def _relation_value(edge: Any) -> str:
    relation = getattr(edge, "relation_type", "")
    if hasattr(relation, "value"):
        return str(relation.value)
    return str(relation)


def _all_close(scores: Sequence[float]) -> bool:
    if not scores:
        return True
    first = scores[0]
    return all(abs(score - first) <= _SCORE_EPS for score in scores)


def _technique_prefix(technique: str) -> str:
    return technique.upper().strip().split(".", 1)[0]


def _technique_latest_tactic(technique: str) -> str | None:
    token = (technique or "").strip()
    if not token:
        return None
    tactics = _technique_tactics_map()
    prefix = _technique_prefix(token)
    names = tactics.get(token.upper()) or tactics.get(prefix)
    if not names:
        fallback = _FALLBACK_TECHNIQUE_TACTICS.get(prefix)
        return fallback
    return max(names, key=tactic_ordinal)


@lru_cache(maxsize=1)
def _technique_tactics_map() -> dict[str, tuple[str, ...]]:
    try:
        payload = json.loads(_ATTACK_TECHNIQUES_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return {
            technique_id: (tactic,) for technique_id, tactic in _FALLBACK_TECHNIQUE_TACTICS.items()
        }
    mapped: dict[str, tuple[str, ...]] = {}
    for item in payload.get("techniques") or []:
        if not isinstance(item, dict):
            continue
        technique_id = str(item.get("technique_id") or "").strip().upper()
        if not technique_id:
            continue
        tactics = tuple(
            normalize_tactic(str(name))
            for name in (item.get("tactics") or [])
            if normalize_tactic(str(name)) in _TACTIC_ORDINAL
        )
        if not tactics:
            continue
        mapped[technique_id] = tactics
        prefix = _technique_prefix(technique_id)
        current = mapped.get(prefix)
        if current is None or tactic_ordinal(max(tactics, key=tactic_ordinal)) > tactic_ordinal(
            max(current, key=tactic_ordinal)
        ):
            mapped[prefix] = tactics
    return mapped or {
        technique_id: (tactic,) for technique_id, tactic in _FALLBACK_TECHNIQUE_TACTICS.items()
    }


DEFAULT_RELATION_STAGE = tactic_stage(DEFAULT_TACTIC)
RELATION_STAGE_HINT: dict[str, float] = {
    relation: tactic_stage(tactic) for relation, tactic in RELATION_TACTIC.items()
}
TECHNIQUE_STAGE: dict[str, float] = {
    technique_id: tactic_stage(tactic)
    for technique_id, tactic in _FALLBACK_TECHNIQUE_TACTICS.items()
}


__all__ = [
    "ATTACK_TACTIC_ORDER",
    "DEFAULT_RELATION_STAGE",
    "PathRankSignals",
    "RELATION_STAGE_HINT",
    "RELATION_TACTIC",
    "TECHNIQUE_STAGE",
    "edge_stage",
    "edge_tactic",
    "kapr_score",
    "kapr_score_hint",
    "normalize_tactic",
    "path_progress",
    "progress_gain",
    "rank_attack_paths",
    "relation_stage",
    "signals_from_evidence",
    "tactic_ordinal",
    "tactic_stage",
    "transition_weight",
]
