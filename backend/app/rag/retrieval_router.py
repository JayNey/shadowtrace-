"""Evidence-aware retrieval routing.

Three heuristic actions — not a learned EIG/cost policy:

- ``conflict``: malicious / contradictory evidence → do not short-circuit org
  exact hybrid; raise attack_kb top_k.
- ``sufficient``: org exact hit and no conflict → stop hybrid for org_context_kb.
- ``uncertain``: exact miss or unstructured query → hybrid as usual.
"""

from __future__ import annotations

from typing import Literal

from app.models.agent_io import EvidenceOutput
from app.services.fp_adjudication_service import evidence_has_conflict

RetrievalAction = Literal["sufficient", "uncertain", "conflict"]

DEFAULT_TOP_K = 5
CONFLICT_ATTACK_TOP_K = 8


def decide_retrieval_action(*, has_conflict: bool, org_exact_hit: bool) -> RetrievalAction:
    if has_conflict:
        return "conflict"
    if org_exact_hit:
        return "sufficient"
    return "uncertain"


def should_short_circuit_org_exact(*, has_conflict: bool) -> bool:
    """Exact org hits skip hybrid only when evidence is not in conflict."""
    return not has_conflict


def attack_kb_top_k(*, has_conflict: bool) -> int:
    return CONFLICT_ATTACK_TOP_K if has_conflict else DEFAULT_TOP_K


def evidence_conflict_present(evidence_output: EvidenceOutput | None) -> bool:
    return evidence_has_conflict(evidence_output)


__all__ = [
    "CONFLICT_ATTACK_TOP_K",
    "DEFAULT_TOP_K",
    "RetrievalAction",
    "attack_kb_top_k",
    "decide_retrieval_action",
    "evidence_conflict_present",
    "should_short_circuit_org_exact",
]
