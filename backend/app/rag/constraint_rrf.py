"""Constrained Reciprocal Rank Fusion (C-RRF).

Vanilla RRF (Cormack et al., SIGIR 2009) fuses ranked lists ``L_1 … L_m``:

    RRF(d) = Σ_i 1 / (k + rank_i(d))     with k = 60

C-RRF adds one *symbolic* ranking ``L_C`` as an extra voter. ``L_C`` is the
candidate pool (union of the retriever lists) sorted by how many org-context
*allow* constraints each document overlaps. Deny-style kinds
(``person_status``, ``data_handling``, ``security_product``) never enter the
constraint set ``H`` and therefore cannot boost a chunk.

Identity (omit ``L_C`` ⇒ C-RRF ≡ RRF):

    C-RRF(L_1,…,L_m ; H) = RRF(L_1,…,L_m)           if H = ∅ or L_C = ∅
    C-RRF(L_1,…,L_m ; H) = RRF(L_1,…,L_m, L_C)      otherwise

``L_C`` is a fusion voter only. It must not mint typed ``OrgContextMatch``
rows and must not skip ``attack_kb``.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from app.models.agent_io import OrgContextMatch
from app.models.knowledge import RetrievedChunk
from app.rag.rrf_fusion import rrf_fuse

# Allow-only kinds. person_status / data_handling / security_product stay out.
CONSTRAINT_KINDS: frozenset[str] = frozenset(
    {
        "allowed_destination",
        "allowed_source",
        "account_role",
        "time_window",
    }
)

_MIN_VALUE_LEN = 3
_DOMAINISH = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class OrgConstraint:
    """One allow-constraint drawn from an exact org-context hit."""

    kind: str
    value: str


def constraints_from_org_matches(
    matches: Sequence[OrgContextMatch],
) -> tuple[OrgConstraint, ...]:
    """Project typed exact hits into the C-RRF constraint set ``H``.

    Only allow-kinds with a value of at least three characters are kept.
    Duplicate ``(kind, value)`` pairs are dropped.
    """
    seen: set[tuple[str, str]] = set()
    out: list[OrgConstraint] = []
    for match in matches:
        if match.kind not in CONSTRAINT_KINDS:
            continue
        value = match.matched_value.strip().lower()
        if len(value) < _MIN_VALUE_LEN:
            continue
        key = (match.kind, value)
        if key in seen:
            continue
        seen.add(key)
        out.append(OrgConstraint(kind=match.kind, value=value))
    return tuple(out)


def constraint_hits_text(constraint: OrgConstraint, text: str) -> bool:
    """True when *constraint.value* occurs in *text* with token bounds.

    Domain-shaped values also match a proper hostname suffix
    (``mail.files.corp.internal`` hits ``files.corp.internal``).
    CIDR matcher values (``10.20.0.88 in 10.20.0.0/24``) match either side.
    """
    for value in _constraint_needles(constraint.value):
        if _token_bounded(value, text.lower()):
            return True
        if _DOMAINISH.match(value) or constraint.kind in {
            "allowed_destination",
            "allowed_source",
        }:
            suffix = r"(?<![a-z0-9])(?:[a-z0-9-]+\.)+" + re.escape(value) + r"(?![a-z0-9])"
            if re.search(suffix, text.lower()) is not None:
                return True
    return False


def rank_constraint_channel(
    chunks: Sequence[RetrievedChunk],
    constraints: Sequence[OrgConstraint],
) -> list[RetrievedChunk]:
    """Build ``L_C``: unique pool members with overlap > 0, highest overlap first."""
    if not constraints:
        return []
    unique: dict[str, RetrievedChunk] = {}
    for chunk in chunks:
        unique.setdefault(f"{chunk.kb_name}:{chunk.chunk_id}", chunk)
    scored: list[tuple[int, str, RetrievedChunk]] = []
    for key, chunk in unique.items():
        hits = sum(1 for item in constraints if constraint_hits_text(item, chunk.content))
        if hits <= 0:
            continue
        scored.append((hits, key, chunk))
    scored.sort(key=lambda row: (-row[0], row[1]))
    return [row[2] for row in scored]


def c_rrf_fuse(
    result_lists: list[list[RetrievedChunk]],
    constraints: Sequence[OrgConstraint] | None = None,
    *,
    k: int = 60,
) -> tuple[list[RetrievedChunk], bool]:
    """Fuse retriever lists with an optional symbolic constraint ranking.

    Returns ``(fused, constraint_channel_used)``. When the channel is omitted
    the fused list is identical to ``rrf_fuse(result_lists, k=k)``.
    """
    if not constraints:
        return rrf_fuse(result_lists, k=k), False
    pool: list[RetrievedChunk] = []
    for lst in result_lists:
        pool.extend(lst)
    channel = rank_constraint_channel(pool, constraints)
    if not channel:
        return rrf_fuse(result_lists, k=k), False
    return rrf_fuse([*result_lists, channel], k=k), True


def _constraint_needles(value: str) -> list[str]:
    raw = value.strip().lower()
    if len(raw) < _MIN_VALUE_LEN:
        return []
    needles = [raw]
    if " in " in raw:
        left, right = raw.split(" in ", 1)
        needles.extend([left.strip(), right.strip()])
    return [item for item in needles if len(item) >= _MIN_VALUE_LEN]


def _token_bounded(value: str, hay: str) -> bool:
    pattern = r"(?<![a-z0-9])" + re.escape(value) + r"(?![a-z0-9])"
    return re.search(pattern, hay) is not None


__all__ = [
    "CONSTRAINT_KINDS",
    "OrgConstraint",
    "c_rrf_fuse",
    "constraint_hits_text",
    "constraints_from_org_matches",
    "rank_constraint_channel",
]
