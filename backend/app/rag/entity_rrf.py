"""Entity extraction, exact hit, L_E ranking, and fusion-time dedupe.

Query rewrite and ``L_E`` share this module. Pipeline and QueryBuilder must not
grow a second matcher; do not import ``constraint_rrf._token_bounded``.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from app.models.agent_io import EvidenceOutput, TriageResult
from app.models.knowledge import RetrievedChunk
from app.rag.constraint_rrf import OrgConstraint

_MIN_VALUE_LEN = 3

# Org allow destinations that must never enter fp query / fp L_E.
ALLOWLIST_DOMAINS: frozenset[str] = frozenset(
    {
        "files.corp.internal",
        "cdn.corp.internal",
        "carbonblack.corp.internal",
    }
)

_FIELD_VALUE = re.compile(
    r"(?:host|account|process|domain)\s*=\s*([^\s;]+)",
    re.IGNORECASE,
)
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_DOMAINISH = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
_EXE = re.compile(r"([A-Za-z0-9._-]+\.exe)\b", re.IGNORECASE)

_FP_QUERY_KINDS = ("account", "host")
_FP_VOTE_KINDS = ("account", "host", "process")
_HISTORY_KINDS = ("account", "host", "domain", "process", "ip")
_ATTACK_KINDS = ("process", "host", "account", "domain", "ip")
_PLAYBOOK_KINDS = ("account", "host", "process", "domain", "ip")


@dataclass(frozen=True, slots=True)
class EntityToken:
    """One investigation entity after trim / length filter."""

    kind: str
    value: str


def extract_investigation_entities(
    triage_result: TriageResult | None,
    evidence_output: EvidenceOutput | None = None,
) -> tuple[EntityToken, ...]:
    """Pull Account/Host/Process/Domain/IP from Triage ``EntitySet`` + evidence."""
    found: list[EntityToken] = []
    seen: set[tuple[str, str]] = set()

    def _add(kind: str, raw: str | None) -> None:
        token = _normalize_token(kind, raw)
        if token is None:
            return
        key = (token.kind, token.value.lower())
        if key in seen:
            return
        seen.add(key)
        found.append(token)

    if triage_result is not None:
        entities = triage_result.entities
        for account in entities.accounts:
            _add("account", account.username)
        for host in entities.hosts:
            _add("host", host.hostname)
            _add("ip", host.ip)
        for ip_e in entities.ips:
            _add("ip", ip_e.address)
        for domain in entities.domains:
            _add("domain", domain.fqdn)
        for proc in entities.processes:
            _add("process", proc.name)
        for ioc in triage_result.ioc_list:
            _classify_loose(ioc, _add)

    if evidence_output is not None:
        for item in evidence_output.evidence_list:
            for related in item.related_entities:
                _classify_loose(related, _add)
            raw = item.raw_data if isinstance(item.raw_data, dict) else {}
            _add("account", _as_str(raw.get("account")))
            _add("host", _as_str(raw.get("hostname")))
            _add("process", _as_str(raw.get("process")))
            _add("domain", _as_str(raw.get("domain")))
            cmdline = _as_str(raw.get("cmdline"))
            if cmdline:
                match = _EXE.search(cmdline)
                if match:
                    _add("process", match.group(1))
            _add("process", _as_str(raw.get("file_name")))

    return tuple(found)


def project_entities_for_kb(
    kb_name: str,
    entities: Sequence[EntityToken],
    *,
    extra_blocked_domains: Sequence[str] = (),
) -> tuple[EntityToken, ...]:
    """KB-specific slice used by both query rewrite and ``L_E``."""
    if kb_name == "org_context_kb":
        return ()

    blocked = {item.strip().lower() for item in extra_blocked_domains if item.strip()}
    blocked |= {item.lower() for item in ALLOWLIST_DOMAINS}

    kinds: tuple[str, ...]
    if kb_name == "fp_case_kb":
        kinds = _FP_VOTE_KINDS
    elif kb_name == "history_case_kb":
        kinds = _HISTORY_KINDS
    elif kb_name == "attack_kb":
        kinds = _ATTACK_KINDS
    elif kb_name == "playbook_kb":
        kinds = _PLAYBOOK_KINDS
    else:
        kinds = _HISTORY_KINDS

    kind_order = {kind: index for index, kind in enumerate(kinds)}
    selected: list[EntityToken] = []
    seen: set[str] = set()
    for token in entities:
        if token.kind not in kind_order:
            continue
        lowered = token.value.strip().lower()
        if lowered in blocked:
            continue
        if kb_name == "fp_case_kb" and token.kind in {"domain", "ip"}:
            continue
        if lowered in seen:
            continue
        seen.add(lowered)
        selected.append(token)
    selected.sort(key=lambda item: kind_order.get(item.kind, 99))
    return tuple(selected)


def fp_query_entities(
    entities: Sequence[EntityToken],
    *,
    extra_blocked_domains: Sequence[str] = (),
) -> tuple[EntityToken, ...]:
    """fp verbose query: Account → Host, then optional Process. No domain/IP."""
    accounts = [item for item in entities if item.kind == "account"][:4]
    hosts = [item for item in entities if item.kind == "host"][:4]
    processes = [item for item in entities if item.kind == "process"][:3]
    blocked = {item.lower() for item in ALLOWLIST_DOMAINS}
    blocked.update(item.strip().lower() for item in extra_blocked_domains if item.strip())
    out: list[EntityToken] = []
    seen: set[str] = set()
    for token in (*accounts, *hosts, *processes):
        lowered = token.value.strip().lower()
        if lowered in blocked or lowered in seen:
            continue
        seen.add(lowered)
        out.append(token)
    return tuple(out)


def blocked_domains_from_constraints(constraints: Sequence[OrgConstraint]) -> tuple[str, ...]:
    extra: list[str] = []
    for item in constraints:
        value = item.value.strip().lower()
        if not value:
            continue
        if item.kind == "allowed_destination" or _DOMAINISH.match(value):
            extra.append(value)
    return tuple(extra)


def entity_hits_chunk(entity: str, chunk: RetrievedChunk) -> bool:
    """True iff *entity* exactly hits *chunk* (口径 B / §1.2.1)."""
    needle = entity.strip().lower()
    if not needle or _is_glob(needle):
        return False
    for text in _field_parse_haystacks(chunk):
        if _field_exact_hit(needle, text):
            return True
    for text in _hyphen_haystacks(chunk):
        if _hyphen_bounded(needle, text.lower()):
            return True
    return False


def entity_hit_count(chunk: RetrievedChunk, entities: Sequence[EntityToken | str]) -> int:
    values = _entity_values(entities)
    if not values:
        return 0
    return sum(1 for value in values if entity_hits_chunk(value, chunk))


def rank_entity_channel(
    chunks: Sequence[RetrievedChunk],
    entities: Sequence[EntityToken | str],
) -> list[RetrievedChunk]:
    """``L_E``: unique pool members with hit count > 0, highest count first."""
    values = _entity_values(entities)
    if not values:
        return []
    unique: dict[str, RetrievedChunk] = {}
    for chunk in chunks:
        unique.setdefault(f"{chunk.kb_name}:{chunk.chunk_id}", chunk)
    scored: list[tuple[int, str, RetrievedChunk]] = []
    for key, chunk in unique.items():
        hits = entity_hit_count(chunk, values)
        if hits <= 0:
            continue
        scored.append((hits, key, chunk))
    scored.sort(key=lambda row: (-row[0], row[1]))
    return [row[2] for row in scored]


def reorder_fp_hits_first(
    chunks: Sequence[RetrievedChunk],
    entities: Sequence[EntityToken | str],
) -> list[RetrievedChunk]:
    """口径 N: exact-hit chunks before zero-hit, then existing score."""
    values = _entity_values(entities)
    if not values or not chunks:
        return list(chunks)
    indexed = list(chunks)
    indexed.sort(
        key=lambda chunk: (
            0 if entity_hit_count(chunk, values) > 0 else 1,
            -float(chunk.score),
            chunk.chunk_id,
        )
    )
    return indexed


def promote_fp_exact_match(
    chunks: Sequence[RetrievedChunk],
    entities: Sequence[EntityToken | str],
) -> list[RetrievedChunk]:
    """Move the first exact-hit chunk to index 0 and lift its score to the list max.

    No exact hit: return the original order unchanged.
    """
    values = _entity_values(entities)
    if not chunks:
        return []
    if not values:
        return list(chunks)
    current = list(chunks)
    max_score = max(item.score for item in current)
    for index, chunk in enumerate(current):
        if entity_hit_count(chunk, values) <= 0:
            continue
        chosen = chunk.model_copy(update={"score": max_score})
        rest = current[:index] + current[index + 1 :]
        return [chosen, *rest]
    return current


def first_fp_exact_chunk(
    chunks: Sequence[RetrievedChunk],
    entities: Sequence[EntityToken | str],
) -> RetrievedChunk | None:
    values = _entity_values(entities)
    if not values:
        return None
    for chunk in chunks:
        if entity_hit_count(chunk, values) > 0:
            return chunk
    return None


def dedupe_retrieved_chunks(
    chunks: Sequence[RetrievedChunk],
    entities: Sequence[EntityToken | str] = (),
) -> list[RetrievedChunk]:
    """Dedupe one retriever list by stable kb key (口径 I)."""
    best: dict[str, RetrievedChunk] = {}
    order: list[str] = []
    values = _entity_values(entities)
    for chunk in chunks:
        key = chunk_dedupe_key(chunk)
        if key not in best:
            best[key] = chunk
            order.append(key)
            continue
        best[key] = _prefer_chunk(best[key], chunk, values)
    return [best[key] for key in order]


def chunk_dedupe_key(chunk: RetrievedChunk) -> str:
    meta = chunk.metadata or {}
    kb = chunk.kb_name
    if kb == "attack_kb":
        technique_id = str(meta.get("technique_id") or "").strip()
        if technique_id:
            return f"attack:{technique_id}"
        object_id = str(meta.get("object_id") or "").strip()
        if object_id:
            return f"attack:{object_id}"
        return f"attack:{chunk.chunk_id}"
    if kb in {"fp_case_kb", "history_case_kb"}:
        case_id = str(meta.get("case_id") or "").strip()
        if case_id:
            return f"{kb}:{case_id}"
        return f"{kb}:{chunk.chunk_id}"
    if kb == "playbook_kb":
        playbook_id = str(meta.get("playbook_id") or "").strip()
        if playbook_id:
            return f"playbook:{playbook_id}"
        return f"playbook:{chunk.chunk_id}"
    return f"{kb}:{chunk.chunk_id}"


def _prefer_chunk(
    left: RetrievedChunk,
    right: RetrievedChunk,
    entities: Sequence[str],
) -> RetrievedChunk:
    left_hits = entity_hit_count(left, entities)
    right_hits = entity_hit_count(right, entities)
    if left_hits != right_hits:
        return left if left_hits > right_hits else right
    left_kw = _has_keywords_or_aliases(left)
    right_kw = _has_keywords_or_aliases(right)
    if left_kw != right_kw:
        return left if left_kw else right
    return left if left.score >= right.score else right


def _has_keywords_or_aliases(chunk: RetrievedChunk) -> bool:
    meta = chunk.metadata or {}
    for key in ("keywords", "aliases"):
        value = meta.get(key)
        if isinstance(value, str) and value.strip():
            return True
        if isinstance(value, (list, tuple)) and any(str(item).strip() for item in value):
            return True
    return False


def _entity_values(entities: Sequence[EntityToken | str]) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    for item in entities:
        raw = item.value if isinstance(item, EntityToken) else item
        value = str(raw or "").strip()
        if not value or _is_glob(value):
            continue
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
    return tuple(out)


def _normalize_token(kind: str, raw: str | None) -> EntityToken | None:
    value = (raw or "").strip()
    if len(value) < _MIN_VALUE_LEN or _is_glob(value):
        return None
    return EntityToken(kind=kind, value=value)


def _is_glob(value: str) -> bool:
    lowered = value.strip().lower()
    if not lowered:
        return True
    if "*" in lowered:
        return True
    return lowered.endswith("-")


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _classify_loose(raw: str | None, add: Any) -> None:
    value = (raw or "").strip()
    if not value:
        return
    if _IPV4.match(value):
        add("ip", value)
        return
    if _DOMAINISH.match(value):
        add("domain", value)
        return
    if value.lower().endswith(".exe"):
        add("process", value)
        return
    if "-" in value or "_" in value:
        add("host", value)


def _structured_identity_texts(chunk: RetrievedChunk) -> list[str]:
    meta = chunk.metadata or {}
    return [
        str(meta.get("entity_pattern") or ""),
        str(meta.get("key_entities") or ""),
    ]


def _field_parse_haystacks(chunk: RetrievedChunk) -> list[str]:
    """§1.2.1 (1): parse host=/account=/process=/domain= from identity fields.

    ``fp_case_kb`` identity lives in ``entity_pattern`` / ``key_entities``.
    Flattened ``content`` / ``fp_reason`` often name counter-IOCs.
    """
    texts = list(_structured_identity_texts(chunk))
    if chunk.kb_name == "fp_case_kb":
        return texts
    texts.append(chunk.content or "")
    for value in (chunk.metadata or {}).values():
        if isinstance(value, str) and value.strip():
            texts.append(value)
        elif isinstance(value, (list, tuple)):
            texts.extend(str(item) for item in value if isinstance(item, str))
    return texts


def _hyphen_haystacks(chunk: RetrievedChunk) -> list[str]:
    """§1.2.1 (2): hyphen-bounded whole words.

    fp_case_kb identity lives in ``entity_pattern``. Flattened ``content`` /
    ``fp_reason`` often name counter-IOCs (「没有 7z.exe」) that must not vote.
    Other KBs still scan ``content`` so attack/history L_E can see process IOCs.
    """
    texts = _structured_identity_texts(chunk)
    if chunk.kb_name != "fp_case_kb":
        texts.append(chunk.content or "")
    return texts


def _field_exact_hit(needle: str, text: str) -> bool:
    for raw in _FIELD_VALUE.findall(text):
        token = raw.strip()
        if not token or _is_glob(token):
            continue
        if token.lower() == needle:
            return True
    return False


def _hyphen_bounded(needle: str, hay: str) -> bool:
    pattern = r"(?<![a-z0-9._-])" + re.escape(needle) + r"(?![a-z0-9._-])"
    return re.search(pattern, hay) is not None


__all__ = [
    "ALLOWLIST_DOMAINS",
    "EntityToken",
    "blocked_domains_from_constraints",
    "chunk_dedupe_key",
    "dedupe_retrieved_chunks",
    "entity_hit_count",
    "entity_hits_chunk",
    "extract_investigation_entities",
    "first_fp_exact_chunk",
    "fp_query_entities",
    "project_entities_for_kb",
    "promote_fp_exact_match",
    "rank_entity_channel",
    "reorder_fp_hits_first",
]
