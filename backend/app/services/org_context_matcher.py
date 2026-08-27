"""Exact-field matcher for org_context_kb (domains, CIDR, accounts, time windows)."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, time
from typing import Any

from app.knowledge.org_context_seed import ORG_CONTEXT_KINDS
from app.models.agent_io import EvidenceOutput, OrgContextKind, OrgContextMatch, TriageResult
from app.models.knowledge import ORG_CONTEXT_KB_NAME, ListedKnowledgeChunk, RetrievedChunk

_TOKEN_RE = re.compile(r"\b(Domain|IP|Host|Account):([^\s,]+)", re.IGNORECASE)
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)

# Field-level exact hits eligible for typed OrgContextMatch rows.
# ``restricted_domain`` is deny-style (data_handling); it never qualifies FP close.
# Vector/keyword scores never qualify.
ORG_CONTEXT_EXACT_MATCH_TYPES: frozenset[str] = frozenset(
    {
        "domain_exact",
        "domain_suffix",
        "restricted_domain",
        "cidr",
        "ip_exact",
        "account_exact",
        "host_exact",
        "window",
        "exact",
    }
)


@dataclass(frozen=True, slots=True)
class OrgContextFacts:
    domains: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    accounts: tuple[str, ...] = ()
    now: datetime | None = None

    def has_structured_entities(self) -> bool:
        return bool(self.domains or self.ips or self.hosts or self.accounts)

    def merge(self, other: OrgContextFacts) -> OrgContextFacts:
        return OrgContextFacts(
            domains=_unique(self.domains + other.domains),
            ips=_unique(self.ips + other.ips),
            hosts=_unique(self.hosts + other.hosts),
            accounts=_unique(self.accounts + other.accounts),
            now=self.now or other.now,
        )


@dataclass(frozen=True, slots=True)
class OrgContextHit:
    chunk_id: str
    kb_name: str
    content: str
    metadata: dict[str, Any]
    kind: str
    matched_value: str
    match_type: str
    created_at: datetime | None = None


def extract_org_context_facts(
    triage_result: TriageResult | None,
    evidence_output: EvidenceOutput | None = None,
    *,
    now: datetime | None = None,
) -> OrgContextFacts:
    domains: list[str] = []
    ips: list[str] = []
    hosts: list[str] = []
    accounts: list[str] = []
    if triage_result is not None:
        for domain in triage_result.entities.domains:
            if domain.fqdn:
                domains.append(domain.fqdn)
        for ip_ent in triage_result.entities.ips:
            if ip_ent.address:
                ips.append(ip_ent.address)
        for host in triage_result.entities.hosts:
            if host.hostname:
                hosts.append(host.hostname)
            if host.ip:
                ips.append(host.ip)
        for account in triage_result.entities.accounts:
            if account.username:
                accounts.append(account.username)
        for ioc in triage_result.ioc_list:
            _classify_token(ioc, domains, ips, hosts)
    if evidence_output is not None:
        for evidence in evidence_output.evidence_list:
            for related in evidence.related_entities:
                _classify_token(related, domains, ips, hosts)
    return OrgContextFacts(
        domains=_unique(tuple(_norm_domain(d) for d in domains if _norm_domain(d))),
        ips=_unique(tuple(_norm_ip(i) for i in ips if _norm_ip(i))),
        hosts=_unique(tuple(_norm_host(h) for h in hosts if _norm_host(h))),
        accounts=_unique(tuple(_norm_account(a) for a in accounts if _norm_account(a))),
        now=now,
    )


def facts_from_query(query: str, *, now: datetime | None = None) -> OrgContextFacts:
    domains: list[str] = []
    ips: list[str] = []
    hosts: list[str] = []
    accounts: list[str] = []
    for kind, raw in _TOKEN_RE.findall(query or ""):
        value = raw.strip().rstrip(".")
        key = kind.lower()
        if key == "domain":
            domains.append(value)
        elif key == "ip":
            ips.append(value)
        elif key == "host":
            hosts.append(value)
        elif key == "account":
            accounts.append(value)
    return OrgContextFacts(
        domains=_unique(tuple(_norm_domain(d) for d in domains if _norm_domain(d))),
        ips=_unique(tuple(_norm_ip(i) for i in ips if _norm_ip(i))),
        hosts=_unique(tuple(_norm_host(h) for h in hosts if _norm_host(h))),
        accounts=_unique(tuple(_norm_account(a) for a in accounts if _norm_account(a))),
        now=now,
    )


class OrgContextMatcher:
    """Exact metadata matcher. Near-miss spelling and vector similarity are not hits."""

    @staticmethod
    def match(
        facts: OrgContextFacts,
        chunks: Sequence[ListedKnowledgeChunk | RetrievedChunk | dict[str, Any]],
        *,
        now: datetime | None = None,
    ) -> list[OrgContextHit]:
        effective_now = now or facts.now
        hits: list[OrgContextHit] = []
        seen: set[str] = set()
        for raw in chunks:
            chunk_id, kb_name, content, metadata, created_at = _unpack_chunk(raw)
            kind = str(metadata.get("kind") or "")
            if kind not in ORG_CONTEXT_KINDS:
                continue
            matched = _match_record(facts, metadata, kind, effective_now)
            if matched is None:
                continue
            match_type, matched_value = matched
            if chunk_id in seen:
                continue
            seen.add(chunk_id)
            stamped = dict(metadata)
            stamped["matched_value"] = matched_value
            stamped["match_type"] = match_type
            hits.append(
                OrgContextHit(
                    chunk_id=chunk_id,
                    kb_name=kb_name,
                    content=content,
                    metadata=stamped,
                    kind=kind,
                    matched_value=matched_value,
                    match_type=match_type,
                    created_at=created_at,
                )
            )
        return hits


def hits_to_retrieved_chunks(hits: list[OrgContextHit]) -> list[RetrievedChunk]:
    chunks: list[RetrievedChunk] = []
    for hit in hits:
        chunks.append(
            RetrievedChunk(
                chunk_id=hit.chunk_id,
                kb_name=hit.kb_name,
                content=hit.content,
                metadata=hit.metadata,
                score=1.0,
                retrieval_method="exact",
                created_at=hit.created_at,
            )
        )
    return chunks


def _match_record(
    facts: OrgContextFacts,
    metadata: dict[str, Any],
    kind: str,
    now: datetime | None,
) -> tuple[str, str] | None:
    if kind == "data_handling":
        return _match_data_handling(facts, metadata)

    domains = _as_str_list(metadata.get("domains"))
    cidrs = _as_str_list(metadata.get("cidrs"))
    ips = _as_str_list(metadata.get("ips"))
    hosts = _as_str_list(metadata.get("hosts"))
    accounts = _as_str_list(metadata.get("accounts"))

    if kind == "time_window":
        return _match_time_window(facts, metadata, now, domains, cidrs, ips, hosts, accounts)

    for candidate in facts.domains:
        for allowed in domains:
            if _domain_matches(candidate, allowed):
                match_type = (
                    "domain_suffix" if candidate != _norm_domain(allowed) else "domain_exact"
                )
                return match_type, candidate
    for candidate in facts.ips:
        for allowed_ip in ips:
            if _norm_ip(candidate) == _norm_ip(allowed_ip):
                return "ip_exact", candidate
        for cidr in cidrs:
            if _ip_in_cidr(candidate, cidr):
                return "cidr", f"{candidate} in {cidr}"
    for candidate in facts.hosts:
        for allowed_host in hosts:
            if _norm_host(candidate) == _norm_host(allowed_host):
                return "host_exact", candidate
    for candidate in facts.accounts:
        for allowed_acct in accounts:
            if _norm_account(candidate) == _norm_account(allowed_acct):
                return "account_exact", candidate
    return None


def _match_data_handling(
    facts: OrgContextFacts,
    metadata: dict[str, Any],
) -> tuple[str, str] | None:
    """Match named destinations; classify approved vs restricted via allowed_channels.

    ``domains`` is what the policy talks about (including unapproved destinations).
    ``allowed_channels`` is the approved path. A named destination that is not an
    allowed channel is a deny-style ``restricted_domain`` hit — never an allow
    ``domain_exact`` / ``domain_suffix`` hit. Approved-channel-only rows (empty
    ``domains``) still match ``allowed_channels`` as allow-style domain hits.
    """
    named_domains = _as_str_list(metadata.get("domains"))
    allowed_channels = _as_str_list(metadata.get("allowed_channels"))
    for candidate in facts.domains:
        for named in named_domains:
            if not _domain_matches(candidate, named):
                continue
            if any(_domain_matches(candidate, allowed) for allowed in allowed_channels):
                match_type = "domain_suffix" if candidate != _norm_domain(named) else "domain_exact"
                return match_type, candidate
            return "restricted_domain", candidate
    if named_domains:
        return None
    for candidate in facts.domains:
        for allowed in allowed_channels:
            if _domain_matches(candidate, allowed):
                match_type = (
                    "domain_suffix" if candidate != _norm_domain(allowed) else "domain_exact"
                )
                return match_type, candidate
    return None


def _match_time_window(
    facts: OrgContextFacts,
    metadata: dict[str, Any],
    now: datetime | None,
    domains: list[str],
    cidrs: list[str],
    ips: list[str],
    hosts: list[str],
    accounts: list[str],
) -> tuple[str, str] | None:
    """Clock-only rows are not hits; window records must bind to entities."""
    if now is None:
        return None
    if not (domains or cidrs or ips or hosts or accounts):
        return None
    if not _facts_overlap_record(facts, domains, cidrs, ips, hosts, accounts):
        return None
    window_start = metadata.get("window_start")
    window_end = metadata.get("window_end")
    if not isinstance(window_start, str) or not isinstance(window_end, str):
        return None
    if _now_in_window(now, window_start, window_end):
        return "window", f"{window_start}/{window_end}"
    return None


def _facts_overlap_record(
    facts: OrgContextFacts,
    domains: list[str],
    cidrs: list[str],
    ips: list[str],
    hosts: list[str],
    accounts: list[str],
) -> bool:
    if any(
        _domain_matches(candidate, allowed) for candidate in facts.domains for allowed in domains
    ):
        return True
    if any(_norm_ip(candidate) == _norm_ip(allowed) for candidate in facts.ips for allowed in ips):
        return True
    if any(_ip_in_cidr(candidate, cidr) for candidate in facts.ips for cidr in cidrs):
        return True
    if any(
        _norm_host(candidate) == _norm_host(allowed)
        for candidate in facts.hosts
        for allowed in hosts
    ):
        return True
    if any(
        _norm_account(candidate) == _norm_account(allowed)
        for candidate in facts.accounts
        for allowed in accounts
    ):
        return True
    return False


def _now_in_window(now: datetime, start_raw: str, end_raw: str) -> bool:
    start_dt = _try_parse_datetime(start_raw)
    end_dt = _try_parse_datetime(end_raw)
    if start_dt is not None and end_dt is not None:
        current = now if now.tzinfo else now.replace(tzinfo=UTC)
        start = start_dt if start_dt.tzinfo else start_dt.replace(tzinfo=UTC)
        end = end_dt if end_dt.tzinfo else end_dt.replace(tzinfo=UTC)
        return start <= current <= end
    start_t = _try_parse_time(start_raw)
    end_t = _try_parse_time(end_raw)
    if start_t is None or end_t is None:
        return False
    current_t = (now if now.tzinfo else now.replace(tzinfo=UTC)).astimezone(UTC).time()
    if start_t <= end_t:
        return start_t <= current_t <= end_t
    return current_t >= start_t or current_t <= end_t


def _try_parse_datetime(raw: str) -> datetime | None:
    text = raw.strip()
    if len(text) < 10 or "T" not in text and " " not in text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed


def _try_parse_time(raw: str) -> time | None:
    text = raw.strip()
    for fmt in ("%H:%M:%S", "%H:%M"):
        try:
            return datetime.strptime(text, fmt).time()
        except ValueError:
            continue
    return None


def _domain_matches(candidate: str, allowed: str) -> bool:
    c = _norm_domain(candidate)
    a = _norm_domain(allowed)
    if not c or not a:
        return False
    return c == a or c.endswith("." + a)


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return addr in net


def _classify_token(raw: str, domains: list[str], ips: list[str], hosts: list[str]) -> None:
    token = (raw or "").strip().rstrip(".")
    if not token:
        return
    if _norm_ip(token):
        ips.append(token)
        return
    if _DOMAIN_RE.match(token):
        domains.append(token)
        return
    if "." not in token:
        hosts.append(token)


def _unpack_chunk(
    raw: ListedKnowledgeChunk | RetrievedChunk | dict[str, Any],
) -> tuple[str, str, str, dict[str, Any], datetime | None]:
    if isinstance(raw, dict):
        return (
            str(raw.get("chunk_id") or ""),
            str(raw.get("kb_name") or "org_context_kb"),
            str(raw.get("content") or ""),
            dict(raw.get("metadata") or {}),
            raw.get("created_at"),
        )
    created_at = getattr(raw, "created_at", None)
    return raw.chunk_id, raw.kb_name, raw.content, dict(raw.metadata or {}), created_at


def _as_str_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if str(item).strip()]
    return []


def _norm_domain(value: str) -> str:
    return value.strip().rstrip(".").lower()


def _norm_host(value: str) -> str:
    return value.strip().rstrip(".").lower()


def _norm_account(value: str) -> str:
    return value.strip().lower()


def _norm_ip(value: str) -> str:
    text = value.strip()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def _unique(values: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for item in values:
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return tuple(out)


def coerce_org_context_kind(raw: str) -> OrgContextKind | None:
    if raw in ORG_CONTEXT_KINDS:
        return raw  # type: ignore[return-value]
    return None


def is_exact_org_context_match(
    match_type: str,
    *,
    retrieval_method: str | None = None,
) -> bool:
    """True when the hit is a typed exact-field match, not a vector/keyword guess."""
    if retrieval_method is not None and retrieval_method != "exact":
        return False
    return match_type in ORG_CONTEXT_EXACT_MATCH_TYPES


def hits_to_org_context_matches(hits: Sequence[OrgContextHit]) -> list[OrgContextMatch]:
    """Project matcher hits into agent-facing OrgContextMatch rows."""
    matches: list[OrgContextMatch] = []
    for hit in hits:
        kind = coerce_org_context_kind(hit.kind)
        if kind is None:
            continue
        if not is_exact_org_context_match(hit.match_type, retrieval_method="exact"):
            continue
        digest = hashlib.sha256(hit.chunk_id.encode()).hexdigest()[:8]
        matches.append(
            OrgContextMatch(
                kind=kind,
                matched_value=hit.matched_value,
                explanation=hit.content,
                citation_id=f"cit-{digest}",
                chunk_id=hit.chunk_id,
                match_type=hit.match_type,
                match_confidence=1.0,
            )
        )
    return matches


async def list_org_context_chunks(store: Any, tenant_id: str) -> list[Any]:
    """Page through org_context_kb. Empty catalog is a real empty list, not an error."""
    page = 1
    page_size = 100
    listed: list[Any] = []
    while page <= 50:
        batch = await store.list_chunks(
            kb_name=ORG_CONTEXT_KB_NAME,
            page=page,
            page_size=page_size,
            tenant_id=tenant_id,
        )
        listed.extend(batch)
        if len(batch) < page_size:
            break
        page += 1
    return listed


async def load_org_context_matches(
    store: Any,
    *,
    triage_result: TriageResult | None,
    evidence_output: EvidenceOutput | None,
    tenant_id: str,
    occurred_at: datetime | None,
    top_k: int = 20,
) -> list[OrgContextMatch]:
    """Exact org-context hits for FP adjudication. Empty store → empty list."""
    if store is None or not hasattr(store, "list_chunks"):
        return []
    facts = extract_org_context_facts(
        triage_result,
        evidence_output,
        now=occurred_at,
    )
    if not facts.has_structured_entities():
        return []
    listed = await list_org_context_chunks(store, tenant_id)
    hits = OrgContextMatcher.match(facts, listed, now=occurred_at or facts.now)
    return hits_to_org_context_matches(hits[:top_k])
