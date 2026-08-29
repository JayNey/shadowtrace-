"""Mock-embedding keyword bridges for hybrid retrieval.

``KnowledgeStore.keyword_search`` uses ``plainto_tsquery`` (AND of every token).
Verbose RAG queries therefore miss; MockEmbedder vectors are non-semantic.
This module turns investigator language into short English FTS queries that
exist in seed chunk text, without calling any vendor XDR API.
"""

from __future__ import annotations

import re

# Exact Chinese (or other) analyst phrases → English FTS query (ISSUE-522).
EXACT_PHRASE_ALIASES: dict[str, str] = {
    "数据外泄": "exfiltration",
    "数据外传": "exfiltration",
    "外泄数据": "exfiltration",
    "内鬼": "insider",
    "账号异常": "valid accounts",
    "可疑域名": "phishing",
    "新注册域名": "registered domain",
    "横向移动": "lateral movement",
    "打包压缩": "archive",
}

# Generic investigator language only. Demo IOC hostnames and account names
# must not live here — they overfit golden packs.
_CONTAINS_ALIASES: tuple[tuple[str, str], ...] = (
    ("数据外泄", "exfiltration"),
    ("数据外传", "exfiltration"),
    ("内鬼", "insider"),
    ("7z", "archive"),
    ("变更窗口", "change window"),
    ("改密", "change window"),
    ("新注册", "registered domain"),
    ("data_exfiltration", "exfiltration"),
    ("insider_threat", "insider"),
    ("account_anomaly", "valid accounts"),
    ("suspicious_domain", "phishing"),
    ("lateral_movement", "lateral movement"),
    ("host_compromise", "credential dumping"),
    ("host_compromise", "scripting"),
    ("malicious_process", "scripting"),
)

_EVENT_TYPE_FTS: dict[str, str] = {
    "data_exfiltration": "exfiltration",
    "insider_threat": "insider",
    "account_anomaly": "valid accounts",
    "suspicious_domain": "phishing",
    "lateral_movement": "lateral movement",
    "host_compromise": "credential dumping",
    "malicious_process": "scripting",
}

_HOST_COMPROMISE_QUERIES: tuple[str, ...] = ("credential dumping", "scripting")

_LABELED_ENTITY = re.compile(
    r"\b(?P<label>Host|IP|Process|Domain|Account|File|IOC)\s*:\s*(?P<value>[^\s,;]+)",
    re.IGNORECASE,
)
_FP_AND_LABELS = frozenset({"account", "host"})
_STOPWORDS = frozenset(
    {
        "event",
        "type",
        "alert",
        "severity",
        "behavior",
        "evidence",
        "historical",
        "case",
        "with",
        "entities",
        "false",
        "positive",
        "pattern",
        "for",
        "analysis",
        "soar",
        "playbook",
        "organization",
        "operating",
        "context",
        "the",
        "and",
        "from",
        "high",
        "low",
        "medium",
        "critical",
        "query",
    }
)
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{1,}")

# Regression anchors for Chinese SOC analyst queries (issue #522).
CHINESE_SOC_QUERY_BENCHMARKS: tuple[tuple[str, str, str], ...] = (
    ("数据外泄", "T1567", "Exfiltration"),
    ("数据外泄", "T1048", "Exfiltration"),
    ("数据外泄", "T1041", "Exfiltration"),
    ("内鬼", "T1078", "Initial Access"),
    ("账号异常", "T1078", "Initial Access"),
    ("可疑域名", "T1566", "Initial Access"),
)


def extra_keyword_queries(query: str, *, limit: int = 2) -> list[str]:
    """Short English FTS queries derived from *query* (AND-safe, 1–2 tokens)."""
    stripped = query.strip()
    if not stripped:
        return []
    extras: list[str] = []
    exact = EXACT_PHRASE_ALIASES.get(stripped)
    if exact:
        extras.append(exact)
    lowered = stripped.lower()
    for needle, expansion in _CONTAINS_ALIASES:
        if needle.lower() in lowered or needle in stripped:
            extras.append(expansion)
    return _dedupe(extras, limit=limit)


def expand_keyword_query(query: str) -> str:
    """Exact phrase → English; otherwise first extra or original."""
    stripped = query.strip()
    if not stripped:
        return stripped
    if stripped in EXACT_PHRASE_ALIASES:
        return EXACT_PHRASE_ALIASES[stripped]
    extras = extra_keyword_queries(stripped, limit=1)
    return extras[0] if extras else stripped


def keyword_queries_for_kb(kb_name: str, query: str, *, limit: int = 2) -> list[str]:
    """AND-safe FTS strings for one KB. Empty means skip keyword search."""
    stripped = query.strip()
    if not stripped:
        return []
    extras = extra_keyword_queries(stripped, limit=limit)
    event_fts = _event_type_fts(stripped)
    capped = max(1, limit)

    if kb_name == "attack_kb":
        ordered: list[str] = []
        if "host_compromise" in stripped.lower():
            ordered.extend(_HOST_COMPROMISE_QUERIES)
        elif event_fts:
            ordered.append(event_fts)
        ordered.extend(extras)
        return _dedupe(ordered, limit=capped)

    if kb_name == "fp_case_kb":
        # 口径 M: first slot is Account+Host AND. extras must not occupy both slots.
        ordered: list[str] = []
        entity_and = _fp_entity_and(stripped)
        if entity_and:
            ordered.append(entity_and)
        second = extras[0] if extras else event_fts
        if second:
            ordered.append(second)
        return _dedupe(ordered, limit=capped)

    if kb_name == "playbook_kb":
        lowered = stripped.lower()
        for event_type in _EVENT_TYPE_FTS:
            if event_type in lowered:
                return [event_type]
        return []

    if kb_name == "history_case_kb":
        # Same queue contract as fp: entity AND occupies slot 1.
        ordered = []
        tokens = _entity_tokens(stripped)
        if tokens:
            ordered.append(" ".join(tokens[:2]))
        second = extras[0] if extras else event_fts
        if second:
            ordered.append(second)
        return _dedupe(ordered, limit=capped)

    if kb_name == "org_context_kb":
        tokens = _entity_tokens(stripped)
        ordered = []
        if tokens:
            ordered.append(" ".join(tokens[:4]))
        ordered.extend(extras)
        return _dedupe(ordered, limit=capped)

    return _dedupe(extras or ([stripped] if stripped else []), limit=capped)


def keyword_query_for_kb(kb_name: str, query: str) -> str:
    """First AND-safe FTS string for one KB (CaseKB / single-query callers)."""
    queries = keyword_queries_for_kb(kb_name, query, limit=2)
    if queries:
        return queries[0]
    return query.strip()


def _event_type_fts(query: str) -> str:
    lowered = query.lower()
    for event_type, fts in _EVENT_TYPE_FTS.items():
        if event_type in lowered:
            return fts
    return ""


def _fp_entity_and(query: str) -> str:
    """First keyword road: labeled Account → Host, else entity-like tokens.

    Process labels never occupy the AND slots (口径 D / M).
    """
    labeled_and: list[str] = []
    seen: set[str] = set()
    for match in _LABELED_ENTITY.finditer(query):
        if match.group("label").lower() not in _FP_AND_LABELS:
            continue
        value = match.group("value")
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        labeled_and.append(value)
        if len(labeled_and) >= 2:
            break
    if labeled_and:
        return " ".join(labeled_and)
    tokens = _entity_tokens(query)
    entity_like = [token for token in tokens if _fp_and_fallback_token(token)]
    if entity_like:
        return " ".join(entity_like[:2])
    return ""


def _entity_tokens(query: str) -> list[str]:
    labeled = [match.group("value") for match in _LABELED_ENTITY.finditer(query)]
    leftover: list[str] = []
    for token in _TOKEN.findall(query):
        lowered = token.lower()
        if lowered in _STOPWORDS or lowered in _EVENT_TYPE_FTS:
            continue
        if token in labeled:
            continue
        leftover.append(token)
    merged: list[str] = []
    seen: set[str] = set()
    for token in [*labeled, *leftover]:
        key = token.lower()
        if key in seen:
            continue
        seen.add(key)
        merged.append(token)
    return merged


_PROCESS_SUFFIXES = frozenset({"exe", "dll", "bin", "so", "dylib"})


def _looks_like_entity(token: str) -> bool:
    """Prefer host/account-like tokens over English filler words."""
    return any(sep in token for sep in ("-", "_", ".")) and token.lower() not in _STOPWORDS


def _fp_and_fallback_token(token: str) -> bool:
    """Account/host-like only. Process and dotted domains never occupy AND slots."""
    if not _looks_like_entity(token):
        return False
    lowered = token.lower()
    suffix = lowered.rsplit(".", 1)[-1]
    if suffix in _PROCESS_SUFFIXES:
        return False
    if token.count(".") >= 2:
        return False
    return True


def _dedupe(items: list[str], *, limit: int) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for item in items:
        stripped = item.strip()
        if not stripped:
            continue
        key = stripped.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(stripped)
        if len(deduped) >= limit:
            break
    return deduped
