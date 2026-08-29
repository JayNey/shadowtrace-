"""RAGQueryBuilder: generate per-KB query strings from triage + evidence context."""

from __future__ import annotations

import re
from collections.abc import Sequence

from app.models.agent_io import EvidenceOutput, TriageResult
from app.models.enums import EventType
from app.rag.entity_rrf import (
    ALLOWLIST_DOMAINS,
    EntityToken,
    extract_investigation_entities,
    fp_query_entities,
    project_entities_for_kb,
)

_EVENT_TYPE_HINTS: dict[EventType, str] = {
    EventType.DATA_EXFILTRATION: "exfiltration archive 数据外泄",
    EventType.INSIDER_THREAT: "insider valid accounts 内鬼",
    EventType.ACCOUNT_ANOMALY: "valid accounts 账号异常 change window",
    EventType.SUSPICIOUS_DOMAIN: "phishing newly registered domain 可疑域名",
    EventType.LATERAL_MOVEMENT: "lateral movement 横向移动",
    EventType.HOST_COMPROMISE: "credential dumping command scripting T1003 T1059",
    EventType.MALICIOUS_PROCESS: "command scripting interpreter",
    EventType.OTHER: "security event",
}


class RAGQueryBuilder:
    """Build per-KB query strings from triage result and evidence output."""

    @staticmethod
    def build_queries(
        triage_result: TriageResult,
        evidence_output: EvidenceOutput | None = None,
        extra_blocked_domains: Sequence[str] = (),
    ) -> dict[str, str]:
        """Return ``{kb_name: query_string}`` for each investigation knowledge base."""

        event_hint = _EVENT_TYPE_HINTS.get(triage_result.event_type, "")
        extracted = extract_investigation_entities(triage_result, evidence_output)
        evidence_bits = _evidence_tokens(evidence_output)

        # attack_kb: 进程优先，再 Host/Account；行为摘要保留
        attack_parts: list[str] = [
            f"Event type: {triage_result.event_type.value}.",
            f"Alert severity: {triage_result.severity.value}.",
        ]
        if event_hint:
            attack_parts.append(event_hint)
        if evidence_output and evidence_output.evidence_list:
            behaviors = [e.description for e in evidence_output.evidence_list if e.description]
            if behaviors:
                attack_parts.append("Behavior evidence: " + "; ".join(behaviors[:3]))
        attack_entities = project_entities_for_kb("attack_kb", extracted)
        attack_labels = _labeled_tokens(
            attack_entities,
            kind_order=("process", "host", "account", "domain", "ip"),
            limits={"process": 3, "host": 4, "account": 4, "domain": 4, "ip": 4},
        )
        if attack_labels:
            attack_parts.append(" ".join(attack_labels))
        if evidence_bits:
            attack_parts.append(" ".join(evidence_bits[:6]))
        attack_query = " ".join(attack_parts)

        # fp_case_kb: Account → Host → optional Process. No domain / IP / allowlist.
        # Labeled IOC tokens MUST precede Analysis so keyword AND cannot steal slots.
        fp_parts: list[str] = [
            f"False positive pattern for event type {triage_result.event_type.value},",
            f"severity {triage_result.severity.value}.",
        ]
        fp_entities = fp_query_entities(
            project_entities_for_kb(
                "fp_case_kb",
                extracted,
                extra_blocked_domains=extra_blocked_domains,
            ),
            extra_blocked_domains=extra_blocked_domains,
        )
        fp_parts.extend(
            _labeled_tokens(
                fp_entities,
                kind_order=("account", "host", "process"),
                limits={"account": 4, "host": 4, "process": 3},
            )
        )
        analysis_src = _fp_analysis_text(triage_result)
        if analysis_src:
            analysis = _strip_entity_labels(analysis_src)
            if analysis:
                fp_parts.append(f"Analysis: {analysis}")
        fp_query = _drop_blocked_tokens(" ".join(fp_parts), extra_blocked_domains)

        # history_case_kb: 抽出函数 + 按库投影，上限与今天同级
        history_parts: list[str] = [
            f"Historical case with event type {triage_result.event_type.value}."
        ]
        history_entities = project_entities_for_kb("history_case_kb", extracted)
        history_labels = _labeled_tokens(
            history_entities,
            kind_order=("host", "account", "process", "domain", "ip"),
            limits={"host": 5, "account": 5, "process": 3, "domain": 4, "ip": 5},
        )
        if history_labels:
            history_parts.append("Entities: " + ", ".join(history_labels))
        if evidence_bits:
            history_parts.append(" ".join(_drop_allowlist(evidence_bits[:4])))
        history_query = " ".join(history_parts)

        # playbook_kb: 只有 type + severity（不追加实体）
        playbook_query = (
            f"SOAR playbook for event type {triage_result.event_type.value}, "
            f"severity {triage_result.severity.value}."
        )

        org_parts = [
            f"Organization operating context for event type {triage_result.event_type.value}."
        ]
        org_tokens: list[str] = []
        for domain in triage_result.entities.domains[:8]:
            if domain.fqdn:
                org_tokens.append(f"Domain:{domain.fqdn}")
        for ip_e in triage_result.entities.ips[:8]:
            if ip_e.address:
                org_tokens.append(f"IP:{ip_e.address}")
        for host_e in triage_result.entities.hosts[:8]:
            if host_e.hostname:
                org_tokens.append(f"Host:{host_e.hostname}")
        for acct in triage_result.entities.accounts[:8]:
            if acct.username:
                org_tokens.append(f"Account:{acct.username}")
        for ioc in triage_result.ioc_list[:8]:
            if ioc:
                org_tokens.append(str(ioc))
        if org_tokens:
            org_parts.append("Entities: " + ", ".join(org_tokens))
        if evidence_output and evidence_output.evidence_list:
            snippets = [e.description for e in evidence_output.evidence_list if e.description]
            if snippets:
                org_parts.append("Evidence: " + "; ".join(snippets[:2]))
        org_query = " ".join(org_parts)

        return {
            "attack_kb": attack_query,
            "fp_case_kb": fp_query,
            "history_case_kb": history_query,
            "playbook_kb": playbook_query,
            "org_context_kb": org_query,
        }


_LABELED_IN_TEXT = re.compile(
    r"\b(?:Host|IP|Process|Domain|Account|File|IOC)\s*:\s*[^\s,;]+",
    re.IGNORECASE,
)


def _fp_analysis_text(triage_result: TriageResult) -> str:
    """Prefer decision_summary; fall back to dumped reasoning without the deprecated accessor."""
    summary = (triage_result.decision_summary or "").strip()
    if summary:
        return summary[:200]
    dumped = triage_result.model_dump()
    return str(dumped.get("reasoning") or "").strip()[:200]


def _strip_entity_labels(text: str) -> str:
    """Drop Host:/Account: tokens from free-text so they cannot occupy keyword AND."""
    return " ".join(_LABELED_IN_TEXT.sub(" ", text).split())


_LABEL_BY_KIND = {
    "account": "Account",
    "host": "Host",
    "process": "Process",
    "domain": "Domain",
    "ip": "IP",
}


def _labeled_tokens(
    entities: Sequence[EntityToken],
    *,
    kind_order: tuple[str, ...],
    limits: dict[str, int],
) -> list[str]:
    counts: dict[str, int] = {kind: 0 for kind in kind_order}
    out: list[str] = []
    by_kind: dict[str, list[str]] = {kind: [] for kind in kind_order}
    for token in entities:
        if token.kind not in limits:
            continue
        if counts[token.kind] >= limits[token.kind]:
            continue
        counts[token.kind] += 1
        by_kind[token.kind].append(f"{_LABEL_BY_KIND[token.kind]}:{token.value}")
    for kind in kind_order:
        out.extend(by_kind[kind])
    return out


def _drop_allowlist(tokens: list[str]) -> list[str]:
    blocked = {item.lower() for item in ALLOWLIST_DOMAINS}
    return [token for token in tokens if token.strip().lower() not in blocked]


def _drop_blocked_tokens(text: str, extra_blocked_domains: Sequence[str] = ()) -> str:
    """Remove allowlist / org-allow domain tokens from the fp query (口径 C)."""
    blocked = {item.lower() for item in ALLOWLIST_DOMAINS}
    blocked.update(item.strip().lower() for item in extra_blocked_domains if item.strip())
    if not blocked:
        return text
    kept: list[str] = []
    for token in text.split():
        stripped = token.strip(".,;:()[]\"'").lower()
        if stripped in blocked:
            continue
        kept.append(token)
    return " ".join(kept)


def _evidence_tokens(evidence_output: EvidenceOutput | None) -> list[str]:
    if evidence_output is None:
        return []
    tokens: list[str] = []
    for item in evidence_output.evidence_list[:8]:
        for related in item.related_entities[:4]:
            if related:
                tokens.append(str(related))
        raw = item.raw_data if isinstance(item.raw_data, dict) else {}
        for key in ("cmdline", "process", "file_name", "domain", "account", "hostname"):
            value = raw.get(key)
            if value:
                tokens.append(str(value))
    return tokens
