"""RAGQueryBuilder: generate per-KB query strings from triage + evidence context."""

from __future__ import annotations

from app.models.agent_io import EvidenceOutput, TriageResult
from app.models.enums import EventType

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
    ) -> dict[str, str]:
        """Return ``{kb_name: query_string}`` for each investigation knowledge base."""

        event_hint = _EVENT_TYPE_HINTS.get(triage_result.event_type, "")
        evidence_bits = _evidence_tokens(evidence_output)

        # attack_kb: 攻击技术查询拼证据行为摘要 + 中英检索提示
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
        if evidence_bits:
            attack_parts.append(" ".join(evidence_bits[:6]))
        attack_query = " ".join(attack_parts)

        # fp_case_kb: 误报查询拼告警特征
        fp_parts: list[str] = [
            f"False positive pattern for event type {triage_result.event_type.value},",
            f"severity {triage_result.severity.value}.",
        ]
        if triage_result.reasoning:
            fp_parts.append(f"Analysis: {triage_result.reasoning[:200]}")
        for account in triage_result.entities.accounts[:4]:
            if account.username:
                fp_parts.append(f"Account:{account.username}")
        fp_query = " ".join(fp_parts)

        # history_case_kb: 案例查询拼事件类型与实体特征
        history_parts: list[str] = [
            f"Historical case with event type {triage_result.event_type.value}."
        ]
        entity_descs: list[str] = []
        for ip_e in triage_result.entities.ips[:5]:
            entity_descs.append(f"IP:{ip_e.address}")
        for host_e in triage_result.entities.hosts[:5]:
            entity_descs.append(f"Host:{host_e.hostname}")
        for acct in triage_result.entities.accounts[:5]:
            if acct.username:
                entity_descs.append(f"Account:{acct.username}")
        for proc_e in triage_result.entities.processes[:3]:
            entity_descs.append(f"Process:{proc_e.name}")
        for domain in triage_result.entities.domains[:4]:
            if domain.fqdn:
                entity_descs.append(f"Domain:{domain.fqdn}")
        if entity_descs:
            history_parts.append("Entities: " + ", ".join(entity_descs))
        if evidence_bits:
            history_parts.append(" ".join(evidence_bits[:4]))
        history_query = " ".join(history_parts)

        # playbook_kb: 剧本查询拼事件类型与严重度
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
