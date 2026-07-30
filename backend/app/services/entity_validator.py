"""Entity semantic validation for Source / LLM / regex extraction (ISSUE-099 / #603).

All extraction paths share ``validate_entity_set`` before merge. Structured
Source fields use syntax-only checks; text-derived entities additionally require
host/device context or high-confidence naming shapes.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from app.models.entities import (
    AccountEntity,
    DomainEntity,
    EntitySet,
    FileEntity,
    HostEntity,
    IPEntity,
    ProcessEntity,
)

EntityProvenance = Literal["source", "llm", "regex"]

_HOSTNAME_SYNTAX = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$"
)
_HIGH_CONF_HOST = re.compile(
    r"^(?:"
    r"[A-Za-z]{2,}\d{1,4}"  # db01, ip-10-0-0-4 style short names
    r"|[A-Za-z0-9]+-(?:WKS|SRV|DC|DB|WEB|OPS|FIN|SQL|AD|FS|APP|JUMP|ADMIN|MAIL|PROXY|VPN|NODE|PRD|STG|DEV|HOST|PC|LAP|VM|K8S|GW|FW|LB|API|APP|BASTION|JUMP|CORE|EDGE|MGMT|MON|LOG|SIEM|XDR|EDR|IAM|NFW|PROXY|DLP|CASB|WAF|IDS|IPS|SAN|NAS|OBJ|BLOB|CACHE|QUEUE|WORKER|CRON|JOB|TASK|BATCH|ETL|DW|BI|ML|AI|GPU|CPU|MEM|DISK|VOL|SNAP|BACKUP|DR|HA|LB|VIP|VIP|VIP|VIP)[A-Za-z0-9_-]*"
    r"|[A-Za-z0-9]+-[A-Za-z0-9]+-\d{2,}"  # DEV-WKS-012
    r")$",
    re.IGNORECASE,
)
_HOST_CONTEXT = re.compile(
    r"\b(?:host(?:name)?|server|endpoint|workstation|device|asset|node|vm|wks|srv|pc)\b",
    re.IGNORECASE,
)
_PROCESS_SYNTAX = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.(?:exe|dll|sys|bat|cmd|ps1|vbs|py|sh|bin|run|out)$",
    re.IGNORECASE,
)
_ACCOUNT_SYNTAX = re.compile(r"^[A-Za-z0-9@._-]{1,64}$")
_DOMAIN_SYNTAX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
_FILE_SYNTAX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")

# Common English phrase tails that regex must not treat as hostnames.
_PHRASE_TAIL = frozenset(
    {
        "like",
        "behavior",
        "activity",
        "detected",
        "attempt",
        "pattern",
        "chain",
        "stage",
        "based",
        "related",
        "suspicious",
        "malicious",
        "unknown",
        "anomaly",
    }
)


@dataclass(frozen=True, slots=True)
class EntityRejection:
    entity_type: str
    value: str
    reason_code: str


@dataclass(frozen=True, slots=True)
class EntityValidationResult:
    entity_set: EntitySet
    rejections: tuple[EntityRejection, ...] = field(default_factory=tuple)

    @property
    def rejection_summary(self) -> dict[str, Any]:
        """Truncated counts for decision trace — no raw rejected values."""
        counts: dict[str, int] = {}
        for item in self.rejections:
            counts[item.reason_code] = counts.get(item.reason_code, 0) + 1
        return {"rejection_counts": counts, "total_rejected": len(self.rejections)}


def validate_entity_set(
    entities: EntitySet | None,
    *,
    provenance: EntityProvenance,
    alert_text: str = "",
) -> EntityValidationResult:
    """Validate and filter an ``EntitySet`` for the given provenance."""
    if entities is None:
        return EntityValidationResult(entity_set=EntitySet())

    rejections: list[EntityRejection] = []
    accounts: list[AccountEntity] = []
    hosts: list[HostEntity] = []
    ips: list[IPEntity] = []
    domains: list[DomainEntity] = []
    processes: list[ProcessEntity] = []
    files: list[FileEntity] = []

    for account in entities.accounts:
        username = (account.username or "").strip()
        if not username:
            continue
        if not _ACCOUNT_SYNTAX.match(username):
            rejections.append(
                EntityRejection("account", username, "invalid_account_syntax")
            )
            continue
        accounts.append(account)

    for host in entities.hosts:
        hostname = (host.hostname or "").strip()
        ip_value = (host.ip or "").strip()
        if hostname:
            ok, reason = _validate_hostname(hostname, provenance=provenance, alert_text=alert_text)
            if not ok:
                rejections.append(EntityRejection("host", hostname, reason))
                hostname = ""
        if ip_value and not _valid_ip_literal(ip_value):
            rejections.append(EntityRejection("host_ip", ip_value, "invalid_ip_literal"))
            ip_value = ""
        if hostname or ip_value:
            hosts.append(
                host.model_copy(
                    update={"hostname": hostname or None, "ip": ip_value or None}
                )
            )

    for ip_entity in entities.ips:
        address = (ip_entity.address or "").strip()
        if not address:
            continue
        if not _valid_ip_literal(address):
            rejections.append(EntityRejection("ip", address, "invalid_ip_literal"))
            continue
        ips.append(ip_entity)

    for domain in entities.domains:
        fqdn = (domain.fqdn or "").strip()
        if not fqdn:
            continue
        if not _DOMAIN_SYNTAX.match(fqdn):
            rejections.append(EntityRejection("domain", fqdn, "invalid_domain_syntax"))
            continue
        domains.append(domain)

    for process in entities.processes:
        name = (process.name or "").strip()
        if not name:
            continue
        if provenance == "source" or _PROCESS_SYNTAX.match(name):
            processes.append(process)
        else:
            rejections.append(EntityRejection("process", name, "invalid_process_syntax"))

    for file_entity in entities.files:
        path = (file_entity.path or file_entity.name or "").strip()
        if not path:
            continue
        if provenance == "source" or _FILE_SYNTAX.match(path):
            files.append(file_entity)
        else:
            rejections.append(EntityRejection("file", path, "invalid_file_syntax"))

    return EntityValidationResult(
        entity_set=EntitySet(
            accounts=accounts,
            hosts=hosts,
            ips=ips,
            domains=domains,
            processes=processes,
            files=files,
        ),
        rejections=tuple(rejections),
    )


def _validate_hostname(
    hostname: str,
    *,
    provenance: EntityProvenance,
    alert_text: str,
) -> tuple[bool, str]:
    if not _HOSTNAME_SYNTAX.match(hostname):
        return False, "invalid_hostname_syntax"
    if provenance == "source":
        return True, ""
    if _HIGH_CONF_HOST.match(hostname):
        return True, ""
    if _HOST_CONTEXT.search(alert_text):
        return True, ""
    parts = hostname.lower().split("-")
    if parts and parts[-1] in _PHRASE_TAIL:
        return False, "phrase_without_host_context"
    if len(parts) >= 2 and all(part.isalpha() and len(part) <= 12 for part in parts):
        return False, "phrase_without_host_context"
    if hostname.lower().endswith("-like"):
        return False, "phrase_without_host_context"
    return True, ""


def _valid_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


__all__ = [
    "EntityProvenance",
    "EntityRejection",
    "EntityValidationResult",
    "validate_entity_set",
]
