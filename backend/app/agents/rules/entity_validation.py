"""Entity semantic validation for Source / LLM / regex extraction (ISSUE-100 / #603).

Shared validator for all extraction paths. Structured Source hostnames require
syntax only; text-derived hostnames additionally need host/device context or a
high-confidence naming shape. Never uses scenario-specific blocklists.
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

# Shared host/device context keywords (extract + validate must stay aligned).
HOST_CONTEXT_PREFIX = r"host(?:name)?|server|endpoint|workstation|device|asset|node|vm|wks|srv|pc"
HOST_CONTEXTUAL_PATTERN: re.Pattern[str] = re.compile(
    rf"\b(?:{HOST_CONTEXT_PREFIX})\s+"
    r"([A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)\b",
    re.IGNORECASE,
)

# RFC-ish hostname label syntax (single token or dotted).
_HOSTNAME_SYNTAX = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$"
)

# High-confidence shapes accepted without explicit host/device context in alert text.
_HIGH_CONF_HOST = re.compile(
    r"^(?:"
    r"[A-Za-z]{2,}\d{2,4}"  # db01, srv12 — require >=2 trailing digits
    r"|[A-Za-z0-9]+(?:-[A-Za-z0-9]+)-\d+"  # DEV-WKS-012, ubuntu-prod-01
    r"|[A-Za-z0-9]+-\d+-[A-Za-z0-9]+"  # web-01-prod, app-3-east
    r"|ip-\d+-\d+-\d+-\d+"  # ip-10-0-0-4 cloud style
    r"|[A-Za-z0-9]+-(?:WKS|SRV|DC|DB|WEB|OPS|FIN|SQL|AD|FS|APP|JUMP|ADMIN|MAIL|"
    r"PROXY|VPN|NODE|PRD|STG|DEV|HOST|PC|LAP|VM|K8S|GW|FW|LB|API|BASTION|CORE|EDGE|"
    r"MGMT|MON|LOG|SIEM|XDR|EDR|IAM|NFW|DLP|CASB|WAF|IDS|IPS|SAN|NAS|WORKER|CRON|"
    r"JOB|TASK|BATCH|ETL|DW|BI|ML|AI|GPU|CPU|MEM|DISK|VOL|SNAP|BACKUP|DR|HA|VIP)"
    r"[A-Za-z0-9_-]*"
    r")$",
    re.IGNORECASE,
)

# Natural-language alert jargon (stage/level/phase + digit) — not scenario blocklist.
# Extend only with paired negative regression samples in test_entity_extraction_rules.
_ALERT_SHORT_TOKEN = frozenset(
    {
        "stage",
        "level",
        "phase",
        "step",
        "tier",
        "type",
        "file",
        "less",
        "like",
        "chain",
        "beacon",
    }
)

# Context keyword must immediately precede the candidate hostname in alert text.

_PROCESS_SYNTAX = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.(?:exe|dll|sys|bat|cmd|ps1|vbs|py|sh|bin|run|out)$",
    re.IGNORECASE,
)
_ACCOUNT_SYNTAX = re.compile(r"^[A-Za-z0-9@._-]{1,64}$")
_DOMAIN_SYNTAX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
_FILE_SYNTAX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")

# English phrase tails that hyphenated regex captures must not become hostnames.
_PHRASE_TAIL = frozenset(
    {
        "like",
        "based",
        "behavior",
        "activity",
        "detected",
        "attempt",
        "pattern",
        "chain",
        "stage",
        "related",
        "suspicious",
        "malicious",
        "unknown",
        "anomaly",
        "beacon",
        "movement",
        "observed",
    }
)

_PHRASE_SUFFIX = re.compile(r"-(?:like|based|related|observed|detected)$", re.IGNORECASE)


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


def validate_host_entity(
    hostname: str,
    *,
    provenance: EntityProvenance,
    alert_text: str = "",
) -> tuple[bool, str]:
    """Validate a single hostname candidate."""
    return _validate_hostname(
        (hostname or "").strip(),
        provenance=provenance,
        alert_text=alert_text,
    )


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
            rejections.append(EntityRejection("account", username, "invalid_account_syntax"))
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
                host.model_copy(update={"hostname": hostname or None, "ip": ip_value or None})
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


def is_plausible_regex_hostname(hostname: str) -> bool:
    """Fast pre-filter for regex extraction candidates (no alert context)."""
    ok, _ = _validate_hostname(
        hostname.strip(),
        provenance="regex",
        alert_text="",
    )
    return ok


def _validate_hostname(
    hostname: str,
    *,
    provenance: EntityProvenance,
    alert_text: str,
) -> tuple[bool, str]:
    if not hostname:
        return False, "invalid_hostname_syntax"
    if not _HOSTNAME_SYNTAX.match(hostname):
        return False, "invalid_hostname_syntax"
    if provenance == "source":
        return True, ""
    if hostname.lower().startswith("ip-"):
        if re.fullmatch(r"ip-\d+-\d+-\d+-\d+", hostname, flags=re.IGNORECASE):
            return True, ""
        return False, "invalid_hostname_syntax"
    if _PHRASE_SUFFIX.search(hostname):
        return False, "phrase_without_host_context"
    parts = hostname.lower().split("-")
    if parts and parts[-1] in _PHRASE_TAIL:
        return False, "phrase_without_host_context"
    if len(parts) >= 2 and all(part.isalpha() and len(part) <= 12 for part in parts):
        return False, "phrase_without_host_context"
    if _is_alert_short_token(hostname):
        return False, "phrase_without_host_context"
    if _HIGH_CONF_HOST.match(hostname):
        return True, ""
    if _hostname_has_explicit_context(hostname, alert_text):
        return True, ""
    return False, "phrase_without_host_context"


def _hostname_has_explicit_context(hostname: str, alert_text: str) -> bool:
    """True when a host/device keyword immediately precedes *hostname* in alert text."""
    if not hostname or not alert_text:
        return False
    pattern = re.compile(
        rf"\b(?:{HOST_CONTEXT_PREFIX})\s+{re.escape(hostname)}\b",
        re.IGNORECASE,
    )
    if pattern.search(alert_text):
        return True
    for match in HOST_CONTEXTUAL_PATTERN.finditer(alert_text):
        if match.group(1).lower() == hostname.lower():
            return True
    return False


def _is_alert_short_token(hostname: str) -> bool:
    """Reject single-token alert jargon like stage3/level2/phase1."""
    token = hostname.lower()
    if "-" in token:
        return False
    match = re.fullmatch(r"([a-z]+)(\d+)", token)
    if match is None:
        return False
    word, digits = match.groups()
    if word in _ALERT_SHORT_TOKEN:
        return True
    return len(digits) == 1 and word in _PHRASE_TAIL


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
    "HOST_CONTEXTUAL_PATTERN",
    "HOST_CONTEXT_PREFIX",
    "is_plausible_regex_hostname",
    "validate_entity_set",
    "validate_host_entity",
]
