"""Deterministic regex-based entity extraction fallback (ISSUE-032 / ISSUE-100).

Used by ``TriageAgent._extract_entities`` when the LLM path is unavailable,
times out, or returns unparseable output. Hostname patterns are intentionally
narrow; semantic validation in ``entity_validation`` is the final gate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.agents.rules.entity_validation import HOST_CONTEXTUAL_PATTERN, validate_host_entity

# --------------------------------------------------------------------------- #
# Regex patterns (compiled once at import time)
# --------------------------------------------------------------------------- #

_IP_PATTERN: re.Pattern[str] = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
IP_PATTERN: re.Pattern[str] = _IP_PATTERN

_DOMAIN_PATTERN: re.Pattern[str] = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b"
)

# Segmented names ending in digits (DEV-WKS-012, PC-FIN-023, ubuntu-prod-01).
_HOST_SEGMENT_NUMERIC: re.Pattern[str] = re.compile(r"\b[A-Za-z0-9]+(?:-[A-Za-z0-9]+)-\d+\b")

# Segmented names with interior digit token (web-01-prod, app-3-east).
_HOST_SEGMENT_MIDDLE_DIGIT: re.Pattern[str] = re.compile(r"\b[A-Za-z0-9]+-\d+-[A-Za-z0-9]+\b")

# Short NetBIOS / asset tags (db01, srv12) — require >=2 trailing digits.
_HOST_SHORT_DIGIT: re.Pattern[str] = re.compile(r"\b[A-Za-z]{2,}\d{2,4}\b")

# Cloud-style ip-10-0-0-4 tokens.
_HOST_IP_STYLE: re.Pattern[str] = re.compile(r"\bip-\d+-\d+-\d+-\d+\b", re.IGNORECASE)

# Known infrastructure role suffixes (optional hardening, not sole acceptance rule).
_HOST_ROLE_SUFFIX: re.Pattern[str] = re.compile(
    r"\b[A-Za-z0-9]+-(?:WKS|SRV|DC|DB|WEB|OPS|FIN|SQL|AD|FS|APP|JUMP|ADMIN|MAIL|"
    r"PROXY|VPN|NODE|PRD|STG|DEV|HOST|PC|LAP|VM|K8S|GW|FW|LB|API|BASTION|CORE|EDGE|"
    r"MGMT|MON|LOG|SIEM|XDR|EDR|IAM|NFW|DLP|CASB|WAF|IDS|IPS|SAN|NAS|WORKER|CRON|"
    r"JOB|TASK|BATCH|ETL|DW|BI|ML|AI|GPU|CPU|MEM|DISK|VOL|SNAP|BACKUP|DR|HA|VIP)"
    r"[A-Za-z0-9_-]*\b",
    re.IGNORECASE,
)

_ACCOUNT_PATTERN: re.Pattern[str] = re.compile(
    r'(?:account|user|username|账号|用户|用户名)\s+["\']?([A-Za-z][A-Za-z0-9@._-]{1,63})["\']?',
    re.IGNORECASE,
)

_PROCESS_PATTERN: re.Pattern[str] = re.compile(
    r"\b([A-Za-z][A-Za-z0-9._-]{0,63}\.(?:exe|dll|sys|bat|cmd|ps1|vbs|py|sh|bin|run|out))\b"
)

_FILE_PATTERN: re.Pattern[str] = re.compile(
    r"\b([A-Za-z][A-Za-z0-9._-]{0,63}\.(?:zip|7z|rar|tar|gz|csv|doc|docx|xls|xlsx|pdf|txt|log|sql|db|bak|pst|ost|eml|msg|json|xml|yaml|yml|ini|cfg|conf|key|pem|crt|cer|p12|pfx|jpg|png|bmp|wav|mp3|mp4|avi|mov))(?:\b|(?=[\s,;\"'<>]|$))",
)


@dataclass(frozen=True, slots=True)
class EntityExtractionResult:
    """Regex fallback extraction output."""

    ips: list[str]
    domains: list[str]
    hostnames: list[str]
    accounts: list[str]
    processes: list[str]
    files: list[str]

    def is_empty(self) -> bool:
        return not any(
            (self.ips, self.domains, self.hostnames, self.accounts, self.processes, self.files)
        )


def extract_entities_regex(alert_text: str) -> EntityExtractionResult:
    """Extract entity strings from raw alert text using deterministic regex."""
    ips = _unique(_IP_PATTERN.findall(alert_text))
    domains = _unique(_DOMAIN_PATTERN.findall(alert_text))

    hostname_candidates: list[str] = []
    for pattern in (
        _HOST_SEGMENT_NUMERIC,
        _HOST_SEGMENT_MIDDLE_DIGIT,
        _HOST_SHORT_DIGIT,
        _HOST_IP_STYLE,
        _HOST_ROLE_SUFFIX,
    ):
        for match in pattern.findall(alert_text):
            if pattern is _HOST_SEGMENT_NUMERIC and match.lower().startswith("ip-"):
                continue
            hostname_candidates.append(match)
    for match in HOST_CONTEXTUAL_PATTERN.finditer(alert_text):
        hostname_candidates.append(match.group(1))

    hostnames = _unique(
        [
            h
            for h in hostname_candidates
            if h not in domains
            and validate_host_entity(h, provenance="regex", alert_text=alert_text)[0]
        ]
    )

    accounts = _unique([m.group(1) for m in _ACCOUNT_PATTERN.finditer(alert_text)])
    processes = _unique(_PROCESS_PATTERN.findall(alert_text))
    files = _unique(_FILE_PATTERN.findall(alert_text))

    return EntityExtractionResult(
        ips=ips,
        domains=domains,
        hostnames=hostnames,
        accounts=accounts,
        processes=processes,
        files=files,
    )


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


__all__ = [
    "EntityExtractionResult",
    "extract_entities_regex",
    "IP_PATTERN",
]
