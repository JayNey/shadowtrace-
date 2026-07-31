"""Project structured Source objects into entity seeds (ISSUE-099).

Reads adapter-normalized fields and typed Source* projections already stored
on ``SourceObject.normalized``. Never reads arbitrary ``raw_payload``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.network_utils import is_internal_ip
from app.models.entities import (
    AccountEntity,
    DomainEntity,
    EntitySet,
    FileEntity,
    HostEntity,
    IPEntity,
    ProcessEntity,
)
from app.models.enums import SourceObjectKind
from app.models.source import SourceReference

_SOURCE_KIND_ORDER: dict[str, int] = {
    SourceObjectKind.INCIDENT.value: 0,
    SourceObjectKind.ASSET.value: 1,
    SourceObjectKind.ALERT.value: 2,
    SourceObjectKind.LOG.value: 3,
}


@dataclass(frozen=True, slots=True)
class SourceEntityEnrichment:
    entity_set: EntitySet
    provenance_summary: tuple[dict[str, Any], ...] = field(default_factory=tuple)


class SourceEntityEnricher:
    """Build entity seeds from linked, structured Source records."""

    @staticmethod
    def enrich_from_sources(
        sources: list[tuple[SourceReference, dict[str, Any]]],
    ) -> SourceEntityEnrichment:
        ordered = sorted(
            sources,
            key=lambda item: (
                _SOURCE_KIND_ORDER.get(item[0].source_kind.value, 99),
                item[0].source_object_id,
            ),
        )
        entities = EntitySet()
        provenance: list[dict[str, Any]] = []
        counters = {
            "accounts": 0,
            "hosts": 0,
            "ips": 0,
            "domains": 0,
            "processes": 0,
            "files": 0,
        }

        for ref, normalized in ordered:
            if not normalized:
                continue
            before = _entity_counts(entities)
            entities = _merge_seed(
                entities,
                _project_single(ref, normalized, counters),
            )
            after = _entity_counts(entities)
            if after != before:
                provenance.append(
                    {
                        "source_kind": ref.source_kind.value,
                        "source_object_id": ref.source_object_id,
                        "connector_id": ref.connector_id,
                        "added": _diff_counts(before, after),
                    }
                )

        return SourceEntityEnrichment(
            entity_set=entities,
            provenance_summary=tuple(provenance),
        )


def enrich_entities_from_source(
    sources: list[tuple[SourceReference, dict[str, Any]]],
) -> SourceEntityEnrichment:
    """Functional alias used by EventService."""
    return SourceEntityEnricher.enrich_from_sources(sources)


def _project_single(
    ref: SourceReference,
    normalized: dict[str, Any],
    counters: dict[str, int],
) -> EntitySet:
    accounts: list[AccountEntity] = []
    hosts: list[HostEntity] = []
    ips: list[IPEntity] = []
    domains: list[DomainEntity] = []
    processes: list[ProcessEntity] = []
    files: list[FileEntity] = []
    attrs = {"provenance": "source", "source_kind": ref.source_kind.value}

    for key in ("account", "owner", "username"):
        value = normalized.get(key)
        if value:
            counters["accounts"] += 1
            accounts.append(
                AccountEntity(
                    entity_id=f"src-acct-{counters['accounts']}",
                    username=str(value),
                    source_refs=[ref],
                    attributes=dict(attrs),
                )
            )
            break

    hostname = normalized.get("hostname") or normalized.get("host")
    host_ip = normalized.get("ip")
    host_ip_str = str(host_ip) if host_ip else None
    if hostname or host_ip:
        counters["hosts"] += 1
        hosts.append(
            HostEntity(
                entity_id=f"src-host-{counters['hosts']}",
                hostname=str(hostname) if hostname else None,
                ip=str(host_ip) if host_ip else None,
                source_refs=[ref],
                attributes=dict(attrs),
            )
        )

    ip_candidates: list[tuple[str, str]] = []
    for key in ("src_ip", "dst_ip", "ip", "source_ip"):
        value = normalized.get(key)
        if value:
            ip_candidates.append((str(value), key))
    seen_ip: set[str] = set()
    for address, key in ip_candidates:
        if address in seen_ip:
            continue
        if host_ip_str and address == host_ip_str:
            continue
        seen_ip.add(address)
        counters["ips"] += 1
        ips.append(
            IPEntity(
                entity_id=f"src-ip-{counters['ips']}",
                address=address,
                scope="internal" if is_internal_ip(address) else "external",
                source_refs=[ref],
                attributes={**attrs, "normalized_field": key},
            )
        )

    domain = normalized.get("domain") or normalized.get("fqdn")
    if domain:
        counters["domains"] += 1
        domains.append(
            DomainEntity(
                entity_id=f"src-dom-{counters['domains']}",
                fqdn=str(domain),
                source_refs=[ref],
                attributes=dict(attrs),
            )
        )

    process = normalized.get("process") or normalized.get("process_name")
    if process:
        counters["processes"] += 1
        processes.append(
            ProcessEntity(
                entity_id=f"src-proc-{counters['processes']}",
                name=str(process),
                source_refs=[ref],
                attributes=dict(attrs),
            )
        )

    file_name = normalized.get("file_name") or normalized.get("file") or normalized.get("path")
    if file_name:
        counters["files"] += 1
        files.append(
            FileEntity(
                entity_id=f"src-file-{counters['files']}",
                name=str(file_name),
                path=str(normalized.get("path") or file_name),
                source_refs=[ref],
                attributes=dict(attrs),
            )
        )

    return EntitySet(
        accounts=accounts,
        hosts=hosts,
        ips=ips,
        domains=domains,
        processes=processes,
        files=files,
    )


def _merge_seed(base: EntitySet, seed: EntitySet) -> EntitySet:
    from app.services.entity_merge import merge_source_layers

    return merge_source_layers(base, seed).entities


def _entity_counts(entity_set: EntitySet) -> dict[str, int]:
    return {
        "accounts": len(entity_set.accounts),
        "hosts": len(entity_set.hosts),
        "ips": len(entity_set.ips),
        "domains": len(entity_set.domains),
        "processes": len(entity_set.processes),
        "files": len(entity_set.files),
    }


def _diff_counts(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    return {
        key: after[key] - before.get(key, 0) for key in after if after[key] > before.get(key, 0)
    }


__all__ = [
    "SourceEntityEnricher",
    "SourceEntityEnrichment",
    "enrich_entities_from_source",
]
