"""Source-priority entity merge contract (ISSUE-099).

Merge order: validated structured source > validated LLM > validated regex.
Dedup by semantic identity; cross-layer slot competition keeps the higher-priority
primary hostname/account/process when layers disagree. Multiple distinct entities
from the same layer are all retained.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.models.entities import (
    AccountEntity,
    DomainEntity,
    EntitySet,
    FileEntity,
    HostEntity,
    IPEntity,
    ProcessEntity,
)


@dataclass(frozen=True, slots=True)
class EntityConflict:
    entity_type: str
    semantic_key: str
    kept_value: str
    kept_source: str
    discarded_value: str
    discarded_source: str
    reason: str = "source_priority"


@dataclass(frozen=True, slots=True)
class EntityMergeResult:
    entities: EntitySet
    conflicts: tuple[EntityConflict, ...] = field(default_factory=tuple)
    degradation_reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def conflict_summary(self) -> dict[str, Any]:
        return {
            "conflict_count": len(self.conflicts),
            "conflicts": [
                {
                    "entity_type": c.entity_type,
                    "semantic_key": c.semantic_key,
                    "kept_source": c.kept_source,
                    "discarded_source": c.discarded_source,
                    "reason": c.reason,
                }
                for c in self.conflicts[:20]
            ],
        }


def merge_entity_sets(
    *,
    source: EntitySet | None = None,
    llm: EntitySet | None = None,
    regex: EntitySet | None = None,
) -> EntityMergeResult:
    """Merge entity layers with source-first priority and semantic dedupe."""
    conflicts: list[EntityConflict] = []
    degradation: list[str] = []

    merged = EntitySet()
    for layer_name, layer in (("source", source), ("llm", llm), ("regex", regex)):
        if layer is None or layer == EntitySet():
            continue
        merged, layer_conflicts = _merge_layer(merged, layer, layer_name=layer_name)
        conflicts.extend(layer_conflicts)

    llm_empty = llm is None or llm == EntitySet()
    regex_empty = regex is None or regex == EntitySet()
    source_present = source is not None and source != EntitySet()

    if source_present and llm_empty and regex_empty:
        degradation.append("text_extraction_empty")
    elif not llm_empty or not regex_empty:
        if llm_empty and not regex_empty:
            degradation.append("text_extraction_empty" if source_present else "regex_fallback")

    return EntityMergeResult(
        entities=merged,
        conflicts=tuple(conflicts),
        degradation_reasons=tuple(dict.fromkeys(degradation)),
    )


def merge_source_layers(base: EntitySet, incoming: EntitySet) -> EntityMergeResult:
    """Merge two structured source layers without mislabeling provenance as llm."""
    if incoming == EntitySet():
        return EntityMergeResult(entities=base.model_copy(deep=True))
    merged, conflicts = _merge_layer(
        base.model_copy(deep=True),
        incoming,
        layer_name="source",
    )
    return EntityMergeResult(entities=merged, conflicts=tuple(conflicts))


def _merge_layer(
    base: EntitySet,
    incoming: EntitySet,
    *,
    layer_name: str,
) -> tuple[EntitySet, list[EntityConflict]]:
    conflicts: list[EntityConflict] = []
    result = base.model_copy(deep=True)

    for category, merger in (
        ("accounts", _merge_accounts),
        ("hosts", _merge_hosts),
        ("ips", _merge_ips),
        ("domains", _merge_domains),
        ("processes", _merge_processes),
        ("files", _merge_files),
    ):
        existing: list[Any] = list(getattr(result, category))
        if category == "ips":
            host_ips = {(h.ip or "").strip() for h in result.hosts if (h.ip or "").strip()}
            additions, cat_conflicts = _merge_ips(
                existing,
                list(getattr(incoming, category)),
                layer_name,
                host_ips=host_ips,
            )
        else:
            additions, cat_conflicts = merger(
                existing, list(getattr(incoming, category)), layer_name
            )
        conflicts.extend(cat_conflicts)
        setattr(result, category, existing + additions)

    return result, conflicts


def _primary_account_username(accounts: list[AccountEntity]) -> str | None:
    for item in accounts:
        username = (item.username or "").strip()
        if username:
            return username.lower()
    return None


def _primary_host_hostname(hosts: list[HostEntity]) -> str | None:
    for item in hosts:
        hostname = (item.hostname or "").strip()
        if hostname:
            return hostname.lower()
    return None


def _merge_accounts(
    existing: list[AccountEntity],
    incoming: list[AccountEntity],
    layer_name: str,
) -> tuple[list[AccountEntity], list[EntityConflict]]:
    index = {_account_key(item): (item, _layer_of(item)) for item in existing}
    primary = _primary_account_username(existing)
    additions: list[AccountEntity] = []
    conflicts: list[EntityConflict] = []
    for item in incoming:
        username = (item.username or "").strip()
        if not username:
            continue
        username_lower = username.lower()
        key = _account_key(item)
        if primary is not None and username_lower != primary:
            kept = next(
                (acct for acct in existing if (acct.username or "").strip().lower() == primary),
                existing[0] if existing else item,
            )
            conflicts.append(
                EntityConflict(
                    entity_type="account",
                    semantic_key="account:primary",
                    kept_value=kept.username or primary,
                    kept_source=_layer_of(kept),
                    discarded_value=username,
                    discarded_source=layer_name,
                )
            )
            continue
        if key in index:
            kept, kept_layer = index[key]
            if (kept.username or "").strip() != username:
                conflicts.append(
                    EntityConflict(
                        entity_type="account",
                        semantic_key=key,
                        kept_value=kept.username or "",
                        kept_source=kept_layer,
                        discarded_value=username,
                        discarded_source=layer_name,
                    )
                )
            continue
        additions.append(item)
        index[key] = (item, layer_name)
    return additions, conflicts


def _merge_hosts(
    existing: list[HostEntity],
    incoming: list[HostEntity],
    layer_name: str,
) -> tuple[list[HostEntity], list[EntityConflict]]:
    index = {_host_key(item): (item, _layer_of(item)) for item in existing}
    primary_hostname = _primary_host_hostname(existing)
    additions: list[HostEntity] = []
    conflicts: list[EntityConflict] = []
    for item in incoming:
        hostname = (item.hostname or "").strip()
        if hostname:
            hostname_lower = hostname.lower()
            if primary_hostname is not None and hostname_lower != primary_hostname:
                kept = next(
                    (
                        host
                        for host in existing
                        if (host.hostname or "").strip().lower() == primary_hostname
                    ),
                    existing[0] if existing else item,
                )
                conflicts.append(
                    EntityConflict(
                        entity_type="host",
                        semantic_key="host:primary",
                        kept_value=_host_value(kept),
                        kept_source=_layer_of(kept),
                        discarded_value=_host_value(item),
                        discarded_source=layer_name,
                    )
                )
                continue
        key = _host_key(item)
        if not key:
            continue
        if key in index:
            kept, kept_layer = index[key]
            if _host_value(kept) != _host_value(item):
                conflicts.append(
                    EntityConflict(
                        entity_type="host",
                        semantic_key=key,
                        kept_value=_host_value(kept),
                        kept_source=kept_layer,
                        discarded_value=_host_value(item),
                        discarded_source=layer_name,
                    )
                )
            continue
        additions.append(item)
        index[key] = (item, layer_name)
    return additions, conflicts


def _merge_ips(
    existing: list[IPEntity],
    incoming: list[IPEntity],
    layer_name: str,
    *,
    host_ips: set[str] | None = None,
) -> tuple[list[IPEntity], list[EntityConflict]]:
    attached_host_ips = host_ips or set()
    index = {_ip_key(item): (item, _layer_of(item)) for item in existing}
    additions: list[IPEntity] = []
    conflicts: list[EntityConflict] = []
    for item in incoming:
        address = (item.address or "").strip()
        key = _ip_key(item)
        if not key:
            continue
        if address in attached_host_ips:
            continue
        if key in index:
            kept, kept_layer = index[key]
            if (kept.address or "") != address:
                conflicts.append(
                    EntityConflict(
                        entity_type="ip",
                        semantic_key=key,
                        kept_value=kept.address or "",
                        kept_source=kept_layer,
                        discarded_value=address,
                        discarded_source=layer_name,
                    )
                )
            continue
        additions.append(item)
        index[key] = (item, layer_name)
    return additions, conflicts


def _merge_domains(
    existing: list[DomainEntity],
    incoming: list[DomainEntity],
    layer_name: str,
) -> tuple[list[DomainEntity], list[EntityConflict]]:
    index = {_domain_key(item): (item, _layer_of(item)) for item in existing}
    additions: list[DomainEntity] = []
    conflicts: list[EntityConflict] = []
    for item in incoming:
        key = _domain_key(item)
        if not key or key in index:
            continue
        additions.append(item)
        index[key] = (item, layer_name)
    return additions, conflicts


def _merge_processes(
    existing: list[ProcessEntity],
    incoming: list[ProcessEntity],
    layer_name: str,
) -> tuple[list[ProcessEntity], list[EntityConflict]]:
    index = {_process_key(item): (item, _layer_of(item)) for item in existing}
    primary = _primary_process_name(existing)
    additions: list[ProcessEntity] = []
    conflicts: list[EntityConflict] = []
    for item in incoming:
        name = (item.name or "").strip()
        if not name:
            continue
        name_lower = name.lower()
        if primary is not None and name_lower != primary:
            kept = next(
                (proc for proc in existing if (proc.name or "").strip().lower() == primary),
                existing[0] if existing else item,
            )
            conflicts.append(
                EntityConflict(
                    entity_type="process",
                    semantic_key="process:primary",
                    kept_value=kept.name or primary,
                    kept_source=_layer_of(kept),
                    discarded_value=name,
                    discarded_source=layer_name,
                )
            )
            continue
        key = _process_key(item)
        if not key or key in index:
            continue
        additions.append(item)
        index[key] = (item, layer_name)
    return additions, conflicts


def _primary_process_name(processes: list[ProcessEntity]) -> str | None:
    for item in processes:
        name = (item.name or "").strip()
        if name:
            return name.lower()
    return None


def _merge_files(
    existing: list[FileEntity],
    incoming: list[FileEntity],
    layer_name: str,
) -> tuple[list[FileEntity], list[EntityConflict]]:
    index = {_file_key(item): (item, _layer_of(item)) for item in existing}
    additions: list[FileEntity] = []
    conflicts: list[EntityConflict] = []
    for item in incoming:
        key = _file_key(item)
        if not key or key in index:
            continue
        additions.append(item)
        index[key] = (item, layer_name)
    return additions, conflicts


def _layer_of(entity: Any) -> str:
    attrs = getattr(entity, "attributes", None) or {}
    return str(attrs.get("provenance") or "unknown")


def _account_key(entity: AccountEntity) -> str:
    username = (entity.username or "").strip().lower()
    return f"account:{username}" if username else ""


def _host_key(entity: HostEntity) -> str:
    hostname = (entity.hostname or "").strip().lower()
    if hostname:
        return f"host:{hostname}"
    ip_value = (entity.ip or "").strip()
    return f"host_ip:{ip_value}" if ip_value else ""


def _host_value(entity: HostEntity) -> str:
    return (entity.hostname or entity.ip or "").strip()


def _ip_key(entity: IPEntity) -> str:
    address = (entity.address or "").strip()
    return f"ip:{address}" if address else ""


def _domain_key(entity: DomainEntity) -> str:
    fqdn = (entity.fqdn or "").strip().lower()
    return f"domain:{fqdn}" if fqdn else ""


def _process_key(entity: ProcessEntity) -> str:
    name = (entity.name or "").strip().lower()
    return f"process:{name}" if name else ""


def _file_key(entity: FileEntity) -> str:
    value = (entity.path or entity.name or "").strip().lower()
    return f"file:{value}" if value else ""


__all__ = [
    "EntityConflict",
    "EntityMergeResult",
    "merge_entity_sets",
    "merge_source_layers",
]
