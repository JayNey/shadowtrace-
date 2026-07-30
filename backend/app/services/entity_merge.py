"""Source-priority entity merge contract (ISSUE-099).

Merge order: validated structured source > validated LLM > validated regex.
Dedup by semantic identity value; conflicts retain source and are surfaced.
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

    if regex is not None and regex != EntitySet() and (llm is None or llm == EntitySet()):
        if source is not None and source != EntitySet():
            degradation.append("text_extraction_empty")
        else:
            degradation.append("regex_fallback")

    if source is not None and source != EntitySet() and (llm is None or llm == EntitySet()):
        if regex is None or regex == EntitySet():
            degradation.append("text_extraction_empty")

    return EntityMergeResult(
        entities=merged,
        conflicts=tuple(conflicts),
        degradation_reasons=tuple(dict.fromkeys(degradation)),
    )


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
        additions, cat_conflicts = merger(existing, list(getattr(incoming, category)), layer_name)
        conflicts.extend(cat_conflicts)
        setattr(result, category, existing + additions)

    return result, conflicts


def _merge_accounts(
    existing: list[AccountEntity],
    incoming: list[AccountEntity],
    layer_name: str,
) -> tuple[list[AccountEntity], list[EntityConflict]]:
    index = {_account_key(item): (item, _layer_of(item)) for item in existing}
    additions: list[AccountEntity] = []
    conflicts: list[EntityConflict] = []
    for item in incoming:
        key = _account_key(item)
        if not key:
            continue
        if key in index:
            kept, kept_layer = index[key]
            if (kept.username or "").lower() != (item.username or "").lower():
                conflicts.append(
                    EntityConflict(
                        entity_type="account",
                        semantic_key=key,
                        kept_value=kept.username or "",
                        kept_source=kept_layer,
                        discarded_value=item.username or "",
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
    additions: list[HostEntity] = []
    conflicts: list[EntityConflict] = []
    for item in incoming:
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
) -> tuple[list[IPEntity], list[EntityConflict]]:
    index = {_ip_key(item): (item, _layer_of(item)) for item in existing}
    additions: list[IPEntity] = []
    conflicts: list[EntityConflict] = []
    for item in incoming:
        key = _ip_key(item)
        if not key or key in index:
            if key and key in index:
                kept, kept_layer = index[key]
                if (kept.address or "") != (item.address or ""):
                    conflicts.append(
                        EntityConflict(
                            entity_type="ip",
                            semantic_key=key,
                            kept_value=kept.address or "",
                            kept_source=kept_layer,
                            discarded_value=item.address or "",
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
    additions: list[ProcessEntity] = []
    conflicts: list[EntityConflict] = []
    for item in incoming:
        key = _process_key(item)
        if not key or key in index:
            continue
        additions.append(item)
        index[key] = (item, layer_name)
    return additions, conflicts


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


__all__ = ["EntityConflict", "EntityMergeResult", "merge_entity_sets"]
