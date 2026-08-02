"""Build offline ATT&CK STIX 2.1 bundles from curated JSON (ISSUE-128 / #634)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.services.knowledge_release_resolver import build_stix_object_id

_TACTIC_PHASE_MAP = {
    "Reconnaissance": "reconnaissance",
    "Resource Development": "resource-development",
    "Initial Access": "initial-access",
    "Execution": "execution",
    "Persistence": "persistence",
    "Privilege Escalation": "privilege-escalation",
    "Defense Evasion": "defense-evasion",
    "Credential Access": "credential-access",
    "Discovery": "discovery",
    "Lateral Movement": "lateral-movement",
    "Collection": "collection",
    "Command and Control": "command-and-control",
    "Exfiltration": "exfiltration",
    "Impact": "impact",
}


def build_attack_pattern(technique: dict[str, Any], *, attack_version: str) -> dict[str, Any]:
    technique_id = str(technique["technique_id"])
    stix_id = build_stix_object_id(technique_id)
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    phases = []
    for tactic in technique.get("tactics") or []:
        phase = _TACTIC_PHASE_MAP.get(str(tactic))
        if phase:
            phases.append({"kill_chain_name": "mitre-attack", "phase_name": phase})
    obj: dict[str, Any] = {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": stix_id,
        "created": now,
        "modified": now,
        "name": technique["technique_name"],
        "description": technique.get("description") or "",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": technique_id,
                "url": f"https://attack.mitre.org/techniques/{technique_id}",
            }
        ],
        "kill_chain_phases": phases,
        "x_mitre_is_subtechnique": "." in technique_id,
        "x_shadowtrace_attack_version": attack_version,
    }
    if technique.get("detection"):
        obj["x_mitre_detection"] = technique["detection"]
    if technique.get("keywords"):
        obj["x_shadowtrace_keywords"] = list(technique["keywords"])
    if technique.get("aliases"):
        obj["x_shadowtrace_aliases"] = list(technique["aliases"])
    return obj


def build_bundle_from_techniques_json(path: str | Path) -> dict[str, Any]:
    """Convert ``attack_techniques.json`` into a STIX 2.1 bundle."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    attack_version = str(data["attack_version"])
    techniques: list[dict[str, Any]] = list(data["techniques"])
    patterns = [build_attack_pattern(item, attack_version=attack_version) for item in techniques]
    relationships = _build_subtechnique_relationships(patterns)
    objects = patterns + relationships
    return {
        "type": "bundle",
        "id": f"bundle--attack-enterprise-{attack_version.replace('.', '-')}",
        "spec_version": "2.1",
        "x_shadowtrace_attack_version": attack_version,
        "x_shadowtrace_object_count": len(objects),
        "objects": objects,
    }


def _build_subtechnique_relationships(patterns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_external_id = {
        ref["external_id"]: obj
        for obj in patterns
        for ref in obj.get("external_references", [])
        if ref.get("source_name") == "mitre-attack" and isinstance(ref.get("external_id"), str)
    }
    relationships: list[dict[str, Any]] = []
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    for obj in patterns:
        for ref in obj.get("external_references", []):
            external_id = ref.get("external_id")
            if not isinstance(external_id, str) or "." not in external_id:
                continue
            parent_id = external_id.split(".", 1)[0]
            parent = by_external_id.get(parent_id)
            if parent is None:
                continue
            rel_id_seed = f"{parent['id']}:{obj['id']}"
            relationships.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{build_stix_object_id(rel_id_seed).split('--', 1)[1]}",
                    "created": now,
                    "modified": now,
                    "relationship_type": "subtechnique-of",
                    "source_ref": obj["id"],
                    "target_ref": parent["id"],
                }
            )
    return relationships


__all__ = ["build_attack_pattern", "build_bundle_from_techniques_json"]
