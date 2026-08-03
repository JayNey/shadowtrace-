"""Deterministic id/hash builders for PlaybookRelease (ISSUE-139 / #645)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from app.models.enums import ActionLevel, EventType
from app.models.playbook import Playbook, PlaybookStep
from app.models.playbook_release import (
    PLAYBOOK_RELEASE_SCHEMA_VERSION,
    PlaybookActionTemplateSnapshot,
)
from app.models.tool_meta import ToolMeta
from app.services.knowledge_release_resolver import canonical_json_bytes, compute_bundle_content_hash
from app.tools.specs import baseline_tool_index

_OTHER_ALLOWED_LEVELS = frozenset({ActionLevel.L0, ActionLevel.L1})


def _validate_steps(steps: list[PlaybookStep], playbook_id: str, event_type: EventType) -> None:
    index = baseline_tool_index()
    for step in steps:
        meta: ToolMeta | None = index.get(step.tool_name)
        if meta is None:
            raise ValueError(
                f"Playbook {playbook_id} step {step.step_order}: "
                f"unknown tool_name '{step.tool_name}'"
            )
        if step.action_level != meta.action_level:
            raise ValueError(
                f"Playbook {playbook_id} step {step.step_order} "
                f"({step.tool_name}): action_level {step.action_level.value} "
                f"does not match ToolMeta.action_level {meta.action_level.value}"
            )
        if event_type == EventType.OTHER and step.action_level not in _OTHER_ALLOWED_LEVELS:
            raise ValueError(
                f"Playbook {playbook_id} step {step.step_order}: "
                f"event_type 'other' only allows l0/l1 actions, "
                f"got {step.action_level.value}"
            )


@dataclass(frozen=True, slots=True)
class PlaybookBundleValidationResult:
    ok: bool
    content_hash: str
    playbooks: tuple[Playbook, ...]
    object_count: int
    errors: tuple[str, ...]


def compute_playbook_object_hash(playbook: Playbook | dict[str, Any]) -> str:
    if isinstance(playbook, Playbook):
        payload = playbook.model_dump(mode="json")
    else:
        payload = playbook
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def build_action_template_snapshot(step: PlaybookStep) -> PlaybookActionTemplateSnapshot:
    canonical = {
        "step_order": step.step_order,
        "tool_name": step.tool_name,
        "action_level": step.action_level.value,
        "action_name": step.action_name,
        "required_capabilities": sorted(step.required_capabilities),
    }
    template_hash = hashlib.sha256(canonical_json_bytes(canonical)).hexdigest()
    return PlaybookActionTemplateSnapshot(
        step_order=step.step_order,
        tool_name=step.tool_name,
        action_level=step.action_level,
        action_name=step.action_name,
        required_capabilities=tuple(sorted(step.required_capabilities)),
        template_hash=template_hash,
    )


def validate_playbook_bundle(data: dict[str, Any]) -> PlaybookBundleValidationResult:
    errors: list[str] = []
    raw_playbooks = data.get("playbooks")
    if not isinstance(raw_playbooks, list) or not raw_playbooks:
        return PlaybookBundleValidationResult(
            ok=False,
            content_hash="",
            playbooks=(),
            object_count=0,
            errors=("playbooks must be a non-empty list",),
        )

    playbooks: list[Playbook] = []
    seen_ids: set[str] = set()
    for idx, raw in enumerate(raw_playbooks):
        if not isinstance(raw, dict):
            errors.append(f"playbooks[{idx}] must be an object")
            continue
        try:
            pb = Playbook.model_validate(raw)
        except Exception as exc:  # noqa: BLE001 — collect all validation errors
            errors.append(f"playbooks[{idx}] invalid: {exc}")
            continue
        if pb.playbook_id in seen_ids:
            errors.append(f"duplicate playbook_id {pb.playbook_id}")
            continue
        seen_ids.add(pb.playbook_id)
        try:
            _validate_steps(pb.steps, pb.playbook_id, pb.event_type)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        playbooks.append(pb)

    if errors:
        return PlaybookBundleValidationResult(
            ok=False,
            content_hash="",
            playbooks=tuple(playbooks),
            object_count=len(playbooks),
            errors=tuple(errors),
        )

    content_hash = compute_bundle_content_hash(data)
    return PlaybookBundleValidationResult(
        ok=True,
        content_hash=content_hash,
        playbooks=tuple(playbooks),
        object_count=len(playbooks),
        errors=(),
    )


def default_playbook_provenance(source_path: str) -> dict[str, str]:
    return {
        "source_path": source_path,
        "imported_by": "playbook_bundle_importer",
        "import_kind": "playbook_bundle",
    }


__all__ = [
    "PlaybookBundleValidationResult",
    "PLAYBOOK_RELEASE_SCHEMA_VERSION",
    "_validate_steps",
    "build_action_template_snapshot",
    "compute_playbook_object_hash",
    "default_playbook_provenance",
    "validate_playbook_bundle",
]
