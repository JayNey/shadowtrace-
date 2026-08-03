"""Approval evidence binding for playbook-pinned response actions (ISSUE-139 / #645)."""

from __future__ import annotations

import hashlib
from typing import Any

from app.core.errors import ValidationError
from app.models.action import Action
from app.models.playbook_release import (
    PlaybookActionTemplateSnapshot,
    PlaybookRef,
)
from app.services.action_approval_policy import APPROVAL_POLICY_SOURCE, APPROVAL_POLICY_VERSION


def compute_playbook_binding_hash(
    *,
    playbook_ref: PlaybookRef | None,
    template_snapshot: PlaybookActionTemplateSnapshot | None,
) -> str:
    if playbook_ref is None:
        return ""
    parts = [
        playbook_ref.release_id,
        playbook_ref.bundle_content_hash,
        playbook_ref.content_hash,
        str(playbook_ref.revision),
    ]
    if template_snapshot is not None:
        parts.append(template_snapshot.template_hash)
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def build_approval_binding_detail(action: Action) -> dict[str, Any]:
    """Evidence fields stored on ApprovalRecord.detail for replay validation."""
    return {
        "plan_revision": action.plan_revision,
        "action_fingerprint": action.action_fingerprint,
        "policy_version": APPROVAL_POLICY_VERSION,
        "policy_source": APPROVAL_POLICY_SOURCE,
        "playbook_binding_hash": compute_playbook_binding_hash(
            playbook_ref=action.playbook_ref,
            template_snapshot=action.action_template_snapshot,
        ),
        "playbook_ref": (
            action.playbook_ref.model_dump(mode="json") if action.playbook_ref is not None else None
        ),
        "action_template_snapshot": (
            action.action_template_snapshot.model_dump(mode="json")
            if action.action_template_snapshot is not None
            else None
        ),
    }


def validate_approval_binding(action: Action, detail: dict[str, Any] | None) -> None:
    """Fail closed when plan/playbook content drifted after approval was recorded."""
    if action.playbook_ref is None:
        return
    if detail is None:
        raise ValidationError(
            "approval binding missing for playbook-pinned action",
            details={
                "action_id": action.action_id,
                "reason": "binding_detail_missing",
            },
        )
    bound_revision = detail.get("plan_revision")
    if isinstance(bound_revision, int) and bound_revision != action.plan_revision:
        raise ValidationError(
            "approval binding stale: plan revision changed",
            details={
                "action_id": action.action_id,
                "bound_plan_revision": bound_revision,
                "current_plan_revision": action.plan_revision,
                "reason": "plan_revision_mismatch",
            },
        )
    bound_fingerprint = detail.get("action_fingerprint")
    if isinstance(bound_fingerprint, str) and bound_fingerprint != action.action_fingerprint:
        raise ValidationError(
            "approval binding stale: action fingerprint changed",
            details={
                "action_id": action.action_id,
                "reason": "action_fingerprint_mismatch",
            },
        )
    bound_policy_version = detail.get("policy_version")
    if not isinstance(bound_policy_version, str) or not bound_policy_version:
        raise ValidationError(
            "approval binding missing policy version for playbook-pinned action",
            details={
                "action_id": action.action_id,
                "reason": "policy_version_missing",
            },
        )
    if bound_policy_version != APPROVAL_POLICY_VERSION:
        raise ValidationError(
            "approval binding stale: policy version changed",
            details={
                "action_id": action.action_id,
                "bound_policy_version": bound_policy_version,
                "current_policy_version": APPROVAL_POLICY_VERSION,
                "reason": "policy_version_mismatch",
            },
        )
    bound_hash = detail.get("playbook_binding_hash")
    if not isinstance(bound_hash, str) or not bound_hash:
        raise ValidationError(
            "approval binding missing playbook hash for playbook-pinned action",
            details={
                "action_id": action.action_id,
                "reason": "playbook_binding_hash_missing",
            },
        )
    current_hash = compute_playbook_binding_hash(
        playbook_ref=action.playbook_ref,
        template_snapshot=action.action_template_snapshot,
    )
    if current_hash != bound_hash:
        raise ValidationError(
            "approval binding stale: playbook binding changed",
            details={
                "action_id": action.action_id,
                "reason": "playbook_binding_mismatch",
            },
        )


__all__ = [
    "build_approval_binding_detail",
    "compute_playbook_binding_hash",
    "validate_approval_binding",
]
