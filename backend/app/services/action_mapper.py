"""Map SQLAlchemy Action rows to domain Action models (shared by API + services)."""

from __future__ import annotations

from app.db import models as orm
from app.models.action import Action
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    WritebackReadiness,
)


def action_from_orm(row: orm.Action) -> Action:
    """Build a validated :class:`Action` from an ORM row."""
    payload = {
        "action_id": row.action_id,
        "event_id": row.event_id,
        "plan_revision": row.plan_revision,
        "action_fingerprint": row.action_fingerprint,
        "action_category": ActionCategory(row.action_category),
        "action_name": row.action_name,
        "tool_name": row.tool_name,
        "action_level": ActionLevel(row.action_level),
        "execution_phase": ActionExecutionPhase(row.execution_phase),
        "activation_condition": row.activation_condition,
        "approved_operation_template_hash": row.approved_operation_template_hash,
        "approved_terminal_dispositions": row.approved_terminal_dispositions or [],
        "target_type": row.target_type,
        "target": row.target,
        "parameters": row.parameters or {},
        "status": ActionStatus(row.status),
        "auto_execute": row.auto_execute,
        "reason": row.reason,
        "impact_assessment": row.impact_assessment,
        "playbook_id": row.playbook_id,
        "playbook_ref": row.playbook_ref,
        "action_template_snapshot": row.action_template_snapshot,
        "provider_name": row.provider_name,
        "execution_owner": row.execution_owner,
        "execution_job_id": row.execution_job_id,
        "tool_call_id": row.tool_call_id,
        "idempotency_key": row.idempotency_key,
        "writeback_required": row.writeback_required,
        "writeback_applicable": row.writeback_applicable,
        "writeback_readiness": WritebackReadiness(row.writeback_readiness),
        "writeback_block_reason": row.writeback_block_reason,
        "writeback_status": row.writeback_status,
        "disposition_source_ref": row.disposition_source_ref,
        "superseded_by_revision": row.superseded_by_revision,
        "executed_at": row.executed_at,
        "effect_verification_status": row.effect_verification_status,
        "rollback_status": row.rollback_status,
        "source_action_id": row.source_action_id,
        "updated_at": row.updated_at,
    }
    return Action.model_validate(payload)
