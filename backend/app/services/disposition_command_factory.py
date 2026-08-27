"""Strict allowlisted disposition command assembly (ISSUE-059)."""

from __future__ import annotations

from app.agents.response_agent import compute_source_locator_hash
from app.core.errors import ValidationError
from app.core.guardrails import allowlisted_message_code
from app.models.action import Action
from app.models.disposition import (
    ENTITY_ACTION_EFFECT_SPECS,
    DispositionCommand,
    RecordCompensationParams,
    RecordExecutionResultParams,
    SetEventDispositionParams,
    SourceObjectLocator,
    SubmitEntityActionParams,
    TargetDispositionResult,
)
from app.models.enums import (
    DispositionIntentKind,
    ExecutionOwner,
    SourceDisposition,
    TargetExecutionStatus,
)
from app.models.execution import ActionExecutionJob


class DispositionCommandFactory:
    """Rebuild outbound commands from approved Action fields only.

    Never copies ``Action.reason``, free-form ``parameters``, or Provider
    ``raw_result`` into outbound payloads. Provider ``message`` text is only
    forwarded as a short allowlisted ``message_code`` (ISSUE-188); long /
    narrative text stays in the internal job and audit trail.
    """

    def build_entity_action_submit(
        self,
        action: Action,
        *,
        source_locator: SourceObjectLocator,
        source_concurrency_token: str | None,
        operator_id: str,
        disposition_id: str,
        writeback_id: str,
        closure_cycle: int,
        entity_action_code: str,
    ) -> DispositionCommand:
        spec = ENTITY_ACTION_EFFECT_SPECS.get(entity_action_code)
        if spec is None:
            allowed = ", ".join(sorted(ENTITY_ACTION_EFFECT_SPECS))
            raise ValueError(
                f"unsupported XDR_MANAGED entity action {entity_action_code}; allowed=[{allowed}]"
            )
        expected_target_type, _ = spec
        if not action.target:
            raise ValueError("XDR_MANAGED entity action requires a non-empty target")
        if action.target_type and action.target_type != expected_target_type:
            raise ValueError(f"{entity_action_code} requires target_type={expected_target_type}")
        canonical_target = f"{expected_target_type}:{action.target}"
        return DispositionCommand(
            disposition_id=disposition_id,
            action_id=action.action_id,
            closure_cycle=closure_cycle,
            intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT,
            source_locator=source_locator,
            operation_code="submit_entity_action",
            operation_params=SubmitEntityActionParams(
                entity_action_code=entity_action_code,
                canonical_target=canonical_target,
            ),
            target_results=[
                TargetDispositionResult(
                    canonical_target=canonical_target,
                    status=TargetExecutionStatus.UNKNOWN,
                )
            ],
            operator_id=operator_id,
            idempotency_key=action.idempotency_key or f"{action.action_id}:entity",
            source_concurrency_token=source_concurrency_token,
            execution_owner=ExecutionOwner.XDR_MANAGED,
        )

    def build_event_status_update(
        self,
        action: Action,
        *,
        source_locator: SourceObjectLocator,
        source_concurrency_token: str | None,
        operator_id: str,
        disposition_id: str,
        closure_cycle: int,
        target_disposition: SourceDisposition,
    ) -> DispositionCommand:
        return DispositionCommand(
            disposition_id=disposition_id,
            action_id=action.action_id,
            closure_cycle=closure_cycle,
            intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE,
            source_locator=source_locator,
            operation_code="set_event_disposition",
            operation_params=SetEventDispositionParams(target_disposition=target_disposition),
            target_results=[],
            operator_id=operator_id,
            idempotency_key=action.idempotency_key or f"{action.action_id}:terminal",
            source_concurrency_token=source_concurrency_token,
            execution_owner=ExecutionOwner.XDR_MANAGED,
        )

    def build_execution_result_record(
        self,
        action: Action,
        job: ActionExecutionJob,
        *,
        source_locator: SourceObjectLocator,
        source_concurrency_token: str | None,
        operator_id: str,
        disposition_id: str,
        closure_cycle: int,
    ) -> DispositionCommand:
        target_results = [
            TargetDispositionResult(
                canonical_target=result.canonical_target,
                status=(
                    TargetExecutionStatus.SUCCESS
                    if result.status.value == "success"
                    else TargetExecutionStatus.FAILED
                ),
                provider_code=result.code,
                message_code=allowlisted_message_code(result.message),
                artifact_ref=result.artifact_id,
            )
            for result in job.target_results
        ]
        summary_code = _execution_summary_code(job)
        return DispositionCommand(
            disposition_id=disposition_id,
            action_id=action.action_id,
            closure_cycle=closure_cycle,
            intent_kind=DispositionIntentKind.EXECUTION_RESULT_RECORD,
            source_locator=source_locator,
            operation_code="record_execution_result",
            operation_params=RecordExecutionResultParams(summary_code=summary_code),
            target_results=target_results,
            operator_id=operator_id,
            idempotency_key=action.idempotency_key or f"{action.action_id}:result",
            source_concurrency_token=source_concurrency_token,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
        )

    def build_compensation_record(
        self,
        rollback_action: Action,
        *,
        source_locator: SourceObjectLocator,
        source_concurrency_token: str | None,
        operator_id: str,
        disposition_id: str,
        closure_cycle: int,
        parent_disposition_id: str,
        summary_code: str | None = None,
    ) -> DispositionCommand:
        """Build a COMPENSATION_RECORD command for a rollback compensation writeback."""
        return DispositionCommand(
            disposition_id=disposition_id,
            action_id=rollback_action.action_id,
            closure_cycle=closure_cycle,
            intent_kind=DispositionIntentKind.COMPENSATION_RECORD,
            source_locator=source_locator,
            operation_code="record_compensation",
            operation_params=RecordCompensationParams(summary_code=summary_code),
            target_results=[],
            operator_id=operator_id,
            idempotency_key=f"{rollback_action.action_id}:compensation:{parent_disposition_id}",
            source_concurrency_token=source_concurrency_token,
            execution_owner=rollback_action.execution_owner or ExecutionOwner.XDR_MANAGED,
            parent_disposition_id=parent_disposition_id,
        )

    @staticmethod
    def locator_hash(locator: SourceObjectLocator) -> str:
        return compute_source_locator_hash(locator)


def _execution_summary_code(job: ActionExecutionJob) -> str:
    if job.status.value == "partial_success":
        return "partial_success"
    if job.status.value == "success":
        return "success"
    if job.status.value in {"failed", "timed_out", "cancelled"}:
        return "failed"
    return "unknown"


def entity_action_code_for(action: Action) -> str:
    """Map approved tool metadata to a stable Mock operation code."""
    if action.tool_name not in ENTITY_ACTION_EFFECT_SPECS:
        raise ValidationError(
            "tool cannot be executed via XDR_MANAGED entity submit",
            error_code="unsupported",
            details={
                "action_id": action.action_id,
                "tool_name": action.tool_name,
                "execution_owner": ExecutionOwner.XDR_MANAGED.value,
                "reason": "not_in_entity_action_effect_specs",
            },
        )
    return action.tool_name


__all__ = [
    "DispositionCommandFactory",
    "entity_action_code_for",
]
