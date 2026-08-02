"""Auto-response mock-loop contract tests (ISSUE-109 / #613 Phase 1)."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.models.action import Action
from app.models.approval import ApprovalDecisionKind
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    EventStatus,
    ExecutionOwner,
    Severity,
)
from app.services.approval_engine import evaluate_level_rules
from app.services.auto_response_policy import AutoResponsePolicyService


def _response_action(*, level: ActionLevel, action_id: str) -> Action:
    return Action.model_validate(
        {
            "action_id": action_id,
            "event_id": "evt-gate",
            "plan_revision": 1,
            "action_fingerprint": f"fp-{action_id}",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "isolate_host",
            "tool_name": "isolate_host",
            "action_level": level,
            "execution_owner": ExecutionOwner.DIRECT_TOOL,
            "execution_phase": ActionExecutionPhase.IMMEDIATE,
            "status": ActionStatus.PENDING,
            "writeback_required": False,
            "writeback_applicable": False,
            "reason": "test",
        }
    )


def test_l3_actions_still_require_human_after_auto_response_entry() -> None:
    """Policy may enter response phase; ApprovalEngine still gates L2-L5."""
    action = _response_action(level=ActionLevel.L3, action_id="act-l3-gate")
    decision = evaluate_level_rules(action, confidence=0.99, severity=Severity.CRITICAL)
    assert decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL
    assert decision.rule_applied == "level_l3_requires_human"


@pytest.mark.parametrize(
    ("level", "rule"),
    [
        (ActionLevel.L2, "level_l2_requires_human"),
        (ActionLevel.L4, "level_l4_l5_manual"),
    ],
)
def test_high_levels_never_auto_approve(level: ActionLevel, rule: str) -> None:
    action = _response_action(level=level, action_id=f"act-{level.value}")
    decision = evaluate_level_rules(action, confidence=1.0, severity=Severity.CRITICAL)
    assert decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL
    assert decision.rule_applied == rule


def test_mock_response_phase_l1_auto_l3_human_after_policy_entry() -> None:
    """Scenario B contract: eligible auto-response entry does not bypass approval gates."""
    from app.db import models as orm

    policy = AutoResponsePolicyService(
        Settings(
            AUTO_RESPONSE_ENABLED=True,
            SOURCE_MODE="mock_xdr",
            TOOL_MODE="mock",
            DISPOSITION_MODE="mock_xdr",
        )
    )
    event = orm.SecurityEvent(
        event_id="evt-scenario-b",
        event_type="malicious_process",
        title="test",
        description="",
        status=EventStatus.NEW.value,
        severity=Severity.HIGH.value,
        final_verdict="none",
        creation_source_ref={"source_product": "mock_xdr"},
        source_reference_snapshots=[],
        disposition_policy="not_required",
        raw_alert_ids=[],
        source_type="mock_xdr",
    )
    entry = policy.evaluate(event, link_role="primary", source_product="mock_xdr")
    assert entry.eligible is True
    assert entry.reason == "auto_response:policy_match"

    l1 = _response_action(level=ActionLevel.L1, action_id="act-l1-auto")
    l3 = _response_action(level=ActionLevel.L3, action_id="act-l3-human")
    l1_decision = evaluate_level_rules(l1, confidence=0.99, severity=Severity.CRITICAL)
    l3_decision = evaluate_level_rules(l3, confidence=0.99, severity=Severity.CRITICAL)
    assert l1_decision.decision is ApprovalDecisionKind.AUTO_APPROVE
    assert l3_decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL
