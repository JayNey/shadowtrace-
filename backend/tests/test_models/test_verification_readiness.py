"""Contract tests for verification readiness predicates (ISSUE-216)."""

from __future__ import annotations

from pathlib import Path

from app.models.agent_io import (
    EffectStatus,
    VerificationActionResult,
    VerificationOverallStatus,
    VerificationPhase,
    VerificationResult,
)
from app.models.enums import WritebackReadiness
from app.models.verification_readiness import (
    IMMEDIATE_PENDING_SKIP_DETAILS,
    has_unverified_applicable_effects,
)

BACKEND_DIR = Path(__file__).resolve().parents[2]
VERIFY_AGENT_SOURCE = (BACKEND_DIR / "app" / "agents" / "verify_agent.py").read_text(
    encoding="utf-8"
)


def test_immediate_pending_skip_details_are_declared_in_verify_agent() -> None:
    """Gate detail strings must exist as literals in VerifyAgent phase-1 paths."""
    for detail in IMMEDIATE_PENDING_SKIP_DETAILS:
        assert f'"{detail}"' in VERIFY_AGENT_SOURCE or f"'{detail}'" in VERIFY_AGENT_SOURCE
    assert "deferred_pending_activation" not in IMMEDIATE_PENDING_SKIP_DETAILS


def test_immediate_pending_skip_details_cover_known_immediate_pending_cases() -> None:
    assert IMMEDIATE_PENDING_SKIP_DETAILS == frozenset(
        {
            "pending_execution",
            "approved_pending_execution",
            "action_not_executed",
        }
    )


def test_has_unverified_applicable_effects_ignores_deferred_pending() -> None:
    verification = VerificationResult(
        results=[
            VerificationActionResult(
                action_id="act-deferred",
                effect_status=EffectStatus.SKIPPED,
                detail="deferred_pending_activation",
                writeback_required=True,
                writeback_readiness=WritebackReadiness.READY,
            ),
        ],
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
    )
    assert has_unverified_applicable_effects(verification) is False


def test_has_unverified_applicable_effects_blocks_non_verifiable_skipped() -> None:
    verification = VerificationResult(
        results=[
            VerificationActionResult(
                action_id="act-ticket",
                effect_status=EffectStatus.SKIPPED,
                detail="non_verifiable_action",
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            ),
        ],
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
    )
    assert has_unverified_applicable_effects(verification) is True


def test_has_unverified_applicable_effects_blocks_no_verification_tool() -> None:
    verification = VerificationResult(
        results=[
            VerificationActionResult(
                action_id="act-unregistered",
                effect_status=EffectStatus.SKIPPED,
                detail="no_verification_tool_registered",
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            ),
        ],
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
    )
    assert has_unverified_applicable_effects(verification) is True


def test_has_unverified_applicable_effects_allows_all_verified_applicable() -> None:
    verification = VerificationResult(
        results=[
            VerificationActionResult(
                action_id="act-verified",
                effect_status=EffectStatus.VERIFIED,
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            ),
            VerificationActionResult(
                action_id="act-deferred",
                effect_status=EffectStatus.SKIPPED,
                detail="deferred_pending_activation",
                writeback_required=True,
                writeback_readiness=WritebackReadiness.READY,
            ),
        ],
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
    )
    assert has_unverified_applicable_effects(verification) is False
