"""Tests for shared writeback side-effect fence (ISSUE-222)."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.core.errors import ValidationError
from app.models.enums import ExecutionOwner
from app.services.writeback_side_effect_fence import (
    assert_live_side_effects_allowed,
    assert_writeback_side_effects_allowed,
    assert_xdr_writeback_allowed,
)


def test_live_side_effects_fence_blocks_when_enabled() -> None:
    settings = Settings.model_validate({"ALLOW_LIVE_SIDE_EFFECTS": True})
    with pytest.raises(ValidationError, match="live side effects are disabled"):
        assert_live_side_effects_allowed(settings=settings, action_id="act-test")


def test_xdr_writeback_fence_blocks_live_mode_without_flag() -> None:
    settings = Settings.model_validate(
        {
            "DISPOSITION_MODE": "live_xdr",
            "ALLOW_XDR_WRITEBACK": False,
        }
    )
    with pytest.raises(ValidationError, match="xdr writeback is not enabled"):
        assert_xdr_writeback_allowed(
            settings=settings,
            action_id="act-test",
            execution_owner=ExecutionOwner.XDR_MANAGED,
        )


def test_xdr_writeback_fence_allows_mock_mode() -> None:
    settings = Settings.model_validate(
        {
            "DISPOSITION_MODE": "mock_xdr",
            "ALLOW_XDR_WRITEBACK": False,
        }
    )
    assert_xdr_writeback_allowed(
        settings=settings,
        action_id="act-test",
        execution_owner=ExecutionOwner.XDR_MANAGED,
    )


def test_xdr_writeback_fence_skips_direct_tool() -> None:
    settings = Settings.model_validate(
        {
            "DISPOSITION_MODE": "live_xdr",
            "ALLOW_XDR_WRITEBACK": False,
        }
    )
    assert_xdr_writeback_allowed(
        settings=settings,
        action_id="act-test",
        execution_owner=ExecutionOwner.DIRECT_TOOL,
    )


def test_combined_fence_blocks_live_xdr_without_writeback_flag() -> None:
    settings = Settings.model_validate(
        {
            "DISPOSITION_MODE": "live_xdr",
            "ALLOW_XDR_WRITEBACK": False,
            "ALLOW_LIVE_SIDE_EFFECTS": False,
        }
    )
    with pytest.raises(ValidationError, match="xdr writeback is not enabled"):
        assert_writeback_side_effects_allowed(
            settings=settings,
            action_id="act-test",
            execution_owner=ExecutionOwner.XDR_MANAGED,
        )


def test_combined_fence_blocks_live_side_effects() -> None:
    live_blocked = Settings.model_validate(
        {
            "DISPOSITION_MODE": "mock_xdr",
            "ALLOW_LIVE_SIDE_EFFECTS": True,
        }
    )
    with pytest.raises(ValidationError, match="live side effects are disabled"):
        assert_writeback_side_effects_allowed(
            settings=live_blocked,
            action_id="act-test",
            execution_owner=ExecutionOwner.XDR_MANAGED,
        )


def test_combined_fence_skips_xdr_gate_when_execution_owner_none() -> None:
    """ISSUE-230: system/verification actions may have no execution_owner."""
    settings = Settings.model_validate(
        {
            "DISPOSITION_MODE": "live_xdr",
            "ALLOW_XDR_WRITEBACK": False,
            "ALLOW_LIVE_SIDE_EFFECTS": False,
        }
    )
    assert_writeback_side_effects_allowed(
        settings=settings,
        action_id="act-verify",
        execution_owner=None,
    )
