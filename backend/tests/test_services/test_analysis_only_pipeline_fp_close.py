"""AnalysisOnlyPipeline FP close-reason helpers (ISSUE-567)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.analysis_only_pipeline import AnalysisOnlyPipeline
from app.services.false_positive_matcher import build_fp_close_reason


def _pipeline(*, context_store: object | None = None) -> AnalysisOnlyPipeline:
    return AnalysisOnlyPipeline(
        triage_agent=MagicMock(),
        evidence_agent=MagicMock(),
        rag_agent=MagicMock(),
        risk_agent=MagicMock(),
        report_agent=MagicMock(),
        context_store=context_store,
    )


@pytest.mark.asyncio
async def test_read_false_positive_match_returns_dict_from_store() -> None:
    store = MagicMock()
    store.get = AsyncMock(
        return_value={
            "recommendation": "close_as_fp",
            "matched_rule": "ops_change_window_bulk_login",
        }
    )
    pipeline = _pipeline(context_store=store)

    fp_match = await pipeline._read_false_positive_match("evt-fp-001")

    assert fp_match == {
        "recommendation": "close_as_fp",
        "matched_rule": "ops_change_window_bulk_login",
    }
    store.get.assert_awaited_once_with("evt-fp-001", "false_positive_match")


@pytest.mark.asyncio
async def test_read_false_positive_match_returns_none_without_store() -> None:
    pipeline = _pipeline(context_store=None)
    assert await pipeline._read_false_positive_match("evt-fp-002") is None


@pytest.mark.asyncio
async def test_complete_not_required_close_reason_includes_matched_rule() -> None:
    fp_match = {
        "recommendation": "close_as_fp",
        "matched_rule": "ops_change_window_bulk_login",
    }
    reason = build_fp_close_reason(fp_match, default="analysis_pipeline:complete_not_required")
    assert "ops_change_window_bulk_login" in reason
    assert reason != "analysis_pipeline:complete_not_required"
