"""AnalysisOnlyPipeline FP close-reason helpers (ISSUE-567)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.errors import DependencyUnavailableError
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
async def test_persist_analysis_only_complete_requires_context_store() -> None:
    pipeline = _pipeline(context_store=None)
    with pytest.raises(DependencyUnavailableError):
        await pipeline._persist_analysis_only_complete("evt-fp-no-store")


@pytest.mark.asyncio
async def test_pre_evidence_close_as_fp_close_reason_falls_back_to_default() -> None:
    fp_match = {
        "recommendation": "close_as_fp",
        "phase": "pre_evidence",
        "matched_rule": "ops_change_window_bulk_login",
    }
    reason = build_fp_close_reason(fp_match, default="analysis_pipeline:complete_not_required")
    assert reason == "analysis_pipeline:complete_not_required"


def test_post_evidence_adjudication_close_reason_uses_window_and_evidence() -> None:
    reason = build_fp_close_reason(
        None,
        fp_adjudication={
            "recommendation": "close_as_fp",
            "matched_window_id": "cw-scheduled-ops-maintenance",
            "supporting_evidence_ids": ["evd-auth-001", "evd-asset-001"],
        },
        default="analysis_pipeline:complete_not_required",
    )
    assert reason.startswith("close_as_fp post_evidence")
    assert "window=cw-scheduled-ops-maintenance" in reason
    assert "evidence=2" in reason
