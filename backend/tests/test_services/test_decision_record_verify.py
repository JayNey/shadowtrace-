"""DecisionRecord enrichment tests for verify_agent (ISSUE-202)."""

from __future__ import annotations

from app.services.decision_record_service import _enrich_agent_output


def test_enrich_verify_agent_success_output() -> None:
    output = {
        "overall_status": "success",
        "verification_phase": "effect",
        "results": [
            {
                "action_id": "act-dead0001",
                "effect_status": "verified",
                "writeback_required": False,
            }
        ],
        "failed_actions": [],
        "need_action_replan": False,
        "need_writeback_recovery": False,
        "need_manual_resolution": False,
    }
    enriched = _enrich_agent_output("verify_agent", {"event_id": "evt-1"}, output)
    assert enriched["reason_code"] == "success"
    assert enriched["selected_action"] == "verify:effect:success"
    assert "overall_status=success" in enriched["decision_summary"]
    assert enriched["candidate_actions"] == [
        {
            "candidate_type": "verification_action",
            "name": "verified",
            "candidate_id": "act-dead0001",
        }
    ]


def test_enrich_verify_agent_failure_output_prefers_need_flags() -> None:
    output = {
        "overall_status": "waiting",
        "verification_phase": "effect",
        "results": [],
        "failed_actions": ["act-beef0002"],
        "need_writeback_recovery": True,
        "need_manual_resolution": False,
        "need_action_replan": False,
        "failed_writebacks": ["wbk-beef0002"],
        "recoverable_writeback_ids": ["wbk-beef0002"],
        "pending_writeback_action_ids": [],
        "blocked_writebacks": [],
    }
    enriched = _enrich_agent_output("verify_agent", {"event_id": "evt-2"}, output)
    assert enriched["reason_code"] == "need_writeback_recovery"
    assert enriched["selected_action"] == "verify:effect:waiting"
    assert enriched["gap_refs"] == [{"source": "writeback", "reason": "wbk-beef0002"}]


def test_enrich_verify_agent_manual_resolution_reason_code() -> None:
    output = {
        "overall_status": "manual_resolution",
        "verification_phase": "disposition",
        "results": [],
        "need_manual_resolution": True,
    }
    enriched = _enrich_agent_output("verify_agent", {"event_id": "evt-3"}, output)
    assert enriched["reason_code"] == "need_manual_resolution"
    assert enriched["selected_action"] == "verify:disposition:manual_resolution"
