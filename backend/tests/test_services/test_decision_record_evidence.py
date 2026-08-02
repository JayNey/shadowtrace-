"""DecisionRecord enrichment tests for evidence_agent (ISSUE-115)."""

from __future__ import annotations

from app.services.decision_record_service import _enrich_agent_output


def test_enrich_evidence_agent_output_projects_query_plan_and_gaps() -> None:
    output = {
        "collection_status": "completed",
        "query_timings": [
            {"tool_name": "query_dns", "dedupe_key": "dedupe-abc123"},
        ],
        "evidence_list": [{"evidence_id": "evd-dead0001"}],
        "gaps": [{"missing_source": "dns", "reason": "no_records"}],
        "query_plan": {
            "plan_step_orders": [1],
            "degraded_reasons": ["budget_trimmed_optional_queries"],
        },
    }
    enriched = _enrich_agent_output("evidence_agent", {"event_id": "evt-1"}, output)
    assert enriched["candidate_actions"] == [
        {
            "candidate_type": "evidence_query",
            "name": "query_dns",
            "candidate_id": "dedupe-abc123",
        }
    ]
    assert enriched["evidence_refs"] == ["evd-dead0001"]
    assert enriched["gap_refs"] == [{"source": "dns", "reason": "no_records"}]
    assert enriched["reason_code"] == "plan_steps:1"
    assert enriched["selected_action"] == "evidence:completed"
