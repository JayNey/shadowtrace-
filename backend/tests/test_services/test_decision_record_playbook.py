"""DecisionRecord persistence tests for playbook-pinned response plans (ISSUE-139)."""

from __future__ import annotations

from app.services.decision_record_service import _build_record_payload, _enrich_agent_output


def test_enrich_response_agent_output_includes_playbook_release_refs() -> None:
    output = {
        "plan_id": "rsp-deadbeef",
        "actions": [
            {
                "action_id": "act-deadbeef",
                "action_name": "Block IP",
                "tool_name": "block_ip",
                "playbook_ref": {
                    "playbook_id": "pb-a1b2c3d4",
                    "release_id": "krel-abcdef012345678",
                    "release_version": "v1-test",
                    "content_hash": "a" * 64,
                    "bundle_content_hash": "b" * 64,
                },
            }
        ],
        "generated_by": "template",
    }
    enriched = _enrich_agent_output("response_agent", {"event_id": "evt-deadbeef"}, output)
    assert enriched["input_refs"] == [
        {"ref_type": "playbook_release_id", "ref_id": "krel-abcdef012345678"},
        {"ref_type": "playbook_id", "ref_id": "pb-a1b2c3d4"},
    ]
    assert enriched["kb_version"] == "v1-test"


def test_build_record_payload_persists_playbook_refs() -> None:
    output = {
        "plan_id": "rsp-deadbeef",
        "actions": [
            {
                "action_id": "act-deadbeef",
                "action_name": "Block IP",
                "tool_name": "block_ip",
                "playbook_ref": {
                    "playbook_id": "pb-a1b2c3d4",
                    "release_id": "krel-abcdef012345678",
                    "release_version": "v1-test",
                    "content_hash": "a" * 64,
                    "bundle_content_hash": "b" * 64,
                },
            }
        ],
        "generated_by": "template",
    }
    record = _build_record_payload(
        event_id="evt-deadbeef",
        agent_name="response_agent",
        trace_id="trc-deadbeef",
        input_data={"event_id": "evt-deadbeef"},
        output_data=output,
        llm_model=None,
    )
    assert record is not None
    ref_types = {(item["ref_type"], item["ref_id"]) for item in record.input_refs}
    assert ("playbook_release_id", "krel-abcdef012345678") in ref_types
    assert ("playbook_id", "pb-a1b2c3d4") in ref_types
    assert record.kb_version == "v1-test"
