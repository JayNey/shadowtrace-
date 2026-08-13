"""Shared prompt block packing tests (ISSUE-326 / #957)."""

from __future__ import annotations

from app.agents.prompts.prompt_blocks import evidence_prompt_block
from app.models.agent_io import CollectionStatus, EvidenceOutput
from app.models.enums import EvidenceSource
from app.models.evidence import Evidence


def _item(index: int, *, description: str | None = None) -> Evidence:
    return Evidence(
        evidence_id=f"ev-{index}",
        event_id="evt-test",
        source=EvidenceSource.NETWORK_FLOW,
        evidence_type="flow",
        description=description or f"sample-{index}",
        confidence=0.5,
    )


def test_evidence_prompt_block_truncates_description_and_caps_sample() -> None:
    long_description = "d" * 250
    evidence = EvidenceOutput(
        evidence_list=[_item(index, description=long_description) for index in range(15)],
        collection_status=CollectionStatus.COMPLETED,
        overall_confidence=0.8,
        success_sources=["network_flow"],
        failed_sources=[],
    )
    block = evidence_prompt_block(evidence)
    assert block["evidence_count"] == 15
    assert len(block["sample"]) == 12
    assert block["sample"][0]["description"] == long_description[:200]
    assert all(len(item["description"]) == 200 for item in block["sample"])


def test_evidence_prompt_block_none_description_coerced() -> None:
    evidence = EvidenceOutput(
        evidence_list=[
            Evidence.model_construct(
                evidence_id="ev-none",
                event_id="evt-test",
                source=EvidenceSource.NETWORK_FLOW,
                evidence_type="flow",
                description=None,
                confidence=0.5,
            )
        ],
        collection_status=CollectionStatus.COMPLETED,
        overall_confidence=0.8,
        success_sources=["network_flow"],
        failed_sources=[],
    )
    block = evidence_prompt_block(evidence)
    assert block["sample"][0]["description"] == ""


def test_evidence_prompt_block_empty_list_keeps_source_keys() -> None:
    evidence = EvidenceOutput(
        evidence_list=[],
        collection_status=CollectionStatus.PARTIAL_DONE,
        overall_confidence=0.1,
        success_sources=[],
        failed_sources=["endpoint_telemetry"],
    )
    block = evidence_prompt_block(evidence)
    assert block["success_sources"] == []
    assert block["failed_sources"] == ["endpoint_telemetry"]
    assert block["sample"] == []
    assert block["evidence_count"] == 0
