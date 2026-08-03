"""Storyline claim ref builder tests (ISSUE-116 Phase B / #621)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.models.agent_io import (
    AttackStoryline,
    StorylineGeneratedBy,
    StorylineGroundingStatus,
    StorylinePhase,
    StorylinePhaseName,
    TimelineEntry,
)
from app.services.storyline_claim_refs import (
    attach_storyline_claim_refs,
    build_storyline_claim_refs,
)


def _storyline(*, evidence_id: str = "evd-00000001") -> AttackStoryline:
    return AttackStoryline(
        storyline_id="sty-test001",
        event_id="evt-test001",
        narrative_summary="test",
        phases=[
            StorylinePhase(
                phase_order=1,
                phase_name=StorylinePhaseName.INITIAL_ACCESS,
                narrative="login",
                entries=[
                    TimelineEntry(
                        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
                        description="login observed",
                        evidence_id=evidence_id,
                    )
                ],
            )
        ],
        generated_by=StorylineGeneratedBy.RULE,
    )


def test_build_storyline_claim_refs_from_timeline_entries() -> None:
    refs = build_storyline_claim_refs(_storyline())

    assert len(refs) == 1
    assert refs[0].evidence_ids == ["evd-00000001"]
    assert refs[0].claim_id == "claim-evt-test001-0"


def test_attach_storyline_claim_refs_sets_schema_v2() -> None:
    attached = attach_storyline_claim_refs(
        _storyline(),
        grounding_status=StorylineGroundingStatus.EVIDENCE_GROUNDED,
    )

    assert attached.schema_version == "2.0"
    assert attached.grounding_status is StorylineGroundingStatus.EVIDENCE_GROUNDED
    assert len(attached.claim_refs) == 1


def test_finalize_storyline_marks_claim_refs_unavailable_on_attach_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-116: claim ref attachment failure preserves storyline and marks unavailable."""
    from app.models.agent_io import StorylineGroundingStatus
    from app.services import storyline_service as storyline_module

    def _boom(*_args: object, **_kwargs: object) -> AttackStoryline:
        raise RuntimeError("claim ref build failed")

    monkeypatch.setattr(storyline_module, "attach_storyline_claim_refs", _boom)

    finalized = storyline_module.StorylineService._finalize_storyline(_storyline())

    assert finalized.grounding_status is StorylineGroundingStatus.CLAIM_REFS_UNAVAILABLE
    assert finalized.claim_refs == []
    assert finalized.schema_version == "1.0"
