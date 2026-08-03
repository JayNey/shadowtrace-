"""Storyline claim ref builder (ISSUE-116 Phase B / #621)."""

from __future__ import annotations

from app.models.agent_io import (
    AttackStoryline,
    StorylineClaimRef,
    StorylineGroundingStatus,
)


def build_storyline_claim_refs(storyline: AttackStoryline) -> list[StorylineClaimRef]:
    """Build stable claim refs from evidence-cited timeline entries only."""
    refs: list[StorylineClaimRef] = []
    ordinal = 0
    for phase in storyline.phases:
        for entry in phase.entries:
            if not entry.evidence_id:
                continue
            refs.append(
                StorylineClaimRef(
                    claim_id=f"claim-{storyline.event_id}-{ordinal}",
                    proposition_kind="timeline_entry",
                    evidence_ids=[entry.evidence_id],
                    ordinal=ordinal,
                )
            )
            ordinal += 1
    return refs


def attach_storyline_claim_refs(
    storyline: AttackStoryline,
    *,
    grounding_status: StorylineGroundingStatus,
) -> AttackStoryline:
    claim_refs = build_storyline_claim_refs(storyline)
    return storyline.model_copy(
        update={
            "schema_version": "2.0",
            "claim_refs": claim_refs,
            "grounding_status": grounding_status,
        }
    )


__all__ = ["attach_storyline_claim_refs", "build_storyline_claim_refs"]
