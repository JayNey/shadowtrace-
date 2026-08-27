"""Constrained RRF identity, polarity, and ranking tests."""

from __future__ import annotations

import pytest

from app.models.agent_io import OrgContextMatch
from app.models.knowledge import RetrievedChunk
from app.rag.constraint_rrf import (
    CONSTRAINT_KINDS,
    OrgConstraint,
    c_rrf_fuse,
    constraint_hits_text,
    constraints_from_org_matches,
    rank_constraint_channel,
)
from app.rag.rrf_fusion import rrf_fuse


def _chunk(chunk_id: str, content: str, kb_name: str = "attack_kb") -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id=chunk_id,
        kb_name=kb_name,
        content=content,
        score=1.0,
        retrieval_method="vector",
    )


def _match(*, kind: str, value: str, chunk_id: str = "org-001") -> OrgContextMatch:
    return OrgContextMatch(
        kind=kind,  # type: ignore[arg-type]
        matched_value=value,
        explanation="seed",
        citation_id="cit-0c000001",
        chunk_id=chunk_id,
        match_type="domain_exact",
    )


def _scores(chunks: list[RetrievedChunk]) -> dict[str, tuple[float, float]]:
    return {item.chunk_id: (item.score, item.raw_rrf_score) for item in chunks}


class TestConstraintSet:
    def test_allow_kinds_only(self) -> None:
        matches = [
            _match(kind="allowed_destination", value="files.corp.internal"),
            _match(kind="allowed_source", value="10.0.0.0/8", chunk_id="org-002"),
            _match(kind="account_role", value="svc-backup", chunk_id="org-003"),
            _match(kind="time_window", value="02:00-04:00", chunk_id="org-004"),
            _match(kind="person_status", value="contractor", chunk_id="org-005"),
            _match(kind="data_handling", value="finance-share", chunk_id="org-006"),
            _match(kind="security_product", value="edr-allow", chunk_id="org-007"),
        ]
        constraints = constraints_from_org_matches(matches)
        kinds = {item.kind for item in constraints}
        assert kinds <= CONSTRAINT_KINDS
        assert "person_status" not in kinds
        assert "data_handling" not in kinds
        assert "security_product" not in kinds
        assert {item.value for item in constraints} == {
            "files.corp.internal",
            "10.0.0.0/8",
            "svc-backup",
            "02:00-04:00",
        }

    def test_short_and_duplicate_values_dropped(self) -> None:
        matches = [
            _match(kind="account_role", value="ab"),
            _match(kind="allowed_destination", value="files.corp.internal"),
            _match(
                kind="allowed_destination",
                value="Files.Corp.Internal",
                chunk_id="org-dup",
            ),
        ]
        constraints = constraints_from_org_matches(matches)
        assert constraints == (
            OrgConstraint(kind="allowed_destination", value="files.corp.internal"),
        )


class TestConstraintOverlap:
    def test_token_boundary_and_domain_suffix(self) -> None:
        constraint = OrgConstraint(kind="allowed_destination", value="files.corp.internal")
        assert constraint_hits_text(
            constraint,
            "Approved destination files.corp.internal for nightly sync.",
        )
        assert constraint_hits_text(
            constraint,
            "Host mail.files.corp.internal received the archive.",
        )
        assert not constraint_hits_text(
            constraint,
            "notfiles.corp.internal.example.net is unrelated.",
        )

    def test_cidr_phrase_matches_ip_or_network(self) -> None:
        constraint = OrgConstraint(
            kind="allowed_source",
            value="10.20.0.88 in 10.20.0.0/24",
        )
        assert constraint_hits_text(constraint, "Scanner 10.20.0.88 probed the jump host.")
        assert constraint_hits_text(constraint, "Allow source net 10.20.0.0/24 for scanners.")
        assert not constraint_hits_text(constraint, "Unrelated 192.168.1.10 host.")

    def test_person_status_value_does_not_enter_channel(self) -> None:
        matches = [_match(kind="person_status", value="contractor-temp")]
        constraints = constraints_from_org_matches(matches)
        chunk = _chunk("chk-a", "contractor-temp accessed the share")
        assert rank_constraint_channel([chunk], constraints) == []


class TestCRRFIdentity:
    def test_empty_constraints_identical_to_rrf(self) -> None:
        list_a = [_chunk("chk-a", "alpha"), _chunk("chk-b", "beta")]
        list_b = [_chunk("chk-b", "beta"), _chunk("chk-c", "gamma")]
        vanilla = rrf_fuse([list_a, list_b], k=60)
        fused, used = c_rrf_fuse([list_a, list_b], (), k=60)
        assert used is False
        assert [item.chunk_id for item in fused] == [item.chunk_id for item in vanilla]
        assert _scores(fused) == _scores(vanilla)

    def test_no_overlap_identical_to_rrf(self) -> None:
        list_a = [_chunk("chk-a", "alpha technique"), _chunk("chk-b", "beta playbook")]
        constraints = (OrgConstraint(kind="allowed_destination", value="files.corp.internal"),)
        vanilla = rrf_fuse([list_a], k=60)
        fused, used = c_rrf_fuse([list_a], constraints, k=60)
        assert used is False
        assert [item.chunk_id for item in fused] == [item.chunk_id for item in vanilla]
        assert _scores(fused) == _scores(vanilla)


class TestCRRFRanking:
    def test_overlap_breaks_rrf_tie(self) -> None:
        overlap = _chunk(
            "chk-a",
            "Nightly archive to files.corp.internal is expected.",
        )
        other = _chunk("chk-b", "Generic exfiltration technique notes.")
        list_vector = [other, overlap]
        list_keyword = [overlap, other]
        vanilla = rrf_fuse([list_vector, list_keyword], k=60)
        assert {item.chunk_id for item in vanilla[:2]} == {"chk-a", "chk-b"}
        assert abs(vanilla[0].raw_rrf_score - vanilla[1].raw_rrf_score) < 1e-12

        constraints = (OrgConstraint(kind="allowed_destination", value="files.corp.internal"),)
        fused, used = c_rrf_fuse([list_vector, list_keyword], constraints, k=60)
        assert used is True
        assert fused[0].chunk_id == "chk-a"
        assert fused[0].raw_rrf_score > fused[1].raw_rrf_score

        k = 60
        raw_a = 1.0 / (k + 2) + 1.0 / (k + 1) + 1.0 / (k + 1)
        raw_b = 1.0 / (k + 1) + 1.0 / (k + 2)
        by_id = {item.chunk_id: item for item in fused}
        assert by_id["chk-a"].raw_rrf_score == pytest.approx(raw_a)
        assert by_id["chk-b"].raw_rrf_score == pytest.approx(raw_b)

    def test_constraint_channel_never_mints_exact_method(self) -> None:
        overlap = _chunk("chk-a", "account svc-backup ran the job")
        other = _chunk("chk-b", "unrelated host compromise notes")
        constraints = (OrgConstraint(kind="account_role", value="svc-backup"),)
        fused, used = c_rrf_fuse([[overlap, other], [other, overlap]], constraints, k=60)
        assert used is True
        assert all(item.retrieval_method == "hybrid" for item in fused)
