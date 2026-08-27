"""Six-dimension rubric landing: band lookup, legacy score mapping, soft merge."""

from __future__ import annotations

from app.agents.risk_rubric import (
    FACTOR_NAMES,
    FACTOR_RUBRICS,
    IN_BAND_ANCHOR_WEIGHT,
    IN_BAND_RULE_WEIGHT,
    land_factor_score,
    nearest_band,
    resolve_factor_choice,
)


def test_each_factor_has_five_overlapping_bands() -> None:
    assert FACTOR_NAMES == tuple(FACTOR_RUBRICS)
    for name, bands in FACTOR_RUBRICS.items():
        assert len(bands) == 5, name
        ids = [band.rubric_id for band in bands]
        assert len(set(ids)) == 5
        for idx in range(len(bands) - 1):
            assert bands[idx].hi > bands[idx + 1].lo, name
            assert bands[idx].lo < bands[idx].center < bands[idx].hi


def test_legacy_score_maps_to_nearest_center() -> None:
    low = nearest_band("attack_stage", 10)
    mid = nearest_band("attack_stage", 54)
    high = nearest_band("attack_stage", 100)
    assert low.rubric_id == "recon_phish"
    assert mid.rubric_id == "collect_stage"
    assert high.rubric_id == "impact_ransom"


def test_resolve_prefers_rubric_id_over_score() -> None:
    choice = resolve_factor_choice(
        "attack_stage",
        {"rubric_id": "exfil_over_c2", "lean": "low", "score": 12, "reason": "upload"},
    )
    assert choice is not None
    assert choice.rubric_id == "exfil_over_c2"
    assert choice.lean == "low"
    assert choice.lo == 58
    assert choice.anchor < choice.center


def test_legacy_score_only_still_resolves() -> None:
    choice = resolve_factor_choice("threat_intel", {"score": 92, "reason": "legacy"})
    assert choice is not None
    assert choice.rubric_id == "confirmed_malicious_intel"


def test_non_adjacent_secondary_is_ignored() -> None:
    choice = resolve_factor_choice(
        "attack_stage",
        {
            "rubric_id": "recon_phish",
            "secondary_rubric_id": "impact_ransom",
            "reason": "unsure",
        },
    )
    assert choice is not None
    assert choice.secondary_rubric_id is None


def test_adjacent_secondary_widens_interval() -> None:
    choice = resolve_factor_choice(
        "attack_stage",
        {
            "rubric_id": "collect_stage",
            "secondary_rubric_id": "exfil_over_c2",
            "lean": "high",
            "reason": "between staging and exfil",
        },
    )
    assert choice is not None
    assert choice.secondary_rubric_id == "exfil_over_c2"
    assert choice.lo == 38
    assert choice.hi == 90


def test_in_band_prefers_rule_and_stays_off_center() -> None:
    choice = resolve_factor_choice(
        "attack_stage",
        {"rubric_id": "exfil_over_c2", "lean": "mid", "reason": "upload"},
    )
    assert choice is not None
    merged, reasoning = land_factor_score(80, choice)
    expected = IN_BAND_RULE_WEIGHT * 80 + IN_BAND_ANCHOR_WEIGHT * choice.anchor
    assert merged == expected
    assert merged != choice.center
    assert "在区间内" in reasoning
    assert "档位=exfil_over_c2" in reasoning


def test_out_of_band_soft_pull_does_not_snap_to_center() -> None:
    choice = resolve_factor_choice(
        "attack_stage",
        {"rubric_id": "exfil_over_c2", "lean": "mid", "reason": "upload"},
    )
    assert choice is not None
    merged, reasoning = land_factor_score(20, choice)
    assert merged != choice.center
    assert merged > 20
    assert merged <= choice.lo
    assert "区间外软拉" in reasoning


def test_unknown_factor_or_empty_payload_returns_none() -> None:
    assert resolve_factor_choice("not_a_factor", {"score": 50}) is None
    assert resolve_factor_choice("attack_stage", {}) is None
    assert resolve_factor_choice("attack_stage", {"rubric_id": "nope"}) is None
