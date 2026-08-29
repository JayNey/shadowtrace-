"""Six-dimension scoring rubrics: LLM picks a band, scores stay on one scale.

Each factor has five overlapping situation bands. The model must not emit a
free 0-100 number; the server lands the rule-engine score inside (or softly
toward) the chosen interval.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

FACTOR_NAMES: tuple[str, ...] = (
    "asset_impact",
    "behavior_anomaly",
    "evidence_confidence",
    "attack_stage",
    "data_sensitivity",
    "threat_intel",
)

Lean = Literal["low", "mid", "high"]
LEAN_VALUES: frozenset[str] = frozenset({"low", "mid", "high"})

# When the rule score already sits in the chosen band, prefer the LLM
# situation call and only keep the rule point as a prior.
IN_BAND_RULE_WEIGHT = 0.35
IN_BAND_ANCHOR_WEIGHT = 0.65
# When the rule score misses the band, pull toward the near edge — not the center.
OUT_BAND_RULE_WEIGHT = 0.30
OUT_BAND_EDGE_WEIGHT = 0.70
OUT_BAND_MARGIN = 8.0
SECONDARY_BLEND = 0.3


@dataclass(frozen=True, slots=True)
class RubricBand:
    rubric_id: str
    lo: float
    hi: float
    center: float
    prompt: str


@dataclass(frozen=True, slots=True)
class LlmFactorChoice:
    factor_name: str
    rubric_id: str
    lean: Lean
    secondary_rubric_id: str | None
    reason: str
    lo: float
    hi: float
    center: float
    anchor: float


def _band(rubric_id: str, lo: float, hi: float, center: float, prompt: str) -> RubricBand:
    return RubricBand(rubric_id=rubric_id, lo=lo, hi=hi, center=center, prompt=prompt)


# Overlapping 0–100 lattices (adjacent bands share ~12 points).
FACTOR_RUBRICS: dict[str, tuple[RubricBand, ...]] = {
    "asset_impact": (
        _band("unknown_or_low", 0, 30, 12, "Unlabeled, lab, or low-value endpoint"),
        _band("standard_workstation", 18, 50, 34, "Ordinary workstation or general-purpose server"),
        _band("departmental_high", 38, 70, 54, "Department-critical host holding business data"),
        _band("finance_or_prod", 58, 90, 74, "Finance, production, or similarly high-value asset"),
        _band(
            "crown_jewel",
            78,
            100,
            92,
            "Domain controller, core database, or customer-facing crown jewel",
        ),
    ),
    "behavior_anomaly": (
        _band("baseline_quiet", 0, 30, 12, "No unusual behavior; consistent with daily baseline"),
        _band("mild_irregular", 18, 50, 34, "Mild irregularity that could still be ops work"),
        _band("encoded_or_script", 38, 70, 54, "Encoded command, unusual script, or packing"),
        _band("archive_upload_chain", 58, 90, 74, "Archive-and-upload or similar staging chain"),
        _band("destructive_or_exfil", 78, 100, 92, "Clear exfiltration or destructive impact"),
    ),
    "evidence_confidence": (
        _band("sparse_or_failed", 0, 30, 12, "Collection failed or evidence is almost absent"),
        _band("partial_single_source", 18, 50, 34, "Partial evidence from a single source"),
        _band("multi_source_incomplete", 38, 70, 54, "Multiple sources present but incomplete"),
        _band("completed_consistent", 58, 90, 74, "Collection completed and sources consistent"),
        _band("high_corroborated", 78, 100, 92, "Multi-source corroboration with high confidence"),
    ),
    "attack_stage": (
        _band("recon_phish", 0, 30, 12, "Reconnaissance or phishing-style initial access"),
        _band("valid_account_exec", 18, 50, 34, "Valid accounts, execution, or early foothold"),
        _band("collect_stage", 38, 70, 54, "Collection, staging, or archival of target data"),
        _band("exfil_over_c2", 58, 90, 74, "Outbound transfer, C2 exfil, or external upload"),
        _band("impact_ransom", 78, 100, 92, "Impact, ransomware, or destructive stage"),
    ),
    "data_sensitivity": (
        _band("public_or_unknown", 0, 30, 12, "Public or unknown data with no classification"),
        _band("internal_routine", 18, 50, 34, "Routine internal files without special handling"),
        _band("confidential_business", 38, 70, 54, "Confidential business documents or reports"),
        _band("restricted_pii", 58, 90, 74, "Restricted, PII, or similarly protected data"),
        _band("bulk_exfil_classified", 78, 100, 92, "Bulk classified or high-volume export"),
    ),
    "threat_intel": (
        _band("none_or_benign", 0, 30, 12, "No intel hit, or indicators look benign"),
        _band("weak_uncorroborated", 18, 50, 34, "Weak or uncorroborated intel mention"),
        _band("tagged_unknown_infra", 38, 70, 54, "Unknown or tagged infrastructure, no match"),
        _band("matched_technique", 58, 90, 74, "ATT&CK or intel technique match, moderate support"),
        _band("confirmed_malicious_intel", 78, 100, 92, "Confirmed malicious or known-bad intel"),
    ),
}


def bands_for(factor_name: str) -> tuple[RubricBand, ...]:
    return FACTOR_RUBRICS[factor_name]


def band_by_id(factor_name: str, rubric_id: str) -> RubricBand | None:
    for band in bands_for(factor_name):
        if band.rubric_id == rubric_id:
            return band
    return None


def band_index(factor_name: str, rubric_id: str) -> int | None:
    for idx, band in enumerate(bands_for(factor_name)):
        if band.rubric_id == rubric_id:
            return idx
    return None


def are_adjacent(factor_name: str, first_id: str, second_id: str) -> bool:
    left = band_index(factor_name, first_id)
    right = band_index(factor_name, second_id)
    if left is None or right is None:
        return False
    return abs(left - right) == 1


def nearest_band(factor_name: str, score: float) -> RubricBand:
    """Map a legacy 0–100 score onto the closest rubric center."""
    clamped = max(0.0, min(100.0, float(score)))
    bands = bands_for(factor_name)
    return min(bands, key=lambda band: (abs(band.center - clamped), -band.center))


def coerce_lean(raw: Any) -> Lean:
    text = str(raw or "mid").strip().lower()
    if text in LEAN_VALUES:
        return text  # type: ignore[return-value]
    return "mid"


def lean_anchor(band: RubricBand, lean: Lean) -> float:
    span = band.hi - band.lo
    if lean == "low":
        return band.lo + 0.28 * span
    if lean == "high":
        return band.lo + 0.72 * span
    return band.center


def rubric_catalog_for_prompt() -> dict[str, list[dict[str, Any]]]:
    catalog: dict[str, list[dict[str, Any]]] = {}
    for name, bands in FACTOR_RUBRICS.items():
        catalog[name] = [
            {
                "rubric_id": band.rubric_id,
                "lo": band.lo,
                "hi": band.hi,
                "prompt": band.prompt,
            }
            for band in bands
        ]
    return catalog


def resolve_factor_choice(factor_name: str, payload: Any) -> LlmFactorChoice | None:
    """Build a typed choice from rubric_id (preferred) or a legacy numeric score."""
    if factor_name not in FACTOR_RUBRICS:
        return None
    data = payload if isinstance(payload, dict) else {}
    rubric_id = str(data.get("rubric_id") or "").strip()
    band = band_by_id(factor_name, rubric_id) if rubric_id else None
    if band is None:
        raw_score = data.get("score")
        if raw_score is None or raw_score == "":
            return None
        try:
            band = nearest_band(factor_name, float(raw_score))
        except (TypeError, ValueError):
            return None
        rubric_id = band.rubric_id

    lean = coerce_lean(data.get("lean"))
    secondary_id = str(data.get("secondary_rubric_id") or "").strip() or None
    secondary = band_by_id(factor_name, secondary_id) if secondary_id else None
    if secondary is not None and not are_adjacent(factor_name, band.rubric_id, secondary.rubric_id):
        secondary = None
        secondary_id = None

    anchor = lean_anchor(band, lean)
    lo, hi = band.lo, band.hi
    if secondary is not None:
        anchor = (1.0 - SECONDARY_BLEND) * anchor + SECONDARY_BLEND * lean_anchor(secondary, "mid")
        lo = min(band.lo, secondary.lo)
        hi = max(band.hi, secondary.hi)

    reason = str(data.get("reason") or data.get("reasoning") or "").strip()
    return LlmFactorChoice(
        factor_name=factor_name,
        rubric_id=band.rubric_id,
        lean=lean,
        secondary_rubric_id=secondary_id,
        reason=reason or "llm",
        lo=lo,
        hi=hi,
        center=band.center,
        anchor=max(0.0, min(100.0, anchor)),
    )


def land_factor_score(rule_score: float, choice: LlmFactorChoice) -> tuple[float, str]:
    """Soft-land a rule score onto the LLM-chosen interval."""
    rule = max(0.0, min(100.0, float(rule_score)))
    inside = choice.lo <= rule <= choice.hi
    if inside:
        merged = IN_BAND_RULE_WEIGHT * rule + IN_BAND_ANCHOR_WEIGHT * choice.anchor
        relation = "在区间内"
    else:
        edge = choice.lo if rule < choice.lo else choice.hi
        pulled = OUT_BAND_RULE_WEIGHT * rule + OUT_BAND_EDGE_WEIGHT * edge
        lo_bound = max(0.0, choice.lo - OUT_BAND_MARGIN)
        hi_bound = min(100.0, choice.hi + OUT_BAND_MARGIN)
        merged = min(max(pulled, lo_bound), hi_bound)
        relation = "区间外软拉"
    merged = max(0.0, min(100.0, merged))
    secondary = f" secondary={choice.secondary_rubric_id}" if choice.secondary_rubric_id else ""
    reasoning = (
        f"档位={choice.rubric_id} [{choice.lo:.0f}-{choice.hi:.0f}] "
        f"lean={choice.lean}{secondary}; 规则 {rule:.0f} {relation}"
        f"; llm: {choice.reason}; rule({rule:.0f})"
    )
    return merged, reasoning
