"""VerdictResolver unit tests (ISSUE-035)."""

from __future__ import annotations

from app.agents.verdict_resolver import VerdictResolver
from app.models.agent_io import FpSimilarity, RAGOutput, RiskAssessment, ScoringMode
from app.models.enums import FinalVerdict, Severity


def _assessment(score: int, *, possible_fp: bool = False) -> RiskAssessment:
    return RiskAssessment(
        risk_score=score,
        severity=Severity.HIGH if score >= 70 else Severity.LOW,
        confidence=0.7,
        possible_false_positive=possible_fp,
        scoring_mode=ScoringMode.RULE_ONLY,
    )


def test_post_evidence_close_as_fp_not_overridden_by_high_risk() -> None:
    """Post-evidence close_as_fp wins at high risk unless #675 high-source guard applies."""
    resolver = VerdictResolver()
    verdict = resolver.resolve(
        _assessment(95),
        fp_adjudication={"recommendation": "close_as_fp", "matched_window_id": "cw-test"},
    )
    assert verdict is FinalVerdict.FALSE_POSITIVE


def test_high_fp_with_low_risk_is_possible_false_positive() -> None:
    resolver = VerdictResolver()
    verdict = resolver.resolve(
        _assessment(20),
        false_positive_match={"max_score": 0.95},
    )
    assert verdict is FinalVerdict.POSSIBLE_FALSE_POSITIVE


def test_medium_fp_signal_is_possible_false_positive() -> None:
    resolver = VerdictResolver()
    rag = RAGOutput(fp_similarity=FpSimilarity(max_score=0.75, matched_case_id="c1"))
    verdict = resolver.resolve(_assessment(55), rag_output=rag)
    assert verdict is FinalVerdict.POSSIBLE_FALSE_POSITIVE


def test_high_risk_confirmed_threat() -> None:
    resolver = VerdictResolver()
    assert resolver.resolve(_assessment(70)) is FinalVerdict.CONFIRMED_THREAT
    assert resolver.resolve(_assessment(69)) is FinalVerdict.NONE


def test_near_threshold_llm_confidence_confirms_threat() -> None:
    resolver = VerdictResolver()
    assessment = RiskAssessment(
        risk_score=63,
        severity=Severity.MEDIUM,
        confidence=0.82,
        scoring_mode=ScoringMode.LLM_AND_RULE,
    )
    assert resolver.resolve(assessment) is FinalVerdict.CONFIRMED_THREAT


def test_near_threshold_rule_only_stays_none() -> None:
    resolver = VerdictResolver()
    assert resolver.resolve(_assessment(63)) is FinalVerdict.NONE


def test_medium_fp_with_high_risk_is_possible_false_positive() -> None:
    """Medium FP signal wins over confirmed-threat score (fixed priority order)."""
    resolver = VerdictResolver()
    rag = RAGOutput(fp_similarity=FpSimilarity(max_score=0.75, matched_case_id="c1"))
    verdict = resolver.resolve(_assessment(85), rag_output=rag)
    assert verdict is FinalVerdict.POSSIBLE_FALSE_POSITIVE


def test_verdict_is_sole_logical_entry() -> None:
    """Resolver is the only place encoding verdict priority rules."""
    resolver = VerdictResolver()
    # Explicit post-evidence close_as_fp wins at confirmed-threat score when guard does not apply.
    assert (
        resolver.resolve(
            _assessment(100),
            fp_adjudication={"recommendation": "close_as_fp"},
        )
        is FinalVerdict.FALSE_POSITIVE
    )


def test_evidence_limited_high_source_blocks_auto_fp_close() -> None:
    resolver = VerdictResolver()
    assessment = RiskAssessment(
        risk_score=75,
        severity=Severity.HIGH,
        confidence=0.3,
        scoring_mode=ScoringMode.RULE_ONLY,
        evidence_limited=True,
        severity_floor_applied=False,
        high_source_evidence_limited=True,
        source_risk_baseline=76,
    )
    verdict = resolver.resolve(
        assessment,
        fp_adjudication={"recommendation": "close_as_fp", "matched_window_id": "cw-test"},
    )
    assert verdict is FinalVerdict.NONE


def test_evidence_limited_low_source_allows_auto_fp_close() -> None:
    resolver = VerdictResolver()
    assessment = RiskAssessment(
        risk_score=22,
        severity=Severity.LOW,
        confidence=0.25,
        scoring_mode=ScoringMode.RULE_ONLY,
        evidence_limited=True,
        severity_floor_applied=False,
        high_source_evidence_limited=False,
        source_risk_baseline=18,
    )
    verdict = resolver.resolve(
        assessment,
        fp_adjudication={"recommendation": "close_as_fp", "matched_window_id": "cw-test"},
    )
    assert verdict is FinalVerdict.FALSE_POSITIVE
