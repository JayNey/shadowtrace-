"""P0 VerdictResolver — sole logical resolver for FinalVerdict (ISSUE-035 / ISSUE-114)."""

from __future__ import annotations

from typing import Any

from app.models.agent_io import RAGOutput, RiskAssessment
from app.models.enums import FinalVerdict
from app.models.workflow import FP_HIGH_THRESHOLD, FP_LOW_THRESHOLD

# Backward-compatible aliases for tests / imports.
FP_HIGH_SCORE = FP_HIGH_THRESHOLD
FP_MEDIUM_SCORE = FP_LOW_THRESHOLD


class VerdictResolver:
    """Resolve ``FinalVerdict`` with fixed priority (must not be overridden).

    Priority (ISSUE-035 / ISSUE-047 / ISSUE-114):
    1. ``fp_adjudication.recommendation == close_as_fp`` → false_positive
       (post-evidence typed decision; never overridden by risk_score >= 70)
    2. Legacy post-evidence ``false_positive_match.close_as_fp`` → false_positive
    3. Pre-evidence vector / RAG FP signal → possible_false_positive (advisory only)
    4. risk_score >= 70 → confirmed_threat
    5. else → none

    Pre-evidence ``false_positive_match`` must never independently yield false_positive.
    """

    def resolve(
        self,
        risk_assessment: RiskAssessment,
        false_positive_match: dict[str, Any] | None = None,
        rag_output: RAGOutput | None = None,
        fp_adjudication: dict[str, Any] | None = None,
    ) -> FinalVerdict:
        adjudication = fp_adjudication or {}
        if str(adjudication.get("recommendation") or "").strip().lower() == "close_as_fp":
            return FinalVerdict.FALSE_POSITIVE

        fp = false_positive_match or {}
        recommendation = str(fp.get("recommendation") or "").strip().lower()
        if recommendation == "close_as_fp" and fp.get("phase") == "post_evidence":
            return FinalVerdict.FALSE_POSITIVE

        fp_score = self._fp_score(fp, rag_output)
        risk_score = int(risk_assessment.risk_score)

        if fp_score >= FP_LOW_THRESHOLD:
            return FinalVerdict.POSSIBLE_FALSE_POSITIVE
        if risk_score >= 70:
            return FinalVerdict.CONFIRMED_THREAT
        return FinalVerdict.NONE

    @staticmethod
    def _fp_score(
        fp_match: dict[str, Any],
        rag_output: RAGOutput | None,
    ) -> float:
        candidates: list[float] = []
        for key in ("max_score", "score", "confidence"):
            raw = fp_match.get(key)
            if raw is not None:
                try:
                    candidates.append(float(raw))
                except (TypeError, ValueError):
                    pass
        if rag_output is not None and rag_output.fp_similarity is not None:
            try:
                candidates.append(float(rag_output.fp_similarity.max_score))
            except (TypeError, ValueError, AttributeError):
                pass
        return max(candidates) if candidates else 0.0


__all__ = ["FP_HIGH_SCORE", "FP_MEDIUM_SCORE", "VerdictResolver"]
