"""ReAct loop engine domain models (ISSUE-053, ISSUE-131).

The engine iterates observe → think → act → reflect rounds and stops on the
first of: confidence ≥ ``CONFIDENCE_THRESHOLD``, ``max_rounds`` reached, the
LLM returning ``finish`` (or a null action), the per-run tool-call budget
being exhausted, the ConvergenceGuard forcing convergence, or an error.

ISSUE-131: auditable surface uses bounded ``decision_summary`` and enum
reason/gap/uncertainty codes — never raw chain-of-thought.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

_MAX_DECISION_SUMMARY_CHARS = 512
_MAX_ACTION_SUMMARY_CHARS = 256


class ReActActionType(StrEnum):
    """What the engine may do next (ISSUE-053 统一命名 §3)."""

    CALL_TOOL = "call_tool"
    CALL_AGENT = "call_agent"
    FINISH = "finish"


class ReActStopReason(StrEnum):
    """Why the loop stopped (ISSUE-053 统一命名 §5)."""

    CONFIDENCE_MET = "confidence_met"
    MAX_ROUNDS = "max_rounds"
    FINISHED = "finished"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CONVERGED = "converged"
    ERROR = "error"


class ReActReasonCode(StrEnum):
    """Structured reason for selecting an action (no free-text rationale)."""

    UNSPECIFIED = "unspecified"
    CORROBORATE_INDICATOR = "corroborate_indicator"
    RESOLVE_ENTITY = "resolve_entity"
    CONFIRM_PATH = "confirm_path"
    FILL_EVIDENCE_GAP = "fill_evidence_gap"
    STOP_SUFFICIENT = "stop_sufficient"
    STOP_NO_TARGET = "stop_no_target"
    DEFAULT_FALLBACK = "default_fallback"


class ReActGapCode(StrEnum):
    """Structured evidence gap code."""

    NONE = "none"
    EVIDENCE_MISSING = "evidence_missing"
    ENTITY_UNRESOLVED = "entity_unresolved"
    PATH_UNCONFIRMED = "path_unconfirmed"
    SCENARIO_EVIDENCE_MISSING = "scenario_evidence_missing"


class ReActUncertaintyCode(StrEnum):
    """Structured uncertainty classification."""

    NONE = "none"
    LOW_CONFIDENCE = "low_confidence"
    CONFLICTING_EVIDENCE = "conflicting_evidence"
    INCOMPLETE_COVERAGE = "incomplete_coverage"


class ReActCandidate(BaseModel):
    """One candidate action (type/name/id only — no params or free reasoning)."""

    model_config = ConfigDict(extra="forbid")

    candidate_type: ReActActionType
    name: str = Field(..., min_length=1)
    candidate_id: str = ""


class ReActAction(BaseModel):
    """One action chosen by the think step.

    ``action_type=finish`` (or a null ``ReActRound.action``) means the LLM
    decided to stop iterating. For ``call_tool`` / ``call_agent`` the
    ``target_name`` must resolve through the injected executor — the engine
    itself never touches tools or agents directly.
    """

    model_config = ConfigDict(extra="forbid")

    action_type: ReActActionType
    target_name: str = ""
    params: dict[str, Any] = Field(default_factory=dict)
    reason_code: ReActReasonCode = ReActReasonCode.UNSPECIFIED
    decision_summary: str = Field(default="", max_length=_MAX_ACTION_SUMMARY_CHARS)

    @field_validator("decision_summary")
    @classmethod
    def _bound_action_summary(cls, value: str) -> str:
        return value[:_MAX_ACTION_SUMMARY_CHARS]


class ReActRound(BaseModel):
    """Auditable record of one observe → think → act → reflect cycle."""

    model_config = ConfigDict(extra="forbid")

    round_index: int = Field(ge=1)
    observation: str = ""
    decision_summary: str = Field(default="", max_length=_MAX_DECISION_SUMMARY_CHARS)
    reason_code: ReActReasonCode = ReActReasonCode.UNSPECIFIED
    gap_code: ReActGapCode = ReActGapCode.NONE
    uncertainty_code: ReActUncertaintyCode = ReActUncertaintyCode.NONE
    action: ReActAction | None = None
    action_result: dict[str, Any] | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    # Deprecated ISSUE-131: retained for backward-compatible parsing only.
    thought: str = Field(default="", deprecated=True)
    reflection: str = Field(default="", deprecated=True)

    @field_validator("decision_summary")
    @classmethod
    def _bound_round_summary(cls, value: str) -> str:
        return value[:_MAX_DECISION_SUMMARY_CHARS]

    @field_validator("thought", "reflection")
    @classmethod
    def _reject_deprecated_cot(cls, value: str) -> str:
        return ""


class ReActResult(BaseModel):
    """Aggregate outcome of ``ReActEngine.run`` (ISSUE-053 统一命名 §5)."""

    model_config = ConfigDict(extra="forbid")

    rounds: list[ReActRound] = Field(default_factory=list)
    final_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    stop_reason: ReActStopReason
    outputs: dict[str, Any] = Field(default_factory=dict)


class ReActThinkOutput(BaseModel):
    """Structured payload expected from the ``react_think`` LLM call."""

    model_config = ConfigDict(extra="forbid")

    decision_summary: str = Field(default="", max_length=_MAX_DECISION_SUMMARY_CHARS)
    reason_code: ReActReasonCode = ReActReasonCode.UNSPECIFIED
    action: ReActAction | None = None
    candidates: list[ReActCandidate] = Field(default_factory=list)

    @field_validator("decision_summary")
    @classmethod
    def _bound_think_summary(cls, value: str) -> str:
        return value[:_MAX_DECISION_SUMMARY_CHARS]


class ReActReflectOutput(BaseModel):
    """Structured payload expected from the ``react_reflect`` LLM call."""

    model_config = ConfigDict(extra="forbid")

    decision_summary: str = Field(default="", max_length=_MAX_DECISION_SUMMARY_CHARS)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    gap_code: ReActGapCode = ReActGapCode.NONE
    uncertainty_code: ReActUncertaintyCode = ReActUncertaintyCode.NONE
    evidence_refs: list[str] = Field(default_factory=list)

    @field_validator("decision_summary")
    @classmethod
    def _bound_reflect_summary(cls, value: str) -> str:
        return value[:_MAX_DECISION_SUMMARY_CHARS]


__all__ = [
    "ReActAction",
    "ReActActionType",
    "ReActCandidate",
    "ReActGapCode",
    "ReActReasonCode",
    "ReActReflectOutput",
    "ReActResult",
    "ReActRound",
    "ReActStopReason",
    "ReActThinkOutput",
    "ReActUncertaintyCode",
]
