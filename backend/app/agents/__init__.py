"""Agents package (ISSUE-005 through ISSUE-057).

Public symbols are exported lazily (PEP 562) so Celery worker / service import
graphs do not eagerly pull ``BaseAgent`` → ``working_memory`` → ``context_service``
during ``app.agents.prompts`` submodule loads (ISSUE-236).
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from app.agents.base import AgentOutput, BaseAgent
    from app.agents.confidence_calibration import calibrate_confidence
    from app.agents.evidence_agent import EvidenceAgent
    from app.agents.evidence_parser import EvidenceParser
    from app.agents.graph_agent import GraphAgent
    from app.agents.graph_builder import GraphBuilder
    from app.agents.planner_agent import PlannerAgent
    from app.agents.report_agent import ReportAgent
    from app.agents.report_section_builder import ReportSectionBuilder
    from app.agents.response_agent import ResponseAgent
    from app.agents.risk_agent import RiskAgent
    from app.agents.risk_scoring_engine import RiskScoringEngine, severity_from_score
    from app.agents.verdict_resolver import VerdictResolver
    from app.agents.verify_agent import VerifyAgent
    from app.models.agent_io import (
        AGENT_INPUT_MODELS,
        AgentInput,
        EvidenceAgentInput,
        GraphAgentInput,
        MemoryAgentInput,
        PlannerAgentInput,
        RAGAgentInput,
        ReportAgentInput,
        ResponseAgentInput,
        RiskAgentInput,
        SuperAgentInput,
        ToolAgentInput,
        TriageAgentInput,
        VerifyAgentInput,
    )

__all__ = [
    "AGENT_INPUT_MODELS",
    "AgentInput",
    "AgentOutput",
    "BaseAgent",
    "EvidenceAgent",
    "EvidenceAgentInput",
    "EvidenceParser",
    "GraphAgent",
    "GraphAgentInput",
    "GraphBuilder",
    "MemoryAgentInput",
    "PlannerAgent",
    "PlannerAgentInput",
    "RAGAgentInput",
    "ReportAgent",
    "ReportAgentInput",
    "ReportSectionBuilder",
    "ResponseAgent",
    "ResponseAgentInput",
    "RiskAgent",
    "RiskAgentInput",
    "RiskScoringEngine",
    "SuperAgentInput",
    "ToolAgentInput",
    "TriageAgentInput",
    "VerdictResolver",
    "VerifyAgent",
    "VerifyAgentInput",
    "calibrate_confidence",
    "severity_from_score",
]

# export_name -> (module_path, attribute_name)
_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "AGENT_INPUT_MODELS": ("app.models.agent_io", "AGENT_INPUT_MODELS"),
    "AgentInput": ("app.models.agent_io", "AgentInput"),
    "AgentOutput": ("app.agents.base", "AgentOutput"),
    "BaseAgent": ("app.agents.base", "BaseAgent"),
    "EvidenceAgent": ("app.agents.evidence_agent", "EvidenceAgent"),
    "EvidenceAgentInput": ("app.models.agent_io", "EvidenceAgentInput"),
    "EvidenceParser": ("app.agents.evidence_parser", "EvidenceParser"),
    "GraphAgent": ("app.agents.graph_agent", "GraphAgent"),
    "GraphAgentInput": ("app.models.agent_io", "GraphAgentInput"),
    "GraphBuilder": ("app.agents.graph_builder", "GraphBuilder"),
    "MemoryAgentInput": ("app.models.agent_io", "MemoryAgentInput"),
    "PlannerAgent": ("app.agents.planner_agent", "PlannerAgent"),
    "PlannerAgentInput": ("app.models.agent_io", "PlannerAgentInput"),
    "RAGAgentInput": ("app.models.agent_io", "RAGAgentInput"),
    "ReportAgent": ("app.agents.report_agent", "ReportAgent"),
    "ReportAgentInput": ("app.models.agent_io", "ReportAgentInput"),
    "ReportSectionBuilder": ("app.agents.report_section_builder", "ReportSectionBuilder"),
    "ResponseAgent": ("app.agents.response_agent", "ResponseAgent"),
    "ResponseAgentInput": ("app.models.agent_io", "ResponseAgentInput"),
    "RiskAgent": ("app.agents.risk_agent", "RiskAgent"),
    "RiskAgentInput": ("app.models.agent_io", "RiskAgentInput"),
    "RiskScoringEngine": ("app.agents.risk_scoring_engine", "RiskScoringEngine"),
    "SuperAgentInput": ("app.models.agent_io", "SuperAgentInput"),
    "ToolAgentInput": ("app.models.agent_io", "ToolAgentInput"),
    "TriageAgentInput": ("app.models.agent_io", "TriageAgentInput"),
    "VerdictResolver": ("app.agents.verdict_resolver", "VerdictResolver"),
    "VerifyAgent": ("app.agents.verify_agent", "VerifyAgent"),
    "VerifyAgentInput": ("app.models.agent_io", "VerifyAgentInput"),
    "calibrate_confidence": ("app.agents.confidence_calibration", "calibrate_confidence"),
    "severity_from_score": ("app.agents.risk_scoring_engine", "severity_from_score"),
}


def __getattr__(name: str) -> Any:
    if name not in _LAZY_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_path, attr_name = _LAZY_EXPORTS[name]
    value = getattr(importlib.import_module(module_path), attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(__all__)
