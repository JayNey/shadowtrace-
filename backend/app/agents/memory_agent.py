"""Post-closure knowledge consolidation agent (ISSUE-080)."""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.agents.base import BaseAgent
from app.core.llm.base import LLMMessage
from app.models.agent_io import (
    CaseRecordSummary,
    FpRuleCandidate,
    GraphOutput,
    MemoryAgentInput,
    MemoryOutput,
    ProfileUpdate,
)
from app.models.context import EventContext
from app.models.enums import EventStatus, FinalVerdict
from app.services.case_kb_service import CaseKBService
from app.services.profile_service import ProfileService

logger = logging.getLogger(__name__)


class _FpRuleDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_summary: str
    alert_signature: str
    confidence: float = Field(ge=0.0, le=1.0)


class MemoryAgent(BaseAgent[MemoryAgentInput, MemoryOutput]):
    """Archive closed cases and derive reviewable knowledge artifacts."""

    agent_name = "memory_agent"

    def __init__(
        self,
        *,
        case_kb_service: CaseKBService,
        profile_service: ProfileService,
        context_store: Any,
        llm_client: Any | None = None,
        working_memory: Any | None = None,
        budget_service: Any | None = None,
        output_guard: Any | None = None,
        trace_service: Any | None = None,
        audit_service: Any | None = None,
        event_bus: Any | None = None,
    ) -> None:
        super().__init__(
            llm_client=llm_client,
            working_memory=working_memory,
            budget_service=budget_service,
            output_guard=output_guard,
            trace_service=trace_service,
            audit_service=audit_service,
            event_bus=event_bus,
        )
        self.case_kb_service = case_kb_service
        self.profile_service = profile_service
        self.context_store: Any = context_store

    async def _run(self, input: MemoryAgentInput) -> MemoryOutput:
        if input.investigation_result.final_status is not EventStatus.CLOSED:
            raise ValueError("MemoryAgent only accepts CLOSED investigations")

        context = await self.context_store.get_full_context(input.event_id)
        if context.memory_output is not None:
            return MemoryOutput.model_validate(context.memory_output)

        output = MemoryOutput()
        if input.investigation_result.external_unsynced or (
            context.event is not None and context.event.external_unsynced
        ):
            logger.info(
                "MemoryAgent consolidation skipped for externally unsynced event=%s",
                input.event_id,
            )
            return await self._persist_output(input.event_id, output)

        try:
            case_id = await self.case_kb_service.archive_event_as_case(input.event_id)
            output.case_records.append(
                CaseRecordSummary(
                    case_id=case_id,
                    event_id=input.event_id,
                    summary=_case_summary(context),
                    archived=True,
                )
            )
        except ValueError as exc:
            logger.info(
                "MemoryAgent case archival ineligible event=%s reason=%s",
                input.event_id,
                exc,
            )
        except Exception:
            logger.warning(
                "MemoryAgent case archival failed event=%s",
                input.event_id,
                exc_info=True,
            )

        if input.investigation_result.final_verdict is FinalVerdict.FALSE_POSITIVE:
            try:
                output.fp_rules.append(await self._build_fp_rule(input.event_id, context))
            except Exception:
                logger.warning(
                    "MemoryAgent false-positive rule skipped event=%s",
                    input.event_id,
                    exc_info=True,
                )

        try:
            profile_updates = _profile_updates(input.event_id, context)
        except Exception:
            logger.warning(
                "MemoryAgent profile extraction skipped event=%s",
                input.event_id,
                exc_info=True,
            )
            profile_updates = []
        for update in profile_updates:
            try:
                await self.profile_service.upsert(update)
                output.profile_updates.append(update)
            except Exception:
                logger.warning(
                    "MemoryAgent profile update skipped event=%s entity=%s:%s",
                    input.event_id,
                    update.entity_type,
                    update.entity_value,
                    exc_info=True,
                )

        if input.investigation_result.final_verdict is FinalVerdict.CONFIRMED_THREAT:
            try:
                output.sigma_drafts.append(_build_sigma_draft(input.event_id, context))
            except Exception:
                logger.warning(
                    "MemoryAgent Sigma draft skipped event=%s",
                    input.event_id,
                    exc_info=True,
                )

        return await self._persist_output(input.event_id, output)

    async def _persist_output(self, event_id: str, output: MemoryOutput) -> MemoryOutput:
        if self.working_memory is None:
            raise RuntimeError("MemoryAgent requires working_memory")
        await self.working_memory.write(
            event_id,
            "memory_output",
            output.model_dump(mode="json"),
        )
        return output

    async def _build_fp_rule(self, event_id: str, context: EventContext) -> FpRuleCandidate:
        signature = _alert_signature(context)
        fallback = _FpRuleDraft(
            rule_summary=(
                f"Review alerts matching {signature} as a potential false positive "
                f"when the validated context matches event {event_id}."
            ),
            alert_signature=signature,
            confidence=0.75,
        )
        draft = fallback
        if self.llm_client is not None:
            try:
                response = await self.llm_client.chat(
                    [
                        LLMMessage(
                            role="system",
                            content=(
                                "Create a concise false-positive rule candidate. "
                                "Return JSON only. The result is advisory and must be reviewed."
                            ),
                        ),
                        LLMMessage(
                            role="user",
                            content=json.dumps(
                                {
                                    "event_id": event_id,
                                    "alert_signature": signature,
                                    "report_summary": _case_summary(context),
                                },
                                ensure_ascii=False,
                                sort_keys=True,
                            ),
                        ),
                    ],
                    event_id=event_id,
                    agent_name=self.agent_name,
                    prompt_key="memory_fp_rule",
                    json_mode=True,
                    response_model=_FpRuleDraft,
                )
                if isinstance(response.parsed, _FpRuleDraft):
                    draft = response.parsed
            except Exception:
                logger.warning(
                    "MemoryAgent LLM unavailable; using FP rule template event=%s",
                    event_id,
                    exc_info=True,
                )
        # Keep the match key deterministic; the LLM may only refine summary/confidence.
        return FpRuleCandidate(
            rule_summary=draft.rule_summary,
            alert_signature=signature,
            confidence=draft.confidence,
            source_event_id=event_id,
            pending_review=True,
        )


def _case_summary(context: EventContext) -> str:
    if context.report is not None and context.report.summary:
        return context.report.summary
    if context.event is not None:
        return context.event.title
    return ""


def _alert_signature(context: EventContext) -> str:
    if context.event is None:
        return "unknown-alert"
    return f"{context.event.event_type.value}:{context.event.title}"[:500]


def _profile_updates(event_id: str, context: EventContext) -> list[ProfileUpdate]:
    entities: dict[tuple[str, str], None] = {}
    if context.graph_output:
        graph = GraphOutput.model_validate(context.graph_output)
        for node in graph.nodes:
            if node.entity_type and node.entity_value:
                entities[(node.entity_type, node.entity_value)] = None

    triage_entities = (context.triage_result or {}).get("entities", {})
    if isinstance(triage_entities, dict):
        for plural, values in triage_entities.items():
            entity_type = {
                "accounts": "account",
                "hosts": "host",
                "ips": "ip",
                "domains": "domain",
                "processes": "process",
                "files": "file",
            }.get(plural) or plural
            if not isinstance(values, list):
                continue
            for value in values:
                rendered = _entity_value(value)
                if rendered:
                    entities[(entity_type, rendered)] = None

    risk_score = context.event.risk_score if context.event is not None else None
    tags = _behavior_tags(context)
    return [
        ProfileUpdate(
            entity_type=entity_type,
            entity_value=entity_value,
            event_id=event_id,
            risk_score=risk_score,
            behavior_tags=tags,
        )
        for entity_type, entity_value in sorted(entities)
    ]


def _entity_value(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in (
            "username",
            "hostname",
            "address",
            "fqdn",
            "name",
            "path",
            "entity_id",
        ):
            rendered = value.get(key)
            if rendered:
                return str(rendered)
    return None


def _behavior_tags(context: EventContext) -> list[str]:
    tags: set[str] = set()
    if context.event is not None:
        tags.update(
            {
                f"event_type:{context.event.event_type.value}",
                f"verdict:{context.event.final_verdict.value}",
            }
        )
    storyline = context.storyline or {}
    phases = storyline.get("phases", []) if isinstance(storyline, dict) else []
    for phase in phases:
        if isinstance(phase, dict) and phase.get("phase_name"):
            tags.add(f"phase:{phase['phase_name']}")
    return sorted(tags)


def _build_sigma_draft(event_id: str, context: EventContext) -> str:
    """Return YAML without adding a runtime YAML dependency (JSON scalars are YAML-safe)."""
    title = f"ShadowTrace confirmed threat {event_id}"
    evidence_types: list[str] = []
    techniques: list[str] = []
    for item in (context.evidence_output or {}).get("evidence_list", []):
        if not isinstance(item, dict):
            continue
        if item.get("evidence_type"):
            evidence_types.append(str(item["evidence_type"]))
        if item.get("mitre_technique"):
            techniques.append(str(item["mitre_technique"]))
    sigma_id = uuid.uuid5(uuid.NAMESPACE_URL, f"shadowtrace:sigma:{event_id}")
    lines = [
        f"title: {json.dumps(title, ensure_ascii=False)}",
        f"id: {sigma_id}",
        "status: experimental",
        f"description: {json.dumps(_case_summary(context), ensure_ascii=False)}",
        "references:",
        f"  - {json.dumps(f'shadowtrace:event:{event_id}')}",
        "tags:",
    ]
    if techniques:
        technique_tags = [_sigma_attack_tag(item) for item in sorted(set(techniques))]
        lines.extend(technique_tags)
    else:
        lines.append("  - attack.discovery")
    lines.extend(
        [
            "logsource:",
            "  product: shadowtrace",
            "  category: security_event",
            "detection:",
            "  selection:",
            f"    event_id: {json.dumps(event_id)}",
        ]
    )
    if evidence_types:
        lines.append("    evidence_type:")
        lines.extend(f"      - {json.dumps(item)}" for item in sorted(set(evidence_types)))
    lines.extend(
        [
            "  condition: selection",
            "falsepositives:",
            "  - Requires analyst validation before promotion",
            "level: high",
        ]
    )
    return "\n".join(lines) + "\n"


def _sigma_attack_tag(technique: str) -> str:
    return f"  - {json.dumps(f'attack.{technique.lower()}')}"
