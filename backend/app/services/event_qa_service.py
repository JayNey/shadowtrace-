"""Grounded conversational event Q&A (ISSUE-076)."""

from __future__ import annotations

from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field

from app.agents.prompts.event_qa_prompt import build_event_qa_messages
from app.core.sanitization import redact_sensitive_text, sanitize_data

ChatRole = Literal["user", "assistant"]
ChatReferenceType = Literal["evidence", "trace", "report"]

_EVENT_FIELDS = (
    "event_id",
    "event_type",
    "title",
    "status",
    "severity",
    "risk_score",
    "final_verdict",
    "occurred_at",
)
_RISK_FIELDS = (
    "risk_score",
    "severity",
    "confidence",
    "scoring_mode",
    "possible_false_positive",
)
_TRACE_DETAIL_FIELDS = (
    "structured_conclusion",
    "evidence_refs",
    "confidence",
    "rule_version",
    "model_version",
    "warnings",
    "reason",
    "status",
    "from_status",
    "to_status",
)


class ChatHistoryItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: ChatRole
    content: str = Field(min_length=1, max_length=4000)


class ChatReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ref_type: ChatReferenceType
    ref_id: str = Field(min_length=1, max_length=200)


class ChatAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    answer: str = Field(min_length=1, max_length=8000)
    references: list[ChatReference] = Field(default_factory=list, max_length=50)


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, BaseModel):
        dumped = value.model_dump(mode="json")
        return dumped if isinstance(dumped, dict) else {}
    return dict(value) if isinstance(value, dict) else {}


def _event_projection(context: Any) -> dict[str, Any]:
    event = _mapping(getattr(context, "event", None))
    return cast(
        dict[str, Any],
        sanitize_data({key: event.get(key) for key in _EVENT_FIELDS if key in event}),
    )


def _risk_projection(context: Any) -> dict[str, Any]:
    risk = _mapping(getattr(context, "risk_assessment", None))
    projected: dict[str, Any] = {key: risk.get(key) for key in _RISK_FIELDS if key in risk}
    factors = risk.get("risk_factors")
    if isinstance(factors, list):
        projected["risk_factors"] = [
            {
                key: item.get(key)
                for key in ("factor_name", "raw_score", "weighted_score", "reasoning")
                if key in item
            }
            for item in factors[:12]
            if isinstance(item, dict)
        ]
    return cast(dict[str, Any], sanitize_data(projected))


def _evidence_projection(context: Any) -> list[dict[str, Any]]:
    evidence_output = _mapping(getattr(context, "evidence_output", None))
    evidence = evidence_output.get("evidence_list")
    if not isinstance(evidence, list):
        return []
    projected = []
    for item in evidence[:20]:
        if not isinstance(item, dict):
            continue
        projected.append(
            {
                key: item.get(key)
                for key in (
                    "evidence_id",
                    "source",
                    "evidence_type",
                    "description",
                    "confidence",
                    "timestamp",
                    "is_conflicting",
                )
                if key in item
            }
        )
    return cast(list[dict[str, Any]], sanitize_data(projected))


def _trace_projection(trace: Any) -> list[dict[str, Any]]:
    entries = getattr(trace, "entries", [])
    if not isinstance(entries, list):
        return []
    projected: list[dict[str, Any]] = []
    for entry in entries[-20:]:
        row = _mapping(entry)
        detail = _mapping(row.get("detail"))
        projected.append(
            cast(
                dict[str, Any],
                sanitize_data(
                    {
                        "entry_id": row.get("entry_id"),
                        "entry_type": row.get("entry_type"),
                        "timestamp": row.get("timestamp"),
                        "actor": row.get("actor"),
                        "title": row.get("title"),
                        "ref_id": row.get("ref_id"),
                        "detail": {
                            key: detail.get(key) for key in _TRACE_DETAIL_FIELDS if key in detail
                        },
                    }
                ),
            )
        )
    return projected


def _valid_reference_ids(
    context: Any,
    trace: Any,
    evidence_summary: list[dict[str, Any]],
) -> dict[ChatReferenceType, set[str]]:
    evidence_ids = {
        str(item["evidence_id"]) for item in evidence_summary if item.get("evidence_id")
    }
    trace_ids: set[str] = set()
    for entry in getattr(trace, "entries", []):
        row = _mapping(entry)
        for key in ("entry_id", "ref_id"):
            if row.get(key):
                trace_ids.add(str(row[key]))

    report_ids: set[str] = set()
    report = getattr(context, "report", None)
    report_data = _mapping(report)
    if report_data.get("report_id"):
        report_ids.add(str(report_data["report_id"]))
    sections = report_data.get("sections")
    if isinstance(sections, list):
        report_ids.update(
            str(section["key"])
            for section in sections
            if isinstance(section, dict) and section.get("key")
        )
    return {
        "evidence": evidence_ids,
        "trace": trace_ids,
        "report": report_ids,
    }


class EventQAService:
    """Answer event questions from a bounded, redacted EventContext projection."""

    def __init__(
        self,
        *,
        context_store: Any,
        decision_trace_service: Any,
        llm_client: Any,
    ) -> None:
        self._context_store = context_store
        self._decision_trace_service = decision_trace_service
        self._llm_client = llm_client

    async def answer(
        self,
        event_id: str,
        question: str,
        history: list[ChatHistoryItem],
    ) -> ChatAnswer:
        context = await self._context_store.get_full_context(event_id)
        trace = await self._decision_trace_service.get_decision_trace(event_id)

        event_summary = _event_projection(context)
        risk_summary = _risk_projection(context)
        evidence_summary = _evidence_projection(context)
        trace_summary = _trace_projection(trace)
        safe_history = [
            (item.role, redact_sensitive_text(item.content)[:4000]) for item in history[-10:]
        ]
        safe_question = redact_sensitive_text(question.strip())[:2000]
        if not safe_question:
            raise ValueError("question must not be empty")

        response = await self._llm_client.chat(
            build_event_qa_messages(
                event_summary=event_summary,
                risk_summary=risk_summary,
                evidence_summary=evidence_summary,
                decision_trace_summary=trace_summary,
                history=safe_history,
                question=safe_question,
            ),
            event_id=event_id,
            agent_name="event_qa_service",
            prompt_key="event_qa",
            json_mode=True,
            response_model=ChatAnswer,
        )
        parsed = response.parsed
        if not isinstance(parsed, ChatAnswer):
            parsed = ChatAnswer.model_validate_json(response.content)

        valid_ids = _valid_reference_ids(context, trace, evidence_summary)
        references: list[ChatReference] = []
        seen: set[tuple[str, str]] = set()
        for reference in parsed.references:
            key = (reference.ref_type, reference.ref_id)
            if reference.ref_id not in valid_ids[reference.ref_type] or key in seen:
                continue
            seen.add(key)
            references.append(reference)

        return ChatAnswer(
            answer=redact_sensitive_text(parsed.answer),
            references=references,
        )


__all__ = [
    "ChatAnswer",
    "ChatHistoryItem",
    "ChatReference",
    "EventQAService",
]
