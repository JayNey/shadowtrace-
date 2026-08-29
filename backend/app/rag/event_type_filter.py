"""Playbook + gated history EventType storage filter (口径 E / G / K).

Not a KnowledgeFilterKind. HybridRetriever / KnowledgeStore apply
``metadata->>'event_type' = :event_type_equals`` as an internal bypass, ANDed
with release / embedding pin. fp / attack / org never inject. ``other`` never
injects on any kb. History injects only for types in
``HISTORY_EVENT_TYPE_FILTER_OPENED`` after §2.2 gates.
"""

from __future__ import annotations

from typing import Any

from app.models.enums import EventType
from app.rag.context import RetrievalContext

PLAYBOOK_KB_NAME = "playbook_kb"
HISTORY_KB_NAME = "history_case_kb"
PLAYBOOK_RELEASE_PIN_EMPTY = "playbook_release_pin_empty"
EVENT_TYPE_FILTER_EMPTY = "event_type_filter_empty"

# §2.2 gate-2/3 smoke (2026-08-29, loaded history_case_kb n=25, no LLM,
# Hybrid + §1.1 rewrite + §1.3 dedupe, type filter OFF, top_k=5 fetch_k=10).
# Pool = union of vector+keyword lists. other recorded but never opened.
HISTORY_TYPE_FILTER_SMOKE: tuple[tuple[str, str, int], ...] = (
    ("account_anomaly_fp", "account_anomaly", 2),
    ("suspicious_domain_access", "suspicious_domain", 2),
    ("insider_data_exfiltration", "data_exfiltration", 1),
    ("host_compromise", "host_compromise", 3),
    ("insider_privilege_abuse", "insider_threat", 3),
    ("malicious_process", "malicious_process", 2),
    ("lateral_movement", "lateral_movement", 2),
    ("other_unclassified", "other", 3),
)

# P0 default: open none. §2.2 smoke numbers below are recorded for later;
# do not add a type here until a Hybrid fetch_k test (loaded KB, no LLM) exists.
HISTORY_EVENT_TYPE_FILTER_OPENED: frozenset[str] = frozenset()


def storage_event_type_equals(
    kb_name: str,
    event_type: EventType | None,
) -> str | None:
    """Value to inject, or None (other / unknown / None / kb not in scope)."""
    if event_type is None or event_type is EventType.OTHER:
        injected = None
    else:
        value = str(event_type.value)
        if kb_name == PLAYBOOK_KB_NAME:
            injected = value
        elif kb_name == HISTORY_KB_NAME and value in HISTORY_EVENT_TYPE_FILTER_OPENED:
            injected = value
        else:
            injected = None
    return injected


async def playbook_empty_degraded_steps(
    store: Any,
    context: RetrievalContext,
) -> tuple[str, ...]:
    """Tag empty playbook retrieval: pin empty vs type-filter empty (口径 G).

    Does not re-query without the type filter (no full-kb fallback).
    """
    pin_id = None
    if context.query_plan is not None and context.query_plan.kb_name == PLAYBOOK_KB_NAME:
        pin_id = (context.query_plan.embedding_release_id or "").strip() or None
    if pin_id and hasattr(store, "count_chunks"):
        pinned = await store.count_chunks(
            kb_name=PLAYBOOK_KB_NAME,
            tenant_id=context.tenant_id,
            embedding_release_id=pin_id,
        )
        if int(pinned) <= 0:
            return (PLAYBOOK_RELEASE_PIN_EMPTY,)
    if storage_event_type_equals(PLAYBOOK_KB_NAME, context.event_type) is not None:
        return (EVENT_TYPE_FILTER_EMPTY,)
    return ()


__all__ = [
    "EVENT_TYPE_FILTER_EMPTY",
    "HISTORY_EVENT_TYPE_FILTER_OPENED",
    "HISTORY_KB_NAME",
    "HISTORY_TYPE_FILTER_SMOKE",
    "PLAYBOOK_KB_NAME",
    "PLAYBOOK_RELEASE_PIN_EMPTY",
    "playbook_empty_degraded_steps",
    "storage_event_type_equals",
]
