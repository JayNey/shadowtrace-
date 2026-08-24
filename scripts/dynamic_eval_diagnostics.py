"""Dynamic-eval failure diagnostics (ISSUE-313)."""

from __future__ import annotations

import json
from typing import Any

from dynamic_eval_approve import DynamicEvalClient, unwrap_event_detail_payload


def _audit_tail(
    client: DynamicEvalClient, event_id: str, *, limit: int = 5
) -> tuple[list[dict[str, Any]], str | None]:
    try:
        payload = client.get_json(
            f"/api/v1/events/{event_id}/audit-logs?page=1&page_size={max(limit, 50)}"
        )
    except Exception as exc:  # noqa: BLE001 — surface error, keep other diagnostics
        return [], f"{type(exc).__name__}:{exc}"
    items = payload.get("items") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        return [], "audit_items_missing"
    tail: list[dict[str, Any]] = []
    for row in items[-limit:]:
        if not isinstance(row, dict):
            continue
        tail.append(
            {
                "from_status": row.get("from_status"),
                "to_status": row.get("to_status"),
                "operator": row.get("operator"),
                "reason": row.get("reason"),
            }
        )
    return tail, None


def _intent_summary(
    client: DynamicEvalClient,
    event_id: str,
    *,
    snapshot: dict[str, Any] | None,
    detail: dict[str, Any],
) -> tuple[dict[str, Any] | None, str | None]:
    """Best-effort investigation / graph-resume intent projection (ISSUE-313)."""
    candidates: list[Any] = []
    for source in (detail, snapshot or {}):
        if not isinstance(source, dict):
            continue
        for key in (
            "investigation_intent",
            "latest_investigation_intent",
            "graph_resume_intent",
            "intent",
        ):
            value = source.get(key)
            if value is not None:
                candidates.append(value)
        for key in ("intent_id", "investigation_intent_id", "graph_resume_intent_id"):
            value = source.get(key)
            if value is not None:
                candidates.append({"intent_id": value, "source_field": key})

    # decision-trace often carries the latest orchestration intent pointer.
    try:
        trace = client.get_json(f"/api/v1/events/{event_id}/decision-trace")
        if isinstance(trace, dict):
            for key in ("intent_id", "investigation_intent_id", "latest_intent"):
                if trace.get(key) is not None:
                    candidates.append(
                        {
                            "intent_id": trace.get(key) if key != "latest_intent" else None,
                            "latest_intent": trace.get("latest_intent")
                            if key == "latest_intent"
                            else None,
                            "source": "decision-trace",
                        }
                    )
            nested = trace.get("investigation_intent") or trace.get("intent")
            if nested is not None:
                candidates.append(nested)
    except Exception as exc:  # noqa: BLE001 — optional enrichment
        if not candidates:
            return None, f"{type(exc).__name__}:{exc}"

    if not candidates:
        return None, None

    chosen = candidates[0]
    if isinstance(chosen, dict):
        return {
            "intent_id": chosen.get("intent_id") or chosen.get("id"),
            "status": chosen.get("status"),
            "phase": chosen.get("phase") or chosen.get("task_type"),
            "source": chosen.get("source") or chosen.get("source_field") or "event_context",
        }, None
    return {"intent_id": str(chosen), "source": "scalar"}, None


def collect_event_diagnostics(
    client: DynamicEvalClient,
    event_id: str,
    *,
    status_trace: list[str] | None = None,
    elapsed_s: float | None = None,
) -> dict[str, Any]:
    """Gather structured observability for eval failures."""
    detail: dict[str, Any] = {}
    event: dict[str, Any] = {}
    try:
        raw = client.get_json(f"/api/v1/events/{event_id}")
        if isinstance(raw, dict) and raw.get("event"):
            detail = raw
            event = unwrap_event_detail_payload(raw, expected_event_id=event_id)
        elif isinstance(raw, dict):
            event = unwrap_event_detail_payload(raw, expected_event_id=event_id)
            detail = {"event": event}
    except Exception as exc:
        return {
            "event_id": event_id,
            "diagnostics_error": str(exc),
            "status_trace": status_trace or [],
            "elapsed_s": elapsed_s,
        }

    snapshot = event.get("event_context_snapshot")
    snapshot_flags: list[str] = []
    if isinstance(snapshot, dict):
        raw_flags = snapshot.get("degraded_flags")
        if isinstance(raw_flags, list):
            snapshot_flags = [str(item) for item in raw_flags]
    else:
        snapshot = None

    recent_transitions, audit_error = _audit_tail(client, event_id)
    intent, intent_error = _intent_summary(
        client, event_id, snapshot=snapshot, detail=detail
    )

    out: dict[str, Any] = {
        "event_id": event_id,
        "status": event.get("status"),
        "final_verdict": event.get("final_verdict"),
        "disposition_policy": event.get("disposition_policy"),
        "degraded_flags": list(event.get("degraded_flags") or []) + snapshot_flags,
        "analysis_only_complete": detail.get("analysis_only_complete")
        or (isinstance(snapshot, dict) and snapshot.get("analysis_only_complete")),
        "writeback_readiness": detail.get("writeback_readiness"),
        "writeback_overall_status": detail.get("writeback_overall_status"),
        "status_trace": status_trace or [],
        "recent_transitions": recent_transitions,
        "elapsed_s": elapsed_s,
        "investigation_intent": intent,
    }
    if audit_error:
        out["audit_error"] = audit_error
    if intent_error:
        out["intent_error"] = intent_error
    return out


def format_eval_failure_message(
    *,
    headline: str,
    event_id: str,
    diagnostics: dict[str, Any],
) -> str:
    """Human-readable failure output with status trajectory and observability."""
    lines = [headline, f"event_id={event_id}"]
    if diagnostics.get("elapsed_s") is not None:
        lines.append(f"elapsed_s={diagnostics['elapsed_s']}")
    status = diagnostics.get("status")
    if status is not None:
        lines.append(f"status={status}")
    trace = diagnostics.get("status_trace") or []
    if trace:
        lines.append(f"status_trace={' -> '.join(str(item) for item in trace)}")
    final_verdict = diagnostics.get("final_verdict")
    if final_verdict is not None:
        lines.append(f"final_verdict={final_verdict}")
    flags = diagnostics.get("degraded_flags") or []
    if flags:
        lines.append(f"degraded_flags={json.dumps(flags, ensure_ascii=False)}")
    transitions = diagnostics.get("recent_transitions") or []
    if transitions:
        lines.append("recent_transitions=" + json.dumps(transitions, ensure_ascii=False))
    if diagnostics.get("audit_error"):
        lines.append(f"audit_error={diagnostics['audit_error']}")
    intent = diagnostics.get("investigation_intent")
    if intent is not None:
        lines.append("investigation_intent=" + json.dumps(intent, ensure_ascii=False))
    if diagnostics.get("intent_error"):
        lines.append(f"intent_error={diagnostics['intent_error']}")
    if diagnostics.get("analysis_only_complete") is not None:
        lines.append(f"analysis_only_complete={diagnostics['analysis_only_complete']}")
    if diagnostics.get("writeback_readiness") is not None:
        lines.append(f"writeback_readiness={diagnostics['writeback_readiness']}")
    if diagnostics.get("writeback_overall_status") is not None:
        lines.append(f"writeback_overall_status={diagnostics['writeback_overall_status']}")
    if diagnostics.get("diagnostics_error"):
        lines.append(f"diagnostics_error={diagnostics['diagnostics_error']}")
    return "\n".join(lines)


__all__ = [
    "collect_event_diagnostics",
    "format_eval_failure_message",
]
