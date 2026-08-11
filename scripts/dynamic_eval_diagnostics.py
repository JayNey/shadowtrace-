"""Dynamic-eval failure diagnostics (ISSUE-313)."""

from __future__ import annotations

import json
from typing import Any

from dynamic_eval_approve import DynamicEvalClient, unwrap_event_detail_payload


def _audit_tail(client: DynamicEvalClient, event_id: str, *, limit: int = 5) -> list[dict[str, Any]]:
    try:
        payload = client.get_json(
            f"/api/v1/events/{event_id}/audit-logs?page=1&page_size={limit}"
        )
    except Exception:
        return []
    items = payload.get("items") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        return []
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
    return tail


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

    return {
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
        "recent_transitions": _audit_tail(client, event_id),
        "elapsed_s": elapsed_s,
    }


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
