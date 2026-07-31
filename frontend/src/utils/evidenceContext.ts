import type {
  EventDetailResponse,
  EventStatus,
  EvidenceTriageContext,
} from "../types/event";

const EVIDENCE_READY_STATUSES: ReadonlySet<EventStatus> = new Set([
  "collecting_evidence",
  "analyzing",
  "scoring",
  "planning_response",
  "waiting_approval",
  "executing_response",
  "verifying",
  "replanning",
  "contained",
  "failed",
  "reporting",
  "closed",
]);

/** Fetch evidence API only when snapshot or lifecycle indicates collection ran. */
export function shouldFetchEventEvidence(detail: EventDetailResponse | null): boolean {
  if (!detail) {
    return false;
  }
  if (detail.event.event_context_snapshot?.evidence_output) {
    return true;
  }
  return EVIDENCE_READY_STATUSES.has(detail.event.status);
}

/** Build triage context banner payload from frozen EventContext snapshot. */
export function triageContextFromSnapshot(
  snapshot: EventDetailResponse["event"]["event_context_snapshot"],
): EvidenceTriageContext | null {
  const raw = snapshot?.triage_result;
  if (!raw || typeof raw !== "object") {
    return null;
  }
  const degraded = Boolean(raw.degraded);
  const degradationReasons = Array.isArray(raw.degradation_reasons)
    ? raw.degradation_reasons.filter((item): item is string => typeof item === "string")
    : [];
  const rejectionSummary =
    typeof raw.entity_rejection_summary === "object" && raw.entity_rejection_summary !== null
      ? (raw.entity_rejection_summary as Record<string, unknown>)
      : {};
  if (!degraded && degradationReasons.length === 0 && Object.keys(rejectionSummary).length === 0) {
    return null;
  }
  return {
    degraded,
    degradation_reasons: degradationReasons,
    entity_rejection_summary: rejectionSummary,
  };
}
