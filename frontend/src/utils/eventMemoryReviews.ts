/** Pending knowledge-review helpers for event detail (CLOSED fire-and-forget). */

export const CLOSED_MEMORY_REVIEW_POLL_MS = [0, 2000, 5000, 10000] as const;

export function countPendingMemoryReviewsForEvent(
  items: Array<{ status: string; payload: Record<string, unknown> }>,
  eventId: string,
): number {
  return items.filter((item) => {
    if (item.status !== "pending") return false;
    const payload = item.payload;
    const sourceEventId =
      (typeof payload.event_id === "string" && payload.event_id) ||
      (typeof payload.source_event_id === "string" && payload.source_event_id) ||
      "";
    return sourceEventId === eventId;
  }).length;
}
