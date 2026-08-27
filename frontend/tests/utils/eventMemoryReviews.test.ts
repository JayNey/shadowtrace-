import { describe, expect, it } from "vitest";
import { countPendingMemoryReviewsForEvent } from "../../src/utils/eventMemoryReviews";

describe("countPendingMemoryReviewsForEvent", () => {
  it("counts pending rows for the event and ignores others", () => {
    const count = countPendingMemoryReviewsForEvent(
      [
        { status: "pending", payload: { event_id: "evt-70" } },
        { status: "pending", payload: { source_event_id: "evt-70" } },
        { status: "promoted", payload: { event_id: "evt-70" } },
        { status: "pending", payload: { event_id: "evt-other" } },
      ],
      "evt-70",
    );
    expect(count).toBe(2);
  });
});
