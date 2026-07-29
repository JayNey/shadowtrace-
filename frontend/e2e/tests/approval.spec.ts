import { test, expect } from "@playwright/test";
import { readSeedState } from "../fixtures/seed";

const BACKEND_BASE_URL =
  process.env.E2E_BACKEND_URL ?? "http://127.0.0.1:8000/api/v1";
const AUTH_TOKEN = process.env.E2E_AUTH_TOKEN ?? "e2e-token";

/** Statuses that mean the plan left waiting_approval without failing. */
const RECOVERED_STATUSES = new Set([
  "responding",
  "monitoring",
  "verifying",
  "reporting",
  "closed",
  "scoring",
  "investigating",
  "triaging",
]);

async function waitEventRecoveredAfterApproval(eventId: string): Promise<string> {
  const deadline = Date.now() + 60_000;
  let lastStatus = "";
  while (Date.now() < deadline) {
    const res = await fetch(`${BACKEND_BASE_URL}/events/${eventId}`, {
      headers: {
        Authorization: `Bearer ${AUTH_TOKEN}`,
        Accept: "application/json",
      },
    });
    if (res.ok) {
      const body = (await res.json()) as { event?: { status?: string } };
      lastStatus = String(body.event?.status ?? "");
      if (lastStatus === "failed") {
        throw new Error(`event ${eventId} entered failed after approval`);
      }
      if (lastStatus && lastStatus !== "waiting_approval") {
        if (!RECOVERED_STATUSES.has(lastStatus)) {
          throw new Error(
            `event ${eventId} left waiting_approval into unexpected status=${lastStatus}`,
          );
        }
        return lastStatus;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 2_000));
  }
  throw new Error(
    `event ${eventId} still waiting_approval (last=${lastStatus || "unknown"})`,
  );
}

test.describe("path 5 · L4 approval", () => {
  test("approves a waiting L4 action and recovers pending state", async ({
    page,
  }) => {
    const { approvalEventId, approvalActionId } = readSeedState();

    await page.goto("/approvals");
    const card = page.getByTestId(`approval-card-${approvalActionId}`);
    await expect(card).toBeVisible({ timeout: 60_000 });

    await card.getByText("批准").click();
    await page.getByRole("button", { name: "批准" }).click();

    await expect(card).toHaveCount(0, { timeout: 60_000 });

    // Event must leave waiting_approval into a non-failed recovered status.
    // UI label is "待审批" (STATUS_CONFIG), not "等待审批".
    const status = await waitEventRecoveredAfterApproval(approvalEventId);
    expect(status).not.toBe("waiting_approval");
    expect(status).not.toBe("failed");

    await page.goto(`/events/${approvalEventId}`);
    await expect(page.getByTestId("event-overview-card")).toBeVisible();
    await expect(page.getByTestId("event-overview-card")).not.toContainText(
      "待审批",
      { timeout: 60_000 },
    );
  });
});
