import { test, expect } from "@playwright/test";
import { readSeedState } from "../fixtures/seed";

const BACKEND_BASE_URL =
  process.env.E2E_BACKEND_URL ?? "http://127.0.0.1:8000/api/v1";
const AUTH_TOKEN = process.env.E2E_AUTH_TOKEN ?? "e2e-token";

async function waitEventLeftWaitingApproval(eventId: string): Promise<string> {
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
      if (lastStatus && lastStatus !== "waiting_approval") {
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

    async function fetchWaitingActionIds(): Promise<string[]> {
      const res = await fetch(
        `${BACKEND_BASE_URL}/events/${approvalEventId}/actions?status=waiting_approval&page_size=50`,
        {
          headers: {
            Authorization: `Bearer ${AUTH_TOKEN}`,
            Accept: "application/json",
          },
        },
      );
      if (!res.ok) {
        throw new Error(`actions fetch failed (${res.status})`);
      }
      const body = (await res.json()) as {
        items?: Array<{ action_id?: string }>;
      };
      return (body.items ?? [])
        .map((item) => item.action_id)
        .filter((id): id is string => Boolean(id));
    }

    async function confirmApprovalDialog(): Promise<void> {
      const dialog = page.getByRole("dialog", { name: "批准动作" });
      await expect(dialog).toBeVisible();
      await dialog.getByRole("button", { name: /批\s*准/ }).click();
      await expect(dialog).toHaveCount(0);
    }

    await page.goto("/approvals");

    for (let attempt = 0; attempt < 8; attempt += 1) {
      const waitingIds = await fetchWaitingActionIds();
      if (waitingIds.length === 0) {
        break;
      }
      const actionId = waitingIds[0];
      const card = page.getByTestId(`approval-card-${actionId}`);
      await expect(card).toBeVisible({ timeout: 60_000 });
      await card.getByText("批准", { exact: true }).click();
      await confirmApprovalDialog();
    }

    expect(await fetchWaitingActionIds()).not.toContain(approvalActionId);

    // Event must leave waiting_approval after the plan is fully decided.
    // UI label is "待审批" (STATUS_CONFIG), not "等待审批".
    const status = await waitEventLeftWaitingApproval(approvalEventId);
    expect(status).not.toBe("waiting_approval");

    await page.goto(`/events/${approvalEventId}`);
    await expect(page.getByTestId("event-overview-card")).toBeVisible();
    await expect(page.getByTestId("event-overview-card")).not.toContainText(
      "待审批",
      { timeout: 60_000 },
    );
  });
});
