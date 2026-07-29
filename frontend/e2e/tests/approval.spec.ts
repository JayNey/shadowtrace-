import { test, expect } from "@playwright/test";
import { readSeedState } from "../fixtures/seed";

test.describe("path 5 · L4 approval", () => {
  test("approves a waiting action and recovers pending state", async ({
    page,
  }) => {
    const { approvalEventId, approvalActionId } = readSeedState();
    test.skip(
      !approvalActionId,
      "no waiting_approval action seeded (response plan produced none)",
    );

    await page.goto("/approvals");
    const card = page.getByTestId(`approval-card-${approvalActionId}`);
    await expect(card).toBeVisible({ timeout: 60_000 });

    await card.getByText("批准").click();
    await page.getByRole("button", { name: "批准" }).click();

    await expect(card).toHaveCount(0, { timeout: 60_000 });

    // Event should leave waiting_approval after the plan is fully decided.
    await page.goto(`/events/${approvalEventId}`);
    await expect(page.getByTestId("event-overview-card")).toBeVisible();
    await expect(page.getByTestId("event-overview-card")).not.toContainText(
      "等待审批",
      { timeout: 60_000 },
    );
  });
});
