import { test, expect } from "@playwright/test";
import { readSeedState } from "../fixtures/seed";

test.describe("path 2 · event detail overview / radar / conflicts", () => {
  test("shows overview, risk radar, and evidence conflict highlights", async ({
    page,
  }) => {
    const { analysisEventId } = readSeedState();

    await page.goto(`/events/${analysisEventId}`);
    await expect(page.getByTestId("event-overview-card")).toBeVisible({
      timeout: 60_000,
    });
    await expect(page.getByTestId("agent-status-panel")).toBeVisible();
    await expect(page.getByTestId("risk-radar")).toBeVisible();

    await page.locator(".shadowtrace-event-tabs").getByText("证据").click();
    const evidenceRow = page.locator("[data-testid^=\"evidence-row-\"]").first();
    await expect(evidenceRow).toBeVisible({ timeout: 30_000 });

    const conflict = page.locator("[data-testid^=\"evidence-conflict-\"]").first();
    await expect(conflict).toBeVisible({ timeout: 30_000 });
  });
});
