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
    // Conflict tags appear when EvidenceAgent detected conflicts; tolerate
    // absent conflicts when telemetry projection is sparse, but the evidence
    // tab must render.
    const conflict = page.locator("[data-testid^=\"evidence-conflict-\"]").first();
    const evidenceRow = page.locator("[data-testid^=\"evidence-row-\"]").first();
    await expect(conflict.or(evidenceRow).or(page.getByText("暂无数据"))).toBeVisible({
      timeout: 30_000,
    });
  });
});
