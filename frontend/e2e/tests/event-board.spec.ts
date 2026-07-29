import { test, expect } from "@playwright/test";
import { readSeedState } from "../fixtures/seed";

test.describe("path 1 · event board filter → detail", () => {
  test("filters by severity and opens event detail", async ({ page }) => {
    const { analysisEventId } = readSeedState();

    await page.goto("/events");
    await expect(page.getByTestId("event-table")).toBeVisible();
    await expect(page.getByTestId(`event-row-${analysisEventId}`)).toBeVisible({
      timeout: 60_000,
    });

    await page.getByTestId("filter-severity").click();
    // Seeded analysis event severity is `high` (risk agent output), not incident `critical`.
    await page
      .locator(".ant-select-dropdown:not(.ant-select-dropdown-hidden)")
      .getByText("高", { exact: true })
      .click();
    await expect(page).toHaveURL(/severity=high/);
    await expect(page.getByTestId(`event-row-${analysisEventId}`)).toBeVisible();

    await page.getByTestId(`event-row-${analysisEventId}`).click();
    await expect(page).toHaveURL(new RegExp(`/events/${analysisEventId}`));
    await expect(page.getByTestId("event-overview-card")).toBeVisible();
  });
});
