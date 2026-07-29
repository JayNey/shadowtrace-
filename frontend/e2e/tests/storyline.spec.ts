import { test, expect } from "@playwright/test";
import { readSeedState } from "../fixtures/seed";

const PHASES = [
  "initial_access",
  "collection",
  "staging",
  "exfiltration",
  "post_action",
] as const;

test.describe("path 3 · storyline timeline", () => {
  test("renders five phases and expands a timeline entry", async ({ page }) => {
    const { analysisEventId } = readSeedState();

    await page.goto(`/events/${analysisEventId}#timeline`);
    await expect(page.getByTestId("storyline-timeline")).toBeVisible({
      timeout: 60_000,
    });

    for (const phase of PHASES) {
      await expect(page.getByTestId(`storyline-phase-${phase}`)).toBeVisible({
        timeout: 60_000,
      });
    }

    const expand = page.getByRole("button", { name: /展开关联证据/ }).first();
    await expect(expand).toBeVisible({ timeout: 30_000 });
    await expand.click();
    await expect(
      page.locator("[data-testid^=\"timeline-evidence-\"]").first(),
    ).toBeVisible();
  });
});
