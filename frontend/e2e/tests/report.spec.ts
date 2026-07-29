import { test, expect } from "@playwright/test";
import path from "node:path";
import { readSeedState } from "../fixtures/seed";

test.describe("path 6 · report viewer", () => {
  test("renders report and downloads markdown", async ({ page }) => {
    const { analysisEventId } = readSeedState();

    await page.goto(`/events/${analysisEventId}#report`);
    await expect(page.getByTestId("report-viewer")).toBeVisible({
      timeout: 60_000,
    });

    const downloadPromise = page.waitForEvent("download");
    await page.getByTestId("report-download-markdown").click();
    const download = await downloadPromise;
    const suggested = download.suggestedFilename();
    expect(suggested).toMatch(/shadowtrace-report-.*\.md$/);

    const target = path.join(
      test.info().outputDir,
      suggested || "report.md",
    );
    await download.saveAs(target);
  });
});
