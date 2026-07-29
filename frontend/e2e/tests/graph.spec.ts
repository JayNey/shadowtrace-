import { test, expect } from "@playwright/test";
import { readSeedState } from "../fixtures/seed";

test.describe("path 4 · entity graph", () => {
  test("renders graph and plays an attack path", async ({ page }) => {
    const { analysisEventId } = readSeedState();

    await page.goto(`/events/${analysisEventId}#graph`);
    await expect(page.getByTestId("entity-graph")).toBeVisible({
      timeout: 60_000,
    });
    await expect(page.getByText("图谱未生成")).toHaveCount(0);

    const play = page.getByTestId("attack-path-play");
    await expect(play).toBeVisible({ timeout: 30_000 });
    await play.click();
    await expect(page.getByTestId("attack-path-step")).toBeVisible();
    await expect(page.getByTestId("attack-path-step")).not.toHaveText(
      "等待播放",
    );
  });
});
