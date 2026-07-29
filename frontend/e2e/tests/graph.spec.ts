import { test, expect } from "@playwright/test";
import { readSeedState } from "../fixtures/seed";

test.describe("path 4 · entity graph", () => {
  test("renders graph and plays an attack path when available", async ({
    page,
  }) => {
    const { analysisEventId } = readSeedState();

    await page.goto(`/events/${analysisEventId}#graph`);
    await expect(page.getByTestId("entity-graph")).toBeVisible({
      timeout: 60_000,
    });

    const play = page.getByTestId("attack-path-play");
    if (await play.count()) {
      await play.click();
      await expect(page.getByTestId("attack-path-step")).toBeVisible();
      await expect(page.getByTestId("attack-path-step")).not.toHaveText(
        "等待播放",
      );
    } else {
      await expect(
        page.getByText(/暂无攻击路径候选|实体关系图|个节点/),
      ).toBeVisible();
    }
  });
});
