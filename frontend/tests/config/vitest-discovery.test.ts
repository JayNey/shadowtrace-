/**
 * ISSUE-111 (#616): guard Vitest discovery boundary vs Playwright e2e specs.
 */
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { VITEST_E2E_EXCLUDE_PATTERN } from "../../vitest.shared";

const frontendRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

describe("vitest discovery boundary (ISSUE-111)", () => {
  it("keeps Vitest default discovery and excludes e2e/** in config source", () => {
    const configSource = readFileSync(path.join(frontendRoot, "vitest.config.ts"), "utf8");
    expect(configSource).toContain("configDefaults.exclude");
    expect(configSource).toContain(VITEST_E2E_EXCLUDE_PATTERN);
    expect(configSource).not.toMatch(/\binclude\s*:/);
  });

  it("retains Playwright specs under e2e/ for the separate runner", () => {
    const specDir = path.join(frontendRoot, "e2e/tests");
    expect(existsSync(specDir)).toBe(true);
    const playwrightSpecs = [
      "approval.spec.ts",
      "event-board.spec.ts",
      "event-detail.spec.ts",
      "graph.spec.ts",
      "investigate-mode.spec.ts",
      "report.spec.ts",
      "storyline.spec.ts",
    ];
    for (const spec of playwrightSpecs) {
      expect(existsSync(path.join(specDir, spec))).toBe(true);
    }
    expect(existsSync(path.join(frontendRoot, "e2e/playwright.config.ts"))).toBe(true);
  });
});
