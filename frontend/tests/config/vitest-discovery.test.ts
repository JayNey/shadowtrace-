/**
 * ISSUE-111 (#616): guard Vitest discovery boundary vs Playwright e2e specs.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { VITEST_E2E_EXCLUDE_PATTERN } from "../../vitest.shared";

const frontendRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const vitestBin = path.join(frontendRoot, "node_modules", ".bin", "vitest");

function collectVitestFiles(): string[] {
  const out = execFileSync(vitestBin, ["list", "--json", "--filesOnly"], {
    cwd: frontendRoot,
    encoding: "utf8",
    env: { ...process.env, CI: "true" },
  });
  const entries = JSON.parse(out) as Array<{ file: string }>;
  return entries.map((entry) => entry.file);
}

describe("vitest discovery boundary (ISSUE-111)", () => {
  it("keeps Vitest default discovery and excludes e2e/** in config source", () => {
    const configSource = readFileSync(path.join(frontendRoot, "vitest.config.ts"), "utf8");
    expect(configSource).toContain("configDefaults.exclude");
    expect(configSource).toContain(VITEST_E2E_EXCLUDE_PATTERN);
    expect(configSource).not.toMatch(/\binclude\s*:/);
  });

  it("does not collect Playwright-owned e2e/** files at runtime", () => {
    const collected = collectVitestFiles();
    expect(collected.length).toBeGreaterThan(0);
    for (const file of collected) {
      const relative = path.relative(frontendRoot, file).replace(/\\/g, "/");
      expect(relative.startsWith("e2e/")).toBe(false);
    }
  });

  it("retains Playwright specs under e2e/ for the separate runner", () => {
    const specDir = path.join(frontendRoot, "e2e/tests");
    expect(existsSync(specDir)).toBe(true);
    const playwrightSpecs = readdirSync(specDir).filter((name) => name.endsWith(".spec.ts"));
    expect(playwrightSpecs.length).toBeGreaterThan(0);
    for (const spec of playwrightSpecs) {
      expect(existsSync(path.join(specDir, spec))).toBe(true);
    }
    expect(existsSync(path.join(frontendRoot, "e2e/playwright.config.ts"))).toBe(true);
  });
});
