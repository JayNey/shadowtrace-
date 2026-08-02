/** Vitest options shared by config and ISSUE-111 regression guard (no vitest/config import). */

export const VITEST_E2E_EXCLUDE_PATTERN = "e2e/**";

export const vitestSharedTestOptions = {
  globals: true,
  environment: "jsdom" as const,
  setupFiles: ["./tests/setup.ts"],
};
