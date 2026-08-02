import { configDefaults, defineConfig } from "vitest/config";
import path from "node:path";
import react from "@vitejs/plugin-react";

import { VITEST_E2E_EXCLUDE_PATTERN, vitestSharedTestOptions } from "./vitest.shared";

// ISSUE-111 (#616): keep Vitest default discovery; exclude Playwright-owned e2e/**.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  test: {
    ...vitestSharedTestOptions,
    exclude: [...configDefaults.exclude, VITEST_E2E_EXCLUDE_PATTERN],
  },
});
