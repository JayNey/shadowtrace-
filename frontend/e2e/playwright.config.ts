/**
 * Playwright config for ISSUE-077 frontend integration verification.
 *
 * Chromium only; baseURL points at the Compose frontend. Global setup runs
 * API seed (ingest demo scenario + trigger investigation). Failures retain
 * screenshots and traces.
 */
import { defineConfig, devices } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FRONTEND_BASE_URL =
  process.env.E2E_FRONTEND_URL ?? "http://127.0.0.1:5173";
const BACKEND_BASE_URL =
  process.env.E2E_BACKEND_URL ?? "http://127.0.0.1:8000/api/v1";
const AUTH_TOKEN = process.env.E2E_AUTH_TOKEN ?? "e2e-token";

export default defineConfig({
  testDir: path.join(__dirname, "tests"),
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  timeout: 120_000,
  expect: { timeout: 30_000 },
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  globalSetup: path.join(__dirname, "fixtures", "seed.ts"),
  outputDir: path.join(__dirname, "test-results"),
  use: {
    baseURL: FRONTEND_BASE_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    extraHTTPHeaders: {
      Authorization: `Bearer ${AUTH_TOKEN}`,
    },
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  metadata: {
    backendBaseUrl: BACKEND_BASE_URL,
    authToken: AUTH_TOKEN,
  },
});
