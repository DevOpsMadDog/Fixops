import { defineConfig, devices } from "@playwright/test";

/**
 * ALdeci E2E Test Configuration
 *
 * Simulates on-prem customer deployment against a running backend (port 8000)
 * and frontend (port 5173). Uses real API data — no mocks.
 *
 * Reporters:
 *  - list: console output
 *  - html: built-in Playwright HTML report
 *  - allure-playwright: enterprise Allure reports (install: npm i -D allure-playwright)
 */
export default defineConfig({
  testDir: "./e2e",
  globalSetup: "./e2e/global-setup.ts",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: [
    ["list"],
    ["html", { open: "never" }],
    ["allure-playwright", { outputFolder: "allure-results", suiteTitle: "ALdeci CTEM+ E2E" }],
  ],
  timeout: 45_000,
  globalTimeout: 600_000,
  expect: { timeout: 15_000 },
  use: {
    baseURL: "http://localhost:5173",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: [
    {
      command: "cd ../.. && source .venv/bin/activate 2>/dev/null; OTEL_SDK_DISABLED=true python -m uvicorn apps.api.app:create_app --factory --port 8000",
      url: "http://localhost:8000/health",
      reuseExistingServer: true,
      timeout: 60_000,
    },
    {
      command: "npx vite --port 5173",
      url: "http://localhost:5173",
      reuseExistingServer: true,
      timeout: 30_000,
    },
  ],
});
