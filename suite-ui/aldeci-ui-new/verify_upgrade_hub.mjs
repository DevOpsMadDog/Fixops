// Playwright verification for /remediate/upgrade hub (S21 fold, 2026-05-02)
import { chromium } from "playwright";
import fs from "node:fs";

const URL = "http://localhost:5173/remediate/upgrade";
const SCREENSHOT_PATH = "/Users/devops.ai/fixops/Fixops/docs/ui-snapshots/ux-consolidation-upgrade-paths-2026-05-02T1200.png";

const apiCalls = [];
const consoleErrors = [];

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  // Seed the auth token + org id the SPA expects so apiFetch() does not bail.
  storageState: undefined,
});
const page = await ctx.newPage();

await page.addInitScript(() => {
  try {
    window.localStorage.setItem("aldeci_api_key", "demo-key");
    window.localStorage.setItem("aldeci_org_id", "default");
  } catch (_) {}
});

page.on("request", (req) => {
  const u = req.url();
  if (u.includes("/api/v1/")) apiCalls.push(`${req.method()} ${u}`);
});
page.on("console", (msg) => {
  if (msg.type() === "error") consoleErrors.push(msg.text());
});
page.on("pageerror", (e) => consoleErrors.push(`pageerror: ${e.message}`));

const resp = await page.goto(URL, { waitUntil: "networkidle", timeout: 20000 });
const status = resp ? resp.status() : 0;

// Cycle through tabs to confirm each tab renders and fires its own API calls.
const tabs = ["resolver", "explorer", "version-graph", "dep-map", "binary-fp", "dep-risk"];
for (const t of tabs) {
  await page.goto(`${URL}?tab=${t}`, { waitUntil: "networkidle", timeout: 15000 });
  await page.waitForTimeout(500);
}

// Final landing screenshot on the dep-map tab (most data-rich).
await page.goto(`${URL}?tab=dep-map`, { waitUntil: "networkidle", timeout: 15000 });
await page.waitForTimeout(800);
await page.screenshot({ path: SCREENSHOT_PATH, fullPage: true });

const domText = await page.evaluate(() => document.body.innerText);
const mockSignatures = ["MOCK_", "lorem ipsum", "Acme Corp", "John Doe", "demo-org"];
const mockHits = mockSignatures.filter((s) => domText.toLowerCase().includes(s.toLowerCase()));

const summary = {
  url: URL,
  status,
  tabs_visited: tabs,
  api_calls_count: apiCalls.length,
  api_calls_unique: [...new Set(apiCalls)],
  mock_signatures_found: mockHits,
  console_errors: consoleErrors.slice(0, 10),
  screenshot: SCREENSHOT_PATH,
};
console.log(JSON.stringify(summary, null, 2));
fs.writeFileSync("/tmp/upgrade_hub_verify.json", JSON.stringify(summary, null, 2));

await browser.close();
