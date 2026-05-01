// Playwright verification v2 for /remediate/upgrade hub (S21 fold, 2026-05-02)
// Uses domcontentloaded + waitForSelector instead of networkidle (SPA polls forever).
import { chromium } from "playwright";
import fs from "node:fs";

const URL = "http://localhost:5173/remediate/upgrade";
const SCREENSHOT_PATH = "/Users/devops.ai/fixops/Fixops/docs/ui-snapshots/ux-consolidation-upgrade-paths-hub-2026-05-02.png";

const apiCalls = [];
const consoleErrors = [];

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
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

const resp = await page.goto(URL, { waitUntil: "domcontentloaded", timeout: 15000 });
const status = resp ? resp.status() : 0;

// Wait for the unified hero heading instead of networkidle.
await page.waitForSelector("text=Upgrade Paths", { timeout: 8000 });

// Cycle each tab via ?tab= query (the hub syncs internal state from the param).
const tabs = ["resolver", "explorer", "version-graph", "dep-map", "binary-fp", "dep-risk"];
const tabApiCounts = {};
for (const t of tabs) {
  const before = apiCalls.length;
  await page.goto(`${URL}?tab=${t}`, { waitUntil: "domcontentloaded", timeout: 12000 });
  await page.waitForSelector("text=Upgrade Paths", { timeout: 8000 });
  // Give the lazy-imported tab pane a chance to mount + fire its initial fetch.
  await page.waitForTimeout(2500);
  tabApiCounts[t] = apiCalls.length - before;
}

// Final landing screenshot on the dep-map tab (most data-rich, real API).
await page.goto(`${URL}?tab=dep-map`, { waitUntil: "domcontentloaded", timeout: 12000 });
await page.waitForSelector("text=Upgrade Paths", { timeout: 8000 });
await page.waitForTimeout(2500);
await page.screenshot({ path: SCREENSHOT_PATH, fullPage: true });

const domText = await page.evaluate(() => document.body.innerText);
const lowerText = domText.toLowerCase();
const mockSignatures = ["mock_", "lorem ipsum", "acme corp", "john doe", "demo-org", "svc-001", "svc-002", "alice.chen", "bob.martinez"];
const mockHits = mockSignatures.filter((s) => lowerText.includes(s));

const summary = {
  url: URL,
  status,
  heading_found: domText.includes("Upgrade Paths"),
  tabs_visited: tabs,
  tab_api_call_counts: tabApiCounts,
  api_calls_total: apiCalls.length,
  api_calls_unique: [...new Set(apiCalls)],
  mock_signatures_found: mockHits,
  console_errors: consoleErrors.slice(0, 10),
  screenshot: SCREENSHOT_PATH,
};
console.log(JSON.stringify(summary, null, 2));
fs.writeFileSync("/tmp/upgrade_hub_verify_v2.json", JSON.stringify(summary, null, 2));

await browser.close();
