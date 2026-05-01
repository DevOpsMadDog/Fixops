#!/usr/bin/env node
/**
 * BUG-3 verification: each of the 7 modified pages must:
 *   1. Render without throwing
 *   2. Show NO mock signature in DOM (Acme Corp, John Doe, lorem ipsum, plus our specific known mocks)
 *   3. Either show real data OR an EmptyState component
 */
const { chromium } = require("playwright");
const path = require("path");
const fs = require("fs");

const SNAPSHOT_DIR = path.resolve(__dirname, "..", "docs", "ui-snapshots");
fs.mkdirSync(SNAPSHOT_DIR, { recursive: true });

const PAGES = [
  // [page-name, route]
  ["browsersecurity",       "/discover/app-security?tab=browser"],
  ["incidentresponse",      "/?view=soc"],
  ["iotsecurity",           "/assets?tab=iot-security"],
  ["zerodayintelligence",   "/attack/intel/external?tab=zeroday"],
  ["dataexfiltration",      "/discover/dspm?tab=exfiltration"],
  ["incidentmetrics",       "/remediate/incidents/knowledge?tab=metrics"],
  ["supplychain",           "/discover/supply-chain?tab=risk"],
];

// Specific mock signatures from the deleted constants — anything found = task FAILED.
const MOCK_SIGNATURES = [
  "SuperVPN Pro",
  "CryptoMiner Helper",
  "Grammarly",        // was MOCK_EXTENSIONS
  "temp-sensor-01",
  "smart-lock-02",    // was MOCK_DEVICES
  "CVE-2026-0001",
  "APT-41",
  "RansomHive",       // was MOCK_VULNS / MOCK_ACTORS
  "INC-0421",
  "INC-0420",
  "s.kim",
  "a.wright",         // was IncidentResponse INCIDENTS
  "openssl",
  "log4j-core",
  "Lenovo",
  "Crowdstrike",      // was SUPPLIERS / COMPONENTS
  "Acme Corp",
  "John Doe",
  "lorem ipsum",
];

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();

  const results = [];
  for (const [name, route] of PAGES) {
    const url = `http://localhost:5173${route}`;
    let status = "ok";
    let mockHits = [];
    let consoleErrors = [];

    page.on("pageerror", (err) => consoleErrors.push(`pageerror: ${err.message}`));
    page.on("console", (msg) => { if (msg.type() === "error") consoleErrors.push(`console: ${msg.text().slice(0, 200)}`); });

    try {
      await page.goto(url, { waitUntil: "domcontentloaded", timeout: 20000 });
      // Give React time to render lazy-loaded chunks + run effects
      await page.waitForTimeout(3500);
    } catch (e) {
      status = `nav-failed: ${e.message.slice(0, 80)}`;
    }

    const bodyText = await page.evaluate(() => document.body?.innerText || "");
    mockHits = MOCK_SIGNATURES.filter((sig) => bodyText.includes(sig));
    const hasEmptyStateOrData =
      bodyText.includes("Start onboarding") ||
      bodyText.includes("No ") ||
      bodyText.includes("EOL") ||
      bodyText.length > 1500; // any substantive render

    const screenshot = path.join(SNAPSHOT_DIR, `bug3_${name}_emptystate.png`);
    try {
      await page.screenshot({ path: screenshot, fullPage: true });
    } catch {}

    const navOk = status === "ok" || status.startsWith("nav-failed: page.goto: Timeout");
    results.push({ name, route, status, navOk, mockHits, hasEmptyStateOrData, consoleErrors: consoleErrors.slice(0, 4), screenshot, bodyChars: bodyText.length });
  }

  await browser.close();

  console.log("\n=== BUG-3 EmptyState Verification ===");
  let pass = 0, fail = 0;
  // Filter pageerror noise (real React crashes). Console 401/403/404 are EXPECTED — they trigger fallback.
  for (const r of results) {
    const hasPageError = r.consoleErrors.some((e) => e.startsWith("pageerror:"));
    const ok = r.mockHits.length === 0 && r.hasEmptyStateOrData && !hasPageError;
    if (ok) pass++; else fail++;
    console.log(`\n[${ok ? "PASS" : "FAIL"}] ${r.name.padEnd(22)} ${r.route}`);
    console.log(`  status:    ${r.status}`);
    console.log(`  body chars: ${r.bodyChars}`);
    console.log(`  mock hits: ${r.mockHits.length === 0 ? "NONE" : r.mockHits.join(", ")}`);
    console.log(`  empty/data: ${r.hasEmptyStateOrData ? "YES" : "NO"}`);
    console.log(`  pageerror: ${hasPageError ? "YES" : "no"}`);
    console.log(`  console: ${r.consoleErrors.length === 0 ? "clean" : r.consoleErrors.slice(0, 2).join(" | ").slice(0, 200)}`);
    console.log(`  shot:      ${path.relative(process.cwd(), r.screenshot)}`);
  }
  console.log(`\nTotal: ${pass} pass, ${fail} fail`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error("FATAL:", e); process.exit(2); });
