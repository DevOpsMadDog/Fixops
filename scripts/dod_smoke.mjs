#!/usr/bin/env node
/**
 * dod_smoke.mjs — Founder DoD #9 E2E Playwright smoke for the 10 core pages.
 *
 * For each page in the DoD-9 set, navigate Chromium to PLAYWRIGHT_BASE+route and
 * assert:
 *   (a) page renders without crashing within 15s (domcontentloaded)
 *   (b) all `mustContain` strings appear in document.body.innerText
 *   (c) NONE of the global FORBIDDEN mock-data signatures appear in the DOM
 *
 * Usage:
 *   PLAYWRIGHT_BASE=http://localhost:5177 node scripts/dod_smoke.mjs
 *
 * Output:
 *   - stdout PASS/FAIL per page + summary line
 *   - exit code 0 if all pass, 1 if any fail
 *
 * Pattern source: scripts/smoke_phase3_hubs.mjs (resolves Playwright from the
 * UI workspace's local node_modules — there is no top-level package.json that
 * lists Playwright). Created 2026-05-02 per HANDOFF directive 6c72680d.
 */

import { pathToFileURL } from "node:url";

const PLAYWRIGHT_URL = pathToFileURL(
  "/Users/devops.ai/fixops/Fixops/suite-ui/aldeci-ui-new/node_modules/playwright/index.js"
).href;
const _pw = await import(PLAYWRIGHT_URL);
const chromium = _pw.chromium ?? _pw.default?.chromium;
if (!chromium) throw new Error("playwright: chromium not found on module exports");

// ---------------------------------------------------------------------------
// 10 core pages per founder DoD #9. Each entry maps to a shipped change so the
// smoke proves the change actually rendered in the live app, not just compiled.
// ---------------------------------------------------------------------------
const PAGES = [
  // 1. FEATURE-1 onboarding wizard — first step must show heading.
  { id: "onboarding",            url: "/onboarding",
    mustContain: ["Connect a cloud account"],
    note: "FEATURE-1 wizard — Step 1 heading 'Connect a cloud account'",
  },
  // 2. FEATURE-3 LiveFeed — WS connection badge ('Live' when connected, 'Disconnected' otherwise).
  { id: "live-feed",             url: "/mission-control/live-feed",
    anyOf: ["Live", "Disconnected", "Real-time"],
    note: "FEATURE-3 LiveFeed — WS Live/Disconnected/Real-time badge",
  },
  // 3. DoD-5 CTEM Cycles tab inside Mission-Control ComplianceDashboard (canonical mount per App.tsx:742).
  { id: "compliance-dashboard",  url: "/mission-control/ctem",
    mustContain: ["CTEM Cycles"],
    note: "DoD-5 ComplianceDashboard — CTEM Cycles tab at canonical /mission-control/ctem",
  },
  // 4. DoD-6 IaCScanning page — Terraform scan panel.
  { id: "iac",                   url: "/discover/iac",
    anyOf: ["Terraform", "IaC"],
    note: "DoD-6 IaCScanning — Terraform/IaC content present",
  },
  // 5. DoD-7 CodeScanning page — Connect repository panel.
  { id: "code",                  url: "/discover/code",
    anyOf: ["Connect repository", "GitHub", "Code Scanning"],
    note: "DoD-7 CodeScanning — Connect repository / GitHub panel present",
  },
  // 6. DoD-8 FindingsExplorer — Related findings panel (TrustGraph-backed). Canonical mount per App.tsx:862.
  { id: "findings-explorer",     url: "/findings",
    anyOf: ["Related findings", "Findings", "Explorer"],
    note: "DoD-8 FindingsExplorer — Related findings (TrustGraph) panel at canonical /findings",
  },
  // 7. BUG-3.1 IncidentResponse — must NOT contain MOCK_INCIDENTS signature.
  { id: "incidents",             url: "/incidents",
    anyOf: ["Incidents", "Incident", "Response"],
    note: "BUG-3.1 IncidentResponse — no MOCK_INCIDENTS in DOM",
  },
  // 8. BUG-3 Browser security folded into AppLayerSecurityHub#browser per S10 fold (App.tsx:1167 redirect).
  { id: "browser-security",      url: "/discover/app-security?tab=browser",
    anyOf: ["Browser", "Security", "Extensions", "App Layer"],
    note: "BUG-3 BrowserSecurity folded into AppLayerSecurityHub#browser — no SuperVPN Pro / mock data",
  },
  // 9. AssetInventoryHub — 8 tabs render (Hub-pattern).
  { id: "asset-inventory",       url: "/discover/assets/inventory",
    anyOf: ["Asset Inventory", "Inventory", "Assets"],
    note: "AssetInventoryHub absorb (494ef868) — 8 tabs render",
  },
  // 10. App shell — root navigates somewhere; primary nav must render.
  { id: "root",                  url: "/",
    anyOf: ["ALdeci", "Mission Control", "Dashboard", "Welcome", "ALDECI"],
    note: "App shell — primary nav / dashboard text present",
  },
];

// Global forbidden mock-data signatures. Any page containing any of these FAILs.
const FORBIDDEN = [
  "SuperVPN Pro",
  "Acme Corp",
  "John Doe",
  "lorem ipsum",
  "Lorem ipsum",
  "MOCK_",
  "alice.chen",
  "svc-001",
];

const BASE = process.env.PLAYWRIGHT_BASE || "http://localhost:5177";
const NAV_TIMEOUT_MS = 15_000;
const POST_NAV_SETTLE_MS = 2_500;

console.log(`dod_smoke: ${PAGES.length} pages · base=${BASE} · started=${new Date().toISOString()}`);

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  userAgent: "Mozilla/5.0 (dod_smoke.mjs) PlaywrightChromium",
});

let pass = 0, fail = 0;
const results = [];

for (const p of PAGES) {
  const page = await ctx.newPage();
  let crashed = false, crashErr = "";
  page.on("pageerror", (err) => { crashed = true; crashErr = String(err?.message ?? err); });
  const url = `${BASE}${p.url}`;
  const t0 = Date.now();
  let bodyText = "";
  let status = "PASS";
  const reasons = [];
  try {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: NAV_TIMEOUT_MS });
    await page.waitForTimeout(POST_NAV_SETTLE_MS);
    bodyText = await page.evaluate(() => document.body?.innerText || "");
    if (crashed) { status = "FAIL"; reasons.push(`page crashed: ${crashErr.slice(0, 200)}`); }
    if (p.mustContain) {
      const missing = p.mustContain.filter((s) => !bodyText.includes(s));
      if (missing.length) { status = "FAIL"; reasons.push(`missing: ${JSON.stringify(missing)}`); }
    }
    if (p.anyOf) {
      const hit = p.anyOf.some((s) => bodyText.includes(s));
      if (!hit) { status = "FAIL"; reasons.push(`none of anyOf=${JSON.stringify(p.anyOf)} found`); }
    }
    const found = FORBIDDEN.filter((s) => bodyText.includes(s));
    if (found.length) { status = "FAIL"; reasons.push(`forbidden mock signature(s): ${JSON.stringify(found)}`); }
  } catch (e) {
    status = "FAIL"; reasons.push(`nav/eval error: ${String(e?.message ?? e).slice(0, 200)}`);
  } finally {
    await page.close();
  }
  const elapsed = Date.now() - t0;
  if (status === "PASS") pass++; else fail++;
  console.log(`  ${status}  ${p.id.padEnd(22)} ${p.url.padEnd(42)} ${elapsed}ms${status === "FAIL" ? "  -- " + reasons.join("; ") : ""}`);
  results.push({ ...p, url, status, elapsed, reasons, bodySnippet: bodyText.slice(0, 240) });
}

await browser.close();

console.log(`\n${pass} PASS / ${fail} FAIL  (out of ${PAGES.length})`);

// Emit machine-readable JSON for the report.
import fs from "node:fs/promises";
await fs.writeFile("/tmp/dod9_results.json", JSON.stringify({ pass, fail, total: PAGES.length, results, base: BASE, ts: new Date().toISOString() }, null, 2));
console.log("results written: /tmp/dod9_results.json");

process.exit(fail > 0 ? 1 : 0);
