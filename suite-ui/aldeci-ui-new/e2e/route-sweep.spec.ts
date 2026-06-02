/**
 * Route Sweep — NO-MOCKS / runtime-health gate.
 *
 * Visits every top-level route declared in src/App.tsx with a REAL authenticated
 * session (real token + real org seeded into localStorage), and records per route:
 *   - JS console errors (React crashes, etc.)
 *   - failed /api/v1 requests (4xx/5xx) — i.e. missing endpoints / auth gaps / wrong paths
 *
 * Writes a JSON report to /tmp/route_sweep_report.json for triage. Does NOT assert
 * pass/fail per route — it is a diagnostic sweep, not a blocking test.
 *
 * Run:
 *   FIXOPS_API_TOKEN="$(cat /tmp/scif_key.txt)" FIXOPS_ORG_ID="$(cat /tmp/scif_org.txt)" \
 *   npx playwright test route-sweep --reporter=line
 */
import { test, expect } from "@playwright/test";
import * as fs from "fs";
import * as path from "path";

const BASE = process.env.SWEEP_BASE_URL || "http://localhost:5173";
const TOKEN = process.env.FIXOPS_API_TOKEN || "";
const ORG = process.env.FIXOPS_ORG_ID || "default";
const REPORT = process.env.SWEEP_REPORT || "/tmp/route_sweep_report.json";

function extractRoutes(): string[] {
  const base = path.resolve(process.cwd(), "src");
  const set = new Set<string>();
  const add = (src: string, re: RegExp) => {
    let m: RegExpExecArray | null;
    while ((m = re.exec(src)) !== null) {
      const p = m[1];
      if (p.includes("{") || p.includes(":") || p.includes("*")) continue; // skip param/splat
      set.add(p);
    }
  };
  // App.tsx <Route path="/a/b/c"> — multi-segment static routes (skip params/splat)
  add(fs.readFileSync(path.join(base, "App.tsx"), "utf8"), /<Route\s+path="(\/[a-zA-Z0-9\-/]+)"/g);
  // config-generated routes (FindingsExplorerView + GenericDashboard): path: "/x"
  for (const cfg of ["config/findingsExplorerRoutes.ts", "config/dashboardRoutes.ts"]) {
    try { add(fs.readFileSync(path.join(base, cfg), "utf8"), /path:\s*"(\/[a-zA-Z0-9\-/]+)"/g); } catch { /* optional */ }
  }
  return [...set].sort();
}

test("route sweep — console errors + failed /api/v1 calls per route", async ({ page }) => {
  const routes = extractRoutes();
  test.setTimeout(routes.length * 12000 + 60000);

  // Seed real auth + org before any app code runs.
  await page.addInitScript(
    ([tok, org]) => {
      localStorage.setItem("aldeci.authToken", tok);
      localStorage.setItem("aldeci.orgId", org);
      localStorage.setItem("aldeci.authStrategy", "api_key");
    },
    [TOKEN, ORG],
  );

  const report: Record<string, { consoleErrors: string[]; failedApi: string[]; crash?: string }> = {};

  for (const route of routes) {
    const consoleErrors: string[] = [];
    const failedApi: string[] = [];

    const onConsole = (msg: import("@playwright/test").ConsoleMessage) => {
      if (msg.type() === "error") consoleErrors.push(msg.text().slice(0, 300));
    };
    const onResponse = (resp: import("@playwright/test").Response) => {
      const u = resp.url();
      if (u.includes("/api/v1/") && resp.status() >= 400) {
        failedApi.push(`${resp.status()} ${u.replace(BASE, "").split("?")[0]}`);
      }
    };
    page.on("console", onConsole);
    page.on("response", onResponse);

    try {
      await page.goto(`${BASE}${route}`, { waitUntil: "domcontentloaded", timeout: 12000 });
      await page.waitForTimeout(1200); // let mount fetches fire
    } catch (e) {
      consoleErrors.push(`NAV_ERROR: ${String(e).slice(0, 200)}`);
    }

    // Throttle: keep total request rate under the backend's READ rate limit
    // (~200/min) AND avoid overwhelming a single-instance backend. Do NOT disable
    // the rate limiter for this sweep — RL-off lets the flood DoS the backend into
    // 500s/connection-failures (false positives); RL-on without this delay just
    // 429-masks. SWEEP_ROUTE_DELAY_MS tunes inter-route pacing (default 2500ms).
    await page.waitForTimeout(Number(process.env.SWEEP_ROUTE_DELAY_MS || 2500));

    // Capture render-state crashes the network/console miss: error-boundary fallback
    // and SPA 404 (both render 200 + index.html, so they only show in the DOM).
    let crash: string | undefined;
    try {
      const txt = (await page.evaluate(() => document.body.innerText || "")).slice(0, 5000);
      if (txt.includes("Page not found")) crash = "404_PAGE_NOT_FOUND";
      else if (txt.includes("Something went wrong") || txt.includes("error boundary")) crash = "ERROR_BOUNDARY";
    } catch { /* page closed */ }

    page.off("console", onConsole);
    page.off("response", onResponse);

    // de-dupe
    const uniq = (a: string[]) => [...new Set(a)];
    if (consoleErrors.length || failedApi.length || crash) {
      report[route] = { consoleErrors: uniq(consoleErrors), failedApi: uniq(failedApi), ...(crash ? { crash } : {}) };
    }
    // Write incrementally so a suite timeout still leaves a usable report.
    fs.writeFileSync(REPORT, JSON.stringify(report, null, 2));
  }

  fs.writeFileSync(REPORT, JSON.stringify(report, null, 2));
  const dirty = Object.keys(report).length;
  console.log(`\n═══ ROUTE SWEEP: ${routes.length} routes, ${dirty} with issues ═══`);
  console.log(`Report: ${REPORT}`);
  for (const [r, info] of Object.entries(report)) {
    console.log(`\n• ${r}`);
    info.consoleErrors.forEach((e) => console.log(`   ERR  ${e}`));
    info.failedApi.forEach((e) => console.log(`   API  ${e}`));
  }
  // Always pass — diagnostic only. Token must be present though.
  expect(TOKEN.length).toBeGreaterThan(10);
});
