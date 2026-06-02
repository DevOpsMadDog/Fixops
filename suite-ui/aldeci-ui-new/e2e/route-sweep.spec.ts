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
  const appPath = path.resolve(process.cwd(), "src/App.tsx");
  const src = fs.readFileSync(appPath, "utf8");
  const set = new Set<string>();
  // top-level single-segment routes: path="/foo" (skip params, redirects handled by app)
  const re = /path="(\/[a-z0-9-]+)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) set.add(m[1]);
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

  const report: Record<string, { consoleErrors: string[]; failedApi: string[] }> = {};

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

    page.off("console", onConsole);
    page.off("response", onResponse);

    // de-dupe
    const uniq = (a: string[]) => [...new Set(a)];
    if (consoleErrors.length || failedApi.length) {
      report[route] = { consoleErrors: uniq(consoleErrors), failedApi: uniq(failedApi) };
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
