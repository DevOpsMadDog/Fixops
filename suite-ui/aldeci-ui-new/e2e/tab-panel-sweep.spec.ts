/**
 * Tab-Panel Sweep — NO-MOCKS / runtime-health gate for NON-DEFAULT tabs.
 *
 * route-sweep.spec.ts only loads each route's DEFAULT tab, so a broken
 * non-default tab panel (404 on mount, crash, console error) is invisible to it.
 * This sweep visits every hub route, clicks EACH [role="tab"] in turn, and
 * records per (route, tab): failed /api/v1 calls (4xx/5xx) + JS console errors.
 *
 * It discovers hub routes dynamically from src/App.tsx (<Route path> entries that
 * render a *Hub component) so it stays in sync as hubs are added/removed.
 *
 * Writes JSON to /tmp/tab_panel_sweep_report.json. Diagnostic (no per-tab assert).
 *
 * Run:
 *   FIXOPS_API_TOKEN="$(cat /tmp/scif_key.txt)" FIXOPS_ORG_ID="$(cat /tmp/scif_org.txt)" \
 *   npx playwright test tab-panel-sweep --reporter=line
 */
import { test } from "@playwright/test";
import * as fs from "fs";
import * as path from "path";

const BASE = process.env.SWEEP_BASE_URL || "http://localhost:5173";
const TOKEN = process.env.FIXOPS_API_TOKEN || "";
const ORG = process.env.FIXOPS_ORG_ID || "default";
const REPORT = process.env.TAB_SWEEP_REPORT || "/tmp/tab_panel_sweep_report.json";

/** Static <Route path="/x"> entries in App.tsx whose element is a *Hub component. */
function hubRoutes(): string[] {
  const appTsx = fs.readFileSync(path.resolve(process.cwd(), "src", "App.tsx"), "utf8");
  const set = new Set<string>();
  // <Route path="/x/y" element={<SomethingHub ...} />  (single line)
  const re = /<Route\s+path="(\/[a-zA-Z0-9\-/]+)"\s+element=\{<([A-Za-z0-9]+)\s*\/?>?\s*\}?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(appTsx)) !== null) {
    const [, p, comp] = m;
    if (p.includes(":") || p.includes("*")) continue;
    if (/Hub$/.test(comp)) set.add(p);
  }
  return [...set].sort();
}

test("tab-panel sweep — failed /api + console errors per non-default tab", async ({ page }) => {
  const routes = hubRoutes();
  // Each route: ~3 tabs x (click + 1.2s settle + 1.5s pace) ≈ 8s; + nav.
  test.setTimeout(routes.length * 30000 + 60000);

  await page.addInitScript(
    ([tok, org]) => {
      localStorage.setItem("aldeci.authToken", tok);
      localStorage.setItem("aldeci.orgId", org);
      localStorage.setItem("aldeci.authStrategy", "api_key");
    },
    [TOKEN, ORG],
  );

  const report: Record<string, { tab: string; failedApi: string[]; consoleErrors: string[] }[]> = {};
  let totalTabs = 0;

  for (const route of routes) {
    try {
      await page.goto(`${BASE}${route}`, { waitUntil: "domcontentloaded", timeout: 12000 });
      await page.waitForTimeout(1000);
    } catch (e) {
      report[route] = [{ tab: "<nav>", failedApi: [`NAV_ERROR ${String(e).slice(0, 120)}`], consoleErrors: [] }];
      continue;
    }

    const tabCount = await page.locator('[role="tab"]').count();
    if (tabCount === 0) continue;

    const routeIssues: { tab: string; failedApi: string[]; consoleErrors: string[] }[] = [];

    for (let i = 0; i < tabCount; i++) {
      const failedApi: string[] = [];
      const consoleErrors: string[] = [];
      const onConsole = (msg: import("@playwright/test").ConsoleMessage) => {
        if (msg.type() === "error") consoleErrors.push(msg.text().slice(0, 200));
      };
      const onResponse = (resp: import("@playwright/test").Response) => {
        const u = resp.url();
        if (u.includes("/api/v1/") && resp.status() >= 400) {
          failedApi.push(`${resp.status()} ${u.replace(BASE, "").split("?")[0]}`);
        }
      };
      page.on("console", onConsole);
      page.on("response", onResponse);

      const tab = page.locator('[role="tab"]').nth(i);
      const label = (await tab.textContent().catch(() => `tab${i}`))?.trim().slice(0, 40) || `tab${i}`;
      try {
        await tab.click({ timeout: 5000 });
        await page.waitForTimeout(1200); // let the panel's mount fetches fire
      } catch (e) {
        consoleErrors.push(`CLICK_ERROR ${String(e).slice(0, 120)}`);
      }
      // Pace under the backend read rate-limit.
      await page.waitForTimeout(Number(process.env.SWEEP_TAB_DELAY_MS || 1500));

      page.off("console", onConsole);
      page.off("response", onResponse);
      totalTabs++;

      const uniq = (a: string[]) => [...new Set(a)];
      if (failedApi.length || consoleErrors.length) {
        routeIssues.push({ tab: label, failedApi: uniq(failedApi), consoleErrors: uniq(consoleErrors) });
      }
    }

    if (routeIssues.length) report[route] = routeIssues;
    fs.writeFileSync(REPORT, JSON.stringify(report, null, 2)); // incremental
  }

  fs.writeFileSync(REPORT, JSON.stringify(report, null, 2));
  const dirtyRoutes = Object.keys(report).length;
  console.log(`\n═══ TAB-PANEL SWEEP: ${routes.length} hubs, ${totalTabs} tabs clicked, ${dirtyRoutes} hubs with issues ═══`);
  console.log(`Report: ${REPORT}`);
  for (const [r, issues] of Object.entries(report)) {
    console.log(`\n• ${r}`);
    for (const it of issues) {
      it.failedApi.forEach((e) => console.log(`   [${it.tab}] API  ${e}`));
      it.consoleErrors.forEach((e) => console.log(`   [${it.tab}] ERR  ${e}`));
    }
  }
});
