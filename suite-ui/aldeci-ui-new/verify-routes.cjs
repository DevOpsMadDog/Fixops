#!/usr/bin/env node
/**
 * verify-routes.cjs
 *
 * Visual + behavioral verification that protected dashboard routes actually
 * render their own page (and call their own API endpoint), rather than
 * silently falling back to CommandDashboard or the index.html shell.
 *
 * Why this exists: a 2026-04-23 Playwright probe observed every dashboard
 * returning the same 1419-byte body. Root cause was twofold:
 *   1) The probe was reading the Vite index.html shell BEFORE hydration —
 *      every SPA route returns the same skeleton HTML.
 *   2) Even after hydration, RequireAuth would Navigate to /login if the
 *      hardcoded demo API key was missing/cleared, leaving deep-link
 *      browsing (and Playwright runs without a real session) broken.
 *
 * Fix: lib/auth.tsx now exports `isDevBypassActive()` which is true when
 * either Vite dev mode is active OR localStorage.FIXOPS_VISUAL_VERIFY === '1'.
 * This script flips the flag via `addInitScript`, so RequireAuth treats every
 * route as authenticated and the page hydrates normally.
 *
 * Exit code: 0 on success, 1 on any failure.
 */

const { chromium } = require("playwright");
const fs = require("fs");
const path = require("path");

const BASE_URL = process.env.BASE_URL || "http://localhost:5173";
const SNAPSHOT_DIR = path.resolve(
  __dirname,
  "..",
  "..",
  "docs",
  "ui-snapshots",
);
const HYDRATION_TIMEOUT = 15_000;

// Routes under test — each maps to a unique page-specific endpoint that the
// dashboard MUST hit. If the page silently falls back to CommandDashboard,
// the dashboard endpoint will not appear in the request log.
const ROUTES = [
  {
    path: "/security-findings",
    expectedHeadingExcludes: ["Command Dashboard", "Mission Control"],
    apiContains: "/api/v1/security-findings",
  },
  {
    path: "/violation-lifecycle",
    expectedHeadingExcludes: ["Command Dashboard", "Mission Control"],
    // Backend endpoint is /findings/lifecycle/* (the page is the
    // "violation lifecycle" UI for findings).
    apiContains: "/api/v1/findings/lifecycle",
  },
  {
    path: "/dca",
    expectedHeadingExcludes: ["Command Dashboard", "Mission Control"],
    // /dca is intentionally not registered in App.tsx — verifies that
    // unknown routes correctly fall through to NotFound (NOT CommandDashboard).
    apiContains: null,
    expectNotFound: true,
  },
  {
    path: "/agentless-snapshot",
    expectedHeadingExcludes: ["Command Dashboard", "Mission Control"],
    apiContains: "/api/v1/agentless-snapshot",
  },
  {
    path: "/dynamic-rule-dsl",
    expectedHeadingExcludes: ["Command Dashboard", "Mission Control"],
    // Backend exposes the DSL under /rules/dsl/* (rules engine sub-tree).
    apiContains: "/api/v1/rules/dsl",
  },
];

function ensureSnapshotDir() {
  if (!fs.existsSync(SNAPSHOT_DIR)) {
    fs.mkdirSync(SNAPSHOT_DIR, { recursive: true });
  }
}

async function verifyRoute(browser, route) {
  const result = {
    path: route.path,
    heading: null,
    apiFired: false,
    devBadgeVisible: false,
    apiUrlsLogged: [],
    pass: false,
    reason: null,
  };

  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
  });

  // Flip the visual-verify bypass BEFORE any page script runs.
  await context.addInitScript(() => {
    try {
      window.localStorage.setItem("FIXOPS_VISUAL_VERIFY", "1");
      // Pin org so dashboards see real data when backend is reachable.
      window.localStorage.setItem("aldeci.orgId", "juice-shop-corp");
    } catch (_) {
      /* no-op */
    }
  });

  const page = await context.newPage();

  // Capture every outbound /api/v1 request for assertion.
  page.on("request", (req) => {
    const url = req.url();
    if (url.includes("/api/v1/")) {
      result.apiUrlsLogged.push(url);
      if (route.apiContains && url.includes(route.apiContains)) {
        result.apiFired = true;
      }
    }
  });

  try {
    // Use `domcontentloaded` rather than `networkidle` — several dashboards
    // long-poll their backend (LIVE badges) and never hit network idle within
    // any reasonable budget. We instead wait a fixed beat for the lazy chunk
    // to import, hydrate, and fire its first render-time fetch.
    await page.goto(`${BASE_URL}${route.path}`, {
      waitUntil: "domcontentloaded",
      timeout: HYDRATION_TIMEOUT,
    });

    // Give React time to hydrate, run useEffect, and fire the first API call.
    await page.waitForTimeout(2500);

    // Collect what's actually on the page after hydration.
    const heading = await page
      .locator("h1, h2")
      .first()
      .textContent({ timeout: 5_000 })
      .catch(() => null);
    result.heading = heading?.trim() ?? null;

    result.devBadgeVisible = await page
      .locator("[data-testid='dev-bypass-badge']")
      .isVisible()
      .catch(() => false);

    // Save screenshot regardless of pass/fail.
    const safe = route.path.replace(/[^a-z0-9]/gi, "_").replace(/^_|_$/g, "");
    const screenshot = path.join(SNAPSHOT_DIR, `route-${safe}.png`);
    await page.screenshot({ path: screenshot, fullPage: false });

    // Decide pass/fail.
    if (route.expectNotFound) {
      // /dca should land on NotFound — not CommandDashboard.
      const bodyText = (await page.textContent("body")) ?? "";
      const looksLikeNotFound =
        /not found|404|page not found/i.test(bodyText) ||
        result.heading?.toLowerCase().includes("not found");
      const looksLikeCommandDash =
        bodyText.includes("Command Dashboard") &&
        !bodyText.toLowerCase().includes("not found");
      if (looksLikeNotFound && !looksLikeCommandDash) {
        result.pass = true;
      } else {
        result.reason = `expected NotFound, heading="${result.heading}"`;
      }
    } else {
      const headingOk =
        result.heading &&
        !route.expectedHeadingExcludes.some((bad) =>
          result.heading.toLowerCase().includes(bad.toLowerCase()),
        );
      if (!headingOk) {
        result.reason = `heading "${result.heading}" looks like CommandDashboard fallback`;
      } else if (route.apiContains && !result.apiFired) {
        result.reason = `expected API call to ${route.apiContains} never fired (only saw: ${result.apiUrlsLogged.slice(0, 5).join(", ") || "none"})`;
      } else {
        result.pass = true;
      }
    }
  } catch (err) {
    result.reason = `navigation/assertion error: ${err.message}`;
  } finally {
    await context.close();
  }

  return result;
}

(async () => {
  ensureSnapshotDir();
  console.log(`→ Verifying ${ROUTES.length} routes against ${BASE_URL}`);
  console.log(`→ Snapshots: ${SNAPSHOT_DIR}\n`);

  const browser = await chromium.launch({ headless: true });
  const results = [];
  for (const route of ROUTES) {
    const r = await verifyRoute(browser, route);
    results.push(r);
    const status = r.pass ? "PASS" : "FAIL";
    const apiNote = r.apiUrlsLogged.length
      ? `${r.apiUrlsLogged.length} api calls`
      : "no api calls";
    console.log(
      `${status.padEnd(4)}  ${r.path.padEnd(28)}  h1=${JSON.stringify(r.heading)}  badge=${r.devBadgeVisible}  ${apiNote}`,
    );
    if (!r.pass) {
      console.log(`        reason: ${r.reason}`);
      if (r.apiUrlsLogged.length) {
        console.log(`        api urls observed:`);
        for (const u of r.apiUrlsLogged.slice(0, 8)) {
          console.log(`          - ${u.replace(BASE_URL, "")}`);
        }
      }
    }
  }
  await browser.close();

  const passed = results.filter((r) => r.pass).length;
  const total = results.length;
  console.log(`\n→ ${passed}/${total} routes verified.`);

  // Persist a JSON report alongside the screenshots.
  const reportPath = path.join(SNAPSHOT_DIR, "verify-routes-report.json");
  fs.writeFileSync(
    reportPath,
    JSON.stringify({ baseUrl: BASE_URL, generatedAt: new Date().toISOString(), passed, total, results }, null, 2),
  );
  console.log(`→ Report: ${reportPath}`);

  process.exit(passed === total ? 0 : 1);
})();
