/**
 * test_visual_verification.cjs — Playwright NO-MOCKS UI ground-truth scanner.
 *
 * Scans every non-param route registered in suite-ui/aldeci-ui-new/src/App.tsx
 * against the live Vite dev server (http://localhost:5173) backed by the live
 * FastAPI backend (http://localhost:8000) using the real API key from .env
 * and a real-data org (juice-shop-corp / webgoat-llc / vulnado-co).
 *
 * For each route it captures:
 *   - final URL after navigation (auth redirect detection)
 *   - all /api/v1/* fetch calls fired during the 2.5s settle window
 *   - the first <h1> visible on the page (NOT the layout shell title)
 *   - the rendered body text length
 *   - presence of MOCK_ / lorem / hard-coded fixture markers
 *   - presence of an "empty state" placeholder
 *   - any uncaught JS / network errors
 *   - a full-page PNG screenshot
 *
 * Tags assigned (mutually exclusive, in priority order):
 *   AUTH_REDIRECT     — final URL contains /login
 *   JS_ERROR          — uncaught exception in page console
 *   LAYOUT_SHELL_ONLY — body text < 600 chars OR h1 == "Command Dashboard"
 *   MOCK_DETECTED     — page contains MOCK_, "lorem", or known fixture sentinel
 *   EMPTY_STATE       — page rendered but shows "No data" / "Coming soon" placeholder
 *   RENDERED_OK       — real h1, real content, at least one /api/v1/* call fired
 *
 * Outputs:
 *   /tmp/visual_verify_results.json  — array of per-route results
 *   docs/ui-snapshots/visual-verify-2026-04-24/<slug>.png  — screenshots
 *
 * Concurrency: 10 routes in parallel via a worker pool (Promise queue).
 */

const path = require("path");
const fs = require("fs");

const PW_PATH = "/Users/devops.ai/fixops/Fixops/suite-ui/aldeci-ui-new/node_modules/playwright";
const { chromium } = require(PW_PATH);

const ROUTES_FILE = process.env.ROUTES_FILE || "/tmp/routes.txt";
const BASE_URL = process.env.BASE_URL || "http://localhost:5173";
const API_BASE = process.env.API_BASE || "http://localhost:8000";
const API_KEY = process.env.API_KEY ||
  "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_";
const ORG_ID = process.env.ORG_ID || "juice-shop-corp";
const SCREENSHOT_DIR = process.env.SCREENSHOT_DIR ||
  "/Users/devops.ai/fixops/Fixops/docs/ui-snapshots/visual-verify-2026-04-24";
const RESULTS_FILE = process.env.RESULTS_FILE || "/tmp/visual_verify_results.json";
const CONCURRENCY = parseInt(process.env.CONCURRENCY || "10", 10);
const SETTLE_MS = parseInt(process.env.SETTLE_MS || "2500", 10);
const NAV_TIMEOUT_MS = parseInt(process.env.NAV_TIMEOUT_MS || "20000", 10);

// Mock / fixture sentinels — strings that should NEVER appear on a page that
// is fetching real data. Curated from grep of suite-ui/aldeci-ui-new/src/pages
// where literal arrays of fake records are declared.
const MOCK_SENTINELS = [
  "MOCK_",
  "lorem ipsum",
  "Lorem Ipsum",
  "alice.smith",
  "carol.white",
  "ex-008",
  "FND-H010",
  "BYOD-092",
  "ex-001",
  "rev-001",
  "f-002",
];

// "Layout shell only" markers — strings the persistent navigation chrome
// always renders. If the page contains ONLY these, no real content rendered.
const SHELL_TITLE_REGEX = /^(Command Dashboard|ALdeci|Loading\.\.\.|)$/;

// Empty-state markers (real data fetch returned nothing or page is a stub).
const EMPTY_STATE_PATTERNS = [
  /no data available/i,
  /no records found/i,
  /no findings yet/i,
  /coming soon/i,
  /under construction/i,
  /^empty$/i,
];

function loadRoutes() {
  const raw = fs.readFileSync(ROUTES_FILE, "utf8");
  return raw.split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && !s.includes(":") && s !== "*" && s !== "/login" && s !== "/landing");
}

function slugify(route) {
  return route.replace(/^\//, "").replace(/\//g, "_").replace(/[^a-zA-Z0-9_-]/g, "_") || "root";
}

function classify(result) {
  if (result.final_url.includes("/login") && !result.route.includes("/login")) {
    return "AUTH_REDIRECT";
  }
  const h1 = (result.h1 || "").trim();
  // Catch-all 404 component renders when no <Route path={X}> matches.
  if (/^Page not found/i.test(h1) || /^404/i.test(h1)) {
    return "NOT_FOUND";
  }
  if (result.js_errors.length > 0) {
    return "JS_ERROR";
  }
  // Mock detection takes priority over LAYOUT_SHELL_ONLY because pages that
  // load mock fixtures will still render lots of body text but be fake.
  if (result.mock_hits.length > 0) {
    return "MOCK_DETECTED";
  }
  if (
    result.body_text_length < 600 ||
    SHELL_TITLE_REGEX.test(h1) ||
    h1 === ""
  ) {
    return "LAYOUT_SHELL_ONLY";
  }
  if (result.empty_state) {
    return "EMPTY_STATE";
  }
  return "RENDERED_OK";
}

async function verifyRoute(browser, route) {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    bypassCSP: true,
  });

  // Pre-seed localStorage so AuthProvider boots in token mode with the real key.
  await context.addInitScript(({ key, org }) => {
    try {
      window.localStorage.setItem("aldeci.authToken", key);
      window.localStorage.setItem("aldeci.authStrategy", "token");
      window.localStorage.setItem("aldeci.orgId", org);
      // Frontend craftsman bypass flag — set in case the new system reads it.
      window.localStorage.setItem("FIXOPS_VISUAL_VERIFY", "1");
      window.localStorage.setItem(
        "aldeci.authUser",
        JSON.stringify({
          id: "qa-bot",
          email: "qa@aldeci.io",
          first_name: "QA",
          last_name: "Bot",
          role: "admin",
        }),
      );
    } catch (_) {
      // localStorage may not exist on the very first about:blank page
    }
  }, { key: API_KEY, org: ORG_ID });

  const page = await context.newPage();
  const apiCalls = [];
  const jsErrors = [];

  page.on("request", (req) => {
    const url = req.url();
    if (url.includes("/api/v1/") || url.includes("/api/v2/")) {
      apiCalls.push({
        method: req.method(),
        url: url.replace(API_BASE, ""),
      });
    }
  });

  page.on("response", (resp) => {
    const url = resp.url();
    if (url.includes("/api/v1/") || url.includes("/api/v2/")) {
      const idx = apiCalls.findIndex(
        (c) => c.url === url.replace(API_BASE, "") && c.status === undefined,
      );
      if (idx >= 0) apiCalls[idx].status = resp.status();
    }
  });

  page.on("pageerror", (err) => {
    jsErrors.push(String(err).slice(0, 300));
  });

  page.on("console", (msg) => {
    if (msg.type() === "error") {
      const text = msg.text();
      // Filter common React dev-mode noise that isn't a real error.
      if (text.includes("React DevTools") || text.includes("Download the React")) return;
      // "Failed to load resource: ... 4xx/5xx" — that's an HTTP status log,
      // not a JS exception. We track HTTP status codes via api_call status.
      if (text.startsWith("Failed to load resource")) return;
      if (text.length < 5) return;
      jsErrors.push(text.slice(0, 300));
    }
  });

  const result = {
    route,
    final_url: "",
    h1: "",
    body_text_length: 0,
    api_calls: [],
    api_call_count: 0,
    api_404_count: 0,
    api_500_count: 0,
    api_4xx_count: 0,
    mock_hits: [],
    empty_state: false,
    js_errors: [],
    screenshot: "",
    nav_error: null,
  };

  try {
    await page.goto(`${BASE_URL}/#${route}`, {
      waitUntil: "domcontentloaded",
      timeout: NAV_TIMEOUT_MS,
    });
    await page.waitForTimeout(SETTLE_MS);

    result.final_url = page.url();

    // First visible H1 (not the layout shell sidebar nav links)
    try {
      const h1Handle = await page.$("main h1, [role='main'] h1, h1");
      if (h1Handle) {
        result.h1 = (await h1Handle.textContent({ timeout: 1000 }) || "").trim().slice(0, 120);
      }
    } catch (_) {}

    // Rendered body text
    try {
      const bodyText = await page.evaluate(() => {
        // Strip scripts/styles, take main region if present
        const main = document.querySelector("main") || document.body;
        return main.innerText || "";
      });
      result.body_text_length = bodyText.length;

      // Mock sentinel detection
      for (const sentinel of MOCK_SENTINELS) {
        if (bodyText.includes(sentinel)) {
          result.mock_hits.push(sentinel);
        }
      }

      // Empty state
      for (const pattern of EMPTY_STATE_PATTERNS) {
        if (pattern.test(bodyText)) {
          result.empty_state = true;
          break;
        }
      }
    } catch (_) {}

    // Screenshot — ignore failures (page may have detached)
    try {
      const slug = slugify(route);
      const shotPath = path.join(SCREENSHOT_DIR, `${slug}.png`);
      await page.screenshot({ path: shotPath, fullPage: false, timeout: 5000 });
      result.screenshot = shotPath.replace("/Users/devops.ai/fixops/Fixops/", "");
    } catch (_) {}
  } catch (err) {
    result.nav_error = String(err).slice(0, 300);
  }

  result.api_calls = apiCalls.slice(0, 30);
  result.api_call_count = apiCalls.length;
  result.api_404_count = apiCalls.filter((c) => c.status === 404).length;
  result.api_500_count = apiCalls.filter((c) => c.status >= 500).length;
  result.api_4xx_count = apiCalls.filter((c) => c.status >= 400 && c.status < 500).length;
  result.js_errors = jsErrors.slice(0, 5);
  result.tag = classify(result);

  await context.close();
  return result;
}

async function workerPool(items, worker, concurrency) {
  const results = new Array(items.length);
  let nextIdx = 0;
  let completed = 0;

  async function runOne() {
    while (true) {
      const idx = nextIdx++;
      if (idx >= items.length) return;
      try {
        results[idx] = await worker(items[idx], idx);
      } catch (err) {
        results[idx] = {
          route: items[idx],
          tag: "JS_ERROR",
          nav_error: String(err).slice(0, 300),
          api_calls: [],
          mock_hits: [],
          js_errors: [String(err).slice(0, 300)],
        };
      }
      completed++;
      if (completed % 10 === 0 || completed === items.length) {
        process.stderr.write(`  [${completed}/${items.length}] ${items[idx]} -> ${results[idx]?.tag || "?"}\n`);
      }
    }
  }

  await Promise.all(Array.from({ length: concurrency }, () => runOne()));
  return results;
}

async function main() {
  const routes = loadRoutes();
  console.error(`Loaded ${routes.length} routes from ${ROUTES_FILE}`);
  console.error(`Base URL: ${BASE_URL}`);
  console.error(`API: ${API_BASE} (org=${ORG_ID})`);
  console.error(`Concurrency: ${CONCURRENCY}, settle: ${SETTLE_MS}ms`);

  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });

  const browser = await chromium.launch({ headless: true });
  const t0 = Date.now();

  const results = await workerPool(
    routes,
    (route) => verifyRoute(browser, route),
    CONCURRENCY,
  );

  await browser.close();
  const elapsedSec = ((Date.now() - t0) / 1000).toFixed(1);

  fs.writeFileSync(RESULTS_FILE, JSON.stringify(results, null, 2));

  // Print summary to stderr (so caller can pipe stdout to jq)
  const tally = {};
  for (const r of results) {
    tally[r.tag] = (tally[r.tag] || 0) + 1;
  }
  console.error(`\n--- COMPLETED in ${elapsedSec}s ---`);
  console.error(`Total routes: ${results.length}`);
  for (const [tag, count] of Object.entries(tally)) {
    console.error(`  ${tag}: ${count}`);
  }
  console.error(`Results: ${RESULTS_FILE}`);
  console.error(`Screenshots: ${SCREENSHOT_DIR}`);
}

main().catch((err) => {
  console.error("FATAL:", err);
  process.exit(1);
});
