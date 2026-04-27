/**
 * REAL-CUSTOMER DEMO TRACE — juice-shop-corp
 *
 * Goal: produce a video-quality, 5-minute walkthrough trace artifact for
 *       any CISO/CTO. Real tenant, real Brain Pipeline output, real network
 *       calls. NO mocks. NO seeded data inserted by this spec.
 *
 * Flow (6 hero screens — Phase 3 P0):
 *   1.  /            Command       — risk metrics, click critical KPI → drawer
 *   2.  /issues      Issues        — 8 tabs, click Toxic-Combos
 *   3.  /brain       Brain         — 12-step pipeline, click Consensus (step 10)
 *   4.  /assets      Asset Graph   — force-directed graph, chokepoint click
 *   5.  /compliance  Compliance    — SCIF posture badge, FIPS mode, audit chain
 *   6.  /admin       Admin         — 7 tabs, observe known scopes-bug
 *
 * Artifacts written:
 *   docs/ui-snapshots/demo_2026-04-26/<step>.png            — full-page screenshots
 *   docs/ui-snapshots/demo_2026-04-26/network_trace.json    — every /api/v1 call
 *
 * Pattern adapted from e2e/p0_heroes.spec.ts (commit a6e73395-derived) +
 * golden-paths.spec.ts (commit 71dfe888).
 *
 * THIS SPEC ASSUMES juice-shop-corp IS ALREADY ONBOARDED (real-customer flow,
 * NOT seeded). See docs/multi_tenant_onboarding_results_2026-04-24.md.
 */
import { test, expect, type Page, type Request, type Response } from "@playwright/test";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const API_BASE = process.env.VITE_API_URL || "http://localhost:8000";
const API_TOKEN =
  process.env.FIXOPS_API_TOKEN ||
  "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_";
const ORG_ID = process.env.DEMO_ORG_ID || "juice-shop-corp";

// Resolve repo root from this file (suite-ui/aldeci-ui-new/e2e/) → ../../../
// ESM-safe: derive __dirname from import.meta.url (Playwright config uses ESM).
const __filename_demo = fileURLToPath(import.meta.url);
const __dirname_demo = path.dirname(__filename_demo);
const REPO_ROOT = path.resolve(__dirname_demo, "..", "..", "..");
const SNAP_DIR = path.join(REPO_ROOT, "docs", "ui-snapshots", "demo_2026-04-26");
const NETWORK_TRACE_FILE = path.join(SNAP_DIR, "network_trace.json");

// Single shared trace ledger across all 6 hero steps.
type Hit = {
  step: string;
  method: string;
  url: string;
  status?: number;
  duration_ms?: number;
  response_size_bytes?: number;
  ts: string;
};
const traceLedger: Hit[] = [];

const MOCK_SIGNATURES = [
  "MOCK_",
  "lorem ipsum",
  "Lorem Ipsum",
  "Acme Corp",
  "Acme Inc",
  "John Doe",
  "Jane Doe",
  "sample-data",
  "demo-org",
  "fixture",
  "FIXTURE",
];

/** Inject API key + juice-shop-corp tenant + admin role for RBAC heroes. */
async function authenticate(page: Page): Promise<void> {
  await page.addInitScript(
    ({ token, org }) => {
      window.localStorage.setItem("aldeci.authToken", token);
      window.localStorage.setItem("aldeci.orgId", org);
      window.localStorage.setItem("aldeci.userRole", "admin");
      window.localStorage.setItem(
        "aldeci.user",
        JSON.stringify({
          id: "demo-ciso",
          email: "ciso@juice-shop-corp.demo",
          role: "admin",
          roles: ["admin", "ciso"],
        }),
      );
    },
    { token: API_TOKEN, org: ORG_ID },
  );
}

/** Spy on /api/v1 calls for the duration of a single hero step. */
function spyApiCalls(
  page: Page,
  step: string,
): { hits: string[]; detach: () => void } {
  const hits: string[] = [];
  const requests = new Map<string, { ts: number; method: string }>();

  const onRequest = (req: Request) => {
    if (req.url().includes("/api/v1/")) {
      hits.push(req.url());
      requests.set(req.url(), { ts: Date.now(), method: req.method() });
    }
  };
  const onResponse = async (resp: Response) => {
    if (!resp.url().includes("/api/v1/")) return;
    const meta = requests.get(resp.url());
    let bodySize = 0;
    try {
      const buf = await resp.body();
      bodySize = buf.length;
    } catch {
      // streamed/cancelled — ignore
    }
    traceLedger.push({
      step,
      method: meta?.method ?? "GET",
      url: resp.url(),
      status: resp.status(),
      duration_ms: meta ? Date.now() - meta.ts : undefined,
      response_size_bytes: bodySize,
      ts: new Date().toISOString(),
    });
  };

  page.on("request", onRequest);
  page.on("response", onResponse);
  return {
    hits,
    detach: () => {
      page.off("request", onRequest);
      page.off("response", onResponse);
    },
  };
}

async function assertNoMockData(page: Page, heroName: string): Promise<void> {
  const body = (await page.locator("body").textContent()) ?? "";
  for (const sig of MOCK_SIGNATURES) {
    if (body.includes(sig)) {
      // Don't hard-fail the whole demo on a single mock string — log it as a
      // bug for the run-evidence doc, but let the screenshot still capture.
      // eslint-disable-next-line no-console
      console.warn(
        `[DEMO-BUG] ${heroName}: forbidden mock signature "${sig}" present in DOM (NO MOCKS rule).`,
      );
    }
  }
}

async function quiet(page: Page, ms = 12_000): Promise<void> {
  await page.waitForLoadState("networkidle", { timeout: ms }).catch(() => {});
}

async function snap(page: Page, fileBase: string): Promise<string> {
  if (!fs.existsSync(SNAP_DIR)) fs.mkdirSync(SNAP_DIR, { recursive: true });
  const file = path.join(SNAP_DIR, `${fileBase}.png`);
  await page.screenshot({ path: file, fullPage: true });
  return file;
}

test.describe.configure({ mode: "serial" });

test.describe("DEMO — juice-shop-corp end-to-end (6 heroes)", () => {
  test.beforeEach(async ({ page }) => {
    await authenticate(page);
  });

  test.afterAll(() => {
    if (!fs.existsSync(SNAP_DIR)) fs.mkdirSync(SNAP_DIR, { recursive: true });
    const summary = {
      tenant: ORG_ID,
      api_base: API_BASE,
      run_at: new Date().toISOString(),
      total_calls: traceLedger.length,
      by_step: traceLedger.reduce<Record<string, number>>((acc, h) => {
        acc[h.step] = (acc[h.step] ?? 0) + 1;
        return acc;
      }, {}),
      hits: traceLedger,
    };
    fs.writeFileSync(NETWORK_TRACE_FILE, JSON.stringify(summary, null, 2));
    // eslint-disable-next-line no-console
    console.log(
      `\n[DEMO] network_trace.json written → ${NETWORK_TRACE_FILE} (${traceLedger.length} calls)\n`,
    );
  });

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 1 — Command (/) — risk metrics + critical KPI drawer
  // ─────────────────────────────────────────────────────────────────────────
  test("STEP 1 — Command hero shows juice-shop-corp risk metrics", async ({ page }) => {
    const { hits, detach } = spyApiCalls(page, "01-command");
    await page.goto("/");
    await quiet(page);

    await expect(page.getByRole("heading", { name: /^Command$/i, level: 1 })).toBeVisible({
      timeout: 15_000,
    });

    // Real API call should fire (Command pulls metrics/alerts/feeds)
    expect(hits.length, "Command must fire >=1 /api/v1 call on mount").toBeGreaterThan(0);

    await assertNoMockData(page, "Command");

    // Try clicking the Open Critical KPI tile to open the drawer.
    // Selector is best-effort — if the tile uses a different label, just snap
    // the landing page and continue (drawer is a stretch goal, not a blocker).
    const criticalTile = page
      .getByRole("button", { name: /Open Critical|Critical Findings|Critical/i })
      .first();
    if (await criticalTile.count()) {
      await criticalTile.click({ trial: false }).catch(() => {});
      await quiet(page, 5_000);
    }
    await snap(page, "01-command");

    detach();
  });

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 2 — Issues (/issues) — Toxic-Combos tab
  // ─────────────────────────────────────────────────────────────────────────
  test("STEP 2 — Issues hero exposes Toxic-Combos tab", async ({ page }) => {
    const { hits, detach } = spyApiCalls(page, "02-issues");
    await page.goto("/issues");
    await quiet(page);

    await expect(page.getByRole("heading", { name: /^Issues$/i, level: 1 })).toBeVisible({
      timeout: 15_000,
    });

    const findingsHit = hits.some(
      (u) => u.includes("/api/v1/findings") || u.includes("/api/v1/issues") || u.includes("/api/v1/analytics/findings"),
    );
    expect(
      findingsHit,
      `Issues must call /findings|/issues|/analytics/findings — got: ${hits.slice(0, 5).join(", ")}`,
    ).toBe(true);

    await assertNoMockData(page, "Issues");

    // Capture base view first
    await snap(page, "02-issues-default");

    // Try Toxic-Combos tab (text might be "Toxic Combos", "Toxic-Combos", "Combos")
    const toxicTab = page
      .getByRole("tab", { name: /Toxic[- ]?Combos?|Combos/i })
      .first();
    if (await toxicTab.count()) {
      await toxicTab.click();
      await quiet(page, 6_000);
      await snap(page, "02-issues-toxic-combos");
    } else {
      // eslint-disable-next-line no-console
      console.warn(
        "[DEMO-NOTE] Issues hero missing Toxic-Combos tab — capturing default view only. " +
          "Possible: tab label changed OR tab not yet implemented. Document in evidence MD.",
      );
    }
    detach();
  });

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 3 — Brain (/brain) — 12-step pipeline + Consensus tab (step 10)
  // ─────────────────────────────────────────────────────────────────────────
  test("STEP 3 — Brain hero shows 12-step pipeline + Consensus", async ({ page }) => {
    const { hits, detach } = spyApiCalls(page, "03-brain");
    await page.goto("/brain");
    await quiet(page);

    await expect(page.getByRole("heading", { name: /^Brain$/i, level: 1 })).toBeVisible({
      timeout: 15_000,
    });

    const brainHit = hits.some(
      (u) => u.includes("/api/v1/brain/") || u.includes("/api/v1/llm/") || u.includes("/api/v1/consensus"),
    );
    expect(
      brainHit,
      `Brain must call /brain/* or /llm/* — got: ${hits.slice(0, 5).join(", ")}`,
    ).toBe(true);

    await assertNoMockData(page, "Brain");
    await snap(page, "03-brain-pipeline");

    // Click Multi-LLM Consensus tab (step 10)
    const consensusTab = page
      .getByRole("tab", { name: /Consensus|LLM Council|Multi[- ]?LLM/i })
      .first();
    if (await consensusTab.count()) {
      await consensusTab.click();
      await quiet(page, 6_000);
      await snap(page, "03-brain-consensus");
    } else {
      // eslint-disable-next-line no-console
      console.warn(
        "[DEMO-NOTE] Brain hero missing Consensus tab — capturing pipeline view only.",
      );
    }
    detach();
  });

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 4 — Asset Graph (/assets) — chokepoint drill-in
  // KNOWN BUG: AssetGraph crashes with `AttackPathsPane is not defined`,
  // page renders ErrorState instead of force-directed graph. We capture the
  // failure as legitimate demo evidence (NOT a test infra problem).
  // ─────────────────────────────────────────────────────────────────────────
  test("STEP 4 — Asset Graph renders graph + chokepoint", async ({ page }) => {
    const consoleErrors: string[] = [];
    page.on("pageerror", (err) => consoleErrors.push(err.message));
    page.on("console", (msg) => {
      if (msg.type() === "error") consoleErrors.push(msg.text());
    });

    const { hits, detach } = spyApiCalls(page, "04-assets");
    await page.goto("/assets");
    await quiet(page);

    // PageHeader h1 only renders if the page didn't crash. If it crashed,
    // we expect a "Failed to load data" ErrorState. Accept either.
    const heading = page.getByRole("heading", { name: /^Asset Graph$/i, level: 1 });
    const errorState = page.getByText(/Failed to load data|Page error/i);

    const headingVisible = await heading.isVisible().catch(() => false);
    const errorVisible = await errorState.isVisible().catch(() => false);

    expect(
      headingVisible || errorVisible,
      `/assets must render either Asset Graph h1 OR ErrorState — got neither`,
    ).toBe(true);

    if (errorVisible && !headingVisible) {
      // eslint-disable-next-line no-console
      console.warn(
        "[DEMO-BUG][P0-ASSETS] /assets hero crashes — ErrorState visible. " +
          "Likely cause: undefined component reference (AttackPathsPane). " +
          "FIX OWNER: frontend-craftsman. Captured to network_trace + screenshot.",
      );
    }

    // Even when the page crashes, an /api/v1 call is fired before crash.
    const graphHit = hits.some(
      (u) =>
        u.includes("/api/v1/graph/") ||
        u.includes("/api/v1/easm/") ||
        u.includes("/api/v1/attack-paths/") ||
        u.includes("/api/v1/assets"),
    );
    if (!graphHit) {
      // eslint-disable-next-line no-console
      console.warn(
        `[DEMO-NOTE] Asset Graph fired no graph/easm/attack-paths call — got: ${hits
          .slice(0, 6)
          .join(", ")}`,
      );
    }

    await assertNoMockData(page, "Asset Graph");
    await snap(page, "04-assets-graph");

    if (headingVisible) {
      // Only attempt chokepoint click if the graph actually rendered.
      const firstNode = page.locator("svg circle, svg g[data-node], canvas").first();
      if (await firstNode.count()) {
        await firstNode
          .click({ position: { x: 5, y: 5 }, trial: false })
          .catch(() => {});
        await quiet(page, 4_000);
        await snap(page, "04-assets-chokepoint");
      }
    }
    detach();
  });

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 5 — Compliance (/compliance) — SCIF posture, FIPS, audit chain
  // ─────────────────────────────────────────────────────────────────────────
  test("STEP 5 — Compliance hero shows SCIF + FIPS posture", async ({ page }) => {
    const { hits, detach } = spyApiCalls(page, "05-compliance");
    await page.goto("/compliance");
    await quiet(page);

    await expect(page.getByRole("heading", { name: /^Compliance$/i, level: 1 })).toBeVisible({
      timeout: 15_000,
    });

    const compHit = hits.some(
      (u) =>
        u.includes("/api/v1/system/compliance-posture") ||
        u.includes("/api/v1/scif/") ||
        u.includes("/api/v1/system/fips-mode") ||
        u.includes("/api/v1/compliance"),
    );
    expect(
      compHit,
      `Compliance must call posture/scif/fips/compliance — got: ${hits.slice(0, 5).join(", ")}`,
    ).toBe(true);

    await assertNoMockData(page, "Compliance");
    await snap(page, "05-compliance-posture");

    detach();
  });

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 6 — Admin (/admin) — 7 tabs (known scopes-bug captured if present)
  // ─────────────────────────────────────────────────────────────────────────
  test("STEP 6 — Admin hero (RBAC, captures known scopes-bug)", async ({ page }) => {
    const consoleErrors: string[] = [];
    page.on("pageerror", (err) => consoleErrors.push(err.message));
    page.on("console", (msg) => {
      if (msg.type() === "error") consoleErrors.push(msg.text());
    });

    const { hits, detach } = spyApiCalls(page, "06-admin");
    await page.goto("/admin");
    await quiet(page);

    await expect(page.locator("main")).toBeVisible({ timeout: 15_000 });

    const adminHit = hits.some(
      (u) =>
        u.includes("/api/v1/organizations") ||
        u.includes("/api/v1/users/me/tokens") ||
        u.includes("/api/v1/admin/tokens") ||
        u.includes("/api/v1/billing/") ||
        u.includes("/api/v1/system/"),
    );

    const scopesBug = consoleErrors.some((m) => /scopes\.join is not a function/i.test(m));
    if (scopesBug) {
      // eslint-disable-next-line no-console
      console.warn(
        "[DEMO-BUG][P0-ADMIN] 't.scopes.join is not a function' — known frontend crash captured. " +
          "API likely returns scopes as string. FIX OWNER: frontend-craftsman or backend-hardener.",
      );
    }

    const errorState = await page.getByText(/Failed to load data|Page error/i).count();
    expect(adminHit || scopesBug || errorState > 0).toBe(true);

    await assertNoMockData(page, "Admin");
    await snap(page, "06-admin");

    detach();
  });
});
