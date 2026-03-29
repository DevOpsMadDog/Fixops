/**
 * Real-World UI Persona Flows — Browser-Based Enterprise Validation
 *
 * Tests that each persona can navigate their key pages without crash.
 * Zero hardcoding — uses env vars for auth injection.
 */
import { test, expect, type Page } from "@playwright/test";
import { PERSONAS, injectAuth } from "./helpers/auth";

const admin = PERSONAS.find((p) => p.role === "admin")!;
const analyst = PERSONAS.find((p) => p.role === "security_analyst")!;
const viewer = PERSONAS.find((p) => p.role === "viewer")!;
const developer = PERSONAS.find((p) => p.role === "developer")!;

async function assertPageLoads(page: Page, route: string, label: string) {
  await page.goto(route, { waitUntil: "domcontentloaded" });
  await expect(page.locator("body")).toBeVisible();
  const main = page.locator("main");
  await expect(main).toBeVisible({ timeout: 20_000 });
  const text = await main.textContent();
  expect((text || "").length).toBeGreaterThan(5);
}

// ═══════════════════════════════════════════
// CISO Dashboard Flow
// ═══════════════════════════════════════════
test.describe("CISO Dashboard Flow", () => {
  test.beforeEach(async ({ page }) => { await injectAuth(page, admin); });

  const CISO_PAGES = [
    { route: "/", label: "Executive Dashboard" },
    { route: "/comply", label: "Compliance Overview" },
    { route: "/comply/evidence", label: "Evidence Bundles" },
    { route: "/comply/frameworks", label: "Compliance Frameworks" },
  ];

  for (const pg of CISO_PAGES) {
    test(`CISO: ${pg.label} loads`, async ({ page }) => {
      await assertPageLoads(page, pg.route, pg.label);
    });
  }
});

// ═══════════════════════════════════════════
// Security Engineer Triage Flow
// ═══════════════════════════════════════════
test.describe("Security Engineer Triage Flow", () => {
  test.beforeEach(async ({ page }) => { await injectAuth(page, analyst); });

  const SEC_ENG_PAGES = [
    { route: "/detect", label: "Detection Dashboard" },
    { route: "/detect/findings", label: "Findings Queue" },
    { route: "/detect/scanners", label: "Scanner Management" },
    { route: "/detect/dedup", label: "Deduplication" },
  ];

  for (const pg of SEC_ENG_PAGES) {
    test(`SecEng: ${pg.label} loads`, async ({ page }) => {
      await assertPageLoads(page, pg.route, pg.label);
    });
  }
});

// ═══════════════════════════════════════════
// VP Eng Remediation Tracking
// ═══════════════════════════════════════════
test.describe("VP Eng Remediation Flow", () => {
  test.beforeEach(async ({ page }) => { await injectAuth(page, admin); });

  const VP_PAGES = [
    { route: "/remediate", label: "Remediation Dashboard" },
    { route: "/remediate/backlog", label: "Remediation Backlog" },
    { route: "/remediate/autofix", label: "AutoFix Engine" },
    { route: "/remediate/sla", label: "SLA Tracking" },
  ];

  for (const pg of VP_PAGES) {
    test(`VP Eng: ${pg.label} loads`, async ({ page }) => {
      await assertPageLoads(page, pg.route, pg.label);
    });
  }
});

// ═══════════════════════════════════════════
// Developer Security Champion Flow
// ═══════════════════════════════════════════
test.describe("Developer Flow", () => {
  test.beforeEach(async ({ page }) => { await injectAuth(page, developer); });

  test("Developer: Dashboard loads", async ({ page }) => {
    await assertPageLoads(page, "/", "Dashboard");
  });

  test("Developer: AI Copilot loads", async ({ page }) => {
    await assertPageLoads(page, "/ai", "Copilot");
  });
});

// ═══════════════════════════════════════════
// Compliance Officer Flow
// ═══════════════════════════════════════════
test.describe("Compliance Officer Flow", () => {
  test.beforeEach(async ({ page }) => { await injectAuth(page, viewer); });

  const COMPLY_PAGES = [
    { route: "/comply", label: "Compliance Dashboard" },
    { route: "/comply/frameworks", label: "Frameworks" },
    { route: "/comply/evidence", label: "Evidence" },
    { route: "/comply/audit", label: "Audit Trail" },
  ];

  for (const pg of COMPLY_PAGES) {
    test(`Compliance: ${pg.label} loads`, async ({ page }) => {
      await assertPageLoads(page, pg.route, pg.label);
    });
  }
});

// ═══════════════════════════════════════════
// Validate MPTE Flow
// ═══════════════════════════════════════════
test.describe("Pentester Validate Flow", () => {
  test.beforeEach(async ({ page }) => { await injectAuth(page, analyst); });

  const VALIDATE_PAGES = [
    { route: "/validate", label: "Validation Dashboard" },
    { route: "/validate/mpte", label: "MPTE Engine" },
    { route: "/validate/attack-sim", label: "Attack Simulation" },
  ];

  for (const pg of VALIDATE_PAGES) {
    test(`Pentester: ${pg.label} loads`, async ({ page }) => {
      await assertPageLoads(page, pg.route, pg.label);
    });
  }
});

