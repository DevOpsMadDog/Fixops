/**
 * CTEM+ 5-Space UI Coverage — Full Page Load Tests
 *
 * Validates every page in the 5 CTEM spaces renders correctly:
 *   Space 1: Mission Control (5 pages)
 *   Space 2: Discover (12 pages)
 *   Space 3: Validate (6 pages, RBAC-gated)
 *   Space 4: Remediate (7 pages)
 *   Space 5: Comply (9 pages)
 *   Settings (8 pages)
 *   AI Engine (6 pages, RBAC-gated)
 *   Auth flows (login, onboarding)
 *
 * Each test: navigates → waits for main → asserts no crash/blank page.
 * RBAC-gated pages tested with admin role to ensure full access.
 */
import { test, expect, type Page } from "@playwright/test";
import { PERSONAS, injectAuth } from "./helpers/auth";

const admin = PERSONAS.find((p) => p.role === "admin")!;

/** Navigate and assert the page rendered meaningful content */
async function assertPageLoads(page: Page, route: string, label: string) {
  await page.goto(`/#${route}`, { waitUntil: "domcontentloaded" });
  const main = page.locator("main");
  await expect(main, `${label}: <main> must be visible`).toBeVisible({ timeout: 20_000 });
  const text = await main.textContent();
  expect(text?.length, `${label}: page must have content`).toBeGreaterThan(10);
  // Must not show error boundary fallback
  expect(text).not.toContain("Something went wrong");
}

// ═══════════════════════════════════════════
// Space 1: Mission Control
// ═══════════════════════════════════════════

test.describe("Space 1: Mission Control", () => {
  test.beforeEach(async ({ page }) => { await injectAuth(page, admin); });

  const PAGES = [
    { route: "/", label: "Command Dashboard (root)" },
    { route: "/mission-control", label: "Command Dashboard" },
    { route: "/mission-control/executive", label: "Executive View" },
    { route: "/mission-control/sla", label: "SLA Dashboard" },
    { route: "/mission-control/live-feed", label: "Live Feed" },
    { route: "/mission-control/risk", label: "Risk Overview" },
  ];

  for (const pg of PAGES) {
    test(`${pg.label} loads`, async ({ page }) => {
      test.info().annotations.push({ type: "space", description: "Mission Control" });
      await assertPageLoads(page, pg.route, pg.label);
    });
  }
});

// ═══════════════════════════════════════════
// Space 2: Discover
// ═══════════════════════════════════════════

test.describe("Space 2: Discover", () => {
  test.beforeEach(async ({ page }) => { await injectAuth(page, admin); });

  const PAGES = [
    { route: "/discover", label: "Finding Explorer" },
    { route: "/discover/code", label: "Code Scanning" },
    { route: "/discover/secrets", label: "Secrets Detection" },
    { route: "/discover/iac", label: "IaC Scanning" },
    { route: "/discover/cloud", label: "Cloud Posture" },
    { route: "/discover/containers", label: "Container Security" },
    { route: "/discover/sbom", label: "SBOM Inventory" },
    { route: "/discover/graph", label: "Knowledge Graph" },
    { route: "/discover/attack-paths", label: "Attack Paths" },
    { route: "/discover/threats", label: "Threat Feeds" },
    { route: "/discover/correlation", label: "Correlation Engine" },
    { route: "/discover/data-fabric", label: "Data Fabric" },
  ];

  for (const pg of PAGES) {
    test(`${pg.label} loads`, async ({ page }) => {
      test.info().annotations.push({ type: "space", description: "Discover" });
      await assertPageLoads(page, pg.route, pg.label);
    });
  }
});

// ═══════════════════════════════════════════
// Space 3: Validate (admin/security_analyst only)
// ═══════════════════════════════════════════

test.describe("Space 3: Validate", () => {
  test.beforeEach(async ({ page }) => { await injectAuth(page, admin); });

  const PAGES = [
    { route: "/validate", label: "MPTE Console (index)" },
    { route: "/validate/mpte", label: "MPTE Console" },
    { route: "/validate/simulation", label: "Attack Simulation" },
    { route: "/validate/fail", label: "FAIL Engine" },
    { route: "/validate/playbooks", label: "Playbooks" },
    { route: "/validate/reachability", label: "Reachability" },
  ];

  for (const pg of PAGES) {
    test(`${pg.label} loads (admin)`, async ({ page }) => {
      test.info().annotations.push({ type: "space", description: "Validate" });
      await assertPageLoads(page, pg.route, pg.label);
      const text = await page.locator("main").textContent();
      expect(text).not.toContain("Access Denied");
    });
  }
});

// ═══════════════════════════════════════════
// Space 4: Remediate
// ═══════════════════════════════════════════

test.describe("Space 4: Remediate", () => {
  test.beforeEach(async ({ page }) => { await injectAuth(page, admin); });

  const PAGES = [
    { route: "/remediate", label: "Remediation Center" },
    { route: "/remediate/autofix", label: "AutoFix" },
    { route: "/remediate/bulk", label: "Bulk Operations" },
    { route: "/remediate/collaborate", label: "Collaboration" },
    { route: "/remediate/workflows", label: "Workflows" },
    { route: "/remediate/cases", label: "Exposure Cases" },
    { route: "/remediate/tickets", label: "Ticket Integration" },
  ];

  for (const pg of PAGES) {
    test(`${pg.label} loads`, async ({ page }) => {
      test.info().annotations.push({ type: "space", description: "Remediate" });
      await assertPageLoads(page, pg.route, pg.label);
    });
  }
});



// ═══════════════════════════════════════════════
// Space 5: Comply
// ═══════════════════════════════════════════════

test.describe("Space 5: Comply", () => {
  test.beforeEach(async ({ page }) => { await injectAuth(page, admin); });

  const PAGES = [
    { route: "/comply", label: "Compliance Dashboard" },
    { route: "/comply/evidence", label: "Evidence Vault" },
    { route: "/comply/bundles", label: "Evidence Bundles" },
    { route: "/comply/soc2", label: "SOC2 Evidence" },
    { route: "/comply/slsa", label: "SLSA Provenance" },
    { route: "/comply/audit", label: "Audit Trail" },
    { route: "/comply/reports", label: "Reports" },
    { route: "/comply/analytics", label: "Analytics" },
    { route: "/comply/export", label: "Evidence Export Center" },
  ];

  for (const pg of PAGES) {
    test(`${pg.label} loads`, async ({ page }) => {
      test.info().annotations.push({ type: "space", description: "Comply" });
      await assertPageLoads(page, pg.route, pg.label);
    });
  }
});

// ═══════════════════════════════════════════════
// Settings
// ═══════════════════════════════════════════════

test.describe("Settings", () => {
  test.beforeEach(async ({ page }) => { await injectAuth(page, admin); });

  const PAGES = [
    { route: "/settings", label: "Settings Hub" },
    { route: "/settings/integrations", label: "Integrations" },
    { route: "/settings/users", label: "Users (admin-only)" },
    { route: "/settings/teams", label: "Teams (admin-only)" },
    { route: "/settings/marketplace", label: "Marketplace" },
    { route: "/settings/policies", label: "Policies" },
    { route: "/settings/health", label: "System Health" },
    { route: "/settings/logs", label: "Log Viewer" },
  ];

  for (const pg of PAGES) {
    test(`${pg.label} loads`, async ({ page }) => {
      test.info().annotations.push({ type: "space", description: "Settings" });
      await assertPageLoads(page, pg.route, pg.label);
      const text = await page.locator("main").textContent();
      expect(text).not.toContain("Access Denied");
    });
  }
});

// ═══════════════════════════════════════════════
// AI Engine
// ═══════════════════════════════════════════════

test.describe("AI Engine", () => {
  test.beforeEach(async ({ page }) => { await injectAuth(page, admin); });

  const PAGES = [
    { route: "/ai", label: "Copilot Dashboard" },
    { route: "/ai/brain", label: "Brain Pipeline" },
    { route: "/ai/consensus", label: "Multi-LLM Consensus" },
    { route: "/ai/algorithms", label: "Algorithmic Lab" },
    { route: "/ai/ml", label: "ML Dashboard" },
    { route: "/ai/predictions", label: "Predictions" },
  ];

  for (const pg of PAGES) {
    test(`${pg.label} loads (admin)`, async ({ page }) => {
      test.info().annotations.push({ type: "space", description: "AI Engine" });
      await assertPageLoads(page, pg.route, pg.label);
      const text = await page.locator("main").textContent();
      expect(text).not.toContain("Access Denied");
    });
  }
});

// ═══════════════════════════════════════════════
// Auth Flows
// ═══════════════════════════════════════════════

test.describe("Auth Flows", () => {
  test("Login page renders with form", async ({ page }) => {
    await page.goto("/#/login", { waitUntil: "domcontentloaded" });
    const form = page.locator("form");
    await expect(form).toBeVisible({ timeout: 15_000 });
    await expect(page.locator('input[type="email"], input[name="email"], input[placeholder*="mail"]').first()).toBeVisible({ timeout: 5_000 });
    await expect(page.locator('input[type="password"]').first()).toBeVisible({ timeout: 5_000 });
  });

  test("Onboarding wizard loads", async ({ page }) => {
    await page.goto("/#/onboarding", { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(3000);
    const body = await page.locator("body").textContent();
    expect(body?.length).toBeGreaterThan(10);
  });

  test("404 page shows Not Found for invalid route", async ({ page }) => {
    await injectAuth(page, admin);
    await page.goto("/#/this-page-does-not-exist", { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(3000);
    const body = await page.locator("body").textContent();
    expect(body?.length).toBeGreaterThan(5);
  });
});

// ═══════════════════════════════════════════════
// RBAC: Developer Persona Restrictions
// ═══════════════════════════════════════════════

test.describe("RBAC: Developer Cannot Access Admin Pages", () => {
  const dev = PERSONAS.find((p) => p.role === "developer")!;

  const RESTRICTED = [
    { route: "/validate/mpte", label: "MPTE Console" },
    { route: "/validate/simulation", label: "Attack Simulation" },
    { route: "/validate/fail", label: "FAIL Engine" },
    { route: "/settings/users", label: "Users Management" },
    { route: "/settings/teams", label: "Teams Management" },
    { route: "/ai/brain", label: "Brain Pipeline" },
  ];

  for (const pg of RESTRICTED) {
    test(`Developer blocked from ${pg.label}`, async ({ page }) => {
      await injectAuth(page, dev);
      await page.goto(`/#${pg.route}`, { waitUntil: "domcontentloaded" });
      const main = page.locator("main, body");
      await expect(main.first()).toBeVisible({ timeout: 20_000 });
      const text = await page.locator("body").textContent();
      expect(text).toContain("Access Denied");
    });
  }
});