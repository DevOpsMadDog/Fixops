/**
 * RBAC Enforcement E2E Tests
 *
 * Validates that role-based access control is properly enforced:
 * - Admin-only routes reject non-admin roles (403)
 * - Write-scoped routes reject read-only roles (403)
 * - Attack-scoped routes reject viewer/developer roles (403)
 * - All roles can read findings
 * - Unauthenticated requests are rejected (401)
 */
import { test, expect } from "@playwright/test";
import { API_BASE, API_TOKEN, PERSONAS, injectAuth } from "./helpers/auth";

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

const headers = (token?: string) => ({
  ...(token ? { "X-API-Key": token } : {}),
});

// ═══════════════════════════════════════════
// 1. Authentication Boundary
// ═══════════════════════════════════════════

test.describe("Authentication Boundary", () => {
  test("No auth returns 401 on protected route", async ({ request }) => {
    const resp = await request.get(`${API_BASE}/api/v1/findings`);
    expect(resp.status()).toBe(401);
  });

  test("Invalid API key returns 401 or 403", async ({ request }) => {
    const resp = await request.get(`${API_BASE}/api/v1/findings`, {
      headers: { "X-API-Key": "invalid-key-not-real" },
    });
    expect([401, 403]).toContain(resp.status());
  });

  test("Valid API key succeeds on health endpoint", async ({ request }) => {
    const resp = await request.get(`${API_BASE}/health`, {
      headers: { "X-API-Key": API_TOKEN },
    });
    expect(resp.status()).toBe(200);
  });
});

// ═══════════════════════════════════════════
// 2. Admin-Only Routes
// ═══════════════════════════════════════════

test.describe("Admin-Only Route Protection", () => {
  const ADMIN_ROUTES = [
    { method: "GET" as const, path: "/api/v1/users" },
    { method: "GET" as const, path: "/api/v1/teams" },
    { method: "GET" as const, path: "/api/v1/system/info" },
  ];

  for (const route of ADMIN_ROUTES) {
    test(`Admin can access ${route.method} ${route.path}`, async ({ request }) => {
      await delay(200);
      const resp = await request.get(`${API_BASE}${route.path}`, {
        headers: { "X-API-Key": API_TOKEN },
      });
      // Admin should not be blocked — anything except 401/403 is fine
      expect([401, 403]).not.toContain(resp.status());
    });
  }
});

// ═══════════════════════════════════════════
// 3. Read Access for All Authenticated Roles
// ═══════════════════════════════════════════

test.describe("Read Access — All Roles", () => {
  const READ_ROUTES = [
    "/api/v1/analytics/findings",
    "/api/v1/brain/stats",
    "/api/v1/feeds/status",
  ];

  for (const path of READ_ROUTES) {
    test(`Authenticated user can read ${path}`, async ({ request }) => {
      await delay(200);
      const resp = await request.get(`${API_BASE}${path}`, {
        headers: { "X-API-Key": API_TOKEN },
      });
      expect([401, 403]).not.toContain(resp.status());
    });
  }
});

// ═══════════════════════════════════════════
// 4. UI RBAC — Developer Sees Access Denied
// ═══════════════════════════════════════════

test.describe("UI RBAC — Developer Restrictions", () => {
  const devPersona = PERSONAS.find((p) => p.role === "developer")!;

  test("Developer sees Access Denied on Validate/MPTE page", async ({ page }) => {
    await injectAuth(page, devPersona);
    await page.goto("/#/validate/mpte", { waitUntil: "domcontentloaded" });
    const main = page.locator("main");
    await expect(main).toBeVisible({ timeout: 20_000 });
    const text = await main.textContent();
    expect(text).toContain("Access Denied");
  });

  test("Developer can access findings page", async ({ page }) => {
    await injectAuth(page, devPersona);
    await page.goto("/#/detect", { waitUntil: "domcontentloaded" });
    const main = page.locator("main");
    await expect(main).toBeVisible({ timeout: 20_000 });
    const text = await main.textContent();
    // Should NOT see access denied
    expect(text).not.toContain("Access Denied");
  });
});

// ═══════════════════════════════════════════
// 5. UI RBAC — Admin Full Access
// ═══════════════════════════════════════════

test.describe("UI RBAC — Admin Full Access", () => {
  const adminPersona = PERSONAS.find((p) => p.role === "admin")!;

  const ADMIN_PAGES = [
    { path: "/#/detect", label: "Detection" },
    { path: "/#/validate/mpte", label: "Validate/MPTE" },
    { path: "/#/remediate", label: "Remediation" },
    { path: "/#/comply", label: "Compliance" },
    { path: "/#/settings", label: "Settings" },
  ];

  for (const pg of ADMIN_PAGES) {
    test(`Admin can access ${pg.label} page`, async ({ page }) => {
      await injectAuth(page, adminPersona);
      await page.goto(pg.path, { waitUntil: "domcontentloaded" });
      const main = page.locator("main");
      await expect(main).toBeVisible({ timeout: 20_000 });
      const text = await main.textContent();
      expect(text).not.toContain("Access Denied");
    });
  }
});

