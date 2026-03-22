/**
 * E2E Test: Remediation & Compliance Flow
 *
 * Continues the customer journey:
 *   5. Remediation Center — task list, AutoFix
 *   6. Compliance — evidence vault, audit trail
 *   7. AI Engine — Copilot, Brain Pipeline
 *   8. Settings — system health, integrations
 *   9. Sidebar RBAC — developer persona sees restricted nav
 */
import { test, expect, type Page } from "@playwright/test";

const API_BASE = process.env.VITE_API_URL || "http://localhost:8000";
const API_TOKEN =
  process.env.FIXOPS_API_TOKEN ||
  "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_";

async function apiGet(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_TOKEN },
  });
  return { status: res.status, data: await res.json().catch(() => null) };
}

async function injectAuth(page: Page, role = "admin") {
  await page.addInitScript((r) => {
    localStorage.setItem("aldeci.authToken", "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_");
    localStorage.setItem("aldeci.authStrategy", "token");
    localStorage.setItem("aldeci.orgId", "default");
    localStorage.setItem("aldeci.authUser", JSON.stringify({
      id: `e2e-${r}`, email: `${r}@aldeci.local`,
      first_name: "E2E", last_name: r.charAt(0).toUpperCase() + r.slice(1),
      role: r, department: "Security",
    }));
  }, role);
}

// ═══════════════════════════════════════════
// STAGE 5: Remediation
// ═══════════════════════════════════════════

test.describe("Stage 5: Remediation", () => {
  test.beforeEach(async ({ page }) => { await injectAuth(page); });
  test("Remediation Center loads", async ({ page }) => {
    await page.goto("/#/remediate", { waitUntil: "domcontentloaded" });
    const main = page.locator("main");
    await expect(main).toBeVisible({ timeout: 20_000 });
    const text = await main.textContent();
    expect(text?.length).toBeGreaterThan(50);
  });

  test("AutoFix page loads", async ({ page }) => {
    await page.goto("/#/remediate/autofix", { waitUntil: "domcontentloaded" });
    const main = page.locator("main");
    await expect(main).toBeVisible({ timeout: 20_000 });
  });

  test("AutoFix backend endpoint is live", async () => {
    // Small delay to avoid 429 rate-limit from rapid sequential API calls
    await new Promise((r) => setTimeout(r, 1500));
    const { status } = await apiGet("/api/v1/autofix/status");
    if (status === 429) {
      await new Promise((r) => setTimeout(r, 3000));
      const retry = await apiGet("/api/v1/autofix/status");
      expect(retry.status).toBe(200);
    } else {
      expect(status).toBe(200);
    }
  });
});

// ═══════════════════════════════════════════
// STAGE 6: Compliance & Evidence
// ═══════════════════════════════════════════

test.describe("Stage 6: Compliance", () => {
  test.beforeEach(async ({ page }) => { await injectAuth(page); });
  test("Compliance Dashboard loads", async ({ page }) => {
    await page.goto("/#/comply", { waitUntil: "domcontentloaded" });
    const main = page.locator("main");
    await expect(main).toBeVisible({ timeout: 20_000 });
  });

  test("Evidence Vault page loads", async ({ page }) => {
    await page.goto("/#/comply/evidence", { waitUntil: "domcontentloaded" });
    const main = page.locator("main");
    await expect(main).toBeVisible({ timeout: 20_000 });
  });

  test("Audit Trail page loads", async ({ page }) => {
    await page.goto("/#/comply/audit", { waitUntil: "domcontentloaded" });
    const main = page.locator("main");
    await expect(main).toBeVisible({ timeout: 20_000 });
  });

  test("Audit backend returns data", async () => {
    // Small delay to avoid 429 rate-limit from rapid sequential API calls
    await new Promise((r) => setTimeout(r, 1500));
    const { status } = await apiGet("/api/v1/audit/logs");
    // Accept 200 (success) or retry once if rate-limited
    if (status === 429) {
      await new Promise((r) => setTimeout(r, 3000));
      const retry = await apiGet("/api/v1/audit/logs");
      expect(retry.status).toBe(200);
    } else {
      expect(status).toBe(200);
    }
  });
});

// ═══════════════════════════════════════════
// STAGE 7: AI Engine
// ═══════════════════════════════════════════

test.describe("Stage 7: AI Engine", () => {
  test.beforeEach(async ({ page }) => { await injectAuth(page); });
  test("Copilot dashboard loads", async ({ page }) => {
    await page.goto("/#/ai", { waitUntil: "domcontentloaded" });
    const main = page.locator("main");
    await expect(main).toBeVisible({ timeout: 20_000 });
  });

  test("Brain Pipeline backend is live", async () => {
    const { status } = await apiGet("/api/v1/brain/status");
    expect(status).toBe(200);
  });
});

// ═══════════════════════════════════════════
// STAGE 8: Settings & Health
// ═══════════════════════════════════════════

test.describe("Stage 8: Settings", () => {
  test.beforeEach(async ({ page }) => { await injectAuth(page); });
  test("Settings Hub loads", async ({ page }) => {
    await page.goto("/#/settings", { waitUntil: "domcontentloaded" });
    const main = page.locator("main");
    await expect(main).toBeVisible({ timeout: 20_000 });
  });

  test("System Health page loads", async ({ page }) => {
    await page.goto("/#/settings/health", { waitUntil: "domcontentloaded" });
    const main = page.locator("main");
    await expect(main).toBeVisible({ timeout: 20_000 });
  });
});

// ═══════════════════════════════════════════
// STAGE 9: RBAC — Developer persona restrictions
// ═══════════════════════════════════════════

test.describe("Stage 9: RBAC Enforcement", () => {
  test("developer user sees Access Denied on Validate routes", async ({ page }) => {
    await injectAuth(page, "developer");
    await page.goto("/#/validate/mpte", { waitUntil: "domcontentloaded" });
    const main = page.locator("main");
    await expect(main).toBeVisible({ timeout: 20_000 });
    const text = await main.textContent();
    expect(text).toContain("Access Denied");
  });
});

