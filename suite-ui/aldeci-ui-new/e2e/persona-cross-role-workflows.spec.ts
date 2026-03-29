/**
 * Cross-Role Workflow E2E Tests
 *
 * Tests realistic multi-step workflows that span across different personas:
 * - Security Engineer ingests scan → SOC Analyst triages → Developer gets fix
 * - CISO reviews dashboard → Compliance Officer exports evidence
 * - Pen Tester runs MPTE → Risk Manager reviews risk scores
 */
import { test, expect } from "@playwright/test";
import { API_BASE, API_TOKEN, PERSONAS, injectAuth } from "./helpers/auth";

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

const apiHeaders = {
  "X-API-Key": API_TOKEN,
  "Content-Type": "application/json",
};

// ═══════════════════════════════════════════
// Workflow 1: Scan Ingest → Triage → AutoFix
// Security Engineer → SOC Analyst → Developer
// ═══════════════════════════════════════════

test.describe("Workflow: Scan → Triage → Fix", () => {
  test.describe.configure({ mode: "serial" });

  test("Step 1: Security Engineer checks scanner support", async ({ request }) => {
    test.info().annotations.push(
      { type: "workflow", description: "scan-triage-fix" },
      { type: "step", description: "1/3" },
    );
    const resp = await request.get(`${API_BASE}/api/v1/scanner-ingest/supported`, {
      headers: { "X-API-Key": API_TOKEN },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data).toBeTruthy();
  });

  test("Step 2: SOC Analyst views findings queue", async ({ request }) => {
    test.info().annotations.push(
      { type: "workflow", description: "scan-triage-fix" },
      { type: "step", description: "2/3" },
    );
    await delay(300);
    const resp = await request.get(`${API_BASE}/api/v1/analytics/findings`, {
      headers: { "X-API-Key": API_TOKEN },
    });
    expect(resp.status()).toBe(200);
  });

  test("Step 3: Developer gets autofix suggestion", async ({ request }) => {
    test.info().annotations.push(
      { type: "workflow", description: "scan-triage-fix" },
      { type: "step", description: "3/3" },
    );
    await delay(300);
    const resp = await request.post(`${API_BASE}/api/v1/autofix/generate`, {
      headers: apiHeaders,
      data: {
        finding_id: "e2e-workflow-001",
        finding_type: "sql_injection",
        language: "python",
        code_context: "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
      },
    });
    expect(resp.status()).toBe(200);
  });
});

// ═══════════════════════════════════════════
// Workflow 2: Executive Dashboard → Compliance Export
// CISO → GRC Analyst → External Auditor
// ═══════════════════════════════════════════

test.describe("Workflow: Executive Review → Compliance Audit", () => {
  test.describe.configure({ mode: "serial" });

  test("Step 1: CISO views executive dashboard", async ({ request }) => {
    const resp = await request.get(`${API_BASE}/api/v1/analytics/dashboard/overview`, {
      headers: { "X-API-Key": API_TOKEN },
    });
    expect(resp.status()).toBe(200);
  });

  test("Step 2: GRC Analyst checks compliance gaps", async ({ request }) => {
    await delay(300);
    const resp = await request.get(`${API_BASE}/api/v1/compliance-engine/gaps`, {
      headers: { "X-API-Key": API_TOKEN },
    });
    expect(resp.status()).toBe(200);
  });

  test("Step 3: External Auditor verifies evidence chain", async ({ request }) => {
    await delay(300);
    const resp = await request.get(`${API_BASE}/api/v1/audit/chain/verify`, {
      headers: { "X-API-Key": API_TOKEN },
    });
    expect(resp.status()).toBe(200);
  });
});

// ═══════════════════════════════════════════
// Workflow 3: Threat Intel → Risk Assessment → Remediation
// Threat Intel Analyst → Pen Tester → Risk Manager → AppSec Lead
// ═══════════════════════════════════════════

test.describe("Workflow: Threat Intel → Risk → Remediation", () => {
  test.describe.configure({ mode: "serial" });

  test("Step 1: Threat Intel Analyst checks NVD feeds", async ({ request }) => {
    const resp = await request.get(`${API_BASE}/api/v1/feeds/nvd/recent`, {
      headers: { "X-API-Key": API_TOKEN },
    });
    expect(resp.status()).toBe(200);
  });

  test("Step 2: Pen Tester scores a CVE via FAIL", async ({ request }) => {
    await delay(300);
    const resp = await request.post(`${API_BASE}/api/v1/fail/score`, {
      headers: apiHeaders,
      data: { cve_id: "CVE-2021-44228", cvss: 10.0, epss: 0.975, is_kev: true },
    });
    expect(resp.status()).toBe(200);
  });

  test("Step 3: Risk Manager reviews top risks", async ({ request }) => {
    await delay(300);
    const resp = await request.get(`${API_BASE}/api/v1/fail/top-risks`, {
      headers: { "X-API-Key": API_TOKEN },
    });
    expect(resp.status()).toBe(200);
  });

  test("Step 4: AppSec Lead checks remediation tasks", async ({ request }) => {
    await delay(300);
    const resp = await request.get(`${API_BASE}/api/v1/remediation/tasks`, {
      headers: { "X-API-Key": API_TOKEN },
    });
    expect(resp.status()).toBe(200);
  });
});

// ═══════════════════════════════════════════
// Workflow 4: UI Journey — Admin full flow
// ═══════════════════════════════════════════

test.describe("Workflow: Admin UI Full Journey", () => {
  const admin = PERSONAS.find((p) => p.id === 1)!; // CISO

  test("Navigate Detect → Validate → Remediate → Comply → Settings", async ({ page }) => {
    await injectAuth(page, admin);

    const pages = ["/#/detect", "/#/validate", "/#/remediate", "/#/comply", "/#/settings"];
    for (const path of pages) {
      await page.goto(path, { waitUntil: "domcontentloaded" });
      const main = page.locator("main");
      await expect(main).toBeVisible({ timeout: 20_000 });
      const text = await main.textContent();
      expect(text?.length).toBeGreaterThan(10);
    }
  });
});

