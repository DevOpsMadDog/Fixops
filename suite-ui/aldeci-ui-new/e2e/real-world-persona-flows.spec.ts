/**
 * Real-World Persona Flows — Enterprise Client Deployment Tests
 *
 * Zero hardcoding. All config from environment variables.
 * Designed to run at ANY client site against their live deployment.
 *
 * Env vars:
 *   VITE_API_URL       — API base URL (default: http://localhost:8000)
 *   FIXOPS_API_TOKEN   — API key (required)
 *   ALDECI_ORG_ID      — Org ID (default: "default")
 */
import { test, expect } from "@playwright/test";
import { API_BASE, API_TOKEN, PERSONAS, injectAuth, apiRequest } from "./helpers/auth";

const ORG_ID = process.env.ALDECI_ORG_ID || "default";

// ═══════════════════════════════════════════
// Phase 1 — Intake & Scope Lock
// ═══════════════════════════════════════════
test.describe("Phase 1: Intake & Scope Lock", () => {
  test("Deployment health gate", async ({ request }) => {
    const r = await apiRequest(request, "GET", "/health");
    expect(r.status()).toBe(200);
  });

  test("System info returns deployment metadata", async ({ request }) => {
    const r = await apiRequest(request, "GET", "/api/v1/system/info");
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(typeof data).toBe("object");
  });

  test("Asset inventory accessible", async ({ request }) => {
    const r = await apiRequest(request, "GET", "/api/v1/inventory/applications");
    expect(r.status()).toBe(200);
  });

  test("Knowledge graph online", async ({ request }) => {
    const r = await apiRequest(request, "GET", "/api/v1/knowledge-graph/status");
    expect(r.status()).toBe(200);
  });
});

// ═══════════════════════════════════════════
// Phase 2 — Discover
// ═══════════════════════════════════════════
test.describe("Phase 2: Discover", () => {
  test("Scanner ingest pipeline ready", async ({ request }) => {
    const r = await apiRequest(request, "GET", "/api/v1/scanner-ingest/supported");
    expect(r.status()).toBe(200);
  });

  test("Deduplication engine running", async ({ request }) => {
    const r = await apiRequest(request, "GET", `/api/v1/deduplication/clusters?org_id=${ORG_ID}`);
    expect(r.status()).toBe(200);
  });

  test("Threat intel feeds available", async ({ request }) => {
    const r = await apiRequest(request, "GET", "/api/v1/feeds/status");
    expect(r.status()).toBe(200);
  });

  test("Copilot responds to analyst queries", async ({ request }) => {
    const r = await apiRequest(request, "POST", "/api/v1/copilot/ask", {
      data: { question: "What findings need attention?" },
    });
    expect(r.status()).toBe(200);
  });
});

// ═══════════════════════════════════════════
// Phase 3 — Prioritize & Decide
// ═══════════════════════════════════════════
test.describe("Phase 3: Prioritize", () => {
  test("FAIL scoring engine operational", async ({ request }) => {
    const r = await apiRequest(request, "GET", "/api/v1/fail/scores");
    expect(r.status()).toBe(200);
  });

  test("Brain pipeline stats available", async ({ request }) => {
    const r = await apiRequest(request, "GET", "/api/v1/brain/stats");
    expect(r.status()).toBe(200);
  });

  test("Risk predictions available", async ({ request }) => {
    const r = await apiRequest(request, "POST", "/api/v1/predictions/risk-trajectory", {
      data: { asset_id: "web-app", timeframe_days: 30 },
    });
    expect(r.status()).toBe(200);
  });
});

// ═══════════════════════════════════════════
// Phase 4 — Validate (MPTE)
// ═══════════════════════════════════════════
test.describe("Phase 4: Validate", () => {
  test("MPTE engine stats accessible", async ({ request }) => {
    const r = await apiRequest(request, "GET", "/api/v1/mpte/stats");
    expect(r.status()).toBe(200);
  });

  test("Attack sim campaigns available", async ({ request }) => {
    const r = await apiRequest(request, "GET", "/api/v1/attack-sim/campaigns");
    expect(r.status()).toBe(200);
  });

  test("LLM Guard protects pipeline", async ({ request }) => {
    const r = await apiRequest(request, "GET", "/api/v1/llm-guard/health");
    expect(r.status()).toBe(200);
  });
});

// ═══════════════════════════════════════════
// Phase 5 — Remediate
// ═══════════════════════════════════════════
test.describe("Phase 5: Remediate", () => {
  test("AutoFix generates fix suggestion", async ({ request }) => {
    const r = await apiRequest(request, "POST", "/api/v1/autofix/generate", {
      data: {
        finding_id: "rw-e2e-xss",
        finding_type: "xss",
        language: "javascript",
        code_context: "document.innerHTML = userInput;",
      },
    });
    expect(r.status()).toBe(200);
  });

  test("Remediation metrics available", async ({ request }) => {
    const r = await apiRequest(request, "GET", "/api/v1/remediation/metrics");
    expect(r.status()).toBe(200);
  });
});

