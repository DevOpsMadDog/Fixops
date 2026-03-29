/**
 * Global Setup — Health Gate
 *
 * Runs before any E2E test. Waits for the backend API to be healthy
 * and validates critical infrastructure before tests start.
 *
 * If the backend is not ready within 60s, the entire suite aborts
 * with a clear error message — no wasted time on flaky failures.
 */
import { FullConfig } from "@playwright/test";

const API_BASE = process.env.VITE_API_URL || "http://localhost:8000";
const API_TOKEN =
  process.env.FIXOPS_API_TOKEN ||
  "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_";

const MAX_RETRIES = 30;
const RETRY_INTERVAL_MS = 2000;

async function waitForHealth(url: string, label: string): Promise<void> {
  for (let i = 1; i <= MAX_RETRIES; i++) {
    try {
      const resp = await fetch(url, {
        headers: { "X-API-Key": API_TOKEN },
        signal: AbortSignal.timeout(5000),
      });
      if (resp.ok) {
        console.log(`  ✅ ${label} is healthy (${resp.status}) — attempt ${i}/${MAX_RETRIES}`);
        return;
      }
      console.log(`  ⏳ ${label} returned ${resp.status} — retrying (${i}/${MAX_RETRIES})`);
    } catch (err) {
      console.log(`  ⏳ ${label} not reachable — retrying (${i}/${MAX_RETRIES})`);
    }
    await new Promise((r) => setTimeout(r, RETRY_INTERVAL_MS));
  }
  throw new Error(`❌ ${label} did not become healthy within ${MAX_RETRIES * RETRY_INTERVAL_MS / 1000}s`);
}

async function validateCriticalEndpoints(): Promise<void> {
  const critical = [
    { path: "/api/v1/analytics/findings", label: "Findings" },
    { path: "/api/v1/brain/stats", label: "Brain Pipeline" },
    { path: "/api/v1/scanner-ingest/supported", label: "Scanner Ingest" },
    { path: "/api/v1/feeds/status", label: "Threat Feeds" },
  ];

  const results: string[] = [];
  for (const ep of critical) {
    try {
      const resp = await fetch(`${API_BASE}${ep.path}`, {
        headers: { "X-API-Key": API_TOKEN },
        signal: AbortSignal.timeout(10000),
      });
      const icon = resp.ok ? "✅" : "⚠️";
      results.push(`  ${icon} ${ep.label}: ${resp.status}`);
    } catch {
      results.push(`  ❌ ${ep.label}: unreachable`);
    }
  }
  console.log("\n📋 Critical Endpoint Status:");
  results.forEach((r) => console.log(r));
}

export default async function globalSetup(_config: FullConfig): Promise<void> {
  console.log("\n🔐 ALdeci CTEM+ E2E — Global Setup");
  console.log("═".repeat(50));
  console.log(`  API Base: ${API_BASE}`);
  console.log(`  Token:    ${API_TOKEN.slice(0, 12)}...${API_TOKEN.slice(-6)}`);
  console.log("");

  // 1. Wait for backend health
  await waitForHealth(`${API_BASE}/health`, "Backend API");

  // 2. Validate critical endpoints are responding
  await validateCriticalEndpoints();

  console.log("\n✅ Global setup complete — starting tests\n");
}

