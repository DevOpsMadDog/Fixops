#!/usr/bin/env node
/**
 * smoke_phase3_hubs.mjs — Phase 3 hub golden-path smoke test (2026-05-02)
 *
 * For every consolidated *Hub route mounted in suite-ui/aldeci-ui-new/src/App.tsx,
 * navigate headless Chromium to http://localhost:5173<route> and assert:
 *   (a) renders without crashing — at least one <h1> appears within 5s
 *   (b) at least one real /api/v1/... request fires on mount
 *   (c) no MOCK signatures present in the rendered DOM text
 *
 * Outputs:
 *   /tmp/smoke_phase3_hubs_2026-05-02.json   (machine-readable per-hub results)
 *   docs/smoke_test_phase3_hubs_2026-05-02.md (human-readable PASS/FAIL summary)
 *
 * Usage:
 *   cd suite-ui/aldeci-ui-new   # so playwright resolves from local node_modules
 *   node ../../scripts/smoke_phase3_hubs.mjs
 *
 * Hub list source: extracted from App.tsx via grep for `Route path=... element={<*Hub />}`
 * snapshot taken 2026-05-02. Catalog reference: docs/UX_HUBS_CATALOG_2026-05-02.md.
 */

// Resolve playwright from the UI workspace's node_modules — there is no top-level
// package.json that lists it, so default ESM resolution fails. Use a file URL.
import { pathToFileURL } from "node:url";
const PLAYWRIGHT_URL = pathToFileURL(
  "/Users/devops.ai/fixops/Fixops/suite-ui/aldeci-ui-new/node_modules/playwright/index.js"
).href;
const _pw = await import(PLAYWRIGHT_URL);
// Local install exports BrowserType instances on the default export, not as
// named ESM exports — handle both shapes.
const chromium = _pw.chromium ?? _pw.default?.chromium;
if (!chromium) throw new Error("playwright: chromium not found on module exports");
import fs from "node:fs/promises";
import path from "node:path";

// ---------------------------------------------------------------------------
// Hub inventory (42 routes mounted as of 2026-05-02 — extracted from App.tsx).
// Catalog claimed 33; the additional 9 are post-snapshot landings:
//   AICopilotAgentsHub, AirGapHub, AppLayerSecurityHub, APISecurityHub,
//   AssetInventoryHub, DataDiscoveryHub, RiskQuantHub, StrategicPostureHub,
//   ThreatModelingHub. CTO told us "44" — best evidence shows 42 actually
//   mounted. Two missing are folded into hero pages (S5/S8/etc.) without
//   dedicated *Hub.tsx — see catalog §4 for explanation.
// ---------------------------------------------------------------------------
const HUBS = [
  { name: "SecretsHub",                 route: "/discover/secrets-hub" },
  { name: "AICopilotAgentsHub",         route: "/ai/agents" },
  { name: "HuntingHub",                 route: "/mission-control/hunt" },
  { name: "CryptoTrustHub",             route: "/discover/crypto" },
  { name: "NetworkMonitoringHub",       route: "/discover/network" },
  { name: "BehaviorAnalyticsHub",       route: "/mission-control/behavior" },
  { name: "AutomationOrchestrationHub", route: "/remediate/automation" },
  { name: "VulnIntelHub",               route: "/discover/vuln-intel" },
  { name: "SupplyChainHub",             route: "/discover/supply-chain" },
  { name: "IdentityGovernanceHub",      route: "/discover/identity-governance" },
  { name: "DeceptionHub",               route: "/brain/fail/deception" },
  { name: "NetworkSegmentationHub",     route: "/discover/network-segmentation" },
  { name: "EmailThreatProtectionHub",   route: "/discover/threat-protection" },
  { name: "AppLayerSecurityHub",        route: "/discover/app-security" },
  { name: "APISecurityHub",             route: "/discover/api-security" },
  { name: "DataDiscoveryHub",           route: "/discover/dspm" },
  { name: "TrainingCultureHub",         route: "/admin/training-culture" },
  { name: "PrivilegedAccessHub",        route: "/discover/privileged-access" },
  { name: "RiskQuantHub",               route: "/comply/risk-quant" },
  { name: "StrategicPostureHub",        route: "/comply/strategic-posture" },
  { name: "ThreatModelingHub",          route: "/attack/threat-modeling" },
  { name: "ExceptionsHub",              route: "/remediate/exceptions" },
  { name: "DetectAndRespondHub",        route: "/discover/detect-respond" },
  { name: "AwarenessHub",               route: "/comply/awareness" },
  { name: "ThreatActorsHub",            route: "/attack/intel/actors" },
  { name: "OffensiveValidationHub",     route: "/validate/offensive" },
  { name: "MaturityHub",                route: "/comply/maturity" },
  { name: "PrivacyComplianceHub",       route: "/comply/privacy" },
  { name: "ContainerSecurityHub",       route: "/discover/container-security" },
  { name: "ComplianceCoverageHub",      route: "/comply/coverage" },
  { name: "ExternalThreatIntelHub",     route: "/attack/intel/external" },
  { name: "IncidentKnowledgeHub",       route: "/remediate/incidents/knowledge" },
  { name: "IncidentExtensionsHub",      route: "/remediate/incidents/extensions" },
  { name: "AssetInventoryHub",          route: "/discover/assets/inventory" },
  { name: "IntegrationTargetsHub",      route: "/connect/targets" },
  { name: "UpgradePathsHub",            route: "/remediate/upgrade" },
  { name: "ForensicsHub",               route: "/remediate/forensics" },
  { name: "FinanceHub",                 route: "/mission-control/finance" },
  { name: "AirGapHub",                  route: "/connect/mcp/air-gap" },
  { name: "SBOMProvenanceHub",          route: "/comply/provenance" },
  { name: "PolicyAuthoringHub",         route: "/comply/policies/authoring" },
  { name: "RulesCatalogHub",            route: "/comply/rules" },
  // 2026-05-02 v2 — 6 hubs added since the v1 baseline (42 → 48 mounted).
  { name: "WebhookIngestionHub",        route: "/connect/webhook-ingestion" },
  { name: "ThreatIntelOpsHub",          route: "/attack/intel/ops" },
  { name: "VulnLifecyclePipelineHub",   route: "/discover/vuln-pipeline" },
  { name: "CloudPostureUnifiedHub",     route: "/discover/cloud-posture" },
  { name: "PolicyLifecycleHub",         route: "/comply/policies/lifecycle" },
  { name: "PostureMetricsHub",          route: "/discover/posture-metrics" },
];

const BASE_URL = process.env.BASE_URL || "http://localhost:5173";
const HEAD_TIMEOUT_MS = 5_000;     // h1 must appear inside this window
const POST_NAV_SETTLE_MS = 2_500;  // give /api/v1 calls time to fire after h1
const NAV_TIMEOUT_MS = 15_000;
const REPO_ROOT = path.resolve(new URL("..", import.meta.url).pathname);
const JSON_OUT = process.env.SMOKE_JSON_OUT || "/tmp/smoke_phase3_hubs_2026-05-02_v2.json";
const MD_OUT = path.join(REPO_ROOT, "docs/smoke_test_phase3_hubs_2026-05-02.md");

const MOCK_RE = /MOCK_|lorem|Acme Corp|John Doe|svc-001|alice\.chen/i;
const API_RE = /\/api\/v1\//;

function nowIso() {
  return new Date().toISOString();
}

async function smokeOne(browser, hub) {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    userAgent: "Mozilla/5.0 (smoke_phase3_hubs.mjs) PlaywrightChromium",
  });
  const page = await context.newPage();
  const apiCalls = [];
  let crashed = false;
  let crashErr = "";

  // Capture outgoing /api/v1 requests to prove the page is wired to real APIs.
  page.on("request", (req) => {
    const u = req.url();
    if (API_RE.test(u)) apiCalls.push({ method: req.method(), url: u });
  });

  // Capture page errors (uncaught React exceptions).
  page.on("pageerror", (err) => { crashed = true; crashErr = String(err?.message ?? err); });

  const url = `${BASE_URL}${hub.route}`;
  const t0 = Date.now();
  let title = "";
  let headingText = "";
  let mockSignaturesCount = 0;
  let mockSnippet = "";
  let h1Found = false;
  let renderError = "";

  try {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: NAV_TIMEOUT_MS });
    try {
      await page.waitForSelector("h1", { timeout: HEAD_TIMEOUT_MS });
      h1Found = true;
    } catch (e) {
      renderError = `h1 missing within ${HEAD_TIMEOUT_MS}ms`;
    }
    // Allow time for tab content to mount + initial /api/v1 calls to fire.
    await page.waitForTimeout(POST_NAV_SETTLE_MS);

    title = await page.title();
    if (h1Found) {
      headingText = (await page.locator("h1").first().textContent({ timeout: 1_000 }).catch(() => "")) || "";
      headingText = headingText.trim().slice(0, 200);
    }

    // Grep DOM body text for mock signatures.
    const bodyText = await page.evaluate(() => document.body?.innerText || "");
    const matches = bodyText.match(new RegExp(MOCK_RE.source, "gi")) || [];
    mockSignaturesCount = matches.length;
    if (matches.length) mockSnippet = matches.slice(0, 5).join(" | ");
  } catch (e) {
    crashed = true;
    crashErr = String(e?.message ?? e);
  }

  await context.close();

  const apiCallCount = apiCalls.length;
  const elapsedMs = Date.now() - t0;

  // PASS criteria: rendered (h1 found, no crash) + ≥1 /api/v1 call + 0 mock matches.
  let verdict = "PASS";
  const reasons = [];
  if (crashed) { verdict = "FAIL"; reasons.push(`page crashed: ${crashErr.slice(0, 200)}`); }
  if (!h1Found) { verdict = "FAIL"; reasons.push(renderError || "no h1 rendered"); }
  if (apiCallCount === 0) { verdict = "FAIL"; reasons.push("zero /api/v1/* calls fired"); }
  if (mockSignaturesCount > 0) { verdict = "FAIL"; reasons.push(`${mockSignaturesCount} mock signature(s): ${mockSnippet}`); }

  return {
    name: hub.name,
    route: hub.route,
    url,
    title,
    headingText,
    h1Found,
    apiCallCount,
    apiSample: apiCalls.slice(0, 5).map((c) => `${c.method} ${c.url.replace(BASE_URL, "")}`),
    mockSignaturesCount,
    mockSnippet,
    crashed,
    crashErr: crashErr.slice(0, 500),
    elapsedMs,
    verdict,
    reasons,
  };
}

async function main() {
  const browser = await chromium.launch({ headless: true });
  const results = [];
  console.log(`smoke_phase3_hubs: ${HUBS.length} hubs · base=${BASE_URL} · started=${nowIso()}`);

  for (const hub of HUBS) {
    process.stdout.write(`  ${hub.name.padEnd(34)} ${hub.route.padEnd(42)} `);
    const r = await smokeOne(browser, hub);
    results.push(r);
    console.log(`${r.verdict}  api=${r.apiCallCount} mock=${r.mockSignaturesCount} ${r.elapsedMs}ms${r.verdict === "FAIL" ? "  -- " + r.reasons.join("; ") : ""}`);
  }

  await browser.close();

  const summary = {
    generatedAt: nowIso(),
    baseUrl: BASE_URL,
    total: results.length,
    passed: results.filter((r) => r.verdict === "PASS").length,
    failed: results.filter((r) => r.verdict === "FAIL").length,
    results,
  };

  await fs.writeFile(JSON_OUT, JSON.stringify(summary, null, 2));
  console.log(`\nwrote ${JSON_OUT}`);

  // Markdown report.
  const mdLines = [];
  mdLines.push(`# Phase 3 Hub Smoke Test — ${summary.generatedAt.split("T")[0]}`);
  mdLines.push("");
  mdLines.push(`> Generated by \`scripts/smoke_phase3_hubs.mjs\` against \`${BASE_URL}\`.`);
  mdLines.push(`> Per-hub raw JSON: \`${JSON_OUT}\`. Catalog reference: \`docs/UX_HUBS_CATALOG_2026-05-02.md\`.`);
  mdLines.push("");
  mdLines.push("## Method");
  mdLines.push("For each hub canonical route: launch headless Chromium, navigate, wait for `<h1>` (5s), then idle 2.5s for `/api/v1/*` calls to fire. PASS = (h1 rendered) AND (no JS crash) AND (≥1 `/api/v1/*` request) AND (zero matches for `/MOCK_|lorem|Acme Corp|John Doe|svc-001|alice\\.chen/i` in rendered DOM text).");
  mdLines.push("");
  mdLines.push("## Result");
  mdLines.push("");
  mdLines.push(`- **Total hubs tested:** ${summary.total}`);
  mdLines.push(`- **PASS:** ${summary.passed}`);
  mdLines.push(`- **FAIL:** ${summary.failed}`);
  mdLines.push("");
  mdLines.push("| # | Hub | Route | Verdict | API calls | Mock hits | Heading | Notes |");
  mdLines.push("|---|---|---|---|---|---|---|---|");
  results.forEach((r, i) => {
    const heading = (r.headingText || "").replace(/\|/g, "\\|").slice(0, 60);
    const notes = r.verdict === "FAIL" ? r.reasons.join("; ").replace(/\|/g, "\\|") : "";
    mdLines.push(`| ${i + 1} | ${r.name} | \`${r.route}\` | ${r.verdict} | ${r.apiCallCount} | ${r.mockSignaturesCount} | ${heading} | ${notes} |`);
  });

  if (summary.failed > 0) {
    mdLines.push("");
    mdLines.push("## Failures (deep-dive)");
    mdLines.push("");
    results.filter((r) => r.verdict === "FAIL").forEach((r) => {
      mdLines.push(`### ${r.name} — \`${r.route}\``);
      mdLines.push("");
      mdLines.push(`- URL: ${r.url}`);
      mdLines.push(`- Reasons: ${r.reasons.join("; ")}`);
      if (r.crashErr) mdLines.push(`- Crash: \`${r.crashErr}\``);
      mdLines.push(`- API call count: ${r.apiCallCount}`);
      if (r.apiSample.length) mdLines.push(`- API sample: ${r.apiSample.map((c) => `\`${c}\``).join(", ")}`);
      if (r.mockSnippet) mdLines.push(`- Mock matches: \`${r.mockSnippet}\``);
      mdLines.push("");
    });
  }

  mdLines.push("");
  mdLines.push("## Coverage gap vs CTO request");
  mdLines.push("CTO target: 50 hubs. Mounted in `App.tsx` as of this v2 run: 48. The 2 remaining clusters were folded directly into hero pages (S5/S8/S15/S19/S23) without standalone `*Hub.tsx` files — see `docs/UX_HUBS_CATALOG_2026-05-02.md` §4. They surface in S-hero smoke tests, not this script.");
  mdLines.push("");

  await fs.writeFile(MD_OUT, mdLines.join("\n"));
  console.log(`wrote ${MD_OUT}`);

  process.exit(summary.failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("FATAL", err);
  process.exit(2);
});
