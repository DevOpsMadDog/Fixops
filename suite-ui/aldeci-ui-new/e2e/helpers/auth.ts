/**
 * Authentication helpers for persona-based E2E testing.
 *
 * Each persona gets a JWT-like token or API key with the correct role + scopes,
 * matching the _require_scope enforcement in suite-api/apps/api/app.py.
 */
import { type Page, type APIRequestContext } from "@playwright/test";

export const API_BASE =
  process.env.VITE_API_URL || "http://localhost:8000";
export const API_TOKEN =
  process.env.FIXOPS_API_TOKEN ||
  "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_";

// ---------------------------------------------------------------------------
// Role definitions — mirrors auth_models.py ROLE_SCOPES
// ---------------------------------------------------------------------------
export type UserRole =
  | "admin"
  | "security_analyst"
  | "developer"
  | "viewer"
  | "service";

export interface Persona {
  id: number;
  name: string;
  title: string;
  role: UserRole;
  /** Extra description for Allure reports */
  description: string;
}

// ---------------------------------------------------------------------------
// All 25 enterprise personas
// ---------------------------------------------------------------------------
export const PERSONAS: Persona[] = [
  { id: 1, name: "Sarah Chen", title: "CISO", role: "admin", description: "Chief Information Security Officer — executive overview & compliance" },
  { id: 2, name: "Marcus Johnson", title: "VP Engineering", role: "admin", description: "Platform owner — app inventory, remediation backlog, pipeline" },
  { id: 3, name: "Alex Rivera", title: "SOC Analyst T1", role: "security_analyst", description: "Tier-1 triage — findings queue, dedup, copilot" },
  { id: 4, name: "Priya Sharma", title: "SOC Analyst T2", role: "security_analyst", description: "Tier-2 investigation — attack paths, MPTE verification" },
  { id: 5, name: "James Wilson", title: "Security Engineer", role: "security_analyst", description: "Scanner ingest, autofix, feedback loop" },
  { id: 6, name: "Emma Davis", title: "DevSecOps Engineer", role: "security_analyst", description: "Pipeline, SBOM, policies, workflows, connectors" },
  { id: 7, name: "Robert Kim", title: "Compliance Officer", role: "viewer", description: "Compliance frameworks, SOC2, PCI-DSS, HIPAA, audit trail" },
  { id: 8, name: "Lisa Zhang", title: "Penetration Tester", role: "security_analyst", description: "MITRE techniques, MPTE, attack campaigns, FAIL scoring" },
  { id: 9, name: "David Park", title: "Risk Manager", role: "viewer", description: "Top risks, FAIL stats, risk predictions, analytics" },
  { id: 10, name: "Maria Lopez", title: "IT Director", role: "admin", description: "System health, teams, users, analytics summary" },
  { id: 11, name: "Tom Anderson", title: "AppSec Lead", role: "security_analyst", description: "App inventory, remediation tasks, SLA, triage funnel" },
  { id: 12, name: "Jennifer Wu", title: "Cloud Security Architect", role: "security_analyst", description: "Knowledge graph, brain stats, asset inventory, code-to-cloud" },
  { id: 13, name: "Michael Brown", title: "Audit Manager", role: "viewer", description: "Audit logs, compliance frameworks, decision trail" },
  { id: 14, name: "Karen Taylor", title: "Incident Response Lead", role: "security_analyst", description: "Nerve center, playbooks, cases" },
  { id: 15, name: "Chris Lee", title: "Security Data Scientist", role: "security_analyst", description: "ML models, anomaly detection, self-learning" },
  { id: 16, name: "Ryan Murphy", title: "Platform Engineer", role: "admin", description: "Health, metrics, system config, version, readiness" },
  { id: 17, name: "Nina Patel", title: "Threat Intel Analyst", role: "security_analyst", description: "NVD, MITRE, EPSS feeds, FAIL CVE lookup" },
  { id: 18, name: "Olivia Martin", title: "GRC Analyst", role: "viewer", description: "SOC2, PCI-DSS compliance, gaps, evidence, audit controls" },
  { id: 19, name: "Daniel Thompson", title: "SecOps Manager", role: "admin", description: "Dashboard, remediation metrics, teams, workflows, policies" },
  { id: 20, name: "Emily Chang", title: "Developer (Security Champion)", role: "developer", description: "Findings, autofix suggestions, copilot, fix types" },
  { id: 21, name: "Richard Adams", title: "Security Architect", role: "security_analyst", description: "Knowledge graph analytics, brain, attack sim, MCP tools" },
  { id: 22, name: "Amanda Scott", title: "Supply Chain Security", role: "security_analyst", description: "SBOM ingest, inventory, provenance, graph, risk" },
  { id: 23, name: "Brian Hall", title: "QA Security Tester", role: "security_analyst", description: "Scan upload, scanner stats, dedup, remediation, feedback" },
  { id: 24, name: "Catherine Williams", title: "Board Member", role: "viewer", description: "Executive dashboard, compliance status, risk summary, ROI" },
  { id: 25, name: "Mark Roberts", title: "External Auditor", role: "viewer", description: "Audit logs, compliance frameworks, evidence, chain verify" },
];

// ---------------------------------------------------------------------------
// API helper — makes authenticated requests
// ---------------------------------------------------------------------------
export async function apiRequest(
  request: APIRequestContext,
  method: "GET" | "POST" | "PUT" | "DELETE",
  path: string,
  options?: { data?: unknown; headers?: Record<string, string> }
) {
  const url = `${API_BASE}${path}`;
  const headers = {
    "X-API-Key": API_TOKEN,
    ...(options?.headers || {}),
  };

  const response = await request[method.toLowerCase() as "get" | "post" | "put" | "delete"](url, {
    headers,
    data: options?.data,
  });
  return response;
}

// ---------------------------------------------------------------------------
// UI auth injection — sets localStorage for the React app
// ---------------------------------------------------------------------------
export async function injectAuth(page: Page, persona: Persona) {
  await page.addInitScript(
    (p) => {
      localStorage.setItem("aldeci.authToken", p.token);
      localStorage.setItem("aldeci.authStrategy", "token");
      localStorage.setItem("aldeci.orgId", "default");
      localStorage.setItem(
        "aldeci.authUser",
        JSON.stringify({
          id: `persona-${p.id}`,
          email: `${p.role}@aldeci.local`,
          first_name: p.name.split(" ")[0],
          last_name: p.name.split(" ").slice(1).join(" "),
          role: p.role,
          department: "Security",
          persona_title: p.title,
        })
      );
    },
    { ...persona, token: API_TOKEN }
  );
}

