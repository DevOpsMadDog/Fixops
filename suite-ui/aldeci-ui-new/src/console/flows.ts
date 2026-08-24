/**
 * The eight flows, and who does each one.
 *
 * Navigation is organised around what a person came here to DO, not around the
 * shape of the backend. That inversion is the whole point: 300 screens grew
 * because every engine got a page, so the product's surface mirrored its
 * implementation instead of its use.
 *
 * Every endpoint referenced here was measured returning tenant-varying data for
 * a seeded tenant. Screens are not built against endpoints that answer nothing —
 * that is how the last surface filled with pages nobody could use.
 */

export type Persona =
  | "analyst"
  | "developer"
  | "compliance"
  | "admin"
  | "risk"
  | "threat-intel"
  | "supply-chain"
  | "executive";

export const PERSONAS: { id: Persona; label: string; blurb: string }[] = [
  { id: "analyst", label: "Security analyst", blurb: "Works the queue and decides what to fix" },
  { id: "developer", label: "Developer", blurb: "Fixes what is assigned, in their own code" },
  { id: "compliance", label: "Compliance", blurb: "Proves control effectiveness to an assessor" },
  { id: "admin", label: "Platform admin", blurb: "Connects sources, runs the platform" },
  { id: "risk", label: "Risk manager", blurb: "Accepts, defers and reports exposure" },
  { id: "threat-intel", label: "Threat intel / IR", blurb: "Tracks what is being exploited now" },
  { id: "supply-chain", label: "Supply chain", blurb: "Owns dependencies and vendor risk" },
  { id: "executive", label: "Executive", blurb: "Wants posture and trend, not findings" },
];

export interface Flow {
  id: string;
  /** The user's job, in their words — not the subsystem's name. */
  label: string;
  /** One line a new user can act on. */
  purpose: string;
  personas: Persona[];
  /** Measured to return tenant-varying data. */
  endpoints: string[];
  hotkey: string;
}

export const FLOWS: Flow[] = [
  {
    id: "ingest",
    label: "Bring findings in",
    purpose: "Upload scanner output or connect a source. Nothing else works until this does.",
    personas: ["admin", "analyst", "supply-chain", "developer"],
    endpoints: ["/api/v1/scanner-ingest/", "/api/v1/scanner-ingest/supported", "/api/v1/scanner-ingest/status"],
    hotkey: "1",
  },
  {
    id: "triage",
    label: "Work the queue",
    purpose: "Every open finding, deduplicated, with the decision already made for you.",
    personas: ["analyst", "developer", "risk"],
    endpoints: ["/api/v1/findings", "/api/v1/security-findings/stats", "/api/v1/deduplication/stats"],
    hotkey: "2",
  },
  {
    id: "decide",
    label: "See the verdict",
    purpose: "Reachability crossed with exploit evidence — act now, schedule, watch or defer.",
    personas: ["analyst", "risk", "threat-intel", "executive"],
    endpoints: ["/api/v1/pipeline/stages", "/api/v1/risk-scoring/summary", "/api/v1/findings"],
    hotkey: "3",
  },
  {
    id: "prove",
    label: "Prove it to an auditor",
    purpose: "Generate a signed evidence bundle. Sealed, tamper-evident, verifiable without us.",
    personas: ["compliance", "risk", "executive"],
    endpoints: [
      "/api/v1/evidence/bundles",
      "/api/v1/evidence-chain/",
      "/api/v1/evidence/compliance-status",
      "/api/v1/evidence/public-key",
    ],
    hotkey: "4",
  },
  {
    id: "declare",
    label: "Teach it your model",
    purpose: "Declare the entities and rules your risk model uses. We do not get to decide them.",
    personas: ["admin", "risk", "compliance"],
    endpoints: ["/api/v1/graph/types", "/api/v1/graph/entities", "/api/v1/graph/rules", "/api/v1/graph/vocabulary"],
    hotkey: "5",
  },
  {
    id: "comply",
    label: "Track a framework",
    purpose: "Control coverage and gaps across the frameworks you are assessed against.",
    personas: ["compliance", "risk", "executive"],
    endpoints: ["/api/v1/compliance/", "/api/v1/compliance/gaps", "/api/v1/compliance/status"],
    hotkey: "6",
  },
  {
    id: "connect",
    label: "Connect systems",
    purpose: "Scanners, SIEM, EDR and threat feeds — what is wired, and what is live.",
    personas: ["admin", "threat-intel", "supply-chain"],
    endpoints: ["/api/v1/connectors/ti/status", "/api/v1/connectors/siem/adapters", "/api/v1/connectors/falcon/status"],
    hotkey: "7",
  },
  {
    id: "operate",
    label: "Run the platform",
    purpose: "Tenants, health and the operational state of the deployment itself.",
    personas: ["admin", "executive"],
    endpoints: ["/api/v1/health/deep", "/api/v1/orgs", "/api/v1/health/database"],
    hotkey: "8",
  },
];

export function flowsFor(persona: Persona | "all"): Flow[] {
  if (persona === "all") return FLOWS;
  return FLOWS.filter((f) => f.personas.includes(persona));
}

export function flowById(id: string): Flow | undefined {
  return FLOWS.find((f) => f.id === id);
}
