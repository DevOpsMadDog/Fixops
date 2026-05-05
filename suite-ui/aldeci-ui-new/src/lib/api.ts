import axios from "axios";

type AuthStrategy = "token" | "jwt";

const AUTH_TOKEN_STORAGE_KEY = "aldeci.authToken";
const AUTH_STRATEGY_STORAGE_KEY = "aldeci.authStrategy";
const ORG_ID_STORAGE_KEY = "aldeci.orgId";

function canUseBrowserStorage() {
  return typeof window !== "undefined" && typeof window.localStorage !== "undefined";
}

function getStoredValue(key: string): string {
  if (!canUseBrowserStorage()) return "";
  return window.localStorage.getItem(key)?.trim() ?? "";
}

function setStoredValue(key: string, value: string | null) {
  if (!canUseBrowserStorage()) return;
  if (!value?.trim()) {
    window.localStorage.removeItem(key);
    return;
  }
  window.localStorage.setItem(key, value.trim());
}

export function getStoredAuthStrategy(): AuthStrategy {
  const strategy = (getStoredValue(AUTH_STRATEGY_STORAGE_KEY) || import.meta.env.VITE_AUTH_STRATEGY || "token").toLowerCase();
  return strategy === "jwt" ? "jwt" : "token";
}

export function setStoredAuthStrategy(strategy: AuthStrategy) {
  setStoredValue(AUTH_STRATEGY_STORAGE_KEY, strategy);
}

const DEMO_API_KEY = 'fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_';

export function getStoredAuthToken() {
  return getStoredValue(AUTH_TOKEN_STORAGE_KEY) || DEMO_API_KEY;
}

export function setStoredAuthToken(token: string | null) {
  setStoredValue(AUTH_TOKEN_STORAGE_KEY, token);
}

export function getStoredOrgId() {
  return getStoredValue(ORG_ID_STORAGE_KEY) || import.meta.env.VITE_ORG_ID || "default";
}

export function setStoredOrgId(orgId: string | null) {
  setStoredValue(ORG_ID_STORAGE_KEY, orgId);
}

export function buildApiUrl(path: string, params?: Record<string, string>) {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const base = import.meta.env.VITE_API_URL?.trim() || window.location.origin;
  const url = new URL(normalizedPath, base);
  Object.entries(params ?? {}).forEach(([key, value]) => {
    if (value) url.searchParams.set(key, value);
  });
  return url.toString();
}

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "",
  headers: {
    "Content-Type": "application/json",
  },
});

api.interceptors.request.use((config) => {
  const strategy = getStoredAuthStrategy();
  const token = getStoredAuthToken() || import.meta.env.VITE_API_KEY || "";
  const orgId = getStoredOrgId();

  config.headers = config.headers ?? {};
  delete config.headers.Authorization;
  delete config.headers["X-API-Key"];

  if (token) {
    if (strategy === "jwt") {
      config.headers.Authorization = token.toLowerCase().startsWith("bearer ") ? token : `Bearer ${token}`;
    } else {
      config.headers["X-API-Key"] = token;
    }
  }

  if (orgId) {
    config.headers["X-Org-ID"] = orgId;
  }

  return config;
});

// ── Request interceptor for token refresh ──
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      window.location.hash = "#/login";
    }
    return Promise.reject(err);
  }
);

// ═══════════════════════════════════════════
// API Namespaces — one per domain
// ═══════════════════════════════════════════

export const healthApi = {
  check: () => api.get("/health"),
};

export const streamApi = {
  eventsUrl: (types?: string) => {
    const token = getStoredAuthToken() || import.meta.env.VITE_API_KEY || "";
    const params: Record<string, string> = {};
    if (token) params.api_key = token;
    if (types) params.types = types;
    return buildApiUrl("/api/v1/stream/events", params);
  },
  // FEATURE-3 — TrustGraph live event WebSocket. Subscribes to the
  // canonical TrustGraphEventBus stream at /ws/events.
  trustGraphWsUrl: (orgId?: string) => {
    const token = getStoredAuthToken() || import.meta.env.VITE_API_KEY || "";
    const httpUrl = buildApiUrl(
      "/ws/events",
      {
        ...(token ? { api_key: token } : {}),
        ...(orgId ? { org_id: orgId } : {}),
      },
    );
    // Convert http(s):// → ws(s)://
    return httpUrl.replace(/^http/, "ws");
  },
};

export const dashboardApi = {
  summary: () => api.get("/api/v1/analytics/dashboard/overview"),
  posture: () => api.get("/api/v1/analytics/dashboard/top-risks"),
  trends: (params?: Record<string, string>) => api.get("/api/v1/analytics/dashboard/trends", { params }),
  compliance: () => api.get("/api/v1/analytics/dashboard/compliance-status"),
};

export const nerveCenterApi = {
  pulse: () => api.get("/api/v1/nerve-center/pulse"),
  state: () => api.get("/api/v1/nerve-center/state"),
  overlay: () => api.get("/api/v1/nerve-center/overlay"),
  intelligenceMap: () => api.get("/api/v1/nerve-center/intelligence-map"),
  playbooks: () => api.get("/api/v1/nerve-center/playbooks"),
  autoRemediate: (data: unknown) => api.post("/api/v1/nerve-center/auto-remediate", data),
};

export const findingsApi = {
  list: async (params?: Record<string, unknown>) => {
    // Fetch real findings from analytics DB
    const analyticsRes = await api.get("/api/v1/analytics/findings", { params });
    const findings = Array.isArray(analyticsRes.data) ? analyticsRes.data : (analyticsRes.data?.items ?? analyticsRes.data?.findings ?? []);
    // Also fetch cases for supplementary data
    let cases: unknown[] = [];
    try {
      const casesRes = await api.get("/api/v1/cases", { params: { limit: 200 } });
      cases = casesRes.data?.cases ?? casesRes.data?.items ?? [];
    } catch { /* cases endpoint may not exist */ }
    // Merge: use analytics findings as primary, enrich with case data
    interface FindingLike {
      id?: string;
      finding_id?: string;
      title?: string;
      severity?: string;
      status?: string;
      cve_id?: string;
      cve?: string;
      source?: string;
      scanner?: string;
      created_at?: string;
      [key: string]: unknown;
    }
    const normalized = (findings as FindingLike[]).map((f: FindingLike) => ({
      ...f,
      finding_id: f.id,
      cve: f.cve_id ?? f.cve ?? undefined,
      scanner: f.source ?? f.scanner ?? undefined,
    }));
    return { data: { cases: normalized, total: normalized.length, items: normalized, findings: normalized, data: normalized } };
  },
  get: (id: string) => api.get(`/api/v1/cases/${id}`),
  triage: (id: string, action: string) => api.post(`/api/v1/cases/${id}/triage`, { action }),
  bulkTriage: (ids: string[], action: string) => api.post("/api/v1/bulk/triage", { finding_ids: ids, action }),
};

export const scannerApi = {
  ingest: (data: unknown) => api.post("/api/v1/scanner/ingest", data),
  list: () => api.get("/api/v1/scanner/parsers"),
};

export const scannerIngestApi = {
  stats: () => api.get("/api/v1/scanner-ingest/stats"),
  status: () => api.get("/api/v1/scanner-ingest/status"),
  supported: () => api.get("/api/v1/scanner-ingest/supported"),
};

export const appsApi = {
  list: (params?: Record<string, unknown>) => api.get("/api/v1/apps/", { params }),
  get: (id: string) => api.get(`/api/v1/apps/${id}`),
  create: (data: unknown) => api.post("/api/v1/apps", data),
  update: (id: string, data: unknown) => api.put(`/api/v1/apps/${id}`, data),
  delete: (id: string) => api.delete(`/api/v1/apps/${id}`),
  health: () => api.get("/api/v1/apps/health"),
  components: (id: string) => api.get(`/api/v1/apps/${id}/components`),
};

export const failApi = {
  stats: (orgId = "default") => api.get("/api/v1/fail/", { params: { org_id: orgId } }),
  inject: (data: unknown) => api.post("/api/v1/fail/inject", data),
  getDrills: (params?: Record<string, string>) => api.get("/api/v1/fail/drills", { params }),
  getDrill: (id: string) => api.get(`/api/v1/fail/drills/${id}`),
  grade: (id: string) => api.post(`/api/v1/fail/drills/${id}/grade`),
  detect: (id: string) => api.post(`/api/v1/fail/drills/${id}/detect`),
  triage: (id: string, data: unknown) => api.post(`/api/v1/fail/drills/${id}/triage`, data),
  remediate: (id: string, data: unknown) => api.post(`/api/v1/fail/drills/${id}/remediate`, data),
  getNeglectZones: (params?: Record<string, string>) => api.get("/api/v1/fail/neglect-zones", { params }),
  getReadinessScore: (params?: Record<string, string>) => api.get("/api/v1/fail/readiness", { params }),
  getScenarios: () => api.get("/api/v1/fail/scenarios"),
  getComparison: (params?: Record<string, string>) => api.get("/api/v1/fail/comparison", { params }),
  getTrainingData: (params?: Record<string, string>) => api.get("/api/v1/fail/training-data", { params }),
  getHistory: (params?: Record<string, string>) => api.get("/api/v1/fail/history", { params }),
};

export const changesApi = {
  analyzeDiff: (data: unknown) => api.post("/api/v1/changes/analyze-diff", data),
  analyzePR: (data: unknown) => api.post("/api/v1/changes/analyze-pr", data),
  riskProfile: (repo: string) => api.get(`/api/v1/changes/risk-profile/${repo}`),
  classify: (data: unknown) => api.post("/api/v1/changes/classify", data),
  velocity: (repo: string) => api.get(`/api/v1/changes/velocity/${repo}`),
  hotspots: (repo: string) => api.get(`/api/v1/changes/hotspots/${repo}`),
  slaImpact: (data: unknown) => api.post("/api/v1/changes/sla-impact", data),
};

export const mpteApi = {
  // Path corrections 2026-04-29: UI was calling routes that don't exist on the backend
  // (verify, status, stats, results, verifications). Mapped to the real registered paths.
  verify: (data: unknown) => api.post("/api/v1/mpte/requests", data),
  status: () => api.get("/api/v1/mpte/health"),
  stats: () => api.get("/api/v1/mpte/monitoring"),
  results: (params?: Record<string, string>) => api.get("/api/v1/mpte/requests", { params }),
  requests: (params?: Record<string, string>) => api.get("/api/v1/mpte/requests", { params }),
  getRequest: (id: string) => api.get(`/api/v1/mpte/requests/${id}`),
  startRequest: (id: string) => api.post(`/api/v1/mpte/requests/${id}/start`),
  cancelRequest: (id: string) => api.post(`/api/v1/mpte/requests/${id}/cancel`),
  verifications: (params?: Record<string, string>) => api.get("/api/v1/mpte/requests", { params }),
  getVerification: (id: string) => api.get(`/api/v1/mpte/requests/${id}`),
  configs: () => api.get("/api/v1/mpte/configs"),
  monitoring: () => api.get("/api/v1/mpte/monitoring"),
  health: () => api.get("/api/v1/mpte/health"),
  comprehensiveScan: (data: unknown) => api.post("/api/v1/mpte/campaigns", data),
  orchestratorRun: (data: unknown) => api.post("/api/v1/mpte-orchestrator/run", data),
  orchestratorSimulate: (data: unknown) => api.post("/api/v1/mpte-orchestrator/simulate", data),
  orchestratorStatus: (id: string) => api.get(`/api/v1/mpte-orchestrator/status/${id}`),
};

export const slaApi = {
  dashboard: () => api.get("/api/v1/sla/dashboard"),
  metrics: () => api.get("/api/v1/sla/metrics"),
  breaches: () => api.get("/api/v1/sla/breaches"),
  health: () => api.get("/api/v1/sla/health"),
};

export const remediationApi = {
  list: (params?: Record<string, unknown>) => api.get("/api/v1/remediation/tasks", { params }),
  get: (id: string) => api.get(`/api/v1/remediation/tasks/${id}`),
  update: (id: string, data: unknown) => api.put(`/api/v1/remediation/tasks/${id}`, data),
  autofix: (id: string) => api.post(`/api/v1/autofix/generate`, { finding_id: id }),
  autofixStatus: (id: string) => api.get(`/api/v1/autofix/status/${id}`),
  bulkAssign: (data: unknown) => api.post("/api/v1/bulk/assign", data),
};

export const evidenceApi = {
  bundles: (params?: Record<string, unknown>) => api.get("/api/v1/evidence/bundles", { params }),
  list: (params?: Record<string, unknown>) => api.get("/api/v1/evidence/bundles", { params }),
  summary: () => api.get("/api/v1/evidence/compliance-status"),
  get: (id: string) => api.get(`/api/v1/evidence/bundles/${id}`),
  generate: (data: unknown) => api.post("/api/v1/evidence/generate", data),
  verify: (id: string) => api.get(`/api/v1/evidence/bundles/${id}/verify`),
  export: (data: unknown) => api.post("/api/v1/evidence/export", data),
  complianceStatus: () => api.get("/api/v1/evidence/compliance-status"),
};

export const complianceEvidenceApi = {
  requests: (params?: Record<string, unknown>) => api.get("/api/v1/compliance-evidence/requests", { params }),
  createRequest: (data: unknown) => api.post("/api/v1/compliance-evidence/requests", data),
  listEvidence: (requestId: string, params?: Record<string, unknown>) => api.get(`/api/v1/compliance-evidence/requests/${requestId}/evidence`, { params }),
  submitEvidence: (requestId: string, data: unknown) => api.post(`/api/v1/compliance-evidence/requests/${requestId}/evidence`, data),
  approve: (requestId: string, data: unknown) => api.post(`/api/v1/compliance-evidence/requests/${requestId}/approve`, data),
  reject: (requestId: string, data: unknown) => api.post(`/api/v1/compliance-evidence/requests/${requestId}/reject`, data),
  autoCollect: (data: unknown) => api.post("/api/v1/compliance-evidence/auto-collect", data),
  auditReadiness: (params?: Record<string, unknown>) => api.get("/api/v1/compliance-evidence/audit-readiness", { params }),
  stats: (params?: Record<string, unknown>) => api.get("/api/v1/compliance-evidence/stats", { params }),
};

export const complianceApi = {
  status: () => api.get("/api/v1/compliance-engine/status"),
  overallStatus: () => api.get("/api/v1/compliance/status"),
  frameworks: () => api.get("/api/v1/compliance-engine/frameworks"),
  gaps: () => api.get("/api/v1/compliance-engine/gaps"),
  assess: (data: unknown) => api.post("/api/v1/compliance-engine/assess", data),
  assessAll: () => api.post("/api/v1/compliance-engine/assess-all"),
  auditBundle: (data: unknown) => api.post("/api/v1/compliance-engine/audit-bundle", data),
  mapFindings: (data: unknown) => api.post("/api/v1/compliance-engine/map-findings", data),
  control: (id: string) => api.get(`/api/v1/compliance-engine/control/${id}`),
  soc2Status: () => api.get("/api/v1/compliance-engine/soc2/status"),
  pciStatus: () => api.get("/api/v1/compliance-engine/pci-dss/status"),
  hipaaStatus: () => api.get("/api/v1/compliance-engine/hipaa/status"),
  health: () => api.get("/api/v1/compliance-engine/health"),
  auditControls: () => api.get("/api/v1/audit/compliance/controls"),
  auditFrameworks: () => api.get("/api/v1/audit/compliance/frameworks"),
};

export const copilotApi = {
  chat: (data: unknown) => api.post("/api/v1/copilot/chat", data),
  suggest: (context: unknown) => api.post("/api/v1/copilot/suggest", context),
  agents: () => api.get("/api/v1/copilot/agents"),
  agentRun: (name: string, data: unknown) => api.post(`/api/v1/copilot/agents/${name}/run`, data),
};

export const integrationsApi = {
  list: () => api.get("/api/v1/integrations"),
  status: () => api.get("/api/v1/integrations/status"),
  test: (id: string) => api.post(`/api/v1/integrations/${id}/test`),
  sync: (id: string) => api.post(`/api/v1/integrations/${id}/sync`),
  configure: (id: string, data: unknown) => api.put(`/api/v1/integrations/${id}`, data),
};

export const connectorsApi = {
  types: () => api.get("/api/v1/connectors/types"),
  list: () => api.get("/api/v1/connectors"),
};

export const reportsApi = {
  list: () => api.get("/api/v1/reports"),
  generate: (data: unknown) => api.post("/api/v1/reports/generate", data),
  get: (id: string) => api.get(`/api/v1/reports/${id}`),
};

export const teamsApi = {
  list: () => api.get("/api/v1/teams"),
  get: (id: string) => api.get(`/api/v1/teams/${id}`),
  create: (data: unknown) => api.post("/api/v1/teams", data),
  update: (id: string, data: unknown) => api.put(`/api/v1/teams/${id}`, data),
};

export const usersApi = {
  login: (data: { email: string; password: string }) => api.post("/api/v1/users/login", data),
  list: () => api.get("/api/v1/users"),
  get: (id: string) => api.get(`/api/v1/users/${id}`),
  create: (data: unknown) => api.post("/api/v1/users", data),
  update: (id: string, data: unknown) => api.put(`/api/v1/users/${id}`, data),
};

export const workflowsApi = {
  list: () => api.get("/api/v1/workflows"),
  rules: () => api.get("/api/v1/workflows/rules"),
  create: (data: unknown) => api.post("/api/v1/workflows", data),
  update: (id: string, data: unknown) => api.put(`/api/v1/workflows/${id}`, data),
  delete: (id: string) => api.delete(`/api/v1/workflows/${id}`),
  trigger: (id: string) => api.post(`/api/v1/workflows/${id}/execute`),
};

export const auditApi = {
  list: (params?: Record<string, unknown>) => api.get("/api/v1/audit", { params }),
  logs: (params?: Record<string, unknown>) => api.get("/api/v1/audit/logs", { params }),
  /** Convenience: fetch the N most recent audit log entries (default 50). */
  recentLogs: (limit = 50) => api.get("/api/v1/audit/logs", { params: { limit } }),
  getLog: (id: string) => api.get(`/api/v1/audit/logs/${id}`),
  exportLogs: (params?: Record<string, unknown>) => api.get("/api/v1/audit/logs/export", { params }),
  decisionTrail: (params?: Record<string, unknown>) => api.get("/api/v1/audit/decision-trail", { params }),
  userActivity: (params?: Record<string, unknown>) => api.get("/api/v1/audit/user-activity", { params }),
  policyChanges: () => api.get("/api/v1/audit/policy-changes"),
  verify: () => api.post("/api/v1/audit/verify-chain"),
  complianceFrameworks: () => api.get("/api/v1/audit/compliance/frameworks"),
};

/** Incidents — /api/v1/incidents/ (incident_response_router.py, commit 2fa0171e)
 *  Index response shape: { router, org_id, stats, items, total, limit, offset }
 *  List  response shape: { incidents: [...], count }
 */
export const incidentsApi = {
  list: (params?: { status?: string; severity?: string; limit?: number; offset?: number; org_id?: string }) =>
    api.get("/api/v1/incidents/", { params }),
  get: (id: string) => api.get(`/api/v1/incidents/${id}`),
  stats: (orgId = "default") => api.get("/api/v1/incidents/stats", { params: { org_id: orgId } }),
  create: (data: Record<string, unknown>) => api.post("/api/v1/incidents/", data),
  updateStatus: (id: string, status: string, notes?: string) =>
    api.post(`/api/v1/incidents/${id}/status`, { status, notes }),
  addTimeline: (id: string, event: Record<string, unknown>) =>
    api.post(`/api/v1/incidents/${id}/timeline`, event),
};

export const policiesApi = {
  list: () => api.get("/api/v1/policies"),
  get: (id: string) => api.get(`/api/v1/policies/${id}`),
  create: (data: unknown) => api.post("/api/v1/policies", data),
  update: (id: string, data: unknown) => api.put(`/api/v1/policies/${id}`, data),
};

export const systemApi = {
  health: () => api.get("/api/v1/system/health"),
  metrics: () => api.get("/api/v1/system/metrics"),
  config: () => api.get("/api/v1/system/config"),
  endpointHealth: () => api.get("/api/v1/system/endpoint-health"),
  logsRecent: (limit = 200) => api.get("/api/v1/system/logs/recent", { params: { limit } }),
  platformHealth: () => api.get("/api/v1/platform/health"),
  prometheusMetrics: () => api.get("/api/v1/metrics/prometheus"),
};

export const knowledgeGraphApi = {
  query: (data: unknown) => api.post("/api/v1/graph/query", data),
  nlQuery: (data: unknown) => api.post("/api/v1/graph/query", data),
  visualize: (params?: Record<string, string>) => api.get("/api/v1/graph/visualize", { params }),
  paths: (data?: unknown) => data ? api.post("/api/v1/graph/attack-paths", data) : api.get("/api/v1/graph/attack-paths"),
  attackPaths: () => api.get("/api/v1/graph/attack-paths"),
  blastRadius: (data: unknown) => api.post("/api/v1/graph/blast-radius", data),
  stats: () => api.get("/api/v1/graph/stats"),
};

export const threatFeedsApi = {
  list: (params?: Record<string, string>) => api.get("/api/v1/feeds", { params }),
  trending: () => api.get("/api/v1/feeds/trending"),
  epss: (cveIds: string) => api.get("/api/v1/feeds/epss", { params: { cve_ids: cveIds } }),
  kev: (cveId?: string) => api.get("/api/v1/feeds/kev", { params: cveId ? { cve_id: cveId } : undefined }),
};

export const reachabilityApi = {
  analysis: () => api.get("/api/v1/reachability/analysis"),
  analyze: (data: unknown) => api.post("/api/v1/reachability/analyze", data),
  health: () => api.get("/api/v1/reachability/health"),
};

export const predictionsApi = {
  list: () => api.get("/api/v1/predictions"),
  details: (id: string) => api.get(`/api/v1/predictions/${id}`),
};

export const playbooks = {
  list: () => api.get("/api/v1/playbooks"),
  get: (id: string) => api.get(`/api/v1/playbooks/${id}`),
  run: (id: string) => api.post(`/api/v1/playbooks/${id}/run`),
  create: (data: unknown) => api.post("/api/v1/playbooks", data),
  update: (id: string, data: unknown) => api.put(`/api/v1/playbooks/${id}`, data),
};

export const sseApi = {
  connect: (endpoint: string) => {
    const baseUrl = import.meta.env.VITE_API_URL || "";
    const url = `${baseUrl}${endpoint}`;
    return new EventSource(url);
  },
};

// ── Specialized Discovery APIs ──
export const secretsApi = {
  list: (params?: Record<string, unknown>) => api.get("/api/v1/secrets", { params }),
  get: (id: string) => api.get(`/api/v1/secrets/${id}`),
  resolve: (id: string) => api.post(`/api/v1/secrets/${id}/resolve`),
  scan: (data: unknown) => api.post("/api/v1/secrets/scan/content", data),
};

export const sbomApi = {
  components: (params?: Record<string, unknown>) => api.get("/api/v1/inventory/sbom/components", { params }),
  licenses: () => api.get("/api/v1/inventory/sbom/licenses"),
  ingest: (data: unknown) => api.post("/api/v1/inventory/sbom/ingest", data),
  correlate: (data: unknown) => api.post("/api/v1/sbom/correlate", data),
  generate: (params?: Record<string, string>) => api.post("/api/v1/sbom/generate", null, { params }),
  export: (params?: Record<string, string>) => api.get("/api/v1/sbom/export", { params }),
};

export const cspmApi = {
  status: () => api.get("/api/v1/cspm/status"),
  rules: () => api.get("/api/v1/cspm/rules"),
  scanTerraform: (data: unknown) => api.post("/api/v1/cspm/scan/terraform", data),
  scanCloudformation: (data: unknown) => api.post("/api/v1/cspm/scan/cloudformation", data),
};

export const containerApi = {
  status: () => api.get("/api/v1/container/status"),
  scanImage: (data: unknown) => api.post("/api/v1/container/scan/image", data),
  scanDockerfile: (data: unknown) => api.post("/api/v1/container/scan/dockerfile", data),
};

export const sastApi = {
  status: () => api.get("/api/v1/sast/status"),
  rules: () => api.get("/api/v1/sast/rules"),
  scanCode: (data: unknown) => api.post("/api/v1/sast/scan/code", data),
  scanFiles: (data: unknown) => api.post("/api/v1/sast/scan/files", data),
};

export const attackSimApi = {
  campaigns: () => api.get("/api/v1/attack-sim/campaigns"),
  scenarios: () => api.get("/api/v1/attack-sim/scenarios"),
  mitreHeatmap: () => api.get("/api/v1/attack-sim/mitre/heatmap"),
  mitreTechniques: () => api.get("/api/v1/attack-sim/mitre/techniques"),
  runCampaign: (data: unknown) => api.post("/api/v1/attack-sim/campaigns/run", data),
};

export const deduplicationApi = {
  clusters: (params?: Record<string, unknown>) => api.get("/api/v1/deduplication/clusters", { params: { ...params, org_id: (params?.org_id as string) || "default" } }),
  stats: () => api.get("/api/v1/deduplication/stats"),
  graph: () => api.get("/api/v1/deduplication/graph"),
  status: () => api.get("/api/v1/deduplication/status"),
};

export const webhookEventsApi = {
  list: (params?: Record<string, unknown>) => api.get("/api/v1/webhooks/events", { params }),
};

export const webhooksApi = {
  /** GET /api/v1/webhooks/?org_id=&limit= → { org_id, items: WebhookEvent[], count } */
  list: (params?: { org_id?: string; limit?: number }) =>
    api.get("/api/v1/webhooks/", { params }),
};

export const vulnIntelApi = {
  index: (orgId = "default") => api.get(`/api/v1/vuln-intel/`, { params: { org_id: orgId } }),
  stats: (orgId = "default") => api.get(`/api/v1/vuln-intel/stats`, { params: { org_id: orgId } }),
};

export const casesApi = {
  list: (params?: Record<string, unknown>) => api.get("/api/v1/cases", { params }),
  get: (id: string) => api.get(`/api/v1/cases/${id}`),
  stats: () => api.get("/api/v1/cases/stats/summary"),
  transition: (caseId: string, action: string) => api.post(`/api/v1/cases/${caseId}/transition`, { action }),
  update: (caseId: string, data: Record<string, unknown>) => api.patch(`/api/v1/cases/${caseId}`, data),
};

export default api;

// ── Bulk Operations ──
export const bulkApi = {
  triage: (ids: string[], action: string, status?: string) =>
    api.post("/api/v1/bulk/triage", { finding_ids: ids, action, status }),
  updateFindings: (ids: string[], updates: Record<string, unknown>) =>
    api.post("/api/v1/bulk/findings/update", { ids, updates }),
  assignFindings: (ids: string[], assignee: string) =>
    api.post("/api/v1/bulk/findings/assign", { ids, assignee }),
  deleteFindings: (ids: string[]) =>
    api.post("/api/v1/bulk/findings/delete", { ids }),
};

// ── Analytics / Findings detail ──
export const analyticsApi = {
  findings: (params?: Record<string, unknown>) => api.get("/api/v1/analytics/findings", { params }),
  getFinding: (id: string) => api.get(`/api/v1/analytics/findings/${id}`),
  triageFunnel: () => api.get("/api/v1/analytics/triage-funnel"),
};

// ── AutoFix ──
export const autofixApi = {
  generate: (findingId: string) => api.post("/api/v1/autofix/generate", { finding_id: findingId }),
  bulkGenerate: (findings: Record<string, unknown>[]) => api.post("/api/v1/autofix/generate/bulk", { findings }),
  suggestions: (findingId: string) => api.get(`/api/v1/autofix/suggestions/${findingId}`),
  apply: (fixId: string) => api.post(`/api/v1/autofix/apply`, { fix_id: fixId }),
  preview: (fixId: string) => api.get(`/api/v1/autofix/preview/${fixId}`),
};

// ── Brain / Pipeline ──
export const brainApi = {
  status: () => api.get("/api/v1/brain/status"),
  stats: () => api.get("/api/v1/brain/stats"),
  pipelineRun: (data?: unknown) => api.post("/api/v1/brain/pipeline/run", data || {}),
  pipelineStatus: () => api.get("/api/v1/brain/pipeline/status"),
  ingestFinding: (data: unknown) => api.post("/api/v1/brain/ingest/finding", data),
  evidenceGenerate: (data: unknown) => api.post("/api/v1/brain/evidence/generate", data),
};

// ── LLM Providers ──
export const llmApi = {
  providers: () => api.get("/api/v1/llm/providers"),
  status: () => api.get("/api/v1/llm/status"),
  consensus: (data: unknown) => api.post("/api/v1/llm/consensus", data),
};

// ── ML / MindsDB ──
export const mlApi = {
  models: () => api.get("/api/v1/ml/models"),
  status: () => api.get("/api/v1/ml/status"),
  train: (modelId: string, data?: unknown) => api.post(`/api/v1/ml/models/${modelId}/train`, data || {}),
  predict: (modelId: string, data: unknown) => api.post(`/api/v1/ml/models/${modelId}/predict`, data),
};

// ── Marketplace ──
export const marketplaceApi = {
  browse: (params?: Record<string, unknown>) => api.get("/api/v1/marketplace/browse", { params }),
  stats: () => api.get("/api/v1/marketplace/stats"),
  recommendations: () => api.get("/api/v1/marketplace/recommendations"),
  getItem: (itemId: string) => api.get(`/api/v1/marketplace/items/${itemId}`),
  rateItem: (itemId: string, rating: number) => api.post(`/api/v1/marketplace/items/${itemId}/rate`, { rating }),
  purchase: (itemId: string) => api.post(`/api/v1/marketplace/purchase/${itemId}`),
  contribute: (data: unknown) => api.post("/api/v1/marketplace/contribute", data),
  contributors: () => api.get("/api/v1/marketplace/contributors"),
};

// ── Access Control Matrix ──
export const accessMatrixApi = {
  /** GET /api/v1/access-matrix/ — stats + resource types */
  index: (orgId = "default") =>
    api.get("/api/v1/access-matrix/", { params: { org_id: orgId } }),
  /** GET /api/v1/access-matrix/stats */
  stats: (orgId = "default") =>
    api.get("/api/v1/access-matrix/stats", { params: { org_id: orgId } }),
  /** GET /api/v1/access-matrix/matrix — full roles × resource-types grid */
  matrix: (orgId = "default") =>
    api.get("/api/v1/access-matrix/matrix", { params: { org_id: orgId } }),
  /** GET /api/v1/access-matrix/rules */
  rules: (orgId = "default") =>
    api.get("/api/v1/access-matrix/rules", { params: { org_id: orgId } }),
  /** GET /api/v1/access-matrix/permissions/:role */
  permissions: (role: string, orgId = "default") =>
    api.get(`/api/v1/access-matrix/permissions/${role}`, { params: { org_id: orgId } }),
};

// ── MCP (Model Context Protocol) ──
export const mcpApi = {
  status: () => api.get("/api/v1/mcp-protocol/status"),
  stats: () => api.get("/api/v1/mcp-protocol/stats"),
  tools: () => api.get("/api/v1/mcp-protocol/tools"),
  resources: () => api.get("/api/v1/mcp-protocol/resources"),
  prompts: () => api.get("/api/v1/mcp-protocol/prompts"),
  callTool: (toolName: string, args: Record<string, unknown>) =>
    api.post("/api/v1/mcp/tools/call", { tool_name: toolName, arguments: args }),
  registerClient: (clientName: string, capabilities?: Record<string, unknown>) =>
    api.post("/api/v1/mcp/clients/register", { client_name: clientName, capabilities }),
  discover: () => api.post("/api/v1/mcp-protocol/discover"),
};
