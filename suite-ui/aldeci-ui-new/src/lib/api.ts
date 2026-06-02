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

export function getStoredAuthToken() {
  // Returns the token from localStorage only — no hardcoded fallback.
  // A hardcoded key here would make every production visitor an authenticated
  // admin without any login. VITE_API_KEY is intentionally blanked in
  // .env.production so nothing leaks into the prod bundle either.
  return getStoredValue(AUTH_TOKEN_STORAGE_KEY);
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

// ── JWT access token: kept in memory only (XSS-safe) ──
const JWT_REFRESH_KEY = "aldeci.refreshToken";

let _jwtAccessToken: string | null = null;

export function getJwtAccessToken(): string | null {
  return _jwtAccessToken;
}

export function setJwtAccessToken(token: string | null) {
  _jwtAccessToken = token;
}

export function getJwtRefreshToken(): string | null {
  return getStoredValue(JWT_REFRESH_KEY) || null;
}

export function setJwtRefreshToken(token: string | null) {
  setStoredValue(JWT_REFRESH_KEY, token);
}

export function clearJwtTokens() {
  _jwtAccessToken = null;
  setStoredValue(JWT_REFRESH_KEY, null);
}

// ── Request interceptor: attach JWT Bearer if access token in memory ──
api.interceptors.request.use((config) => {
  const access = _jwtAccessToken;
  if (access && getStoredAuthStrategy() === "jwt") {
    config.headers = config.headers ?? {};
    config.headers.Authorization = `Bearer ${access}`;
  }
  return config;
});

// ── Response interceptor: 401 → try refresh → redirect to /login ──
let _refreshPromise: Promise<void> | null = null;

api.interceptors.response.use(
  (res) => res,
  async (err) => {
    const originalRequest = err.config as typeof err.config & { _retried?: boolean };
    const status = err.response?.status;

    if (status === 401 && !originalRequest._retried && getStoredAuthStrategy() === "jwt") {
      originalRequest._retried = true;

      // Deduplicate concurrent refresh attempts
      if (!_refreshPromise) {
        _refreshPromise = (async () => {
          try {
            const refresh = getJwtRefreshToken();
            if (!refresh) throw new Error("no refresh token");
            const res = await api.post("/api/v1/auth/refresh", { refresh_token: refresh });
            const newAccess = res.data?.access_token as string | undefined;
            if (!newAccess) throw new Error("no access_token in refresh response");
            setJwtAccessToken(newAccess);
            // Update legacy token store so existing request interceptor stays in sync
            setStoredAuthToken(newAccess);
          } finally {
            _refreshPromise = null;
          }
        })();
      }

      try {
        await _refreshPromise;
        // Retry original request with new access token
        return api(originalRequest);
      } catch {
        // Refresh failed — clear session and redirect
        clearJwtTokens();
        setStoredAuthToken(null);
        const next = encodeURIComponent(window.location.pathname + window.location.search);
        window.location.assign(`/login?next=${next}`);
        return Promise.reject(err);
      }
    }

    if (status === 401) {
      // Redirect to login on any 401 — no localStorage escape hatch.
      // In dev, isDevBypassActive() in auth.tsx prevents real 401s from
      // occurring so this path is not reached during local development.
      const next = encodeURIComponent(window.location.pathname + window.location.search);
      window.location.assign(`/login?next=${next}`);
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
  exportFramework: (framework: string) =>
    api.post("/api/v1/audit-evidence/export", { framework }, { responseType: "blob" }),
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
  status: () => api.get("/api/v1/integrations/health"),
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

// ── Auth API (JWT login + token refresh) ──
export const authApi = {
  login: (data: { email: string; password: string }) =>
    api.post<{ access_token: string; refresh_token: string; token_type: string; user: AuthUser }>(
      "/api/v1/auth/login",
      data,
    ),
  refresh: (refresh_token: string) =>
    api.post<{ access_token: string }>("/api/v1/auth/refresh", { refresh_token }),
};

// AuthUser minimal type for authApi response (avoids circular import with auth.tsx)
interface AuthUser {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  role: string;
  department?: string;
}

export const usersApi = {
  login: (data: { email: string; password: string }) => api.post("/api/v1/auth/login", data),
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

export const apiKeysApi = {
  list: (params?: { include_revoked?: boolean; user_id?: string }) =>
    api.get("/api/v1/auth/keys", { params }),
  create: (data: { name: string; user_id: string; role?: string; scopes?: string[]; ttl_days?: number | null }) =>
    api.post<{ id: string; key_prefix: string; name: string; user_id: string; role: string; scopes: string[]; is_active: boolean; created_at: string; expires_at: string | null; last_used_at: string | null; plaintext_key: string }>("/api/v1/auth/keys", data),
  revoke: (keyId: string) => api.delete(`/api/v1/auth/keys/${keyId}`),
  expiring: (withinDays = 7) => api.get("/api/v1/auth/keys/expiring", { params: { within_days: withinDays } }),
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
  /** GET /api/v1/audit/compliance/controls — control-by-control status for AuditorEvidenceHub */
  auditControls: (params?: Record<string, unknown>) => api.get("/api/v1/audit/compliance/controls", { params }),
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

// ── Finance domain APIs ──────────────────────────────────────────────────────

export const fairApi = {
  businessUnits: (orgId = "default") =>
    api.get("/api/v1/fair/business-units", { params: { org_id: orgId } }),
  stats: (orgId = "default") =>
    api.get("/api/v1/fair/stats", { params: { org_id: orgId } }),
  roiTrend: (orgId = "default", windowDays = 90) =>
    api.get("/api/v1/fair/roi-trend", { params: { org_id: orgId, window_days: windowDays } }),
  computePerBuRisk: (data: unknown, orgId = "default") =>
    api.post("/api/v1/fair/per-bu-risk", data, { params: { org_id: orgId } }),
};

export const securityBudgetApi = {
  stats: (orgId = "default", fiscalYear?: number) =>
    api.get("/api/v1/security-budget/stats", {
      params: { org_id: orgId, ...(fiscalYear ? { fiscal_year: fiscalYear } : {}) },
    }),
  allocations: (orgId = "default", fiscalYear?: number, category?: string) =>
    api.get("/api/v1/security-budget/allocations", {
      params: {
        org_id: orgId,
        ...(fiscalYear ? { fiscal_year: fiscalYear } : {}),
        ...(category ? { category } : {}),
      },
    }),
  transactions: (orgId = "default") =>
    api.get("/api/v1/security-budget/transactions", { params: { org_id: orgId } }),
  roiAssessments: (orgId = "default") =>
    api.get("/api/v1/security-budget/roi-assessments", { params: { org_id: orgId } }),
};

export const incidentCostsApi = {
  analytics: (orgId = "default") =>
    api.get("/api/v1/incident-costs/analytics", { params: { org_id: orgId } }),
  summaries: (orgId = "default", incidentType?: string, severity?: string) =>
    api.get("/api/v1/incident-costs/summaries", {
      params: {
        org_id: orgId,
        ...(incidentType ? { incident_type: incidentType } : {}),
        ...(severity ? { severity } : {}),
      },
    }),
};

export const cyberInsuranceApi = {
  stats: (orgId = "default") =>
    api.get("/api/v1/cyber-insurance/stats", { params: { org_id: orgId } }),
  policies: (orgId = "default") =>
    api.get("/api/v1/cyber-insurance/policies", { params: { org_id: orgId } }),
  claims: (orgId = "default", status?: string) =>
    api.get("/api/v1/cyber-insurance/claims", {
      params: { org_id: orgId, ...(status ? { status } : {}) },
    }),
  assessments: (orgId = "default") =>
    api.get("/api/v1/cyber-insurance/assessments", { params: { org_id: orgId } }),
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

export const riskQuantApi = {
  // /api/v1/risk-quantification (FAIR scenarios + treatments + financial impacts)
  listScenarios: (orgId = "default") =>
    api.get("/api/v1/risk-quantification/scenarios", { params: { org_id: orgId } }),
  stats: (orgId = "default") =>
    api.get("/api/v1/risk-quantification/stats", { params: { org_id: orgId } }),
  treatments: (orgId = "default", scenarioId?: string) =>
    api.get("/api/v1/risk-quantification/treatments", {
      params: { org_id: orgId, ...(scenarioId ? { scenario_id: scenarioId } : {}) },
    }),
  financialImpacts: (orgId = "default") =>
    api.get("/api/v1/risk-quantification/financial-impacts", { params: { org_id: orgId } }),
  // /api/v1/risk-quantifier (Monte Carlo engine)
  portfolio: (orgId = "default") =>
    api.get("/api/v1/risk-quantifier/portfolio", { params: { org_id: orgId } }),
  heatmap: (orgId = "default") =>
    api.get("/api/v1/risk-quantifier/heatmap", { params: { org_id: orgId } }),
  quantifierScenarios: (orgId = "default") =>
    api.get("/api/v1/risk-quantifier/scenarios", { params: { org_id: orgId } }),
  roi: (orgId = "default") =>
    api.get("/api/v1/risk-quantifier/roi", { params: { org_id: orgId } }),
  // /api/v1/risk-scenarios (scenario lifecycle engine)
  scenariosList: (orgId = "default") =>
    api.get("/api/v1/risk-scenarios/scenarios", { params: { org_id: orgId } }),
  topRisks: (orgId = "default", limit = 10) =>
    api.get("/api/v1/risk-scenarios/top-risks", { params: { org_id: orgId, limit } }),
  riskReduction: (orgId = "default") =>
    api.get("/api/v1/risk-scenarios/risk-reduction", { params: { org_id: orgId } }),
  scenarioStats: (orgId = "default") =>
    api.get("/api/v1/risk-scenarios/stats", { params: { org_id: orgId } }),
};

export const threatFeedsApi = {
  list: (params?: Record<string, string>) => api.get("/api/v1/feeds", { params }),
  trending: () => api.get("/api/v1/feeds/trending"),
  epss: (cveIds: string) => api.get("/api/v1/feeds/epss", { params: { cve_ids: cveIds } }),
  kev: (cveId?: string) => api.get("/api/v1/threat-intel/kev", { params: cveId ? { cve_id: cveId } : undefined }),
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
  // Scanner endpoints
  root: (params?: Record<string, unknown>) => api.get("/api/v1/secrets/", { params }),
  active: (params?: Record<string, unknown>) => api.get("/api/v1/secrets/active", { params }),
  rotationStatus: (params?: Record<string, unknown>) => api.get("/api/v1/secrets/rotation-status", { params }),
  patterns: () => api.get("/api/v1/secrets/patterns"),
  markFalsePositive: (id: string) => api.post(`/api/v1/secrets/${id}/false-positive`),
  rotate: (id: string, data: unknown) => api.post(`/api/v1/secrets/${id}/rotate`, data),
};

export const sbomApi = {
  components: (params?: Record<string, unknown>) => api.get("/api/v1/inventory/sbom/components", { params }),
  licenses: () => api.get("/api/v1/inventory/sbom/licenses"),
  ingest: (data: unknown) => api.post("/api/v1/inventory/sbom/ingest", data),
  correlate: (data: unknown) => api.post("/api/v1/sbom/correlate", data),
  generate: (params?: Record<string, string>) => api.post("/api/v1/sbom/generate", null, { params }),
  export: (params?: Record<string, string>) => api.get("/api/v1/sbom/export", { params }),
};

export const sbomExportApi = {
  list: (orgId = "default") => api.get("/api/v1/sbom-export/", { params: { org_id: orgId } }),
  projects: (orgId = "default") => api.get("/api/v1/sbom-export/projects", { params: { org_id: orgId } }),
  projectSummary: (project: string, orgId = "default") =>
    api.get(`/api/v1/sbom-export/projects/${encodeURIComponent(project)}/summary`, { params: { org_id: orgId } }),
  history: (project: string, orgId = "default") =>
    api.get(`/api/v1/sbom-export/projects/${encodeURIComponent(project)}/history`, { params: { org_id: orgId } }),
};

export const pbomApi = {
  stats: (orgId = "default") => api.get("/api/v1/pbom/stats", { params: { org_id: orgId } }),
  artifactProvenance: (sha256: string, orgId = "default") =>
    api.get(`/api/v1/pbom/artifact/${encodeURIComponent(sha256)}/provenance`, { params: { org_id: orgId } }),
  exportRun: (runId: string) => api.get(`/api/v1/pbom/run/${encodeURIComponent(runId)}/export`),
};

export const slsaApi = {
  stats: (orgId = "default") => api.get("/api/v1/slsa/stats", { params: { org_id: orgId } }),
  attestations: (orgId = "default", filters?: { subject_name?: string; builder_id?: string }) =>
    api.get("/api/v1/slsa/attestations", { params: { org_id: orgId, ...filters } }),
  getAttestation: (id: string) => api.get(`/api/v1/slsa/attestations/${encodeURIComponent(id)}`),
  /** POST /api/v1/slsa/attest — generate a new in-toto SLSA v0.2 attestation */
  attest: (payload: {
    subject_name: string;
    subject_digest: string;
    builder_id?: string;
    build_type?: string;
    slsa_level?: number;
    org_id?: string;
  }) => api.post("/api/v1/slsa/attest", payload),
  /** POST /api/v1/slsa/verify/{id} — verify an attestation by id */
  verify: (attestationId: string, verifier = "internal") =>
    api.post(`/api/v1/slsa/verify/${encodeURIComponent(attestationId)}`, null, {
      params: { verifier },
    }),
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

/** Container image / build scanning — /api/v1/containers (container_scanner_router) */
export const containerScannerApi = {
  stats: (org_id = "default") => api.get("/api/v1/containers/stats", { params: { org_id } }),
  history: (org_id = "default", limit = 50) => api.get("/api/v1/containers/history", { params: { org_id, limit } }),
  checks: () => api.get("/api/v1/containers/checks"),
};

/** Container workload protection — /api/v1/cwpp */
export const cwppApi = {
  summary: (org_id = "default") => api.get("/api/v1/cwpp/summary", { params: { org_id } }),
  workloads: (org_id = "default", limit = 50) => api.get("/api/v1/cwpp/workloads", { params: { org_id, limit } }),
  threats: (org_id = "default", limit = 50) => api.get("/api/v1/cwpp/threats", { params: { org_id, limit } }),
};

/** Container posture — /api/v1/container-posture */
export const containerPostureApi = {
  stats: (org_id = "default") => api.get("/api/v1/container-posture/stats", { params: { org_id } }),
  clusters: (org_id = "default") => api.get("/api/v1/container-posture/clusters", { params: { org_id } }),
  findings: (org_id = "default", limit = 50) => api.get("/api/v1/container-posture/findings", { params: { org_id, limit } }),
};

/** Data discovery — /api/v1/data-discovery */
export const dataDiscoveryApi = {
  stats: (org_id = "default") => api.get("/api/v1/data-discovery/stats", { params: { org_id } }),
  datastores: (org_id = "default", limit = 50) => api.get("/api/v1/data-discovery/datastores", { params: { org_id, limit } }),
  discoveries: (org_id = "default", limit = 50) => api.get("/api/v1/data-discovery/discoveries", { params: { org_id, limit } }),
  scans: (org_id = "default") => api.get("/api/v1/data-discovery/scans", { params: { org_id } }),
};

/** Data exfiltration — /api/v1/data-exfiltration */
export const dataExfiltrationApi = {
  stats: (org_id = "default") => api.get("/api/v1/data-exfiltration/stats", { params: { org_id } }),
  incidents: (org_id = "default", limit = 50) => api.get("/api/v1/data-exfiltration/incidents", { params: { org_id, limit } }),
  policies: (org_id = "default") => api.get("/api/v1/data-exfiltration/policies", { params: { org_id } }),
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
  /** /api/v1/vuln-intel/ has no GET root — use /cves which is the actual list endpoint */
  index: (orgId = "default") => api.get(`/api/v1/vuln-intel/cves`, { params: { org_id: orgId } }),
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

// ── EPSS (Exploit Prediction Scoring System) ──
export const epssApi = {
  /** GET /api/v1/epss/scores — list scores ordered by epss_score DESC */
  scores: (params?: { cve_id?: string; epss_min?: number; percentile_min?: number; page?: number; page_size?: number }) =>
    api.get("/api/v1/epss/scores", { params }),
  /** GET /api/v1/epss/scores/{cve_id} — score for a single CVE */
  byCve: (cveId: string) => api.get(`/api/v1/epss/scores/${encodeURIComponent(cveId)}`),
  /** POST /api/v1/epss/import — trigger FIRST.org daily CSV import */
  triggerImport: () => api.post("/api/v1/epss/import"),
};

// ── Webhook DLQ (Dead Letter Queue) ──
export const webhookDlqApi = {
  /** GET /api/v1/webhooks/dlq/ — list all deliveries */
  list: (params?: { limit?: number; offset?: number }) =>
    api.get("/api/v1/webhooks/dlq/", { params }),
  /** GET /api/v1/webhooks/dlq/pending — deliveries ready for retry */
  pending: (params?: { limit?: number }) =>
    api.get("/api/v1/webhooks/dlq/pending", { params }),
  /** GET /api/v1/webhooks/dlq/stats — DLQ status counts */
  stats: () => api.get("/api/v1/webhooks/dlq/stats"),
  /** POST /api/v1/webhooks/dlq/{delivery_id}/replay — replay single delivery */
  replay: (deliveryId: string) =>
    api.post(`/api/v1/webhooks/dlq/${encodeURIComponent(deliveryId)}/replay`),
};

// ── Deception Analytics ──
export const deceptionAnalyticsApi = {
  /** GET /api/v1/deception-analytics/stats */
  stats: (orgId = "default") =>
    api.get("/api/v1/deception-analytics/stats", { params: { org_id: orgId } }),
  /** GET /api/v1/deception-analytics/assets */
  assets: (orgId = "default", assetType?: string, active?: boolean) =>
    api.get("/api/v1/deception-analytics/assets", {
      params: { org_id: orgId, asset_type: assetType, active },
    }),
  /** GET /api/v1/deception-analytics/interactions */
  interactions: (orgId = "default") =>
    api.get("/api/v1/deception-analytics/interactions", { params: { org_id: orgId } }),
};

// ── Identity Governance ──
export const identityGovernanceApi = {
  /** GET /api/v1/identity-governance/reviews */
  reviews: (orgId: string, status?: string) =>
    api.get("/api/v1/identity-governance/reviews", { params: { org_id: orgId, status } }),
  /** GET /api/v1/identity-governance/entitlements */
  entitlements: (orgId: string, isOrphaned?: boolean, isExcessive?: boolean) =>
    api.get("/api/v1/identity-governance/entitlements", {
      params: { org_id: orgId, is_orphaned: isOrphaned, is_excessive: isExcessive },
    }),
  /** GET /api/v1/identity-governance/stats */
  stats: (orgId: string) =>
    api.get("/api/v1/identity-governance/stats", { params: { org_id: orgId } }),
};

// ── MCP (Model Context Protocol) ──
export const assetGroupsApi = {
  list: (params?: Record<string, string>) => api.get("/api/v1/asset-groups/groups", { params }),
  stats: (orgId = "default") => api.get("/api/v1/asset-groups/stats", { params: { org_id: orgId } }),
};

export const assetTagsApi = {
  listTags: (orgId = "default") => api.get("/api/v1/asset-tags/tags", { params: { org_id: orgId } }),
  stats: (orgId = "default") => api.get("/api/v1/asset-tags/stats", { params: { org_id: orgId } }),
};

export const assetCriticalityApi = {
  list: (orgId = "default") => api.get("/api/v1/asset-criticality/assets", { params: { org_id: orgId } }),
  summary: (orgId = "default") => api.get("/api/v1/asset-criticality/summary", { params: { org_id: orgId } }),
};

export const cmdbApi = {
  listCIs: (params?: Record<string, string>) => api.get("/api/v1/cmdb/cis", { params }),
  listChanges: (orgId = "default") => api.get("/api/v1/cmdb/changes", { params: { org_id: orgId } }),
  stats: (orgId = "default") => api.get("/api/v1/cmdb/stats", { params: { org_id: orgId } }),
};

export const assetRiskApi = {
  listAssets: (orgId = "default", assetType?: string, criticality?: string) =>
    api.get("/api/v1/asset-risk/assets", { params: { org_id: orgId, asset_type: assetType, criticality } }),
  listScores: (orgId = "default", riskLevel?: string) =>
    api.get("/api/v1/asset-risk/scores", { params: { org_id: orgId, risk_level: riskLevel } }),
  stats: (orgId = "default") =>
    api.get("/api/v1/asset-risk/stats", { params: { org_id: orgId } }),
};

export const cloudInventoryApi = {
  listResources: (orgId = "default", provider?: string, resourceType?: string) =>
    api.get("/api/v1/cloud-inventory/resources", {
      params: { org_id: orgId, provider, resource_type: resourceType },
    }),
  listFindings: (orgId = "default", severity?: string) =>
    api.get("/api/v1/cloud-inventory/findings", { params: { org_id: orgId, severity } }),
  stats: (orgId = "default") =>
    api.get("/api/v1/cloud-inventory/stats", { params: { org_id: orgId } }),
};

export const agentlessSnapshotApi = {
  listSnapshots: (orgId = "default", provider?: string, scanStatus?: string) =>
    api.get("/api/v1/agentless-snapshot/snapshots", {
      params: { org_id: orgId, provider, scan_status: scanStatus },
    }),
  listFindings: (orgId = "default", severity?: string) =>
    api.get("/api/v1/agentless-snapshot/findings", { params: { org_id: orgId, severity } }),
  stats: (orgId = "default") =>
    api.get("/api/v1/agentless-snapshot/stats", { params: { org_id: orgId } }),
};

export const cloudAccountsApi = {
  listAccounts: (orgId = "default", provider?: string) =>
    api.get("/api/v1/cloud-accounts/accounts", { params: { org_id: orgId, provider } }),
  riskSummary: (orgId = "default") =>
    api.get("/api/v1/cloud-accounts/risk-summary", { params: { org_id: orgId } }),
  unresolvedEvents: (orgId = "default", severity?: string) =>
    api.get("/api/v1/cloud-accounts/events/unresolved", { params: { org_id: orgId, severity } }),
};

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

// ── Upgrade Path Resolver ──
export const upgradePathApi = {
  /** GET /api/v1/upgrade-path/stats — resolution counts + rate */
  stats: (orgId?: string) =>
    api.get("/api/v1/upgrade-path/stats", { params: orgId ? { org_id: orgId } : {} }),
  /** POST /api/v1/upgrade-path/resolve — resolve single purl */
  resolve: (orgId: string, purl: string, cveIds: string[]) =>
    api.post("/api/v1/upgrade-path/resolve", { org_id: orgId, purl, cve_ids: cveIds }),
  /** POST /api/v1/upgrade-path/bulk-resolve — batch resolve */
  bulkResolve: (orgId: string, findings: Array<{ purl: string; cve_ids: string[] }>) =>
    api.post("/api/v1/upgrade-path/bulk-resolve", { org_id: orgId, findings }),
};

// ── Network Topology ──
export const networkTopologyApi = {
  /** GET /api/v1/network-topology/stats */
  stats: (orgId = "default") =>
    api.get("/api/v1/network-topology/stats", { params: { org_id: orgId } }),
  /** GET /api/v1/network-topology/nodes */
  nodes: (orgId = "default", nodeType?: string, criticality?: string) =>
    api.get("/api/v1/network-topology/nodes", {
      params: { org_id: orgId, node_type: nodeType, criticality },
    }),
  /** GET /api/v1/network-topology/segments */
  segments: (orgId = "default") =>
    api.get("/api/v1/network-topology/segments", { params: { org_id: orgId } }),
  /** GET /api/v1/network-topology/exposure */
  exposure: (orgId = "default") =>
    api.get("/api/v1/network-topology/exposure", { params: { org_id: orgId } }),
};

// ── Binary Fingerprint ──
export const binaryFpApi = {
  /** GET /api/v1/binary-fp/stats — fingerprint counters per org */
  stats: (orgId = "default") =>
    api.get("/api/v1/binary-fp/stats", { params: { org_id: orgId } }),
};

// ── Threat Actors ──
export const threatActorsApi = {
  list: (orgId = "default", actorType?: string, active?: boolean) =>
    api.get("/api/v1/threat-actors/actors", {
      params: { org_id: orgId, actor_type: actorType, active },
    }),
  stats: (orgId = "default") =>
    api.get("/api/v1/threat-actors/stats", { params: { org_id: orgId } }),
  watchlist: (orgId = "default") =>
    api.get("/api/v1/threat-actors/watchlist", { params: { org_id: orgId } }),
  iocs: (orgId = "default", actorId?: string) =>
    api.get("/api/v1/threat-actors/iocs", { params: { org_id: orgId, actor_id: actorId } }),
};

// ── Threat Attribution ──
export const threatAttributionApi = {
  listActors: (orgId = "default", actorType?: string, active?: boolean) =>
    api.get("/api/v1/threat-attribution/actors", {
      params: { org_id: orgId, actor_type: actorType, active },
    }),
  listAttributions: (orgId = "default", status?: string, confidence?: string) =>
    api.get("/api/v1/threat-attribution/attributions", {
      params: { org_id: orgId, status, confidence },
    }),
  stats: (orgId = "default") =>
    api.get("/api/v1/threat-attribution/stats", { params: { org_id: orgId } }),
};

// ── Threat Indicators ──
export const threatIndicatorsApi = {
  list: (orgId = "default", indicatorType?: string, severity?: string) =>
    api.get("/api/v1/threat-indicators/indicators", {
      params: { org_id: orgId, indicator_type: indicatorType, severity },
    }),
  summary: (orgId = "default") =>
    api.get("/api/v1/threat-indicators/summary", { params: { org_id: orgId } }),
  search: (orgId = "default", query: string) =>
    api.get("/api/v1/threat-indicators/search", { params: { org_id: orgId, query } }),
};

// ── IOC Enrichment ──
export const iocEnrichmentApi = {
  list: (orgId = "default", iocType?: string, severity?: string, limit = 50) =>
    api.get("/api/v1/ioc-enrichment/iocs", {
      params: { org_id: orgId, ioc_type: iocType, severity, limit },
    }),
  stats: (orgId = "default") =>
    api.get("/api/v1/ioc-enrichment/stats", { params: { org_id: orgId } }),
  enrich: (iocId: string, orgId = "default") =>
    api.post(`/api/v1/ioc-enrichment/iocs/${iocId}/enrich`, null, {
      params: { org_id: orgId },
    }),
};

// ── Actor Tracking ──
export const actorTrackingApi = {
  list: (orgId = "default", actorType?: string, threatLevel?: string) =>
    api.get("/api/v1/actor-tracking/actors", {
      params: { org_id: orgId, actor_type: actorType, threat_level: threatLevel },
    }),
  summary: (orgId = "default") =>
    api.get("/api/v1/actor-tracking/summary", { params: { org_id: orgId } }),
  activeThreats: (orgId = "default") =>
    api.get("/api/v1/actor-tracking/active", { params: { org_id: orgId } }),
  ttpSummary: (orgId = "default") =>
    api.get("/api/v1/actor-tracking/ttp-summary", { params: { org_id: orgId } }),
};

// ── Crypto Key Management ──
export const cryptoKeysApi = {
  list: (orgId = "default", status?: string) =>
    api.get("/api/v1/crypto-keys/", { params: { org_id: orgId, status } }),
  stats: (orgId = "default") =>
    api.get("/api/v1/crypto-keys/stats", { params: { org_id: orgId } }),
  expiring: (orgId = "default", days = 30) =>
    api.get("/api/v1/crypto-keys/expiring", { params: { org_id: orgId, days } }),
  rotate: (keyId: string) =>
    api.post(`/api/v1/crypto-keys/${keyId}/rotate`),
};

// ── Certificates ──
export const certificatesApi = {
  list: (orgId = "default", certType?: string, status?: string) =>
    api.get("/api/v1/certificates/", { params: { org_id: orgId, cert_type: certType, status } }),
  stats: (orgId = "default") =>
    api.get("/api/v1/certificates/stats", { params: { org_id: orgId } }),
  expiryAlerts: (orgId = "default") =>
    api.get("/api/v1/certificates/alerts/expiry", { params: { org_id: orgId } }),
  weak: (orgId = "default") =>
    api.get("/api/v1/certificates/weak", { params: { org_id: orgId } }),
  check: (domain: string, port = 443) =>
    api.post("/api/v1/certificates/check", { domain, port }),
};

// ── PKI Management ──
export const pkiApi = {
  stats: (orgId = "default") =>
    api.get("/api/v1/pki/stats", { params: { org_id: orgId } }),
  listCAs: (orgId = "default") =>
    api.get("/api/v1/pki/cas", { params: { org_id: orgId } }),
  listCertificates: (orgId = "default", caId?: string) =>
    api.get("/api/v1/pki/certificates", { params: { org_id: orgId, ca_id: caId } }),
  expiringCerts: (orgId = "default", days = 30) =>
    api.get("/api/v1/pki/certificates/expiring", { params: { org_id: orgId, days } }),
};

// ── Quantum Crypto ──
export const quantumCryptoApi = {
  health: () => api.get("/api/v1/quantum-crypto/health"),
  status: () => api.get("/api/v1/quantum-crypto/status"),
  keys: () => api.get("/api/v1/quantum-crypto/keys"),
  rotateKeys: () => api.post("/api/v1/quantum-crypto/keys/rotate"),
};

// ── Secrets Rotation ──
export const secretsRotationApi = {
  list: (orgId = "default") =>
    api.get("/api/v1/secrets-rotation/", { params: { org_id: orgId } }),
  metrics: (orgId = "default") =>
    api.get("/api/v1/secrets-rotation/metrics", { params: { org_id: orgId } }),
  overdue: (orgId = "default") =>
    api.get("/api/v1/secrets-rotation/overdue", { params: { org_id: orgId } }),
};

// ── Security Investment ──
export const securityInvestmentApi = {
  portfolio: (orgId = "default") =>
    api.get("/api/v1/security-investment/portfolio", { params: { org_id: orgId } }),
  list: (orgId = "default", status?: string) =>
    api.get("/api/v1/security-investment/investments", { params: { org_id: orgId, status } }),
  budgetUtilization: (orgId = "default", fiscalYear?: number) =>
    api.get(`/api/v1/security-investment/budgets/${fiscalYear ?? new Date().getFullYear()}`, {
      params: { org_id: orgId },
    }),
};

// ── Feed Subscriptions ──
export const feedSubscriptionsApi = {
  list: (orgId = "default", status?: string) =>
    api.get("/api/v1/feed-subscriptions/subscriptions", { params: { org_id: orgId, status } }),
  stats: (orgId = "default") =>
    api.get("/api/v1/feed-subscriptions/stats", { params: { org_id: orgId } }),
  logs: (orgId = "default", limit = 50) =>
    api.get("/api/v1/feed-subscriptions/logs", { params: { org_id: orgId, limit } }),
  refresh: (subscriptionId: string, orgId = "default") =>
    api.post(`/api/v1/feed-subscriptions/subscriptions/${subscriptionId}/refresh`, null, {
      params: { org_id: orgId },
    }),
};

// ── Threat Briefs ──
export const threatBriefsApi = {
  list: (orgId = "default", tlp?: string, briefType?: string, limit = 50) =>
    api.get("/api/v1/threat-briefs/briefs", {
      params: { org_id: orgId, tlp, brief_type: briefType, limit },
    }),
  stats: (orgId = "default") =>
    api.get("/api/v1/threat-briefs/stats", { params: { org_id: orgId } }),
};

// ── Threat Response ──
export const threatResponseApi = {
  activeIncidents: (orgId = "default") =>
    api.get("/api/v1/threat-response/incidents/active", { params: { org_id: orgId } }),
  playbooks: (orgId = "default", status?: string) =>
    api.get("/api/v1/threat-response/playbooks", { params: { org_id: orgId, status } }),
  stats: (orgId = "default") =>
    api.get("/api/v1/threat-response/summary", { params: { org_id: orgId } }),
};

// ── Risk Overview (suite-evidence-risk) ──
export const riskOverviewApi = {
  /** GET /api/v1/risk/overview — overall risk posture summary */
  overview: () => api.get("/api/v1/risk/overview"),
  /** GET /api/v1/risk/scores — per-component risk scores */
  scores: (params?: Record<string, string>) =>
    api.get("/api/v1/risk/scores", { params }),
};

// ── Unified Rules Catalog (/api/v1/rules/unified) ──
export interface UnifiedRule {
  rule_key: string;
  domain: string;
  category: string;
  severity: string;
  rule_type: string;
  source_engine: string;
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface RuleTaxonomyCategory {
  rule_keys: string[];
  severity_distribution?: Record<string, number>;
}

export interface RuleTaxonomyDomain {
  categories: Record<string, RuleTaxonomyCategory>;
  rule_count?: number;
}

export interface RuleTaxonomy {
  domains: Record<string, RuleTaxonomyDomain>;
  total_rules?: number;
  generated_at?: string;
}

export const unifiedRulesApi = {
  /** GET /api/v1/rules/unified */
  list: (params?: { domain?: string; source_engine?: string; enabled?: boolean; org_id?: string }) =>
    api.get<UnifiedRule[]>("/api/v1/rules/unified", { params }),
  /** GET /api/v1/rules/unified/taxonomy */
  taxonomy: () => api.get<RuleTaxonomy>("/api/v1/rules/unified/taxonomy"),
  /** POST /api/v1/rules/unified/{rule_key}/enable */
  enable: (ruleKey: string, orgId = "default") =>
    api.post(`/api/v1/rules/unified/${encodeURIComponent(ruleKey)}/enable`, null, {
      params: { org_id: orgId },
    }),
  /** POST /api/v1/rules/unified/{rule_key}/disable */
  disable: (ruleKey: string, orgId = "default") =>
    api.post(`/api/v1/rules/unified/${encodeURIComponent(ruleKey)}/disable`, null, {
      params: { org_id: orgId },
    }),
};

// ── DSL Rules (/api/v1/rules/dsl) ──
export interface DslRule {
  key: string;
  status: string;
  severity?: string;
  version?: number;
  authored_by?: string;
  created_at?: string;
}

export interface DslSchemaField {
  name: string;
  type: string;
  required: boolean;
  description?: string;
}

export interface DslSchema {
  fields: DslSchemaField[];
  example?: string;
}

export interface DslValidateResult {
  valid: boolean;
  compiled?: Record<string, unknown>;
  errors?: string[];
  warnings?: string[];
}

export const dslRulesApi = {
  /** GET /api/v1/rules/dsl */
  list: (status?: string) =>
    api.get<DslRule[]>("/api/v1/rules/dsl", { params: status ? { status } : undefined }),
  /** GET /api/v1/rules/dsl/schema */
  schema: () => api.get<DslSchema>("/api/v1/rules/dsl/schema"),
  /** POST /api/v1/rules/dsl/validate */
  validate: (dsl_text: string, dsl_format: "yaml" | "json" = "yaml") =>
    api.post<DslValidateResult>("/api/v1/rules/dsl/validate", { dsl_text, dsl_format }),
  /** POST /api/v1/rules/dsl/publish */
  publish: (payload: {
    key: string;
    dsl_text: string;
    dsl_format?: string;
    severity?: string;
    authored_by?: string;
  }) => api.post("/api/v1/rules/dsl/publish", payload),
};

// ---------------------------------------------------------------------------
// Posture Score — /api/v1/posture-score
// ---------------------------------------------------------------------------

export interface PostureStats {
  current_score: number;
  grade: string;
  trend_30d: number | null;
  days_at_risk: number | null;
  computed_at: string | null;
}

export interface PostureComponent {
  // API (/api/v1/posture-score/components) returns id + component (not name).
  id: string;
  component: string;
  score: number;
  weight: number | null;
  source: string;
}

export const postureScoreApi = {
  /** GET /api/v1/posture-score/stats */
  stats: (org_id = "default") =>
    api.get<PostureStats>("/api/v1/posture-score/stats", { params: { org_id } }),
  /** GET /api/v1/posture-score/components */
  components: (org_id = "default") =>
    api.get<PostureComponent[]>("/api/v1/posture-score/components", { params: { org_id } }),
  /** GET /api/v1/posture-score/history */
  history: (org_id = "default", days = 30) =>
    api.get<Record<string, unknown>[]>("/api/v1/posture-score/history", { params: { org_id, days } }),
  /** POST /api/v1/posture-score/compute */
  compute: (org_id = "default", save = true) =>
    api.post("/api/v1/posture-score/compute", { org_id, save }),
};

// ---------------------------------------------------------------------------
// Security Roadmap — /api/v1/security-roadmap
// ---------------------------------------------------------------------------

export interface RoadmapInitiative {
  id?: string;
  title: string;
  description?: string;
  category?: string;
  priority?: string;
  status: string;
  owner?: string;
  budget_usd?: number;
  start_date?: string;
  target_date?: string;
  risk_reduction_score?: number;
}

export interface RoadmapGap {
  id?: string;
  title: string;
  description?: string;
  gap_type?: string;
  severity?: string;
  linked_initiative_id?: string;
}

export interface RoadmapStats {
  total_initiatives: number;
  in_progress: number;
  completed: number;
  open_gaps: number;
}

export const securityRoadmapApi = {
  /** GET /api/v1/security-roadmap/initiatives */
  initiatives: (params: { org_id: string; status?: string; category?: string }) =>
    api.get<RoadmapInitiative[]>("/api/v1/security-roadmap/initiatives", { params }),
  /** GET /api/v1/security-roadmap/gaps */
  gaps: (params: { org_id: string; severity?: string }) =>
    api.get<RoadmapGap[]>("/api/v1/security-roadmap/gaps", { params }),
  /** GET /api/v1/security-roadmap/stats */
  stats: (org_id: string) =>
    api.get<RoadmapStats>("/api/v1/security-roadmap/stats", { params: { org_id } }),
};

// ---------------------------------------------------------------------------
// GRC — /api/v1/grc
// ---------------------------------------------------------------------------

export interface GrcStats {
  total_frameworks: number;
  total_controls: number;
  implemented_controls: number;
  open_risks: number;
}

export interface GrcFramework {
  id?: string;
  framework_id?: string; // API (/api/v1/grc/frameworks) returns framework_id, not id
  name: string;
  version?: string;
  total_controls?: number;
  implemented_controls?: number;
  compliance_score?: number;
  last_assessed?: string;
}

export interface GrcControl {
  id?: string;
  control_id?: string; // API (/api/v1/grc/controls) returns control_id, not id
  framework_id?: string;
  control_ref?: string;
  title?: string;
  category?: string;
  status: string;
  evidence_count?: number;
  owner?: string;
  due_date?: string;
}

export interface GrcRisk {
  id?: string;
  risk_id?: string; // API (/api/v1/grc/risks) returns risk_id, not id
  title: string;
  category?: string;
  likelihood?: number;
  impact?: number;
  treatment?: string;
  owner?: string;
  status?: string;
  notes?: string;
}

// ---------------------------------------------------------------------------
// Agent Tasks (wave_d /agents/{role}/task) + Queue (/queue/*)
// ---------------------------------------------------------------------------

export interface AgentTaskDispatch {
  task_id: string;
  org_id: string;
  role: string;
  title: string;
  prompt_preview: string;
  priority: string;
  status: string;
  created_at: number;
  metadata: Record<string, unknown>;
}

export interface QueueStatus {
  backend: string;
  depth: number;
  workers: number;
}

export interface QueuePeekItem {
  task_id?: string;
  task_type?: string;
  priority?: number;
  [key: string]: unknown;
}

export const agentTasksApi = {
  /** POST /api/v1/agents/{role}/task */
  dispatch: (role: string, body: { title: string; prompt: string; priority?: string; metadata?: Record<string, unknown> }) =>
    api.post<AgentTaskDispatch>(`/api/v1/agents/${role}/task`, body),
  /** GET /api/v1/queue/status */
  queueStatus: () =>
    api.get<QueueStatus>("/api/v1/queue/status"),
  /** GET /api/v1/queue/peek */
  queuePeek: (limit = 20) =>
    api.get<{ tasks: QueuePeekItem[] }>("/api/v1/queue/peek", { params: { limit } }),
};

// ---------------------------------------------------------------------------
// Shadow AI (/shadow-ai/*)
// ---------------------------------------------------------------------------

export interface ShadowAiStats {
  registered_services: number;
  total_signals: number;
  unregistered_count: number;
  registered_count: number;
  coverage_pct: number;
  top_providers: string[];
}

export interface ShadowAiService {
  service_name: string;
  provider: string;
  data_classification: string;
  approved_by: string;
  [key: string]: unknown;
}

export const shadowAiApi = {
  /** GET /api/v1/shadow-ai/stats */
  stats: (org_id = "default") =>
    api.get<ShadowAiStats>("/api/v1/shadow-ai/stats", { params: { org_id } }),
  /** GET /api/v1/shadow-ai/registry */
  registry: (org_id = "default") =>
    api.get<ShadowAiService[]>("/api/v1/shadow-ai/registry", { params: { org_id } }),
  /** POST /api/v1/shadow-ai/discover */
  discover: (org_id = "default", flag_unregistered = false) =>
    api.post<Record<string, unknown>>("/api/v1/shadow-ai/discover", { sources: [], flag_unregistered }, { params: { org_id } }),
};

export const grcApi = {
  /** GET /api/v1/grc/stats */
  stats: (org_id = "default") =>
    api.get<GrcStats>("/api/v1/grc/stats", { params: { org_id } }),
  /** GET /api/v1/grc/frameworks */
  frameworks: (org_id = "default") =>
    api.get<GrcFramework[]>("/api/v1/grc/frameworks", { params: { org_id } }),
  /** GET /api/v1/grc/controls */
  controls: (params?: { org_id?: string; framework_id?: string; status?: string }) =>
    api.get<GrcControl[]>("/api/v1/grc/controls", { params: { org_id: "default", ...params } }),
  /** GET /api/v1/grc/risks */
  risks: (params?: { org_id?: string; status?: string; category?: string }) =>
    api.get<GrcRisk[]>("/api/v1/grc/risks", { params: { org_id: "default", ...params } }),
  /** GET /api/v1/grc/assessments */
  assessments: (org_id = "default") =>
    api.get<Record<string, unknown>[]>("/api/v1/grc/assessments", { params: { org_id } }),
};

// ── Security Exceptions ──
export const securityExceptionsApi = {
  list: (orgId = "default", status?: string, riskLevel?: string) =>
    api.get(`/api/v1/security-exceptions/${orgId}`, {
      params: { ...(status ? { status } : {}), ...(riskLevel ? { risk_level: riskLevel } : {}) },
    }),
  stats: (orgId = "default") =>
    api.get(`/api/v1/security-exceptions/${orgId}/stats`),
  expiring: (orgId = "default", daysAhead = 7) =>
    api.get(`/api/v1/security-exceptions/${orgId}/expiring`, { params: { days_ahead: daysAhead } }),
};

// ── Exception Workflow ──
export const exceptionWorkflowApi = {
  list: (orgId = "default", status?: string) =>
    api.get("/api/v1/exception-workflow/requests", {
      params: { org_id: orgId, ...(status ? { status } : {}) },
    }),
  summary: (orgId = "default") =>
    api.get("/api/v1/exception-workflow/summary", { params: { org_id: orgId } }),
  expiring: (orgId = "default", daysAhead = 30) =>
    api.get("/api/v1/exception-workflow/expiring", { params: { org_id: orgId, days_ahead: daysAhead } }),
};

// ── Auto-Waiver ──
export const autoWaiverApi = {
  rules: (orgId = "default") =>
    api.get("/api/v1/auto-waiver/rules", { params: { org_id: orgId } }),
  stats: (orgId = "default") =>
    api.get("/api/v1/auto-waiver/stats", { params: { org_id: orgId } }),
};

// ── STRIDE Threat Modeling ──
export const threatModelingApi = {
  models: (orgId = "default") =>
    api.get("/api/v1/threat-modeling/models", { params: { org_id: orgId } }),
  strideCategories: () =>
    api.get("/api/v1/threat-modeling/stride-categories"),
};

// ── Cyber Threat Models ──
export const cyberThreatModelsApi = {
  summary: (orgId = "default") =>
    api.get("/api/v1/cyber-threat-models/summary", { params: { org_id: orgId } }),
  unmitigated: (orgId = "default") =>
    api.get("/api/v1/cyber-threat-models/unmitigated", { params: { org_id: orgId } }),
};

// ── Threat Modeling Pipeline ──
export const threatModelingPipelineApi = {
  models: (orgId = "default", status?: string) =>
    api.get("/api/v1/threat-modeling-pipeline/models", {
      params: { org_id: orgId, ...(status ? { status } : {}) },
    }),
  unmitigated: (orgId = "default") =>
    api.get("/api/v1/threat-modeling-pipeline/unmitigated", { params: { org_id: orgId } }),
};

// ── Identity Analytics — /api/v1/identity-analytics ──
export const identityAnalyticsApi = {
  profiles: (orgId = "default", limit = 50) =>
    api.get("/api/v1/identity-analytics/identities", { params: { org_id: orgId, limit } }),
  getProfile: (userId: string, orgId = "default") =>
    api.get(`/api/v1/identity-analytics/identities/${encodeURIComponent(userId)}`, { params: { org_id: orgId } }),
};

// ── Digital Identity — /api/v1/digital-identity ──
export const digitalIdentityApi = {
  identities: (orgId = "default", limit = 50, offset = 0) =>
    api.get("/api/v1/digital-identity/profiles", { params: { org_id: orgId, limit, offset } }),
  stats: (orgId = "default") =>
    api.get("/api/v1/digital-identity/stats", { params: { org_id: orgId } }),
  risks: (orgId = "default", limit = 50) =>
    api.get("/api/v1/digital-identity/risks", { params: { org_id: orgId, limit } }),
};

// ── IP Reputation — /api/v1/ip-reputation ──
export const ipReputationApi = {
  blocklist: (orgId = "default", limit = 100, offset = 0) =>
    api.get("/api/v1/ip-reputation/blocklist", { params: { org_id: orgId, limit, offset } }),
  stats: (orgId = "default") =>
    api.get("/api/v1/ip-reputation/stats", { params: { org_id: orgId } }),
  bulkCheck: (ips: string[], orgId = "default") =>
    api.post("/api/v1/ip-reputation/bulk-check", { ips, org_id: orgId }),
};

// ── Threat Geolocation — /api/v1/threat-geolocation ──
export const threatGeolocationApi = {
  heatmap: (orgId = "default") =>
    api.get("/api/v1/threat-geolocation/heatmap", { params: { org_id: orgId } }),
  events: (orgId = "default", limit = 50) =>
    api.get("/api/v1/threat-geolocation/events", { params: { org_id: orgId, limit } }),
  stats: (orgId = "default") =>
    api.get("/api/v1/threat-geolocation/stats", { params: { org_id: orgId } }),
  blockRules: (orgId = "default") =>
    api.get("/api/v1/threat-geolocation/block-rules", { params: { org_id: orgId } }),
};

// ── Connector Mapping Dry-Run — /api/v1/connectors/mapping/dry-run ──
export const connectorMappingApi = {
  dryRun: (payload: {
    connector_id: string;
    sample_payload: Record<string, unknown>;
    mappings: Array<{ source_field: string; target_field: string }>;
  }) => api.post("/api/v1/connectors/mapping/dry-run", payload),
};

// ── Threat Deception — /api/v1/threat-deception ──
export const threatDeceptionApi = {
  listDecoys: (orgId = "default", decoyType?: string, active?: boolean) =>
    api.get("/api/v1/threat-deception/decoys", {
      params: { org_id: orgId, ...(decoyType ? { decoy_type: decoyType } : {}), ...(active !== undefined ? { active } : {}) },
    }),
  stats: (orgId = "default") =>
    api.get("/api/v1/threat-deception/stats", { params: { org_id: orgId } }),
  listCampaigns: (orgId = "default") =>
    api.get("/api/v1/threat-deception/campaigns", { params: { org_id: orgId } }),
};

// ── Risk — /api/v1/risk ──
export const riskApi = {
  topRisks: (n = 5) =>
    api.get("/api/v1/risk/top", { params: { n } }),
  score: () =>
    api.get("/api/v1/risk/score"),
};

// ── Exec Reporting — /api/v1/exec-reporting ──
export const execReportingApi = {
  summary: () => api.get("/api/v1/exec-reporting/summary"),
  kpis: () => api.get("/api/v1/exec-reporting/kpis"),
};

// ── Digital Forensics — /api/v1/digital-forensics ──
export const digitalForensicsApi = {
  listCases: (orgId = "default", status?: string) =>
    api.get("/api/v1/digital-forensics/cases", {
      params: { org_id: orgId, ...(status ? { status } : {}) },
    }),
  stats: (orgId = "default") =>
    api.get("/api/v1/digital-forensics/stats", { params: { org_id: orgId } }),
};

// ── Billing API ────────────────────────────────────────────────────────────

export type BillingTier = "starter" | "pro" | "enterprise";

export interface BillingTierResponse {
  tier: BillingTier;
}

export interface BillingUpgradeResponse {
  checkout_url: string;
}

export const billingApi = {
  tier: () => api.get<BillingTierResponse>("/api/v1/billing/tier"),
  upgrade: (target_tier: BillingTier) =>
    api.post<BillingUpgradeResponse>("/api/v1/billing/upgrade", { target_tier }),
};

// ── Orgs API — /api/v1/orgs ───────────────────────────────────────────────

export interface OrgItem {
  org_id: string;
  name: string;
  slug?: string;
}

export interface OrgListResponse {
  items?: OrgItem[];
  orgs?: OrgItem[];
}

export const orgsApi = {
  list: (includeDiscovered = false) =>
    api.get<OrgListResponse>("/api/v1/orgs", {
      params: { include_discovered: includeDiscovered },
    }),
  export: (orgId: string) =>
    api.post<{ download_url: string }>(`/api/v1/orgs/${orgId}/export`, {}),
};
