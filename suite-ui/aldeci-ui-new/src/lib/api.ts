import axios from "axios";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "",
  headers: {
    "X-API-Key": import.meta.env.VITE_API_KEY || "",
    "Content-Type": "application/json",
  },
});

// ── Request interceptor for token refresh ──
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      window.location.href = "/settings";
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
  list: (params?: Record<string, unknown>) => api.get("/api/v1/cases", { params }),
  get: (id: string) => api.get(`/api/v1/cases/${id}`),
  triage: (id: string, action: string) => api.post(`/api/v1/cases/${id}/triage`, { action }),
  bulkTriage: (ids: string[], action: string) => api.post("/api/v1/bulk/triage", { finding_ids: ids, action }),
};

export const scannerApi = {
  ingest: (data: unknown) => api.post("/api/v1/scanner/ingest", data),
  list: () => api.get("/api/v1/scanner/parsers"),
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
  verify: (data: unknown) => api.post("/api/v1/mpte/verify", data),
  status: () => api.get("/api/v1/mpte/status"),
  stats: () => api.get("/api/v1/mpte/stats"),
  results: (params?: Record<string, string>) => api.get("/api/v1/mpte/results", { params }),
  requests: (params?: Record<string, string>) => api.get("/api/v1/mpte/requests", { params }),
  getRequest: (id: string) => api.get(`/api/v1/mpte/requests/${id}`),
  startRequest: (id: string) => api.post(`/api/v1/mpte/requests/${id}/start`),
  cancelRequest: (id: string) => api.post(`/api/v1/mpte/requests/${id}/cancel`),
  verifications: (params?: Record<string, string>) => api.get("/api/v1/mpte/verifications", { params }),
  getVerification: (id: string) => api.get(`/api/v1/mpte/verifications/${id}`),
  configs: () => api.get("/api/v1/mpte/configs"),
  monitoring: () => api.get("/api/v1/mpte/monitoring"),
  health: () => api.get("/api/v1/mpte/health"),
  comprehensiveScan: (data: unknown) => api.post("/api/v1/mpte/scan/comprehensive", data),
  orchestratorRun: (data: unknown) => api.post("/api/v1/mpte-orchestrator/run", data),
  orchestratorSimulate: (data: unknown) => api.post("/api/v1/mpte-orchestrator/simulate", data),
  orchestratorStatus: (id: string) => api.get(`/api/v1/mpte-orchestrator/status/${id}`),
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
  get: (id: string) => api.get(`/api/v1/evidence/bundles/${id}`),
  generate: (data: unknown) => api.post("/api/v1/evidence/generate", data),
  verify: (id: string) => api.get(`/api/v1/evidence/bundles/${id}/verify`),
  export: (data: unknown) => api.post("/api/v1/evidence/export", data),
  complianceStatus: () => api.get("/api/v1/evidence/compliance-status"),
};

export const complianceApi = {
  status: () => api.get("/api/v1/compliance-engine/status"),
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
  test: (id: string) => api.post(`/api/v1/integrations/${id}/test`),
  sync: (id: string) => api.post(`/api/v1/integrations/${id}/sync`),
  configure: (id: string, data: unknown) => api.put(`/api/v1/integrations/${id}`, data),
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
  verify: () => api.post("/api/v1/audit/verify-chain"),
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
};

export const knowledgeGraphApi = {
  query: (data: unknown) => api.post("/api/v1/graph/query", data),
  visualize: (params?: Record<string, string>) => api.get("/api/v1/graph/visualize", { params }),
  paths: (data: unknown) => api.post("/api/v1/graph/attack-paths", data),
};

export const threatFeedsApi = {
  list: (params?: Record<string, string>) => api.get("/api/v1/feeds", { params }),
  trending: () => api.get("/api/v1/feeds/trending"),
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
  suggestions: (findingId: string) => api.get(`/api/v1/autofix/suggestions/${findingId}`),
  apply: (fixId: string) => api.post(`/api/v1/autofix/apply`, { fix_id: fixId }),
  preview: (fixId: string) => api.get(`/api/v1/autofix/preview/${fixId}`),
};

// ── Brain / Pipeline ──
export const brainApi = {
  pipelineRun: (data?: unknown) => api.post("/api/v1/brain/pipeline/run", data || {}),
  pipelineStatus: () => api.get("/api/v1/brain/pipeline/status"),
  ingestFinding: (data: unknown) => api.post("/api/v1/brain/ingest/finding", data),
  evidenceGenerate: (data: unknown) => api.post("/api/v1/brain/evidence/generate", data),
};
