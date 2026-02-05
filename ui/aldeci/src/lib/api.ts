import axios, { AxiosError } from 'axios'
import { toast } from 'sonner'

// ═══════════════════════════════════════════════════════════════════════════
// API Configuration
// ═══════════════════════════════════════════════════════════════════════════

// @ts-ignore - Vite env types
const API_BASE_URL = (import.meta as any).env?.VITE_API_URL || 'http://localhost:8000'
// @ts-ignore - Vite env types  
const API_KEY = (import.meta as any).env?.VITE_API_KEY || 'demo-token'

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': API_KEY,
  },
  timeout: 30000,
})

// Request interceptor
api.interceptors.request.use(
  (config) => {
    const storedKey = localStorage.getItem('aldeci_api_key')
    if (storedKey) {
      config.headers['X-API-Key'] = storedKey
    }
    return config
  },
  (error) => Promise.reject(error)
)

// Response interceptor
api.interceptors.response.use(
  (response) => response,
  (error: AxiosError<{ detail?: string }>) => {
    const message = error.response?.data?.detail || error.message || 'An error occurred'
    if (error.response?.status === 401) {
      toast.error('Authentication failed. Please check your API key.')
    } else if (error.response?.status === 500) {
      toast.error(`Server error: ${message}`)
    }
    return Promise.reject(error)
  }
)

// ═══════════════════════════════════════════════════════════════════════════
// Type Definitions
// ═══════════════════════════════════════════════════════════════════════════

export interface Finding {
  id: string
  cve_id?: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: string
  source: string
  asset?: string
  epss_score?: number
  kev?: boolean
  created_at: string
}

export interface Cluster {
  id: string
  canonical_cve: string
  severity: string
  finding_count: number
  sources: string[]
  status: string
  assignee?: string
}

export interface PentAGIRequest {
  id: string
  target: string
  scope?: string
  priority: string
  status: string
  created_at: string
}

export interface PentAGIResult {
  id: string
  request_id: string
  exploitability: string
  evidence: string
  risk_score: number
}

export interface Workflow {
  id: string
  name: string
  description?: string
  trigger: string
  actions: unknown[]
  enabled: boolean
}

export interface Policy {
  id: string
  name: string
  description?: string
  rules: unknown[]
  enabled: boolean
}

export interface LLMProvider {
  name: string
  enabled: boolean
  configured: boolean
  model: string
  status: string
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. DASHBOARD & ANALYTICS (Overview)
// ═══════════════════════════════════════════════════════════════════════════

const dashboard = {
  // Main dashboard
  getOverview: (orgId = 'default') => api.get('/api/v1/analytics/dashboard/overview', { params: { org_id: orgId } }).then(r => r.data),
  getTrends: (orgId = 'default', days = 30) => api.get('/api/v1/analytics/dashboard/trends', { params: { org_id: orgId, days } }).then(r => r.data),
  getTopRisks: (orgId = 'default', limit = 10) => api.get('/api/v1/analytics/dashboard/top-risks', { params: { org_id: orgId, limit } }).then(r => r.data),
  getComplianceStatus: (orgId = 'default') => api.get('/api/v1/analytics/dashboard/compliance-status', { params: { org_id: orgId } }).then(r => r.data),

  // Metrics
  getMTTR: (orgId = 'default') => api.get('/api/v1/analytics/mttr', { params: { org_id: orgId } }).then(r => r.data),
  getNoiseReduction: () => api.get('/api/v1/analytics/noise-reduction').then(r => r.data),
  getROI: () => api.get('/api/v1/analytics/roi').then(r => r.data),
  getCoverage: () => api.get('/api/v1/analytics/coverage').then(r => r.data),
  
  // Custom
  customQuery: (query: string) => api.post('/api/v1/analytics/custom-query', { query }).then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. COPILOT (AI Chat & Agents)
// ═══════════════════════════════════════════════════════════════════════════

const copilot = {
  chat: {
    createSession: (data?: { context?: unknown }) => api.post('/api/v1/copilot/sessions', data).then(r => r.data),
    getSessions: () => api.get('/api/v1/copilot/sessions').then(r => r.data),
    getSession: (sessionId: string) => api.get(`/api/v1/copilot/sessions/${sessionId}`).then(r => r.data),
    sendMessage: (sessionId: string, message: string, context?: unknown) => api.post(`/api/v1/copilot/sessions/${sessionId}/messages`, { message, context }).then(r => r.data),
    getMessages: (sessionId: string) => api.get(`/api/v1/copilot/sessions/${sessionId}/messages`).then(r => r.data),
    quickAnalyze: (data: { target: string, context?: unknown }) => api.post('/api/v1/copilot/quick/analyze', data).then(r => r.data),
    getHealth: () => api.get('/api/v1/copilot/health').then(r => r.data),
  },
  agents: {
    // Security Analyst
    analyst: {
      analyze: (data: { findings: unknown[], context?: unknown }) => api.post('/api/v1/copilot/agents/analyst/analyze', data).then(r => r.data),
      threatIntel: (data: { cve_ids: string[] }) => api.post('/api/v1/copilot/agents/analyst/threat-intel', data).then(r => r.data),
      prioritize: (data: { findings: unknown[] }) => api.post('/api/v1/copilot/agents/analyst/prioritize', data).then(r => r.data),
      attackPath: (data: { asset_id: string }) => api.post('/api/v1/copilot/agents/analyst/attack-path', data).then(r => r.data),
    },
    // Pentest Agent
    pentest: {
      validate: (data: { target: string, cve_ids?: string[] }) => api.post('/api/v1/copilot/agents/pentest/validate', data).then(r => r.data),
      generatePOC: (data: { cve_id: string, target: string }) => api.post('/api/v1/copilot/agents/pentest/generate-poc', data).then(r => r.data),
      schedule: (data: { target: string, schedule: string }) => api.post('/api/v1/copilot/agents/pentest/schedule', data).then(r => r.data),
    },
    // Compliance Agent
    compliance: {
      mapFindings: (data: { findings: unknown[], framework: string }) => api.post('/api/v1/copilot/agents/compliance/map-findings', data).then(r => r.data),
      gapAnalysis: (data: { framework: string, scope?: unknown }) => api.post('/api/v1/copilot/agents/compliance/gap-analysis', data).then(r => r.data),
      regulatoryAlerts: (data: { regions?: string[] }) => api.post('/api/v1/copilot/agents/compliance/regulatory-alerts', data).then(r => r.data),
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. CODE SUITE (Ingest)
// ═══════════════════════════════════════════════════════════════════════════

const codeSuite = {
  scanning: {
    ingestSBOM: (file: File) => {
      const formData = new FormData()
      formData.append('file', file)
      return api.post('/inputs/sbom', formData, { headers: { 'Content-Type': 'multipart/form-data' } }).then(r => r.data)
    },
    ingestSARIF: (file: File) => {
      const formData = new FormData()
      formData.append('file', file)
      return api.post('/inputs/sarif', formData, { headers: { 'Content-Type': 'multipart/form-data' } }).then(r => r.data)
    },
    validateInput: (data: unknown) => api.post('/api/v1/validate/input', data).then(r => r.data),
  },
  secrets: {
    list: () => api.get('/api/v1/secrets').then(r => r.data),
    create: (data: unknown) => api.post('/api/v1/secrets', data).then(r => r.data),
    get: (id: string) => api.get(`/api/v1/secrets/${id}`).then(r => r.data),
    resolve: (id: string) => api.post(`/api/v1/secrets/${id}/resolve`).then(r => r.data),
    scanContent: (content: string) => api.post('/api/v1/secrets/scan/content', { content }).then(r => r.data),
  },
  iac: {
    list: () => api.get('/api/v1/iac').then(r => r.data),
    create: (data: unknown) => api.post('/api/v1/iac', data).then(r => r.data),
    get: (id: string) => api.get(`/api/v1/iac/${id}`).then(r => r.data),
    scanContent: (content: string, type: string) => api.post('/api/v1/iac/scan/content', { content, type }).then(r => r.data),
  },
  inventory: {
    search: (query: string) => api.get('/api/v1/inventory/search', { params: { query } }).then(r => r.data),
    getApplications: () => api.get('/api/v1/inventory/applications').then(r => r.data),
    getAssets: () => api.get('/api/v1/inventory/assets').then(r => r.data),
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. CLOUD SUITE (Correlate)
// ═══════════════════════════════════════════════════════════════════════════

const cloudSuite = {
  cspm: {
    ingestCNAPP: (file: File) => {
      const formData = new FormData()
      formData.append('file', file)
      return api.post('/inputs/cnapp', formData, { headers: { 'Content-Type': 'multipart/form-data' } }).then(r => r.data)
    },
    getFindings: () => api.get('/api/v1/analytics/findings', { params: { source: 'cnapp' } }).then(r => r.data),
    scan: (options?: { provider?: string; full_scan?: boolean }) => api.post('/api/v1/iac/scan', { scan_type: 'cloud', ...options }).then(r => r.data),
  },
  feeds: {
    getEPSS: (cveIds?: string[]) => api.get('/api/v1/feeds/epss', { params: cveIds ? { cve_ids: cveIds.join(',') } : {} }).then(r => r.data),
    getKEV: (cveIds?: string[]) => api.get('/api/v1/feeds/kev', { params: cveIds ? { cve_ids: cveIds.join(',') } : {} }).then(r => r.data),
    getExploits: () => api.get('/api/v1/feeds/exploits').then(r => r.data),
    getThreatActors: () => api.get('/api/v1/feeds/threat-actors').then(r => r.data),
  },
  correlation: {
    getClusters: (params?: Record<string, unknown>) => api.get('/api/v1/deduplication/clusters', { params }).then(r => r.data),
    getCluster: (id: string) => api.get(`/api/v1/deduplication/clusters/${id}`).then(r => r.data),
    processFinding: (data: unknown) => api.post('/api/v1/deduplication/process', data).then(r => r.data),
  },
  attackPath: {
    getGraph: () => api.get('/graph/').then(r => r.data),
    analyzeSurface: (data: { asset_ids?: string[], depth?: number }) => api.post('/api/v1/algorithms/gnn/attack-surface', data).then(r => r.data),
    getCriticalNodes: (threshold?: number) => api.post('/api/v1/algorithms/gnn/critical-nodes', { threshold }).then(r => r.data),
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. ATTACK SUITE (Verify)
// ═══════════════════════════════════════════════════════════════════════════

const attackSuite = {
  pentagi: {
    getRequests: () => api.get('/api/v1/pentagi/requests').then(r => r.data),
    createRequest: (data: { target: string, scope?: string, priority?: string }) => api.post('/api/v1/pentagi/requests', data).then(r => r.data),
    getResults: () => api.get('/api/v1/pentagi/results').then(r => r.data),
    verify: (data: { cve_id: string, target: string }) => api.post('/api/v1/pentagi/verify', data).then(r => r.data),
  },
  microPentest: {
    run: (data: { target: string, cve_id?: string, safe_mode?: boolean }) => api.post('/api/v1/micro-pentest/run', data).then(r => r.data),
    getStatus: (flowId: string) => api.get(`/api/v1/micro-pentest/status/${flowId}`).then(r => r.data),
  },
  simulation: {
    simulateAttack: (data: { scenario: string, assets: string[] }) => api.post('/api/v1/predictions/simulate-attack', data).then(r => r.data),
    attackChain: (data: { target: string }) => api.post('/api/v1/predictions/attack-chain', data).then(r => r.data),
  },
  reachability: {
    analyze: (data: { cve_id: string, target?: string }) => api.post('/api/v1/reachability/analyze', data).then(r => r.data),
    getResults: (cveId: string) => api.get(`/api/v1/reachability/results/${cveId}`).then(r => r.data),
  },
  discovery: {
    reportDiscovered: (data: { title: string, severity: string }) => api.post('/api/v1/vulns/discovered', data).then(r => r.data),
    getInternal: () => api.get('/api/v1/vulns/internal').then(r => r.data),
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. PROTECT SUITE (Remediate)
// ═══════════════════════════════════════════════════════════════════════════

const protectSuite = {
  remediation: {
    getTasks: (orgId = 'default') => api.get('/api/v1/remediation/tasks', { params: { org_id: orgId } }).then(r => r.data),
    createTask: (data: unknown) => api.post('/api/v1/remediation/tasks', data).then(r => r.data),
    generateFix: (cveId: string) => api.post('/api/v1/enhanced/analysis', { service: 'remediation', context: { cve_id: cveId, action: 'generate_fix' } }).then(r => r.data),
    createPR: (data: { cve: string, fix?: string, title: string }) => api.post('/api/v1/webhooks/alm/work-items', { type: 'pull_request', ...data }).then(r => r.data),
  },
  bulk: {
    updateFindings: (data: { finding_ids: string[], updates: unknown }) => api.post('/api/v1/bulk/findings/update', data).then(r => r.data),
    assignClusters: (data: { cluster_ids: string[], assignee: string }) => api.post('/api/v1/bulk/clusters/assign', data).then(r => r.data),
  },
  collaboration: {
    getComments: (params?: { entity_type?: string, entity_id?: string }) => api.get('/api/v1/collaboration/comments', { params }).then(r => r.data),
    addComment: (data: { entity_type: string, entity_id: string, content: string }) => api.post('/api/v1/collaboration/comments', data).then(r => r.data),
    getNotifications: () => api.get('/api/v1/collaboration/notifications/pending').then(r => r.data),
  },
  workflows: {
    list: () => api.get('/api/v1/workflows').then(r => r.data),
    execute: (id: string, context?: unknown) => api.post(`/api/v1/workflows/${id}/execute`, context).then(r => r.data),
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. AI ENGINE (Decide)
// ═══════════════════════════════════════════════════════════════════════════

const aiEngine = {
  labs: {
    monteCarloQuantify: (data: { cve_ids: string[], simulations?: number }) => api.post('/api/v1/algorithms/monte-carlo/quantify', data).then(r => r.data),
    causalAnalyze: (data: { finding_ids: string[] }) => api.post('/api/v1/algorithms/causal/analyze', data).then(r => r.data),
  },
  llm: {
    getStatus: () => api.get('/api/v1/llm/status').then(r => r.data),
    getProviders: () => api.get('/api/v1/llm/providers').then(r => r.data),
  },
  consensus: {
    analyze: (data: { service: string, context?: unknown }) => api.post('/api/v1/enhanced/analysis', data).then(r => r.data),
    compareLLMs: (data: { prompt: string }) => api.post('/api/v1/enhanced/compare-llms', data).then(r => r.data),
  },
  predictions: {
    riskTrajectory: (data: { cve_ids: string[] }) => api.post('/api/v1/predictions/risk-trajectory', data).then(r => r.data),
  },
  policies: {
    list: () => api.get('/api/v1/policies').then(r => r.data),
    validate: (id: string) => api.post(`/api/v1/policies/${id}/validate`).then(r => r.data),
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. EVIDENCE (Vault)
// ═══════════════════════════════════════════════════════════════════════════

const evidence = {
  bundles: {
    list: () => api.get('/evidence/').then(r => r.data),
    get: (release: string) => api.get(`/evidence/${release}`).then(r => r.data),
    verify: (bundleId: string) => api.post('/evidence/verify', { bundle_id: bundleId }).then(r => r.data),
  },
  audit: {
    getLogs: (params?: { limit?: number }) => api.get('/api/v1/audit/logs', { params }).then(r => r.data),
    complianceFrameworks: () => api.get('/api/v1/audit/compliance/frameworks').then(r => r.data),
  },
  reports: {
    list: () => api.get('/api/v1/reports').then(r => r.data),
    generate: (data: { type: string, format: string }) => api.post('/api/v1/reports/generate', data).then(r => r.data),
  },
  analytics: {
    getFindings: (params?: Record<string, unknown>) => api.get('/api/v1/analytics/findings', { params }).then(r => r.data),
    getDecisions: () => api.get('/api/v1/analytics/decisions').then(r => r.data),
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. SETTINGS
// ═══════════════════════════════════════════════════════════════════════════

const settings = {
  access: {
    users: () => api.get('/api/v1/users').then(r => r.data),
    teams: () => api.get('/api/v1/teams').then(r => r.data),
    sso: () => api.get('/api/v1/auth/sso').then(r => r.data),
  },
  integrations: {
    list: () => api.get('/api/v1/integrations').then(r => r.data),
    test: (id: string) => api.post(`/api/v1/integrations/${id}/test`).then(r => r.data),
  },
  marketplace: {
    browse: () => api.get('/api/v1/marketplace/browse').then(r => r.data),
    install: (itemId: string) => api.post(`/api/v1/marketplace/purchase/${itemId}`).then(r => r.data),
  },
  system: {
    health: () => api.get('/health').then(r => r.data),
    version: () => api.get('/api/v1/version').then(r => r.data),
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN EXPORT
// ═══════════════════════════════════════════════════════════════════════════

export default {
  dashboard,
  copilot,
  code: codeSuite,
  cloud: cloudSuite,
  attack: attackSuite,
  protect: protectSuite,
  ai: aiEngine,
  evidence,
  settings,
}

// ═══════════════════════════════════════════════════════════════════════════
// BACKWARD COMPATIBILITY EXPORTS (for legacy code)
// ═══════════════════════════════════════════════════════════════════════════

// Dashboard API
export const dashboardApi = {
  getOverview: dashboard.getOverview,
  getTrends: dashboard.getTrends,
  getStatus: () => api.get('/api/v1/status').then(r => r.data),
}

// Feeds API
export const feedsApi = {
  getEPSS: cloudSuite.feeds.getEPSS,
  getKEV: cloudSuite.feeds.getKEV,
  getExploits: cloudSuite.feeds.getExploits,
  getThreatActors: cloudSuite.feeds.getThreatActors,
  health: () => api.get('/api/v1/feeds/health').then(r => r.data),
  getHealth: () => api.get('/api/v1/feeds/health').then(r => r.data),
  getStats: () => api.get('/api/v1/feeds/stats').then(r => r.data),
}

// System API
export const systemApi = {
  getHealth: settings.system.health,
  getVersion: settings.system.version,
  getStatus: () => api.get('/api/v1/status').then(r => r.data),
  getCapabilities: () => api.get('/api/v1/algorithms/capabilities').then(r => r.data),
}

// Algorithms API
export const algorithmsApi = {
  getStatus: () => api.get('/api/v1/algorithms/status').then(r => r.data),
  getCapabilities: () => api.get('/api/v1/algorithms/capabilities').then(r => r.data),
  monteCarlo: aiEngine.labs.monteCarloQuantify,
  causal: aiEngine.labs.causalAnalyze,
  prioritize: (data: unknown) => api.post('/api/v1/algorithms/prioritize', data).then(r => r.data),
}

// Ingest API
export const ingestApi = {
  uploadSBOM: codeSuite.scanning.ingestSBOM,
  uploadSARIF: codeSuite.scanning.ingestSARIF,
  uploadCNAPP: cloudSuite.cspm.ingestCNAPP,
  ingestSBOM: codeSuite.scanning.ingestSBOM,
  ingestSARIF: codeSuite.scanning.ingestSARIF,
  ingestCNAPP: cloudSuite.cspm.ingestCNAPP,
}

// Pentest API
export const pentestApi = {
  getRequests: attackSuite.pentagi.getRequests,
  createRequest: attackSuite.pentagi.createRequest,
  getResults: attackSuite.pentagi.getResults,
  verify: attackSuite.pentagi.verify,
  getConfigs: () => api.get('/api/v1/pentagi/configs').then(r => r.data),
  getTests: attackSuite.pentagi.getRequests,
  runMicroPentest: attackSuite.microPentest.run,
  validateExploit: (cve: string) => api.post('/api/v1/pentagi/verify', { cve_id: cve, target: 'auto' }).then(r => r.data),
  getExploitability: (cve: string) => api.get(`/api/v1/reachability/results/${cve}`).then(r => r.data),
  comprehensiveScan: (data: unknown) => api.post('/api/v1/pentagi/comprehensive-scan', data).then(r => r.data),
}

// PentAGI API (alias)
export const pentagiApi = {
  ...pentestApi,
  getConfigs: () => api.get('/api/v1/pentagi/configs').then(r => r.data),
}

// Remediation API
export const remediationApi = {
  getTasks: protectSuite.remediation.getTasks,
  createTask: protectSuite.remediation.createTask,
  generateFix: protectSuite.remediation.generateFix,
  createPR: protectSuite.remediation.createPR,
  getMetrics: () => api.get('/api/v1/remediation/metrics').then(r => r.data),
  assignTask: (id: string, assignee: string) => api.post(`/api/v1/remediation/tasks/${id}/assign`, { assignee }).then(r => r.data),
}

// Compliance API
export const complianceApi = {
  getFrameworks: evidence.audit.complianceFrameworks,
  getFindings: evidence.analytics.getFindings,
  getReports: evidence.reports.list,
  getStatus: () => api.get('/api/v1/compliance/status').then(r => r.data),
  generateReport: (framework: string) => api.post('/api/v1/reports/generate', { framework, format: 'pdf' }).then(r => r.data),
  collectEvidence: (id: string) => api.post(`/api/v1/evidence/${id}/collect`).then(r => r.data),
}

// Reachability API
export const reachabilityApi = {
  analyze: attackSuite.reachability.analyze,
  getResults: attackSuite.reachability.getResults,
  getMetrics: () => api.get('/api/v1/reachability/metrics').then(r => r.data),
}

// Search API
export const searchApi = {
  search: (query: string) => api.get('/api/v1/search', { params: { q: query } }).then(r => r.data),
  inventory: codeSuite.inventory.search,
  searchFindings: (query: string) => api.get('/api/v1/analytics/findings', { params: { q: query } }).then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// ADDITIONAL BACKWARD COMPATIBILITY EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

// Dedup API
export const dedupApi = {
  getClusters: cloudSuite.correlation.getClusters,
  getCluster: cloudSuite.correlation.getCluster,
  process: cloudSuite.correlation.processFinding,
  getStats: () => api.get('/api/v1/deduplication/stats').then(r => r.data),
}

// Evidence API
export const evidenceApi = {
  list: evidence.bundles.list,
  get: evidence.bundles.get,
  verify: evidence.bundles.verify,
  getStats: () => api.get('/api/v1/evidence/stats').then(r => r.data),
  getBundles: evidence.bundles.list,
}

// LLM API
export const llmApi = {
  getStatus: aiEngine.llm.getStatus,
  getProviders: aiEngine.llm.getProviders,
  analyze: (data: unknown) => api.post('/api/v1/enhanced/analysis', data).then(r => r.data),
}

// Enhanced API
export const enhancedApi = {
  analyze: aiEngine.consensus.analyze,
  compareLLMs: aiEngine.consensus.compareLLMs,
  getCapabilities: () => api.get('/api/v1/enhanced/capabilities').then(r => r.data),
}

// Micro Pentest API
export const microPentestApi = {
  run: attackSuite.microPentest.run,
  getStatus: attackSuite.microPentest.getStatus,
  getHealth: () => api.get('/api/v1/micro-pentest/health').then(r => r.data),
}

// Graph API
export const graphApi = {
  get: cloudSuite.attackPath.getGraph,
  getGraph: cloudSuite.attackPath.getGraph,
  analyzeSurface: cloudSuite.attackPath.analyzeSurface,
  getCriticalNodes: cloudSuite.attackPath.getCriticalNodes,
}

// Attack Graph API
export const attackGraphApi = {
  ...graphApi,
  getGraph: graphApi.get,
  analyze: (data: unknown) => api.post('/api/v1/algorithms/gnn/analyze', data).then(r => r.data),
  export: (format: string) => api.get(`/graph/export?format=${format}`).then(r => r.data),
}

// Inventory API
export const inventoryApi = {
  search: codeSuite.inventory.search,
  getApplications: codeSuite.inventory.getApplications,
  getAssets: codeSuite.inventory.getAssets,
}

// Secrets API
export const secretsApi = {
  list: codeSuite.secrets.list,
  get: codeSuite.secrets.get,
  resolve: codeSuite.secrets.resolve,
  scan: codeSuite.secrets.scanContent,
  scanContent: codeSuite.secrets.scanContent,
  getStatus: () => api.get('/api/v1/secrets/status').then(r => r.data),
  getScannersStatus: () => api.get('/api/v1/secrets/scanners').then(r => r.data),
}

// CNAPP API
export const cnappApi = {
  ingest: cloudSuite.cspm.ingestCNAPP,
  getFindings: cloudSuite.cspm.getFindings,
  scan: cloudSuite.cspm.scan,
  getSummary: () => api.get('/api/v1/cspm/summary').then(r => r.data),
  export: (format: string) => api.get(`/api/v1/cspm/export?format=${format}`).then(r => r.data),
  remediate: (id: string) => api.post(`/api/v1/cspm/findings/${id}/remediate`).then(r => r.data),
}

// Integrations API
export const integrationsApi = {
  list: settings.integrations.list,
  test: settings.integrations.test,
  configure: (id: string, config: unknown) => api.put(`/api/v1/integrations/${id}`, config).then(r => r.data),
  create: (data: unknown) => api.post('/api/v1/integrations', data).then(r => r.data),
  delete: (id: string) => api.delete(`/api/v1/integrations/${id}`).then(r => r.data),
  sync: (id: string) => api.post(`/api/v1/integrations/${id}/sync`).then(r => r.data),
}

// Webhooks API
export const webhooksApi = {
  list: () => api.get('/api/v1/webhooks').then(r => r.data),
  create: (data: unknown) => api.post('/api/v1/webhooks', data).then(r => r.data),
  delete: (id: string) => api.delete(`/api/v1/webhooks/${id}`).then(r => r.data),
  getMappings: () => api.get('/api/v1/webhooks/mappings').then(r => r.data),
}

// Workflows API
export const workflowsApi = {
  list: protectSuite.workflows.list,
  execute: protectSuite.workflows.execute,
  getRules: () => api.get('/api/v1/workflows/rules').then(r => r.data),
  create: (data: unknown) => api.post('/api/v1/workflows', data).then(r => r.data),
  update: (id: string, data: unknown) => api.put(`/api/v1/workflows/${id}`, data).then(r => r.data),
  delete: (id: string) => api.delete(`/api/v1/workflows/${id}`).then(r => r.data),
}

// Automation API
export const automationApi = {
  getRules: () => api.get('/api/v1/automation/rules').then(r => r.data),
  createRule: (data: unknown) => api.post('/api/v1/automation/rules', data).then(r => r.data),
}

// Reports API
export const reportsApi = {
  list: evidence.reports.list,
  generate: evidence.reports.generate,
  getTemplates: () => api.get('/api/v1/reports/templates').then(r => r.data),
  create: (data: unknown) => api.post('/api/v1/reports', data).then(r => r.data),
}

// Audit API
export const auditApi = {
  getLogs: evidence.audit.getLogs,
  getFrameworks: evidence.audit.complianceFrameworks,
}

// Analytics API
export const analyticsApi = {
  getFindings: evidence.analytics.getFindings,
  getDecisions: evidence.analytics.getDecisions,
  getStats: () => api.get('/api/v1/analytics/stats').then(r => r.data),
}
