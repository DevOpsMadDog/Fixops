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

// Helper for form data uploads
const uploadFile = (url: string, file: File, fieldName = 'file') => {
  const formData = new FormData()
  formData.append(fieldName, file)
  return api.post(url, formData, { headers: { 'Content-Type': 'multipart/form-data' } }).then(r => r.data)
}

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
// 1. HEALTH & SYSTEM
// ═══════════════════════════════════════════════════════════════════════════

export const healthApi = {
  check: () => api.get('/health').then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. ANALYTICS & DASHBOARD (16 endpoints)
// ═══════════════════════════════════════════════════════════════════════════

export const analyticsApi = {
  // Dashboard
  getOverview: (orgId = 'default') => api.get('/api/v1/analytics/dashboard/overview', { params: { org_id: orgId } }).then(r => r.data),
  getTrends: (orgId = 'default', days = 30) => api.get('/api/v1/analytics/dashboard/trends', { params: { org_id: orgId, days } }).then(r => r.data),
  getTopRisks: (orgId = 'default', limit = 10) => api.get('/api/v1/analytics/dashboard/top-risks', { params: { org_id: orgId, limit } }).then(r => r.data),
  getComplianceStatus: (orgId = 'default') => api.get('/api/v1/analytics/dashboard/compliance-status', { params: { org_id: orgId } }).then(r => r.data),
  
  // Findings
  getFindings: (params?: Record<string, unknown>) => api.get('/api/v1/analytics/findings', { params }).then(r => r.data),
  createFinding: (data: unknown) => api.post('/api/v1/analytics/findings', data).then(r => r.data),
  getFinding: (id: string) => api.get(`/api/v1/analytics/findings/${id}`).then(r => r.data),
  updateFinding: (id: string, data: unknown) => api.put(`/api/v1/analytics/findings/${id}`, data).then(r => r.data),
  
  // Decisions
  getDecisions: () => api.get('/api/v1/analytics/decisions').then(r => r.data),
  createDecision: (data: unknown) => api.post('/api/v1/analytics/decisions', data).then(r => r.data),
  
  // Metrics
  getMTTR: (orgId = 'default') => api.get('/api/v1/analytics/mttr', { params: { org_id: orgId } }).then(r => r.data),
  getCoverage: () => api.get('/api/v1/analytics/coverage').then(r => r.data),
  getROI: () => api.get('/api/v1/analytics/roi').then(r => r.data),
  getNoiseReduction: () => api.get('/api/v1/analytics/noise-reduction').then(r => r.data),
  
  // Custom
  customQuery: (query: string) => api.post('/api/v1/analytics/custom-query', { query }).then(r => r.data),
  export: (params?: Record<string, unknown>) => api.get('/api/v1/analytics/export', { params }).then(r => r.data),
}

// Alias for backward compat
export const dashboardApi = analyticsApi

// ═══════════════════════════════════════════════════════════════════════════
// 3. PREDICTIONS (Markov, Bayesian, Attack Chain) - 8 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const predictionsApi = {
  // Attack predictions
  attackChain: (data: { target: string, context?: unknown }) => api.post('/api/v1/predictions/attack-chain', data).then(r => r.data),
  riskTrajectory: (data: { cve_ids: string[], horizon_days?: number }) => api.post('/api/v1/predictions/risk-trajectory', data).then(r => r.data),
  simulateAttack: (data: { scenario: string, assets: string[] }) => api.post('/api/v1/predictions/simulate-attack', data).then(r => r.data),
  combinedAnalysis: (data: unknown) => api.post('/api/v1/predictions/combined-analysis', data).then(r => r.data),
  
  // Markov chain
  getMarkovStates: () => api.get('/api/v1/predictions/markov/states').then(r => r.data),
  getMarkovTransitions: () => api.get('/api/v1/predictions/markov/transitions').then(r => r.data),
  
  // Bayesian
  bayesianUpdate: (data: { prior: unknown, evidence: unknown }) => api.post('/api/v1/predictions/bayesian/update', data).then(r => r.data),
  bayesianRiskAssessment: (data: { assets: string[], threat_model?: unknown }) => api.post('/api/v1/predictions/bayesian/risk-assessment', data).then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. ALGORITHMS (Monte Carlo, Causal, GNN) - 11 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const algorithmsApi = {
  // Monte Carlo
  monteCarloQuantify: (data: { cve_ids: string[], simulations?: number }) => api.post('/api/v1/algorithms/monte-carlo/quantify', data).then(r => r.data),
  monteCarloCVE: (data: { cve_id: string }) => api.post('/api/v1/algorithms/monte-carlo/cve', data).then(r => r.data),
  monteCarloPortfolio: (data: { assets: unknown[], simulations?: number }) => api.post('/api/v1/algorithms/monte-carlo/portfolio', data).then(r => r.data),
  
  // Causal Inference
  causalAnalyze: (data: { finding_ids: string[] }) => api.post('/api/v1/algorithms/causal/analyze', data).then(r => r.data),
  causalCounterfactual: (data: { scenario: unknown }) => api.post('/api/v1/algorithms/causal/counterfactual', data).then(r => r.data),
  causalTreatmentEffect: (data: { treatment: string, outcome: string }) => api.post('/api/v1/algorithms/causal/treatment-effect', data).then(r => r.data),
  
  // GNN Attack Graph
  gnnAttackSurface: (data: { asset_ids?: string[], depth?: number }) => api.post('/api/v1/algorithms/gnn/attack-surface', data).then(r => r.data),
  gnnCriticalNodes: (data: { threshold?: number }) => api.post('/api/v1/algorithms/gnn/critical-nodes', data).then(r => r.data),
  gnnRiskPropagation: (data: { source_nodes: string[] }) => api.post('/api/v1/algorithms/gnn/risk-propagation', data).then(r => r.data),
  
  // Status
  getStatus: () => api.get('/api/v1/algorithms/status').then(r => r.data),
  getCapabilities: () => api.get('/api/v1/algorithms/capabilities').then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. LLM (Language Model Config) - 6 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const llmApi = {
  getStatus: () => api.get('/api/v1/llm/status').then(r => r.data),
  test: (data: { prompt: string, provider?: string }) => api.post('/api/v1/llm/test', data).then(r => r.data),
  getSettings: () => api.get('/api/v1/llm/settings').then(r => r.data),
  updateSettings: (data: unknown) => api.patch('/api/v1/llm/settings', data).then(r => r.data),
  getProviders: () => api.get('/api/v1/llm/providers').then(r => r.data),
  getHealth: () => api.get('/api/v1/llm/health').then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. ENHANCED AI (Multi-LLM Consensus) - 4 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const enhancedApi = {
  analyze: (data: { service: string, context?: unknown }) => api.post('/api/v1/enhanced/analysis', data).then(r => r.data),
  compareLLMs: (data: { prompt: string, providers?: string[] }) => api.post('/api/v1/enhanced/compare-llms', data).then(r => r.data),
  getCapabilities: () => api.get('/api/v1/enhanced/capabilities').then(r => r.data),
  getSignals: () => api.get('/api/v1/enhanced/signals').then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. COPILOT (AI Chat Sessions) - 14 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const copilotApi = {
  // Sessions
  createSession: (data?: { context?: unknown }) => api.post('/api/v1/copilot/sessions', data).then(r => r.data),
  getSessions: () => api.get('/api/v1/copilot/sessions').then(r => r.data),
  getSession: (sessionId: string) => api.get(`/api/v1/copilot/sessions/${sessionId}`).then(r => r.data),
  deleteSession: (sessionId: string) => api.delete(`/api/v1/copilot/sessions/${sessionId}`).then(r => r.data),
  
  // Messages
  sendMessage: (sessionId: string, message: string, context?: unknown) => api.post(`/api/v1/copilot/sessions/${sessionId}/messages`, { message, context }).then(r => r.data),
  getMessages: (sessionId: string) => api.get(`/api/v1/copilot/sessions/${sessionId}/messages`).then(r => r.data),
  
  // Actions
  executeAction: (sessionId: string, action: unknown) => api.post(`/api/v1/copilot/sessions/${sessionId}/actions`, action).then(r => r.data),
  getAction: (actionId: string) => api.get(`/api/v1/copilot/actions/${actionId}`).then(r => r.data),
  
  // Context
  updateContext: (sessionId: string, context: unknown) => api.post(`/api/v1/copilot/sessions/${sessionId}/context`, context).then(r => r.data),
  
  // Suggestions
  getSuggestions: (params?: Record<string, unknown>) => api.get('/api/v1/copilot/suggestions', { params }).then(r => r.data),
  
  // Quick Actions
  quickAnalyze: (data: { target: string, context?: unknown }) => api.post('/api/v1/copilot/quick/analyze', data).then(r => r.data),
  quickPentest: (data: { target: string, cve_id?: string }) => api.post('/api/v1/copilot/quick/pentest', data).then(r => r.data),
  quickReport: (data: { type: string, scope?: unknown }) => api.post('/api/v1/copilot/quick/report', data).then(r => r.data),
  
  // Health
  getHealth: () => api.get('/api/v1/copilot/health').then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. AGENTS (Analyst, Pentest, Compliance) - 21 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const agentsApi = {
  // Security Analyst Agent
  analyst: {
    analyze: (data: { findings: unknown[], context?: unknown }) => api.post('/api/v1/copilot/agents/analyst/analyze', data).then(r => r.data),
    threatIntel: (data: { cve_ids: string[] }) => api.post('/api/v1/copilot/agents/analyst/threat-intel', data).then(r => r.data),
    prioritize: (data: { findings: unknown[] }) => api.post('/api/v1/copilot/agents/analyst/prioritize', data).then(r => r.data),
    attackPath: (data: { asset_id: string }) => api.post('/api/v1/copilot/agents/analyst/attack-path', data).then(r => r.data),
    getTrending: () => api.get('/api/v1/copilot/agents/analyst/trending').then(r => r.data),
    getRiskScore: (assetId: string) => api.get(`/api/v1/copilot/agents/analyst/risk-score/${assetId}`).then(r => r.data),
    getCVE: (cveId: string) => api.get(`/api/v1/copilot/agents/analyst/cve/${cveId}`).then(r => r.data),
  },
  
  // Pentest Agent
  pentest: {
    validate: (data: { target: string, cve_ids?: string[] }) => api.post('/api/v1/copilot/agents/pentest/validate', data).then(r => r.data),
    generatePOC: (data: { cve_id: string, target: string }) => api.post('/api/v1/copilot/agents/pentest/generate-poc', data).then(r => r.data),
    reachability: (data: { cve_id: string, target: string }) => api.post('/api/v1/copilot/agents/pentest/reachability', data).then(r => r.data),
    simulate: (data: { scenario: unknown }) => api.post('/api/v1/copilot/agents/pentest/simulate', data).then(r => r.data),
    getResults: (taskId: string) => api.get(`/api/v1/copilot/agents/pentest/results/${taskId}`).then(r => r.data),
    getEvidence: (evidenceId: string) => api.get(`/api/v1/copilot/agents/pentest/evidence/${evidenceId}`).then(r => r.data),
    schedule: (data: { target: string, schedule: string }) => api.post('/api/v1/copilot/agents/pentest/schedule', data).then(r => r.data),
  },
  
  // Compliance Agent
  compliance: {
    mapFindings: (data: { findings: unknown[], framework: string }) => api.post('/api/v1/copilot/agents/compliance/map-findings', data).then(r => r.data),
    gapAnalysis: (data: { framework: string, scope?: unknown }) => api.post('/api/v1/copilot/agents/compliance/gap-analysis', data).then(r => r.data),
    auditEvidence: (data: { control_id: string }) => api.post('/api/v1/copilot/agents/compliance/audit-evidence', data).then(r => r.data),
    regulatoryAlerts: (data: { regions?: string[] }) => api.post('/api/v1/copilot/agents/compliance/regulatory-alerts', data).then(r => r.data),
    getControls: (framework: string) => api.get(`/api/v1/copilot/agents/compliance/controls/${framework}`).then(r => r.data),
    getDashboard: () => api.get('/api/v1/copilot/agents/compliance/dashboard').then(r => r.data),
    generateReport: (data: { framework: string }) => api.post('/api/v1/copilot/agents/compliance/generate-report', data).then(r => r.data),
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. FEEDS (EPSS, KEV, Exploits, Threat Actors) - 23 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const feedsApi = {
  // EPSS
  getEPSS: (cveIds?: string[]) => api.get('/api/v1/feeds/epss', { params: cveIds ? { cve_ids: cveIds.join(',') } : {} }).then(r => r.data),
  refreshEPSS: () => api.post('/api/v1/feeds/epss/refresh').then(r => r.data),
  
  // KEV
  getKEV: (cveIds?: string[]) => api.get('/api/v1/feeds/kev', { params: cveIds ? { cve_ids: cveIds.join(',') } : {} }).then(r => r.data),
  refreshKEV: () => api.post('/api/v1/feeds/kev/refresh').then(r => r.data),
  
  // Exploits
  getExploits: () => api.get('/api/v1/feeds/exploits').then(r => r.data),
  getExploitsByCVE: (cveId: string) => api.get(`/api/v1/feeds/exploits/${cveId}`).then(r => r.data),
  createExploit: (data: unknown) => api.post('/api/v1/feeds/exploits', data).then(r => r.data),
  
  // Threat Actors
  getThreatActors: () => api.get('/api/v1/feeds/threat-actors').then(r => r.data),
  getThreatActorsByCVE: (cveId: string) => api.get(`/api/v1/feeds/threat-actors/${cveId}`).then(r => r.data),
  getThreatActorsByActor: (actor: string) => api.get(`/api/v1/feeds/threat-actors/by-actor/${actor}`).then(r => r.data),
  createThreatActor: (data: unknown) => api.post('/api/v1/feeds/threat-actors', data).then(r => r.data),
  
  // Supply Chain
  getSupplyChain: () => api.get('/api/v1/feeds/supply-chain').then(r => r.data),
  getSupplyChainByPackage: (pkg: string) => api.get(`/api/v1/feeds/supply-chain/${pkg}`).then(r => r.data),
  createSupplyChainAlert: (data: unknown) => api.post('/api/v1/feeds/supply-chain', data).then(r => r.data),
  
  // Enrichment
  getExploitConfidence: (cveId: string) => api.get(`/api/v1/feeds/exploit-confidence/${cveId}`).then(r => r.data),
  getGeoRisk: (cveId: string) => api.get(`/api/v1/feeds/geo-risk/${cveId}`).then(r => r.data),
  enrich: (data: { cve_ids: string[] }) => api.post('/api/v1/feeds/enrich', data).then(r => r.data),
  
  // Meta
  getStats: () => api.get('/api/v1/feeds/stats').then(r => r.data),
  getCategories: () => api.get('/api/v1/feeds/categories').then(r => r.data),
  getSources: () => api.get('/api/v1/feeds/sources').then(r => r.data),
  getHealth: () => api.get('/api/v1/feeds/health').then(r => r.data),
  getSchedulerStatus: () => api.get('/api/v1/feeds/scheduler/status').then(r => r.data),
  refreshAll: () => api.post('/api/v1/feeds/refresh/all').then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. DEDUPLICATION & CORRELATION - 18 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const dedupApi = {
  // Process
  process: (data: unknown) => api.post('/api/v1/deduplication/process', data).then(r => r.data),
  processBatch: (data: { findings: unknown[] }) => api.post('/api/v1/deduplication/process/batch', data).then(r => r.data),
  
  // Clusters
  getClusters: (params?: Record<string, unknown>) => api.get('/api/v1/deduplication/clusters', { params }).then(r => r.data),
  getCluster: (id: string) => api.get(`/api/v1/deduplication/clusters/${id}`).then(r => r.data),
  updateClusterStatus: (id: string, status: string) => api.put(`/api/v1/deduplication/clusters/${id}/status`, { status }).then(r => r.data),
  assignCluster: (id: string, assignee: string) => api.put(`/api/v1/deduplication/clusters/${id}/assign`, { assignee }).then(r => r.data),
  updateClusterTicket: (id: string, ticket: unknown) => api.put(`/api/v1/deduplication/clusters/${id}/ticket`, ticket).then(r => r.data),
  getRelatedClusters: (id: string) => api.get(`/api/v1/deduplication/clusters/${id}/related`).then(r => r.data),
  mergeClusters: (data: { cluster_ids: string[] }) => api.post('/api/v1/deduplication/clusters/merge', data).then(r => r.data),
  splitCluster: (id: string, data: { finding_ids: string[] }) => api.post(`/api/v1/deduplication/clusters/${id}/split`, data).then(r => r.data),
  
  // Correlations
  getCorrelations: () => api.get('/api/v1/deduplication/correlations').then(r => r.data),
  createCorrelation: (data: unknown) => api.post('/api/v1/deduplication/correlations', data).then(r => r.data),
  correlateCrossStage: (data: { stages: string[] }) => api.post('/api/v1/deduplication/correlate/cross-stage', data).then(r => r.data),
  
  // Graph & Stats
  getGraph: () => api.get('/api/v1/deduplication/graph').then(r => r.data),
  getStats: (orgId?: string) => api.get('/api/v1/deduplication/stats', { params: orgId ? { org_id: orgId } : {} }).then(r => r.data),
  
  // Feedback & Baseline
  submitFeedback: (data: unknown) => api.post('/api/v1/deduplication/feedback', data).then(r => r.data),
  compareBaseline: (data: { baseline_id: string }) => api.post('/api/v1/deduplication/baseline/compare', data).then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 11. PENTAGI (Penetration Testing AI) - 19 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const pentagiApi = {
  // Requests
  getRequests: () => api.get('/api/v1/pentagi/requests').then(r => r.data),
  createRequest: (data: { target: string, scope?: string, priority?: string }) => api.post('/api/v1/pentagi/requests', data).then(r => r.data),
  getRequest: (id: string) => api.get(`/api/v1/pentagi/requests/${id}`).then(r => r.data),
  updateRequest: (id: string, data: unknown) => api.put(`/api/v1/pentagi/requests/${id}`, data).then(r => r.data),
  startRequest: (id: string) => api.post(`/api/v1/pentagi/requests/${id}/start`).then(r => r.data),
  cancelRequest: (id: string) => api.post(`/api/v1/pentagi/requests/${id}/cancel`).then(r => r.data),
  
  // Results
  getResults: () => api.get('/api/v1/pentagi/results').then(r => r.data),
  createResult: (data: unknown) => api.post('/api/v1/pentagi/results', data).then(r => r.data),
  getResultsByRequest: (requestId: string) => api.get(`/api/v1/pentagi/results/by-request/${requestId}`).then(r => r.data),
  
  // Configs
  getConfigs: () => api.get('/api/v1/pentagi/configs').then(r => r.data),
  createConfig: (data: unknown) => api.post('/api/v1/pentagi/configs', data).then(r => r.data),
  getConfig: (id: string) => api.get(`/api/v1/pentagi/configs/${id}`).then(r => r.data),
  updateConfig: (id: string, data: unknown) => api.put(`/api/v1/pentagi/configs/${id}`, data).then(r => r.data),
  deleteConfig: (id: string) => api.delete(`/api/v1/pentagi/configs/${id}`).then(r => r.data),
  
  // Advanced
  verify: (data: { cve_id: string, target: string }) => api.post('/api/v1/pentagi/verify', data).then(r => r.data),
  monitor: (data: unknown) => api.post('/api/v1/pentagi/monitoring', data).then(r => r.data),
  comprehensiveScan: (data: unknown) => api.post('/api/v1/pentagi/scan/comprehensive', data).then(r => r.data),
  getExploitability: (findingId: string) => api.get(`/api/v1/pentagi/findings/${findingId}/exploitability`).then(r => r.data),
  getStats: () => api.get('/api/v1/pentagi/stats').then(r => r.data),
}

// Alias
export const pentestApi = pentagiApi

// ═══════════════════════════════════════════════════════════════════════════
// 12. MICRO PENTEST - 13 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const microPentestApi = {
  // Basic
  run: (data: { target: string, cve_id?: string, safe_mode?: boolean }) => api.post('/api/v1/micro-pentest/run', data).then(r => r.data),
  getStatus: (flowId: string) => api.get(`/api/v1/micro-pentest/status/${flowId}`).then(r => r.data),
  runBatch: (data: { targets: string[], options?: unknown }) => api.post('/api/v1/micro-pentest/batch', data).then(r => r.data),
  
  // Enterprise
  enterpriseScan: (data: unknown) => api.post('/api/v1/micro-pentest/enterprise/scan', data).then(r => r.data),
  getEnterpriseScan: (scanId: string) => api.get(`/api/v1/micro-pentest/enterprise/scan/${scanId}`).then(r => r.data),
  getEnterpriseScans: () => api.get('/api/v1/micro-pentest/enterprise/scans').then(r => r.data),
  cancelEnterpriseScan: (scanId: string) => api.post(`/api/v1/micro-pentest/enterprise/scan/${scanId}/cancel`).then(r => r.data),
  getAuditLogs: () => api.get('/api/v1/micro-pentest/enterprise/audit-logs').then(r => r.data),
  getHealth: () => api.get('/api/v1/micro-pentest/enterprise/health').then(r => r.data),
  
  // Reference Data
  getAttackVectors: () => api.get('/api/v1/micro-pentest/enterprise/attack-vectors').then(r => r.data),
  getThreatCategories: () => api.get('/api/v1/micro-pentest/enterprise/threat-categories').then(r => r.data),
  getComplianceFrameworks: () => api.get('/api/v1/micro-pentest/enterprise/compliance-frameworks').then(r => r.data),
  getScanModes: () => api.get('/api/v1/micro-pentest/enterprise/scan-modes').then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 13. REACHABILITY - 7 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const reachabilityApi = {
  analyze: (data: { cve_id: string, target?: string, context?: unknown }) => api.post('/api/v1/reachability/analyze', data).then(r => r.data),
  analyzeBulk: (data: { cve_ids: string[], targets?: string[] }) => api.post('/api/v1/reachability/analyze/bulk', data).then(r => r.data),
  getJob: (jobId: string) => api.get(`/api/v1/reachability/job/${jobId}`).then(r => r.data),
  getResults: (cveId: string) => api.get(`/api/v1/reachability/results/${cveId}`).then(r => r.data),
  deleteResults: (cveId: string) => api.delete(`/api/v1/reachability/results/${cveId}`).then(r => r.data),
  getHealth: () => api.get('/api/v1/reachability/health').then(r => r.data),
  getMetrics: () => api.get('/api/v1/reachability/metrics').then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 14. VULNERABILITY DISCOVERY - 10 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const vulnDiscoveryApi = {
  reportDiscovered: (data: { title: string, severity: string, description?: string }) => api.post('/api/v1/vulns/discovered', data).then(r => r.data),
  contribute: (data: unknown) => api.post('/api/v1/vulns/contribute', data).then(r => r.data),
  getInternal: () => api.get('/api/v1/vulns/internal').then(r => r.data),
  getInternalById: (vulnId: string) => api.get(`/api/v1/vulns/internal/${vulnId}`).then(r => r.data),
  updateInternal: (vulnId: string, data: unknown) => api.patch(`/api/v1/vulns/internal/${vulnId}`, data).then(r => r.data),
  trainModel: (data: unknown) => api.post('/api/v1/vulns/train', data).then(r => r.data),
  getTrainingJob: (jobId: string) => api.get(`/api/v1/vulns/train/${jobId}`).then(r => r.data),
  getStats: () => api.get('/api/v1/vulns/stats').then(r => r.data),
  getContributions: () => api.get('/api/v1/vulns/contributions').then(r => r.data),
  getHealth: () => api.get('/api/v1/vulns/health').then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 15. SECRETS DETECTION - 6 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const secretsApi = {
  list: (params?: Record<string, unknown>) => api.get('/api/v1/secrets', { params }).then(r => r.data),
  create: (data: unknown) => api.post('/api/v1/secrets', data).then(r => r.data),
  get: (id: string) => api.get(`/api/v1/secrets/${id}`).then(r => r.data),
  resolve: (id: string, data?: { resolution?: string }) => api.post(`/api/v1/secrets/${id}/resolve`, data).then(r => r.data),
  getScannersStatus: () => api.get('/api/v1/secrets/scanners/status').then(r => r.data),
  scanContent: (content: string) => api.post('/api/v1/secrets/scan/content', { content }).then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 16. IAC SCANNING - 6 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const iacApi = {
  list: (params?: Record<string, unknown>) => api.get('/api/v1/iac', { params }).then(r => r.data),
  create: (data: unknown) => api.post('/api/v1/iac', data).then(r => r.data),
  get: (id: string) => api.get(`/api/v1/iac/${id}`).then(r => r.data),
  resolve: (id: string, data?: unknown) => api.post(`/api/v1/iac/${id}/resolve`, data).then(r => r.data),
  getScannersStatus: () => api.get('/api/v1/iac/scanners/status').then(r => r.data),
  scanContent: (content: string, type: string) => api.post('/api/v1/iac/scan/content', { content, type }).then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 17. INVENTORY - 15 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const inventoryApi = {
  // Applications
  getApplications: () => api.get('/api/v1/inventory/applications').then(r => r.data),
  createApplication: (data: unknown) => api.post('/api/v1/inventory/applications', data).then(r => r.data),
  getApplication: (id: string) => api.get(`/api/v1/inventory/applications/${id}`).then(r => r.data),
  updateApplication: (id: string, data: unknown) => api.put(`/api/v1/inventory/applications/${id}`, data).then(r => r.data),
  deleteApplication: (id: string) => api.delete(`/api/v1/inventory/applications/${id}`).then(r => r.data),
  getApplicationComponents: (id: string) => api.get(`/api/v1/inventory/applications/${id}/components`).then(r => r.data),
  getApplicationAPIs: (id: string) => api.get(`/api/v1/inventory/applications/${id}/apis`).then(r => r.data),
  getApplicationDependencies: (id: string) => api.get(`/api/v1/inventory/applications/${id}/dependencies`).then(r => r.data),
  
  // Services
  getServices: () => api.get('/api/v1/inventory/services').then(r => r.data),
  createService: (data: unknown) => api.post('/api/v1/inventory/services', data).then(r => r.data),
  getService: (id: string) => api.get(`/api/v1/inventory/services/${id}`).then(r => r.data),
  
  // APIs
  getAPIs: () => api.get('/api/v1/inventory/apis').then(r => r.data),
  createAPI: (data: unknown) => api.post('/api/v1/inventory/apis', data).then(r => r.data),
  getAPISecurity: (id: string) => api.get(`/api/v1/inventory/apis/${id}/security`).then(r => r.data),
  
  // Search
  search: (query: string) => api.get('/api/v1/inventory/search', { params: { query } }).then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 18. REMEDIATION - 13 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const remediationApi = {
  // Tasks
  createTask: (data: unknown) => api.post('/api/v1/remediation/tasks', data).then(r => r.data),
  getTasks: (params?: Record<string, unknown>) => api.get('/api/v1/remediation/tasks', { params }).then(r => r.data),
  getTask: (taskId: string) => api.get(`/api/v1/remediation/tasks/${taskId}`).then(r => r.data),
  updateTaskStatus: (taskId: string, status: string) => api.put(`/api/v1/remediation/tasks/${taskId}/status`, { status }).then(r => r.data),
  assignTask: (taskId: string, assignee: string) => api.put(`/api/v1/remediation/tasks/${taskId}/assign`, { assignee }).then(r => r.data),
  verifyTask: (taskId: string, data: unknown) => api.post(`/api/v1/remediation/tasks/${taskId}/verification`, data).then(r => r.data),
  updateTaskTicket: (taskId: string, ticket: unknown) => api.put(`/api/v1/remediation/tasks/${taskId}/ticket`, ticket).then(r => r.data),
  transitionTask: (taskId: string, transition: string) => api.put(`/api/v1/remediation/tasks/${taskId}/transition`, { transition }).then(r => r.data),
  
  // SLA & Metrics
  checkSLA: (data: { task_ids: string[] }) => api.post('/api/v1/remediation/sla/check', data).then(r => r.data),
  getMetrics: (orgId?: string) => api.get('/api/v1/remediation/metrics', { params: orgId ? { org_id: orgId } : {} }).then(r => r.data),
  getStatuses: () => api.get('/api/v1/remediation/statuses').then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 19. COLLABORATION - 21 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const collaborationApi = {
  // Comments
  createComment: (data: { entity_type: string, entity_id: string, content: string }) => api.post('/api/v1/collaboration/comments', data).then(r => r.data),
  getComments: (params?: { entity_type?: string, entity_id?: string }) => api.get('/api/v1/collaboration/comments', { params }).then(r => r.data),
  promoteComment: (commentId: string) => api.put(`/api/v1/collaboration/comments/${commentId}/promote`).then(r => r.data),
  
  // Watchers
  addWatcher: (data: { entity_type: string, entity_id: string, user_id: string }) => api.post('/api/v1/collaboration/watchers', data).then(r => r.data),
  removeWatcher: (data: { entity_type: string, entity_id: string, user_id: string }) => api.delete('/api/v1/collaboration/watchers', { data }).then(r => r.data),
  getWatchers: (params?: { entity_type?: string, entity_id?: string }) => api.get('/api/v1/collaboration/watchers', { params }).then(r => r.data),
  getUserWatched: (userId: string) => api.get(`/api/v1/collaboration/watchers/user/${userId}`).then(r => r.data),
  
  // Activities
  createActivity: (data: unknown) => api.post('/api/v1/collaboration/activities', data).then(r => r.data),
  getActivities: (params?: Record<string, unknown>) => api.get('/api/v1/collaboration/activities', { params }).then(r => r.data),
  
  // Mentions
  getMentions: (userId: string) => api.get(`/api/v1/collaboration/mentions/${userId}`).then(r => r.data),
  acknowledgeMention: (mentionId: string) => api.put(`/api/v1/collaboration/mentions/${mentionId}/acknowledge`).then(r => r.data),
  
  // Meta
  getEntityTypes: () => api.get('/api/v1/collaboration/entity-types').then(r => r.data),
  getActivityTypes: () => api.get('/api/v1/collaboration/activity-types').then(r => r.data),
  
  // Notifications
  queueNotification: (data: unknown) => api.post('/api/v1/collaboration/notifications/queue', data).then(r => r.data),
  notifyWatchers: (data: { entity_type: string, entity_id: string, event: string }) => api.post('/api/v1/collaboration/notifications/notify-watchers', data).then(r => r.data),
  getPendingNotifications: () => api.get('/api/v1/collaboration/notifications/pending').then(r => r.data),
  markNotificationSent: (notificationId: string) => api.put(`/api/v1/collaboration/notifications/${notificationId}/sent`).then(r => r.data),
  getNotificationPreferences: (userId: string) => api.get(`/api/v1/collaboration/notifications/preferences/${userId}`).then(r => r.data),
  updateNotificationPreferences: (userId: string, prefs: unknown) => api.put(`/api/v1/collaboration/notifications/preferences/${userId}`, prefs).then(r => r.data),
  deliverNotification: (notificationId: string) => api.post(`/api/v1/collaboration/notifications/${notificationId}/deliver`).then(r => r.data),
  processNotifications: () => api.post('/api/v1/collaboration/notifications/process').then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 20. WEBHOOKS & ALM - 23 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const webhooksApi = {
  // Mappings
  createMapping: (data: unknown) => api.post('/api/v1/webhooks/mappings', data).then(r => r.data),
  getMappings: () => api.get('/api/v1/webhooks/mappings').then(r => r.data),
  getMapping: (mappingId: string) => api.get(`/api/v1/webhooks/mappings/${mappingId}`).then(r => r.data),
  syncMapping: (mappingId: string) => api.put(`/api/v1/webhooks/mappings/${mappingId}/sync`).then(r => r.data),
  
  // Drift
  getDrift: () => api.get('/api/v1/webhooks/drift').then(r => r.data),
  resolveDrift: (driftId: string) => api.put(`/api/v1/webhooks/drift/${driftId}/resolve`).then(r => r.data),
  
  // Events
  getEvents: () => api.get('/api/v1/webhooks/events').then(r => r.data),
  
  // Outbox
  createOutboxItem: (data: unknown) => api.post('/api/v1/webhooks/outbox', data).then(r => r.data),
  getOutbox: () => api.get('/api/v1/webhooks/outbox').then(r => r.data),
  getPendingOutbox: () => api.get('/api/v1/webhooks/outbox/pending').then(r => r.data),
  processOutboxItem: (outboxId: string) => api.put(`/api/v1/webhooks/outbox/${outboxId}/process`).then(r => r.data),
  deleteOutboxItem: (outboxId: string) => api.delete(`/api/v1/webhooks/outbox/${outboxId}`).then(r => r.data),
  retryOutboxItem: (outboxId: string) => api.post(`/api/v1/webhooks/outbox/${outboxId}/retry`).then(r => r.data),
  getOutboxStats: () => api.get('/api/v1/webhooks/outbox/stats').then(r => r.data),
  executeOutboxItem: (outboxId: string) => api.post(`/api/v1/webhooks/outbox/${outboxId}/execute`).then(r => r.data),
  processPendingOutbox: () => api.post('/api/v1/webhooks/outbox/process-pending').then(r => r.data),
  
  // ALM Work Items
  createALMWorkItem: (data: unknown) => api.post('/api/v1/webhooks/alm/work-items', data).then(r => r.data),
  updateALMWorkItem: (mappingId: string, data: unknown) => api.put(`/api/v1/webhooks/alm/work-items/${mappingId}`, data).then(r => r.data),
  getALMWorkItems: () => api.get('/api/v1/webhooks/alm/work-items').then(r => r.data),
  
  // Receivers
  receiveJira: (data: unknown) => api.post('/api/v1/webhooks/jira', data).then(r => r.data),
  receiveServiceNow: (data: unknown) => api.post('/api/v1/webhooks/servicenow', data).then(r => r.data),
  receiveGitLab: (data: unknown) => api.post('/api/v1/webhooks/gitlab', data).then(r => r.data),
  receiveAzureDevOps: (data: unknown) => api.post('/api/v1/webhooks/azure-devops', data).then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 21. BULK OPERATIONS - 12 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const bulkApi = {
  // Clusters
  updateClustersStatus: (data: { cluster_ids: string[], status: string }) => api.post('/api/v1/bulk/clusters/status', data).then(r => r.data),
  assignClusters: (data: { cluster_ids: string[], assignee: string }) => api.post('/api/v1/bulk/clusters/assign', data).then(r => r.data),
  acceptRiskClusters: (data: { cluster_ids: string[], reason: string }) => api.post('/api/v1/bulk/clusters/accept-risk', data).then(r => r.data),
  createTicketsForClusters: (data: { cluster_ids: string[], ticket_type: string }) => api.post('/api/v1/bulk/clusters/create-tickets', data).then(r => r.data),
  
  // Export
  export: (data: { format: string, filters?: unknown }) => api.post('/api/v1/bulk/export', data).then(r => r.data),
  
  // Jobs
  getJob: (jobId: string) => api.get(`/api/v1/bulk/jobs/${jobId}`).then(r => r.data),
  getJobs: () => api.get('/api/v1/bulk/jobs').then(r => r.data),
  deleteJob: (jobId: string) => api.delete(`/api/v1/bulk/jobs/${jobId}`).then(r => r.data),
  
  // Findings
  updateFindings: (data: { finding_ids: string[], updates: unknown }) => api.post('/api/v1/bulk/findings/update', data).then(r => r.data),
  deleteFindings: (data: { finding_ids: string[] }) => api.post('/api/v1/bulk/findings/delete', data).then(r => r.data),
  assignFindings: (data: { finding_ids: string[], assignee: string }) => api.post('/api/v1/bulk/findings/assign', data).then(r => r.data),
  
  // Policies
  applyPolicies: (data: { policy_ids: string[], scope: unknown }) => api.post('/api/v1/bulk/policies/apply', data).then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 22. POLICIES - 8 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const policiesApi = {
  list: () => api.get('/api/v1/policies').then(r => r.data),
  create: (data: unknown) => api.post('/api/v1/policies', data).then(r => r.data),
  get: (id: string) => api.get(`/api/v1/policies/${id}`).then(r => r.data),
  update: (id: string, data: unknown) => api.put(`/api/v1/policies/${id}`, data).then(r => r.data),
  delete: (id: string) => api.delete(`/api/v1/policies/${id}`).then(r => r.data),
  validate: (id: string) => api.post(`/api/v1/policies/${id}/validate`).then(r => r.data),
  test: (id: string, testData?: unknown) => api.post(`/api/v1/policies/${id}/test`, testData).then(r => r.data),
  getViolations: (id: string) => api.get(`/api/v1/policies/${id}/violations`).then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 23. WORKFLOWS - 7 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const workflowsApi = {
  list: () => api.get('/api/v1/workflows').then(r => r.data),
  create: (data: unknown) => api.post('/api/v1/workflows', data).then(r => r.data),
  get: (id: string) => api.get(`/api/v1/workflows/${id}`).then(r => r.data),
  update: (id: string, data: unknown) => api.put(`/api/v1/workflows/${id}`, data).then(r => r.data),
  delete: (id: string) => api.delete(`/api/v1/workflows/${id}`).then(r => r.data),
  execute: (id: string, context?: unknown) => api.post(`/api/v1/workflows/${id}/execute`, context).then(r => r.data),
  getHistory: (id: string) => api.get(`/api/v1/workflows/${id}/history`).then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 24. INTEGRATIONS - 8 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const integrationsApi = {
  list: () => api.get('/api/v1/integrations').then(r => r.data),
  create: (data: unknown) => api.post('/api/v1/integrations', data).then(r => r.data),
  get: (id: string) => api.get(`/api/v1/integrations/${id}`).then(r => r.data),
  update: (id: string, data: unknown) => api.put(`/api/v1/integrations/${id}`, data).then(r => r.data),
  delete: (id: string) => api.delete(`/api/v1/integrations/${id}`).then(r => r.data),
  test: (id: string) => api.post(`/api/v1/integrations/${id}/test`).then(r => r.data),
  getSyncStatus: (id: string) => api.get(`/api/v1/integrations/${id}/sync-status`).then(r => r.data),
  sync: (id: string) => api.post(`/api/v1/integrations/${id}/sync`).then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 25. REPORTS - 13 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const reportsApi = {
  list: () => api.get('/api/v1/reports').then(r => r.data),
  create: (data: unknown) => api.post('/api/v1/reports', data).then(r => r.data),
  getStats: () => api.get('/api/v1/reports/stats').then(r => r.data),
  get: (id: string) => api.get(`/api/v1/reports/${id}`).then(r => r.data),
  download: (id: string) => api.get(`/api/v1/reports/${id}/download`).then(r => r.data),
  getFile: (id: string) => api.get(`/api/v1/reports/${id}/file`, { responseType: 'blob' }).then(r => r.data),
  schedule: (data: unknown) => api.post('/api/v1/reports/schedule', data).then(r => r.data),
  getSchedules: () => api.get('/api/v1/reports/schedules/list').then(r => r.data),
  getTemplates: () => api.get('/api/v1/reports/templates/list').then(r => r.data),
  exportSARIF: (data: unknown) => api.post('/api/v1/reports/export/sarif', data).then(r => r.data),
  exportCSV: (data: unknown) => api.post('/api/v1/reports/export/csv', data).then(r => r.data),
  downloadCSV: (exportId: string) => api.get(`/api/v1/reports/export/csv/${exportId}/download`).then(r => r.data),
  exportJSON: () => api.get('/api/v1/reports/export/json').then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 26. AUDIT - 10 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const auditApi = {
  getLogs: (params?: { limit?: number, offset?: number }) => api.get('/api/v1/audit/logs', { params }).then(r => r.data),
  getLog: (id: string) => api.get(`/api/v1/audit/logs/${id}`).then(r => r.data),
  getUserActivity: (params?: Record<string, unknown>) => api.get('/api/v1/audit/user-activity', { params }).then(r => r.data),
  getPolicyChanges: (params?: Record<string, unknown>) => api.get('/api/v1/audit/policy-changes', { params }).then(r => r.data),
  getDecisionTrail: (params?: Record<string, unknown>) => api.get('/api/v1/audit/decision-trail', { params }).then(r => r.data),
  getComplianceFrameworks: () => api.get('/api/v1/audit/compliance/frameworks').then(r => r.data),
  getFrameworkStatus: (id: string) => api.get(`/api/v1/audit/compliance/frameworks/${id}/status`).then(r => r.data),
  getFrameworkGaps: (id: string) => api.get(`/api/v1/audit/compliance/frameworks/${id}/gaps`).then(r => r.data),
  generateFrameworkReport: (id: string) => api.post(`/api/v1/audit/compliance/frameworks/${id}/report`).then(r => r.data),
  getComplianceControls: () => api.get('/api/v1/audit/compliance/controls').then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 27. USERS - 6 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const usersApi = {
  login: (data: { username: string, password: string }) => api.post('/api/v1/users/login', data).then(r => r.data),
  list: () => api.get('/api/v1/users').then(r => r.data),
  create: (data: unknown) => api.post('/api/v1/users', data).then(r => r.data),
  get: (id: string) => api.get(`/api/v1/users/${id}`).then(r => r.data),
  update: (id: string, data: unknown) => api.put(`/api/v1/users/${id}`, data).then(r => r.data),
  delete: (id: string) => api.delete(`/api/v1/users/${id}`).then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 28. TEAMS - 8 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const teamsApi = {
  list: () => api.get('/api/v1/teams').then(r => r.data),
  create: (data: unknown) => api.post('/api/v1/teams', data).then(r => r.data),
  get: (id: string) => api.get(`/api/v1/teams/${id}`).then(r => r.data),
  update: (id: string, data: unknown) => api.put(`/api/v1/teams/${id}`, data).then(r => r.data),
  delete: (id: string) => api.delete(`/api/v1/teams/${id}`).then(r => r.data),
  getMembers: (id: string) => api.get(`/api/v1/teams/${id}/members`).then(r => r.data),
  addMember: (id: string, data: { user_id: string }) => api.post(`/api/v1/teams/${id}/members`, data).then(r => r.data),
  removeMember: (id: string, userId: string) => api.delete(`/api/v1/teams/${id}/members/${userId}`).then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 29. SSO/AUTH - 4 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const authApi = {
  getSSOConfigs: () => api.get('/api/v1/auth/sso').then(r => r.data),
  createSSOConfig: (data: unknown) => api.post('/api/v1/auth/sso', data).then(r => r.data),
  getSSOConfig: (id: string) => api.get(`/api/v1/auth/sso/${id}`).then(r => r.data),
  updateSSOConfig: (id: string, data: unknown) => api.put(`/api/v1/auth/sso/${id}`, data).then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 30. IDE - 5 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const ideApi = {
  getStatus: () => api.get('/api/v1/ide/status').then(r => r.data),
  getConfig: () => api.get('/api/v1/ide/config').then(r => r.data),
  analyze: (data: { code: string, language?: string }) => api.post('/api/v1/ide/analyze', data).then(r => r.data),
  getSuggestions: () => api.get('/api/v1/ide/suggestions').then(r => r.data),
  ingestSARIF: (data: unknown) => api.post('/api/v1/ide/sarif', data).then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 31. VALIDATION - 3 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const validationApi = {
  validateInput: (data: unknown) => api.post('/api/v1/validate/input', data).then(r => r.data),
  validateBatch: (data: { items: unknown[] }) => api.post('/api/v1/validate/batch', data).then(r => r.data),
  getSupportedFormats: () => api.get('/api/v1/validate/supported-formats').then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 32. MARKETPLACE - 12 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const marketplaceApi = {
  getPacks: (framework: string, control: string) => api.get(`/api/v1/marketplace/packs/${framework}/${control}`).then(r => r.data),
  browse: () => api.get('/api/v1/marketplace/browse').then(r => r.data),
  getRecommendations: () => api.get('/api/v1/marketplace/recommendations').then(r => r.data),
  getItem: (itemId: string) => api.get(`/api/v1/marketplace/items/${itemId}`).then(r => r.data),
  contribute: (data: unknown) => api.post('/api/v1/marketplace/contribute', data).then(r => r.data),
  updateItem: (itemId: string, data: unknown) => api.put(`/api/v1/marketplace/items/${itemId}`, data).then(r => r.data),
  rateItem: (itemId: string, rating: number) => api.post(`/api/v1/marketplace/items/${itemId}/rate`, { rating }).then(r => r.data),
  purchase: (itemId: string) => api.post(`/api/v1/marketplace/purchase/${itemId}`).then(r => r.data),
  download: (token: string) => api.get(`/api/v1/marketplace/download/${token}`).then(r => r.data),
  getContributors: () => api.get('/api/v1/marketplace/contributors').then(r => r.data),
  getComplianceContent: (stage: string) => api.get(`/api/v1/marketplace/compliance-content/${stage}`).then(r => r.data),
  getStats: () => api.get('/api/v1/marketplace/stats').then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 33. INTELLIGENT ENGINE - 11 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const intelligentEngineApi = {
  getStatus: () => api.get('/intelligent-engine/status').then(r => r.data),
  getSessions: () => api.get('/intelligent-engine/sessions').then(r => r.data),
  startScan: (data: unknown) => api.post('/intelligent-engine/scan', data).then(r => r.data),
  getScan: (sessionId: string) => api.get(`/intelligent-engine/scan/${sessionId}`).then(r => r.data),
  stopScan: (sessionId: string) => api.post(`/intelligent-engine/scan/${sessionId}/stop`).then(r => r.data),
  gatherIntelligence: (data: unknown) => api.post('/intelligent-engine/intelligence/gather', data).then(r => r.data),
  generatePlan: (data: unknown) => api.post('/intelligent-engine/plan/generate', data).then(r => r.data),
  executePlan: (planId: string) => api.post(`/intelligent-engine/plan/${planId}/execute`).then(r => r.data),
  getMindsDBStatus: () => api.get('/intelligent-engine/mindsdb/status').then(r => r.data),
  mindsDBPredict: (data: unknown) => api.post('/intelligent-engine/mindsdb/predict', data).then(r => r.data),
  consensusAnalyze: (data: unknown) => api.post('/intelligent-engine/consensus/analyze', data).then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 34. EVIDENCE & PROVENANCE - 6 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const evidenceApi = {
  list: () => api.get('/evidence/').then(r => r.data),
  get: (release: string) => api.get(`/evidence/${release}`).then(r => r.data),
  downloadBundle: (bundleId: string) => api.get(`/evidence/bundles/${bundleId}/download`).then(r => r.data),
  verify: (data: { bundle_id: string }) => api.post('/evidence/verify', data).then(r => r.data),
}

export const provenanceApi = {
  list: () => api.get('/provenance/').then(r => r.data),
  get: (artifactName: string) => api.get(`/provenance/${artifactName}`).then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 35. GRAPH - 7 endpoints
// ═══════════════════════════════════════════════════════════════════════════

export const graphApi = {
  get: () => api.get('/graph/').then(r => r.data),
  getLineage: (artifactName: string) => api.get(`/graph/lineage/${artifactName}`).then(r => r.data),
  getKEVComponents: () => api.get('/graph/kev-components').then(r => r.data),
  getAnomalies: () => api.get('/graph/anomalies').then(r => r.data),
}

export const sbomApi = {
  list: () => api.get('/sbom/').then(r => r.data),
  getComponent: (componentSlug: string) => api.get(`/sbom/component/${componentSlug}`).then(r => r.data),
  getCVE: (cveId: string) => api.get(`/sbom/cve/${cveId}`).then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 36. FILE INGEST
// ═══════════════════════════════════════════════════════════════════════════

export const ingestApi = {
  uploadSBOM: (file: File) => uploadFile('/inputs/sbom', file),
  uploadSARIF: (file: File) => uploadFile('/inputs/sarif', file),
  uploadCNAPP: (file: File) => uploadFile('/inputs/cnapp', file),
  uploadVEX: (file: File) => uploadFile('/inputs/vex', file),
}

// ═══════════════════════════════════════════════════════════════════════════
// COMPLIANCE API (Combined from agents + audit)
// ═══════════════════════════════════════════════════════════════════════════

export const complianceApi = {
  // From agents
  mapFindings: agentsApi.compliance.mapFindings,
  gapAnalysis: agentsApi.compliance.gapAnalysis,
  auditEvidence: agentsApi.compliance.auditEvidence,
  regulatoryAlerts: agentsApi.compliance.regulatoryAlerts,
  getControls: agentsApi.compliance.getControls,
  getDashboard: agentsApi.compliance.getDashboard,
  generateReport: agentsApi.compliance.generateReport,
  
  // From audit
  getFrameworks: auditApi.getComplianceFrameworks,
  getFrameworkStatus: auditApi.getFrameworkStatus,
  getFrameworkGaps: auditApi.getFrameworkGaps,
}

// ═══════════════════════════════════════════════════════════════════════════
// SYSTEM API
// ═══════════════════════════════════════════════════════════════════════════

export const systemApi = {
  getHealth: healthApi.check,
  getVersion: () => api.get('/api/v1/version').then(r => r.data),
  getStatus: () => api.get('/api/v1/status').then(r => r.data),
  getCapabilities: algorithmsApi.getCapabilities,
}

// ═══════════════════════════════════════════════════════════════════════════
// SEARCH API
// ═══════════════════════════════════════════════════════════════════════════

export const searchApi = {
  search: (query: string) => api.get('/api/v1/search', { params: { q: query } }).then(r => r.data),
  searchFindings: (query: string) => api.get('/api/v1/analytics/findings', { params: { q: query } }).then(r => r.data),
  searchInventory: inventoryApi.search,
}

// ═══════════════════════════════════════════════════════════════════════════
// CNAPP API (alias for cloud security)
// ═══════════════════════════════════════════════════════════════════════════

export const cnappApi = {
  ingest: ingestApi.uploadCNAPP,
  getFindings: () => analyticsApi.getFindings({ source: 'cnapp' }),
  scan: iacApi.scanContent,
}

// ═══════════════════════════════════════════════════════════════════════════
// ATTACK GRAPH API (alias)
// ═══════════════════════════════════════════════════════════════════════════

export const attackGraphApi = {
  getGraph: graphApi.get,
  analyzeSurface: algorithmsApi.gnnAttackSurface,
  getCriticalNodes: algorithmsApi.gnnCriticalNodes,
  getRiskPropagation: algorithmsApi.gnnRiskPropagation,
}

// ═══════════════════════════════════════════════════════════════════════════
// AUTOMATION API
// ═══════════════════════════════════════════════════════════════════════════

export const automationApi = {
  getRules: workflowsApi.list,
  createRule: workflowsApi.create,
  executeRule: workflowsApi.execute,
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN DEFAULT EXPORT (Organized by UI Suite)
// ═══════════════════════════════════════════════════════════════════════════

export default {
  // Core
  health: healthApi,
  system: systemApi,
  search: searchApi,
  
  // Analytics & Dashboard
  analytics: analyticsApi,
  dashboard: dashboardApi,
  
  // AI & Predictions
  predictions: predictionsApi,
  algorithms: algorithmsApi,
  llm: llmApi,
  enhanced: enhancedApi,
  copilot: copilotApi,
  agents: agentsApi,
  intelligentEngine: intelligentEngineApi,
  
  // Threat Intelligence
  feeds: feedsApi,
  
  // Correlation & Dedup
  dedup: dedupApi,
  
  // Attack & Pentest
  pentagi: pentagiApi,
  pentest: pentestApi,
  microPentest: microPentestApi,
  reachability: reachabilityApi,
  vulnDiscovery: vulnDiscoveryApi,
  attackGraph: attackGraphApi,
  graph: graphApi,
  
  // Code Security
  secrets: secretsApi,
  iac: iacApi,
  inventory: inventoryApi,
  sbom: sbomApi,
  ingest: ingestApi,
  validation: validationApi,
  ide: ideApi,
  
  // Cloud Security
  cnapp: cnappApi,
  
  // Remediation & Workflow
  remediation: remediationApi,
  collaboration: collaborationApi,
  workflows: workflowsApi,
  automation: automationApi,
  bulk: bulkApi,
  
  // Compliance & Audit
  compliance: complianceApi,
  audit: auditApi,
  policies: policiesApi,
  
  // Integrations
  integrations: integrationsApi,
  webhooks: webhooksApi,
  marketplace: marketplaceApi,
  
  // Reports & Evidence
  reports: reportsApi,
  evidence: evidenceApi,
  provenance: provenanceApi,
  
  // Users & Access
  users: usersApi,
  teams: teamsApi,
  auth: authApi,
}
