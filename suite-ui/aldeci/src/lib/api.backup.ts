import axios, { AxiosError } from 'axios'
import { toast } from 'sonner'

// API Configuration
const API_BASE_URL = 'http://localhost:8000'
const API_KEY = 'demo-token'

// Create axios instance with defaults
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
    // Get API key from localStorage if available
    const storedKey = localStorage.getItem('aldeci_api_key')
    if (storedKey) {
      config.headers['X-API-Key'] = storedKey
    }
    return config
  },
  (error) => Promise.reject(error)
)

// Response interceptor for error handling
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

export interface DashboardOverview {
  total_findings: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  clusters_count: number
  dedup_rate: number
  mttr_hours: number
  sla_compliance: number
}

export interface EPSSScore {
  cve: string
  epss: number
  percentile: number
}

export interface KEVEntry {
  cve_id: string
  vendor_project: string
  product: string
  vulnerability_name: string
  date_added: string
  short_description: string
  required_action: string
  due_date: string
}

export interface Algorithm {
  name: string
  endpoint: string
  method: string
  description: string
  use_cases: string[]
}

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
  created_at: string
}

export interface MonteCarloResult {
  cve_id: string
  risk_score: number
  breach_probability: number
  expected_loss: number
  var_95: number
  confidence_interval: [number, number]
}

export interface CausalAnalysis {
  root_causes: Array<{
    cause: string
    impact: number
    recommendation: string
  }>
  intervention_effects: Array<{
    intervention: string
    expected_reduction: number
  }>
}

export interface AttackPath {
  nodes: Array<{
    id: string
    type: string
    risk: number
  }>
  edges: Array<{
    source: string
    target: string
    probability: number
  }>
  critical_paths: string[][]
}

// ═══════════════════════════════════════════════════════════════════════════
// API Functions - Dashboard & Analytics
// ═══════════════════════════════════════════════════════════════════════════

export const dashboardApi = {
  getOverview: async (orgId: string = 'default') => {
    const response = await api.get<DashboardOverview>('/api/v1/analytics/dashboard/overview', {
      params: { org_id: orgId }
    })
    return response.data
  },

  getTrends: async (orgId: string = 'default', days: number = 30) => {
    const response = await api.get('/api/v1/analytics/dashboard/trends', {
      params: { org_id: orgId, days }
    })
    return response.data
  },

  getTopRisks: async (orgId: string = 'default', limit: number = 10) => {
    const response = await api.get('/api/v1/analytics/dashboard/top-risks', {
      params: { org_id: orgId, limit }
    })
    return response.data
  },

  getComplianceStatus: async (orgId: string = 'default') => {
    const response = await api.get('/api/v1/analytics/dashboard/compliance-status', {
      params: { org_id: orgId }
    })
    return response.data
  },

  getMTTR: async (orgId: string = 'default') => {
    const response = await api.get('/api/v1/analytics/mttr', {
      params: { org_id: orgId }
    })
    return response.data
  },

  getNoiseReduction: async () => {
    const response = await api.get('/api/v1/analytics/noise-reduction')
    return response.data
  },

  getROI: async () => {
    const response = await api.get('/api/v1/analytics/roi')
    return response.data
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// API Functions - Feeds (EPSS, KEV, etc.)
// ═══════════════════════════════════════════════════════════════════════════

export const feedsApi = {
  getEPSS: async (cveIds?: string[]) => {
    const response = await api.get<{ scores: EPSSScore[]; count: number }>('/api/v1/feeds/epss', {
      params: cveIds ? { cve_ids: cveIds.join(',') } : {}
    })
    return response.data
  },

  refreshEPSS: async () => {
    const response = await api.post('/api/v1/feeds/epss/refresh')
    return response.data
  },

  getKEV: async (cveIds?: string[]) => {
    const response = await api.get('/api/v1/feeds/kev', {
      params: cveIds ? { cve_ids: cveIds.join(',') } : {}
    })
    return response.data
  },

  refreshKEV: async () => {
    const response = await api.post('/api/v1/feeds/kev/refresh')
    return response.data
  },

  getHealth: async () => {
    const response = await api.get('/api/v1/feeds/health')
    return response.data
  },

  getSources: async () => {
    const response = await api.get('/api/v1/feeds/sources')
    return response.data
  },

  getCategories: async () => {
    const response = await api.get('/api/v1/feeds/categories')
    return response.data
  },

  getExploits: async (cveId?: string) => {
    const url = cveId ? `/api/v1/feeds/exploits/${cveId}` : '/api/v1/feeds/exploits'
    const response = await api.get(url)
    return response.data
  },

  getExploitConfidence: async (cveId: string) => {
    const response = await api.get(`/api/v1/feeds/exploit-confidence/${cveId}`)
    return response.data
  },

  refreshAll: async () => {
    const response = await api.post('/api/v1/feeds/refresh/all')
    return response.data
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// API Functions - Findings & Deduplication
// ═══════════════════════════════════════════════════════════════════════════

export const findingsApi = {
  list: async (params?: { severity?: string; status?: string; limit?: number; offset?: number }) => {
    const response = await api.get<{ findings: Finding[]; total: number }>('/api/v1/analytics/findings', {
      params
    })
    return response.data
  },

  get: async (id: string) => {
    const response = await api.get<Finding>(`/api/v1/analytics/findings/${id}`)
    return response.data
  },

  getClusters: async (params?: { severity?: string; status?: string }) => {
    const response = await api.get<{ clusters: Cluster[]; total: number }>('/api/v1/deduplication/clusters', {
      params
    })
    return response.data
  },

  getCluster: async (id: string) => {
    const response = await api.get<Cluster>(`/api/v1/deduplication/clusters/${id}`)
    return response.data
  },

  updateClusterStatus: async (id: string, status: string) => {
    const response = await api.put(`/api/v1/deduplication/clusters/${id}/status`, { status })
    return response.data
  },

  assignCluster: async (id: string, userId: string) => {
    const response = await api.put(`/api/v1/deduplication/clusters/${id}/assign`, { user_id: userId })
    return response.data
  },

  getDedupStats: async () => {
    const response = await api.get('/api/v1/deduplication/stats')
    return response.data
  },

  getCorrelationGraph: async () => {
    const response = await api.get('/api/v1/deduplication/graph')
    return response.data
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// API Functions - Algorithms (Monte Carlo, Causal, GNN)
// ═══════════════════════════════════════════════════════════════════════════

export const algorithmsApi = {
  getCapabilities: async () => {
    const response = await api.get<{ algorithms: Algorithm[]; differentiators: string[] }>('/api/v1/algorithms/capabilities')
    return response.data
  },

  getStatus: async () => {
    const response = await api.get('/api/v1/algorithms/status')
    return response.data
  },

  // Monte Carlo Risk Quantification
  monteCarloQuantify: async (data: { cve_ids: string[]; simulations?: number }) => {
    const response = await api.post<{ results: MonteCarloResult[] }>('/api/v1/algorithms/monte-carlo/quantify', data)
    return response.data
  },

  monteCarloCVE: async (cveId: string) => {
    const response = await api.post<MonteCarloResult>('/api/v1/algorithms/monte-carlo/cve', { cve_id: cveId })
    return response.data
  },

  monteCarloPortfolio: async (data: { cve_ids: string[] }) => {
    const response = await api.post('/api/v1/algorithms/monte-carlo/portfolio', data)
    return response.data
  },

  // Causal Analysis
  causalAnalyze: async (data: { finding_ids: string[]; depth?: number }) => {
    const response = await api.post<CausalAnalysis>('/api/v1/algorithms/causal/analyze', data)
    return response.data
  },

  causalCounterfactual: async (data: { intervention: string; targets: string[] }) => {
    const response = await api.post('/api/v1/algorithms/causal/counterfactual', data)
    return response.data
  },

  causalTreatmentEffect: async (data: { treatment: string; outcome: string }) => {
    const response = await api.post('/api/v1/algorithms/causal/treatment-effect', data)
    return response.data
  },

  // GNN Attack Graph
  gnnAttackSurface: async (data: { asset_ids?: string[]; depth?: number }) => {
    const response = await api.post<AttackPath>('/api/v1/algorithms/gnn/attack-surface', data)
    return response.data
  },

  gnnCriticalNodes: async (data: { threshold?: number }) => {
    const response = await api.post('/api/v1/algorithms/gnn/critical-nodes', data)
    return response.data
  },

  gnnRiskPropagation: async (data: { source_id: string }) => {
    const response = await api.post('/api/v1/algorithms/gnn/risk-propagation', data)
    return response.data
  },

  // Prioritization
  prioritize: async (data: { algorithms: string[]; context?: Record<string, unknown> }) => {
    const response = await api.post('/api/v1/algorithms/prioritize', data)
    return response.data
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// API Functions - Ingestion
// ═══════════════════════════════════════════════════════════════════════════

export const ingestApi = {
  uploadSBOM: async (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    const response = await api.post('/inputs/sbom', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    return response.data
  },

  uploadSARIF: async (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    const response = await api.post('/inputs/sarif', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    return response.data
  },

  uploadDesign: async (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    const response = await api.post('/inputs/design', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    return response.data
  },

  uploadCVE: async (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    const response = await api.post('/inputs/cve', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    return response.data
  },

  uploadVEX: async (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    const response = await api.post('/inputs/vex', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    return response.data
  },

  uploadCNAPP: async (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    const response = await api.post('/inputs/cnapp', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    return response.data
  },

  // JSON ingest methods
  ingestSBOM: async (data: Record<string, unknown>) => {
    const response = await api.post('/api/v1/ingest/sbom', data)
    return response.data
  },

  ingestSARIF: async (data: Record<string, unknown>) => {
    const response = await api.post('/api/v1/ingest/sarif', data)
    return response.data
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// API Functions - Pentest / Attack
// ═══════════════════════════════════════════════════════════════════════════

export const pentestApi = {
  // Enterprise scan endpoints
  getScans: async () => {
    const response = await api.get('/api/v1/micro-pentest/enterprise/scans')
    return response.data
  },

  startScan: async (data: { cve_ids: string[]; target_urls: string[]; scan_mode?: string }) => {
    const response = await api.post('/api/v1/micro-pentest/enterprise/scan', data)
    return response.data
  },

  getScan: async (scanId: string) => {
    const response = await api.get(`/api/v1/micro-pentest/enterprise/scan/${scanId}`)
    return response.data
  },

  cancelScan: async (scanId: string) => {
    const response = await api.post(`/api/v1/micro-pentest/enterprise/scan/${scanId}/cancel`)
    return response.data
  },

  // Run micro pentest
  runMicroPentest: async (data: { cve_ids: string[]; target_urls: string[]; safe_mode?: boolean }) => {
    const response = await api.post('/api/v1/micro-pentest/run', data)
    return response.data
  },

  // Batch pentest
  runBatch: async (data: { cve_ids: string[]; target_urls: string[] }) => {
    const response = await api.post('/api/v1/micro-pentest/batch', data)
    return response.data
  },

  // Get status of a running pentest
  getStatus: async (flowId: string) => {
    const response = await api.get(`/api/v1/micro-pentest/status/${flowId}`)
    return response.data
  },

  // Enterprise metadata endpoints
  getHealth: async () => {
    const response = await api.get('/api/v1/micro-pentest/enterprise/health')
    return response.data
  },

  getScanModes: async () => {
    const response = await api.get('/api/v1/micro-pentest/enterprise/scan-modes')
    return response.data
  },

  getAttackVectors: async () => {
    const response = await api.get('/api/v1/micro-pentest/enterprise/attack-vectors')
    return response.data
  },

  getThreatCategories: async () => {
    const response = await api.get('/api/v1/micro-pentest/enterprise/threat-categories')
    return response.data
  },

  getTests: async () => {
    const response = await api.get('/api/v1/micro-pentest/enterprise/scans')
    return response.data
  },

  validateExploit: async (cve: string, targetUrl: string = 'http://localhost') => {
    const response = await api.post('/api/v1/micro-pentest/run', { 
      cve_ids: [cve], 
      target_urls: [targetUrl],
      safe_mode: true
    })
    return response.data
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// API Functions - Compliance
// ═══════════════════════════════════════════════════════════════════════════

export const complianceApi = {
  getFrameworks: async () => {
    const response = await api.get('/api/v1/audit/compliance/frameworks')
    return response.data
  },

  getFrameworkStatus: async (id: string) => {
    const response = await api.get(`/api/v1/audit/compliance/frameworks/${id}/status`)
    return response.data
  },

  getFrameworkGaps: async (id: string) => {
    const response = await api.get(`/api/v1/audit/compliance/frameworks/${id}/gaps`)
    return response.data
  },

  getControls: async () => {
    const response = await api.get('/api/v1/audit/compliance/controls')
    return response.data
  },

  generateReport: async (frameworkId: string) => {
    const response = await api.get(`/api/v1/audit/compliance/frameworks/${frameworkId}/report`)
    return response.data
  },

  getStatus: async () => {
    const response = await api.get('/api/v1/audit/compliance/status')
    return response.data
  },

  collectEvidence: async (evidenceId: string) => {
    const response = await api.post(`/api/v1/audit/evidence/collect`, { evidence_id: evidenceId })
    return response.data
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// API Functions - Health & Status
// ═══════════════════════════════════════════════════════════════════════════

export const systemApi = {
  health: async () => {
    const response = await api.get('/health')
    return response.data
  },

  status: async () => {
    const response = await api.get('/api/v1/status')
    return response.data
  },

  getHealth: async () => {
    const response = await api.get('/health')
    return response.data
  },

  getStatus: async () => {
    const response = await api.get('/api/v1/status')
    return response.data
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// API Functions - Chat (AI Copilot)
// ═══════════════════════════════════════════════════════════════════════════

export const chatApi = {
  sendMessage: async (message: string, _sessionId?: string) => {
    // Use IDE analyze endpoint as a fallback for chat-like functionality
    try {
      const response = await api.post('/api/v1/ide/analyze', {
        code: message,
        language: 'text',
      })
      return {
        response: response.data.suggestions?.[0] || response.data.analysis || 'Analysis complete',
        session_id: crypto.randomUUID(),
      }
    } catch {
      // Return a helpful fallback response
      return {
        response: `I can help with vulnerability analysis, risk assessment, and remediation guidance. 
Try asking about:
• EPSS scores and KEV data
• Risk quantification using Monte Carlo simulation
• Attack path analysis with GNN
• Causal root cause analysis
• Compliance status and gaps`,
        session_id: crypto.randomUUID(),
      }
    }
  },

  getHistory: async (_sessionId: string) => {
    // No chat history endpoint - return empty
    return { messages: [] }
  },

  getSuggestions: async () => {
    const response = await api.get('/api/v1/ide/suggestions')
    return response.data
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// API Functions - Remediation
// ═══════════════════════════════════════════════════════════════════════════

export const remediationApi = {
  getTasks: async (orgId: string = 'default') => {
    const response = await api.get('/api/v1/remediation/tasks', {
      params: { org_id: orgId }
    })
    return response.data
  },

  getTask: async (taskId: string) => {
    const response = await api.get(`/api/v1/remediation/tasks/${taskId}`)
    return response.data
  },

  assignTask: async (taskId: string, assignee: string) => {
    const response = await api.post(`/api/v1/remediation/tasks/${taskId}/assign`, { assignee })
    return response.data
  },

  transitionTask: async (taskId: string, status: string) => {
    const response = await api.post(`/api/v1/remediation/tasks/${taskId}/transition`, { status })
    return response.data
  },

  verifyTask: async (taskId: string) => {
    const response = await api.post(`/api/v1/remediation/tasks/${taskId}/verify`)
    return response.data
  },

  createTicket: async (taskId: string, data: { system: string; project?: string }) => {
    const response = await api.post(`/api/v1/remediation/tasks/${taskId}/ticket`, data)
    return response.data
  },

  getMetrics: async (orgId: string = 'default') => {
    const response = await api.get(`/api/v1/remediation/metrics/${orgId}`)
    return response.data
  },

  getStatuses: async () => {
    const response = await api.get('/api/v1/remediation/statuses')
    return response.data
  },

  checkSLA: async () => {
    const response = await api.get('/api/v1/remediation/sla/check')
    return response.data
  },

  generateFix: async (cve: string) => {
    // This endpoint may need to be implemented - fallback to tasks
    const response = await api.post('/api/v1/remediation/tasks', { cve_id: cve })
    return response.data
  },

  createPR: async (data: { cve?: string; fix?: string; title: string }) => {
    // Create ticket as PR equivalent
    const response = await api.post('/api/v1/remediation/tasks', data)
    return response.data
  },

  getRemediations: async (orgId: string = 'default') => {
    const response = await api.get('/api/v1/remediation/tasks', {
      params: { org_id: orgId }
    })
    return response.data
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// API Functions - Search
// ═══════════════════════════════════════════════════════════════════════════

export const searchApi = {
  search: async (query: string) => {
    const response = await api.get('/api/v1/inventory/search', {
      params: { query }
    })
    return response.data
  },

  searchFindings: async (query: string) => {
    const response = await api.get('/api/v1/analytics/findings', {
      params: { search: query }
    })
    return response.data
  },
}

export default api
