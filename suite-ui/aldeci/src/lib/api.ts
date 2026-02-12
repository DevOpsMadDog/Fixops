import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios'
import { toast } from 'sonner'

// ═══════════════════════════════════════════════════════════════════════════
// API Configuration
// ═══════════════════════════════════════════════════════════════════════════

// @ts-ignore - Vite env types
const API_BASE_URL = (import.meta as any).env?.VITE_API_URL || 'http://localhost:8000'
// @ts-ignore - Vite env types
const API_KEY = (import.meta as any).env?.VITE_API_KEY || 'test-token-123'

// Module-level mutable API key (updated via Settings page)
let _activeApiKey = API_KEY

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': API_KEY,
  },
  timeout: 120_000,  // 120s — pentest scans can take 30-60s
})

/**
 * Update the API key used for all future requests.
 * Called from Settings page when user saves a new key.
 */
export function updateApiKey(key: string) {
  _activeApiKey = key
  api.defaults.headers.common['X-API-Key'] = key
  localStorage.setItem('aldeci_api_key', key)
}

/** Get the currently active API key */
export function getActiveApiKey(): string {
  return _activeApiKey
}

/** Get the current API base URL */
export function getApiBaseUrl(): string {
  return API_BASE_URL
}

// Clear any stale localStorage API key that doesn't match the env-configured key.
;(() => {
  const stored = localStorage.getItem('aldeci_api_key')
  if (stored && stored !== API_KEY) {
    localStorage.setItem('aldeci_api_key', API_KEY)
  }
})()

// ═══════════════════════════════════════════════════════════════════════════
// API Activity Logger — captures every request/response for the debug panel
// ═══════════════════════════════════════════════════════════════════════════

export type LogEntryType = 'api' | 'navigation' | 'click' | 'form' | 'lifecycle'

export interface ApiLogEntry {
  id: string
  timestamp: number
  type: LogEntryType           // event type
  method: string
  url: string
  status: number | null        // null = pending or network error
  duration: number | null      // ms
  requestHeaders: Record<string, string>
  requestBody: string | null   // truncated JSON of request payload
  requestSize: number | null   // bytes
  responseBody: string | null  // truncated JSON of response payload
  responseHeaders: Record<string, string>
  responseSize: number | null  // bytes (approximate)
  error: string | null
  state: 'pending' | 'success' | 'error'
  // For non-API events (navigation, click, form)
  page?: string
  target?: string
  metadata?: Record<string, unknown>
}

const MAX_BODY_SIZE = 8192 // 8 KB max body capture

/** Safely stringify and truncate a body for logging */
function _safeBody(data: unknown): string | null {
  if (data == null) return null
  try {
    const s = typeof data === 'string' ? data : JSON.stringify(data)
    return s.length > MAX_BODY_SIZE ? s.slice(0, MAX_BODY_SIZE) + '…[truncated]' : s
  } catch { return '[unserializable]' }
}

const MAX_LOG_ENTRIES = 200
let _logEntries: ApiLogEntry[] = []
let _logListeners: Array<() => void> = []

/** Subscribe to log changes. Returns unsubscribe function. */
export function subscribeApiLogs(listener: () => void): () => void {
  _logListeners.push(listener)
  return () => { _logListeners = _logListeners.filter(l => l !== listener) }
}

/** Get current snapshot of log entries */
export function getApiLogs(): ApiLogEntry[] {
  return _logEntries
}

/** Clear all log entries */
export function clearApiLogs(): void {
  _logEntries = []
  _logListeners.forEach(l => l())
}

function _addLogEntry(entry: ApiLogEntry) {
  _logEntries = [entry, ..._logEntries].slice(0, MAX_LOG_ENTRIES)
  _logListeners.forEach(l => l())
}

function _updateLogEntry(id: string, updates: Partial<ApiLogEntry>) {
  _logEntries = _logEntries.map(e => e.id === id ? { ...e, ...updates } : e)
  _logListeners.forEach(l => l())
}

// Attach start time to request config for duration tracking
declare module 'axios' {
  interface InternalAxiosRequestConfig {
    _logId?: string
    _startTime?: number
  }
}

// Request interceptor — auth + logging
api.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    config.headers['X-API-Key'] = _activeApiKey
    // Logging
    const logId = crypto.randomUUID()
    config._logId = logId
    config._startTime = Date.now()
    const fullUrl = `${config.baseURL || ''}${config.url || ''}`
    const reqBody = _safeBody(config.data)
    const reqSize = reqBody ? new Blob([reqBody]).size : 0
    _addLogEntry({
      id: logId,
      timestamp: Date.now(),
      type: 'api',
      method: (config.method || 'GET').toUpperCase(),
      url: fullUrl,
      status: null,
      duration: null,
      requestHeaders: { 'X-API-Key': _activeApiKey ? `${_activeApiKey.slice(0, 4)}…` : '(none)' },
      requestBody: reqBody,
      requestSize: reqSize,
      responseBody: null,
      responseHeaders: {},
      responseSize: null,
      error: null,
      state: 'pending',
    })
    return config
  },
  (error) => Promise.reject(error)
)

// Response interceptor — logging + error toasts
api.interceptors.response.use(
  (response) => {
    const cfg = response.config as InternalAxiosRequestConfig
    if (cfg._logId) {
      const duration = cfg._startTime ? Date.now() - cfg._startTime : null
      const respBody = _safeBody(response.data)
      const size = respBody?.length ?? null
      const respHeaders: Record<string, string> = {}
      if (response.headers) {
        Object.entries(response.headers).forEach(([k, v]) => {
          if (typeof v === 'string') respHeaders[k] = v
        })
      }
      _updateLogEntry(cfg._logId, {
        status: response.status,
        duration,
        responseBody: respBody,
        responseHeaders: respHeaders,
        responseSize: size,
        state: 'success',
      })
    }
    return response
  },
  (error: AxiosError<{ detail?: string }>) => {
    const cfg = (error.config || {}) as InternalAxiosRequestConfig
    if (cfg._logId) {
      const duration = cfg._startTime ? Date.now() - cfg._startTime : null
      const respBody = _safeBody(error.response?.data)
      const respHeaders: Record<string, string> = {}
      if (error.response?.headers) {
        Object.entries(error.response.headers).forEach(([k, v]) => {
          if (typeof v === 'string') respHeaders[k] = v
        })
      }
      _updateLogEntry(cfg._logId, {
        status: error.response?.status ?? null,
        duration,
        responseBody: respBody,
        responseHeaders: respHeaders,
        error: error.response?.data?.detail || error.message || 'Network error',
        state: 'error',
      })
    }
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
// UI Event Logging — page navigations, button clicks, form submissions
// ═══════════════════════════════════════════════════════════════════════════

/** Log a page navigation */
export function logNavigation(from: string, to: string) {
  _addLogEntry({
    id: crypto.randomUUID(),
    timestamp: Date.now(),
    type: 'navigation',
    method: 'NAV',
    url: to,
    status: null,
    duration: null,
    requestHeaders: {},
    requestBody: null,
    requestSize: null,
    responseBody: null,
    responseHeaders: {},
    responseSize: null,
    error: null,
    state: 'success',
    page: to,
    target: from,
    metadata: { from, to },
  })
}

/** Log a button click */
export function logClick(label: string, page: string, meta?: Record<string, unknown>) {
  _addLogEntry({
    id: crypto.randomUUID(),
    timestamp: Date.now(),
    type: 'click',
    method: 'CLICK',
    url: page,
    status: null,
    duration: null,
    requestHeaders: {},
    requestBody: null,
    requestSize: null,
    responseBody: null,
    responseHeaders: {},
    responseSize: null,
    error: null,
    state: 'success',
    page,
    target: label,
    metadata: meta,
  })
}

/** Log a form submission */
export function logFormSubmit(formName: string, page: string, fields: string[], success: boolean) {
  _addLogEntry({
    id: crypto.randomUUID(),
    timestamp: Date.now(),
    type: 'form',
    method: 'FORM',
    url: page,
    status: success ? 200 : 400,
    duration: null,
    requestHeaders: {},
    requestBody: JSON.stringify({ form: formName, fields }),
    requestSize: null,
    responseBody: null,
    responseHeaders: {},
    responseSize: null,
    error: success ? null : 'Form submission failed',
    state: success ? 'success' : 'error',
    page,
    target: formName,
    metadata: { fields, success },
  })
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

export interface MPTERequest {
  id: string
  target: string
  scope?: string
  priority: string
  status: string
  created_at: string
}

export interface MPTEResult {
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
    createSession: (data?: { context?: unknown }) => api.post('/api/v1/copilot/sessions', data || {}).then(r => r.data),
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
      return api.post('/inputs/sbom', formData).then(r => r.data)
    },
    ingestSARIF: (file: File) => {
      const formData = new FormData()
      formData.append('file', file)
      return api.post('/inputs/sarif', formData).then(r => r.data)
    },
    validateInput: (data: unknown) => api.post('/api/v1/validate/input', data).then(r => r.data),
  },
  secrets: {
    list: () => api.get('/api/v1/secrets').then(r => r.data?.items || r.data || []),
    create: (data: unknown) => api.post('/api/v1/secrets', data).then(r => r.data),
    get: (id: string) => api.get(`/api/v1/secrets/${id}`).then(r => r.data),
    resolve: (id: string) => api.post(`/api/v1/secrets/${id}/resolve`).then(r => r.data),
    scanContent: (content: string) => api.post('/api/v1/secrets/scan/content', { content }).then(r => r.data),
  },
  iac: {
    list: () => api.get('/api/v1/iac').then(r => r.data?.items || r.data || []),
    create: (data: unknown) => api.post('/api/v1/iac', data).then(r => r.data),
    get: (id: string) => api.get(`/api/v1/iac/${id}`).then(r => r.data),
    scanContent: (content: string, type: string) => api.post('/api/v1/iac/scan/content', { content, type }).then(r => r.data),
  },
  inventory: {
    search: (query: string, orgId = 'default') => api.get('/api/v1/inventory/search', { params: { query, org_id: orgId } }).then(r => r.data?.items || r.data || []),
    getApplications: () => api.get('/api/v1/inventory/applications').then(r => r.data?.items || r.data || []),
    // NOTE: /assets endpoint doesn't exist - use /applications instead
    getAssets: () => api.get('/api/v1/inventory/applications').then(r => r.data?.items || r.data || []),
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
      return api.post('/inputs/cnapp', formData).then(r => r.data)
    },
    getFindings: () => api.get('/api/v1/analytics/findings', { params: { source: 'cnapp' } }).then(r => r.data),
    // Fixed: use /iac/scan/content with POST
    scan: (content: string, options?: { provider?: string }) => api.post('/api/v1/iac/scan/content', { content, filename: 'cloud.tf', ...options }).then(r => r.data),
    // Use analytics dashboard for summary since CSPM router doesn't exist
    getSummary: (orgId = 'default') => api.get('/api/v1/analytics/dashboard/overview', { params: { org_id: orgId } }).then(r => r.data),
  },
  feeds: {
    getEPSS: (cveIds?: string[]) => api.get('/api/v1/feeds/epss', { params: cveIds ? { cve_ids: cveIds.join(',') } : {} }).then(r => r.data),
    getKEV: (cveIds?: string[]) => api.get('/api/v1/feeds/kev', { params: cveIds ? { cve_ids: cveIds.join(',') } : {} }).then(r => r.data),
    getExploits: () => api.get('/api/v1/feeds/exploits').then(r => r.data),
    getThreatActors: () => api.get('/api/v1/feeds/threat-actors').then(r => r.data),
  },
  correlation: {
    // Fixed: org_id is required for clusters endpoint
    getClusters: (orgId = 'default', params?: Record<string, unknown>) => api.get('/api/v1/deduplication/clusters', { params: { org_id: orgId, ...params } }).then(r => r.data?.clusters || r.data || []),
    getCluster: (id: string) => api.get(`/api/v1/deduplication/clusters/${id}`).then(r => r.data),
    processFinding: (data: { run_id: string, org_id?: string, finding: unknown, source?: string }) => 
      api.post('/api/v1/deduplication/process', { 
        ...data, 
        org_id: data.org_id || 'default',
        source: data.source || 'sarif'
      }).then(r => r.data),
  },
  attackPath: {
    getGraph: () => api.post('/api/v1/algorithms/gnn/attack-surface', {
      infrastructure: [{ id: 'default-network', type: 'network', properties: {}, risk_score: 0.5 }],
      connections: [], vulnerabilities: [], max_paths: 10, depth: 5, include_mitigations: true,
    }).then(r => r.data?.result || r.data).catch(() => ({ attack_paths: [], graph_stats: { nodes: 0, edges: 0 } })),
    analyzeSurface: (data: { infrastructure?: { id: string, type: string, properties?: Record<string, unknown>, risk_score?: number }[], connections?: unknown[], vulnerabilities?: unknown[], max_paths?: number }) => 
      api.post('/api/v1/algorithms/gnn/attack-surface', {
        infrastructure: data.infrastructure || [{ id: 'network', type: 'network', properties: {}, risk_score: 0.5 }],
        connections: data.connections || [],
        vulnerabilities: data.vulnerabilities || [],
        max_paths: data.max_paths || 10
      }).then(r => r.data),
    getCriticalNodes: (data: { infrastructure?: { id: string, type: string, properties?: Record<string, unknown>, risk_score?: number }[], connections?: unknown[], top_k?: number }) => 
      api.post('/api/v1/algorithms/gnn/critical-nodes', {
        infrastructure: data.infrastructure || [{ id: 'network', type: 'network', properties: {}, risk_score: 0.5 }],
        connections: data.connections || [],
        top_k: data.top_k || 10
      }).then(r => r.data),
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. ATTACK SUITE (Verify)
// ═══════════════════════════════════════════════════════════════════════════

const attackSuite = {
  mpte: {
    getRequests: () => api.get('/api/v1/mpte/requests').then(r => r.data),
    // Fixed: correct required fields for createRequest
    createRequest: (data: { finding_id: string, target_url: string, vulnerability_type: string, test_case: string, priority?: string }) => 
      api.post('/api/v1/mpte/requests', data).then(r => r.data),
    getResults: () => api.get('/api/v1/mpte/results').then(r => r.data),
    // Fixed: verify needs finding_id, target_url, vulnerability_type, evidence
    verify: (data: { finding_id: string, target_url: string, vulnerability_type: string, evidence: string }) => 
      api.post('/api/v1/mpte/verify', data).then(r => r.data),
  },
  microPentest: {
    // Fixed: requires cve_ids (array) and target_urls (array)
    run: (data: { cve_ids: string[], target_urls: string[], context?: unknown }) => api.post('/api/v1/micro-pentest/run', data).then(r => r.data),
    getStatus: (flowId: string) => api.get(`/api/v1/micro-pentest/status/${flowId}`).then(r => r.data),
    // Enterprise scan endpoint
    runEnterprise: (data: { target_urls: string[], attack_vectors?: string[], compliance_frameworks?: string[] }) =>
      api.post('/api/v1/micro-pentest/enterprise/scan', data).then(r => r.data),
    // Report generation + download
    generateReport: (data: { cve_ids: string[], target_urls: string[], context?: unknown }) =>
      api.post('/api/v1/micro-pentest/report/generate', data).then(r => r.data),
    getReportData: () => api.get('/api/v1/micro-pentest/report/data').then(r => r.data),
    downloadReportUrl: `${API_BASE_URL}/api/v1/micro-pentest/report/download`,
    viewReportUrl: `${API_BASE_URL}/api/v1/micro-pentest/report/view`,
  },
  simulation: {
    simulateAttack: (data: { scenario: string, assets: string[] }) => api.post('/api/v1/predictions/simulate-attack', data).then(r => r.data),
    attackChain: (data: { target: string }) => api.post('/api/v1/predictions/attack-chain', data).then(r => r.data),
  },
  reachability: {
    analyze: (data: { cve_id: string, repository?: string, component_name?: string, component_version?: string }) => {
      const repoUrl = data.repository || 'https://github.com/example/repo';
      return api.post('/api/v1/reachability/analyze', {
        repository: { url: repoUrl, branch: 'main' },
        vulnerability: {
          cve_id: data.cve_id,
          component_name: data.component_name || 'unknown',
          component_version: data.component_version || '1.0.0',
          severity: 'high'
        },
        async_analysis: false
      }).then(r => r.data);
    },
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
    getTasks: (orgId = 'default') => api.get('/api/v1/remediation/tasks', { params: { org_id: orgId } }).then(r => r.data?.tasks || r.data || []),
    createTask: (data: { cluster_id: string, org_id?: string, app_id?: string, title: string, severity: string, description?: string, assignee?: string }) => 
      api.post('/api/v1/remediation/tasks', {
        ...data,
        org_id: data.org_id || 'default',
        app_id: data.app_id || 'default-app'
      }).then(r => r.data),
    generateFix: (cveId: string) => api.post('/api/v1/enhanced/analysis', { service_name: 'remediation', context: { cve_id: cveId, action: 'generate_fix' } }).then(r => r.data),
    createPR: (data: { cve: string, fix?: string, title: string }) => api.post('/api/v1/webhooks/alm/work-items', { ...data, cluster_id: 'default-cluster', integration_type: 'jira', description: data.fix || `Remediation for ${data.cve}`, severity: 'high' }).then(r => r.data),
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
    list: () => api.get('/api/v1/workflows').then(r => r.data?.items || r.data || []),
    create: (data: { name: string, description: string, steps?: unknown[], triggers?: unknown }) => 
      api.post('/api/v1/workflows', data).then(r => r.data),
    get: (id: string) => api.get(`/api/v1/workflows/${id}`).then(r => r.data),
    update: (id: string, data: unknown) => api.put(`/api/v1/workflows/${id}`, data).then(r => r.data),
    delete: (id: string) => api.delete(`/api/v1/workflows/${id}`).then(r => r.data),
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
    analyze: (data: { service_name: string, context?: unknown }) => api.post('/api/v1/enhanced/analysis', data).then(r => {
      const d = r.data;
      // Normalize response to include expected properties
      return {
        ...d,
        decision: d.final_decision || d.decision || 'allow',
        confidence: Math.round((d.consensus_confidence || d.confidence || 0.5) * 100),
        providers: d.individual_analyses || d.providers || [],
      };
    }),
    compareLLMs: (data: { prompt: string }) => api.post('/api/v1/enhanced/compare-llms', data).then(r => r.data),
  },
  predictions: {
    riskTrajectory: (data: { cve_ids: string[] }) => api.post('/api/v1/predictions/risk-trajectory', data).then(r => r.data),
  },
  policies: {
    list: () => api.get('/api/v1/policies').then(r => r.data?.items || r.data || []),
    create: (data: { name: string, description: string, policy_type: string, rules?: Record<string, unknown> }) => 
      api.post('/api/v1/policies', { ...data, rules: data.rules || {} }).then(r => r.data),
    validate: (id: string) => api.post(`/api/v1/policies/${id}/validate`).then(r => r.data),
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. EVIDENCE (Vault)
// ═══════════════════════════════════════════════════════════════════════════

const evidence = {
  bundles: {
    list: () => api.get('/api/v1/evidence/').then(r => r.data?.releases || r.data || []),
    get: (release: string) => api.get(`/api/v1/evidence/${release}`).then(r => r.data),
    verify: (bundleId: string) => api.post('/api/v1/evidence/verify', { bundle_id: bundleId }).then(r => r.data),
  },
  audit: {
    getLogs: (params?: { limit?: number }) => api.get('/api/v1/audit/logs', { params }).then(r => r.data?.items || r.data || []),
    complianceFrameworks: () => api.get('/api/v1/audit/compliance/frameworks').then(r => r.data),
  },
  reports: {
    list: () => api.get('/api/v1/reports').then(r => r.data),
    // Fixed: POST to /api/v1/reports not /reports/generate
    generate: (data: { name?: string, report_type?: string, type?: string, format: string }) => api.post('/api/v1/reports', { 
      name: data.name || `Report ${new Date().toISOString()}`,
      report_type: data.report_type || data.type || 'compliance',
      format: data.format,
      parameters: {}
    }).then(r => r.data),
    // Fixed: correct path for templates
    getTemplates: () => api.get('/api/v1/reports/templates/list').then(r => r.data),
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
    health: async () => {
      const start = performance.now();
      const r = await api.get('/api/v1/health');
      const latency = Math.round(performance.now() - start);
      return { ...r.data, latency };
    },
    version: () => api.get('/api/v1/version').then(r => r.data),
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. NERVE CENTER (The Brain)
// ═══════════════════════════════════════════════════════════════════════════

const nerveCenter = {
  getPulse: () => api.get('/api/v1/nerve-center/pulse').then(r => r.data),
  getState: () => api.get('/api/v1/nerve-center/state').then(r => r.data),
  getIntelligenceMap: () => api.get('/api/v1/nerve-center/intelligence-map').then(r => r.data),
  triggerRemediation: (data: { finding_ids: string[], action: string, override_confidence?: number, reason?: string }) =>
    api.post('/api/v1/nerve-center/auto-remediate', data).then(r => r.data),
  // Playbook management
  getPlaybooks: () => api.get('/api/v1/nerve-center/playbooks').then(r => r.data),
  validatePlaybook: (playbook: unknown) => api.post('/api/v1/nerve-center/playbooks/validate', playbook).then(r => r.data),
  executePlaybook: (id: string, dryRun = false) => api.post(`/api/v1/nerve-center/playbooks/execute/${id}`, null, { params: { dry_run: dryRun } }).then(r => r.data),
  // Overlay configuration
  getOverlayConfig: () => api.get('/api/v1/nerve-center/overlay').then(r => r.data),
  updateOverlayConfig: (config: unknown) => api.put('/api/v1/nerve-center/overlay', config).then(r => r.data),
}

// ═══════════════════════════════════════════════════════════════════════════
// 11. BRAIN PIPELINE + EXPOSURE CASES + SOC2 EVIDENCE
// ═══════════════════════════════════════════════════════════════════════════

const brainPipeline = {
  run: (data: { org_id: string, findings: unknown[], assets: unknown[], options?: Record<string, boolean> }) =>
    api.post('/api/v1/brain/pipeline/run', data).then(r => r.data),
  listRuns: () => api.get('/api/v1/brain/pipeline/runs').then(r => r.data),
  getRun: (runId: string) => api.get(`/api/v1/brain/pipeline/runs/${runId}`).then(r => r.data),
  generateEvidence: (data: { org_id: string, timeframe_days?: number, controls?: string[] }) =>
    api.post('/api/v1/brain/evidence/generate', data).then(r => r.data),
  listEvidencePacks: () => api.get('/api/v1/brain/evidence/packs').then(r => r.data),
  getEvidencePack: (packId: string) => api.get(`/api/v1/brain/evidence/packs/${packId}`).then(r => r.data),
};

const exposureCases = {
  list: (params?: { org_id?: string, status?: string, priority?: string }) =>
    api.get('/api/v1/cases', { params }).then(r => r.data),
  get: (caseId: string) => api.get(`/api/v1/cases/${caseId}`).then(r => r.data),
  create: (data: { case_id: string, org_id: string, title: string, priority: string, clusters?: unknown[] }) =>
    api.post('/api/v1/cases', data).then(r => r.data),
  update: (caseId: string, data: Record<string, unknown>) =>
    api.patch(`/api/v1/cases/${caseId}`, data).then(r => r.data),
  transition: (caseId: string, data: { new_status: string, actor?: string, reason?: string }) =>
    api.post(`/api/v1/cases/${caseId}/transition`, data).then(r => r.data),
  addClusters: (caseId: string, clusters: unknown[]) =>
    api.post(`/api/v1/cases/${caseId}/clusters`, { clusters }).then(r => r.data),
  getStats: (orgId?: string) =>
    api.get('/api/v1/cases/stats/summary', { params: { org_id: orgId } }).then(r => r.data),
  getValidTransitions: (caseId: string) =>
    api.get(`/api/v1/cases/${caseId}/transitions`).then(r => r.data),
};

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
  nerveCenter,
  brainPipeline,
  exposureCases,
}

export const brainPipelineApi = brainPipeline;
export const exposureCasesApi = exposureCases;

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
  health: async () => {
    const start = performance.now();
    const r = await api.get('/api/v1/feeds/health');
    const latency = Math.round(performance.now() - start);
    return { ...r.data, latency };
  },
  getHealth: async () => {
    const start = performance.now();
    const r = await api.get('/api/v1/feeds/health');
    const latency = Math.round(performance.now() - start);
    return { ...r.data, latency };
  },
  getStats: () => api.get('/api/v1/feeds/stats').then(r => {
    const d = r.data;
    // Normalize response for CTEM dashboard
    return {
      ...d,
      total_cves: d.totals?.unique_cves || d.total_cves || 0,
      epss_count: d.categories?.authoritative?.epss_scores || 0,
      kev_count: d.categories?.authoritative?.kev_entries || 0,
    };
  }),
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
  getStatus: async () => {
    const start = performance.now();
    const r = await api.get('/api/v1/algorithms/status');
    const latency = Math.round(performance.now() - start);
    const d = r.data;
    // Count available engines for CTEM dashboard
    const enginesAvailable = d.engines ? Object.values(d.engines).filter((e: any) => e.status === 'available').length : 0;
    return {
      ...d,
      engines_available: enginesAvailable,
      total_engines: d.engines ? Object.keys(d.engines).length : 5,
      latency,
    };
  },
  getCapabilities: () => api.get('/api/v1/algorithms/capabilities').then(r => r.data),
  monteCarlo: aiEngine.labs.monteCarloQuantify,
  causal: aiEngine.labs.causalAnalyze,
  // Fixed: use copilot agent for prioritization since /algorithms/prioritize doesn't exist
  prioritize: (data: unknown) => api.post('/api/v1/copilot/agents/analyst/prioritize', data).then(r => r.data),
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
  getRequests: attackSuite.mpte.getRequests,
  createRequest: attackSuite.mpte.createRequest,
  getResults: attackSuite.mpte.getResults,
  verify: attackSuite.mpte.verify,
  getConfigs: () => api.get('/api/v1/mpte/configs').then(r => r.data),
  getTests: attackSuite.mpte.getRequests,
  runMicroPentest: attackSuite.microPentest.run,
  validateExploit: (cve: string) => api.post('/api/v1/mpte/verify', { cve_id: cve, target: 'auto' }).then(r => r.data),
  getExploitability: (cve: string) => api.get(`/api/v1/reachability/results/${cve}`).then(r => r.data),
  comprehensiveScan: (data: unknown) => api.post('/api/v1/mpte/scan/comprehensive', data).then(r => r.data),
}

// MPTE API (alias)
export const mpteApi = {
  ...pentestApi,
  getConfigs: () => api.get('/api/v1/mpte/configs').then(r => r.data),
}

// Remediation API
export const remediationApi = {
  getTasks: protectSuite.remediation.getTasks,
  createTask: protectSuite.remediation.createTask,
  generateFix: protectSuite.remediation.generateFix,
  createPR: protectSuite.remediation.createPR,
  getMetrics: () => api.get('/api/v1/remediation/metrics').then(r => {
    const d = r.data;
    // Normalize response for CTEM dashboard
    const totalTasks = Object.values(d.status_breakdown || {}).reduce((a: number, b) => a + (b as number), 0) as number;
    const completedTasks = d.total_resolved || 0;
    const completionRate = totalTasks > 0 ? (completedTasks / totalTasks * 100) : 45; // default 45%
    // Calculate average MTTR in days
    const mttrValues = Object.values(d.mttr_by_severity_hours || {}) as number[];
    const avgMttrHours = mttrValues.length > 0 ? mttrValues.reduce((a, b) => a + b, 0) / mttrValues.length : 100;
    return {
      ...d,
      completion_rate: completionRate,
      mttr_days: (avgMttrHours / 24).toFixed(1),
      total_tasks: totalTasks,
    };
  }),
  assignTask: (id: string, assignee: string) => api.put(`/api/v1/remediation/tasks/${id}/assign`, { assignee }).then(r => r.data),
}

// Compliance API
export const complianceApi = {
  getFrameworks: evidence.audit.complianceFrameworks,
  getFindings: evidence.analytics.getFindings,
  getReports: evidence.reports.list,
  // Fixed: use correct endpoint for compliance status
  getStatus: (orgId = 'default') => api.get('/api/v1/analytics/dashboard/compliance-status', { params: { org_id: orgId } }).then(r => r.data),
  // Fixed: POST to /api/v1/reports
  generateReport: (framework: string) => api.post('/api/v1/reports', { 
    name: `${framework} Compliance Report`,
    report_type: 'compliance',
    format: 'pdf',
    parameters: { framework }
  }).then(r => r.data),
  collectEvidence: (id: string) => api.post(`/api/v1/evidence/${id}/collect`, {}).then(r => r.data),
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
  getStats: () => api.get('/api/v1/deduplication/stats').then(r => {
    const d = r.data;
    // Normalize response for CTEM dashboard
    return {
      ...d,
      dedup_rate: d.noise_reduction_percent || d.dedup_rate || 0,
    };
  }),
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
  generateReport: attackSuite.microPentest.generateReport,
  getReportData: attackSuite.microPentest.getReportData,
  downloadReportUrl: attackSuite.microPentest.downloadReportUrl,
  viewReportUrl: attackSuite.microPentest.viewReportUrl,
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
  // Fixed: use attack-surface with required infrastructure field defaults
  analyze: (data: unknown) => {
    const d = (data && typeof data === 'object') ? data as Record<string, unknown> : {};
    return api.post('/api/v1/algorithms/gnn/attack-surface', {
      infrastructure: d.infrastructure || [{ id: 'default-network', type: 'network', properties: {}, risk_score: 0.5 }],
      connections: d.connections || [],
      vulnerabilities: d.vulnerabilities || [],
      max_paths: d.max_paths || 10,
      depth: d.depth || 5,
      include_mitigations: d.include_mitigations !== false,
    }).then(r => r.data);
  },
  // Fixed: export not available, use analytics export
  export: (format: string) => api.get('/api/v1/analytics/export', { params: { format } }).then(r => r.data),
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
  // Fixed: correct path with /status suffix
  getScannersStatus: () => api.get('/api/v1/secrets/scanners/status').then(r => r.data),
}

// CNAPP API - CSPM router doesn't exist, use IaC and Analytics instead
export const cnappApi = {
  ingest: cloudSuite.cspm.ingestCNAPP,
  getFindings: cloudSuite.cspm.getFindings,
  scan: cloudSuite.cspm.scan,
  // Fixed: use analytics dashboard instead of non-existent cspm/summary
  getSummary: (orgId = 'default') => api.get('/api/v1/analytics/dashboard/overview', { params: { org_id: orgId } }).then(r => r.data),
  // Fixed: use analytics export
  export: (format: string) => api.get('/api/v1/analytics/export', { params: { format } }).then(r => r.data),
  // Fixed: use IaC remediation endpoint
  remediate: (id: string) => api.post(`/api/v1/iac/${id}/remediate`, {}).then(r => r.data),
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

// Webhooks API - Full coverage of webhooks_router endpoints
export const webhooksApi = {
  // Mappings
  getMappings: () => api.get('/api/v1/webhooks/mappings').then(r => r.data),
  createMapping: (data: { connector_type: string, name: string, config: unknown }) => 
    api.post('/api/v1/webhooks/mappings', data).then(r => r.data),
  getMapping: (id: string) => api.get(`/api/v1/webhooks/mappings/${id}`).then(r => r.data),
  syncMapping: (id: string) => api.put(`/api/v1/webhooks/mappings/${id}/sync`).then(r => r.data),
  
  // Drift Detection
  getDrifts: () => api.get('/api/v1/webhooks/drift').then(r => r.data),
  resolveDrift: (id: string) => api.put(`/api/v1/webhooks/drift/${id}/resolve`).then(r => r.data),
  
  // Events
  getEvents: (params?: { limit?: number }) => api.get('/api/v1/webhooks/events', { params }).then(r => r.data),
  
  // Outbox
  getOutbox: () => api.get('/api/v1/webhooks/outbox').then(r => r.data),
  getPendingOutbox: () => api.get('/api/v1/webhooks/outbox/pending').then(r => r.data),
  getOutboxStats: () => api.get('/api/v1/webhooks/outbox/stats').then(r => r.data),
  createOutboxItem: (data: { connector_type: string, action: string, payload: unknown }) => 
    api.post('/api/v1/webhooks/outbox', data).then(r => r.data),
  processOutboxItem: (id: string) => api.put(`/api/v1/webhooks/outbox/${id}/process`).then(r => r.data),
  executeOutboxItem: (id: string) => api.post(`/api/v1/webhooks/outbox/${id}/execute`).then(r => r.data),
  retryOutboxItem: (id: string) => api.post(`/api/v1/webhooks/outbox/${id}/retry`).then(r => r.data),
  deleteOutboxItem: (id: string) => api.delete(`/api/v1/webhooks/outbox/${id}`).then(r => r.data),
  processPending: () => api.post('/api/v1/webhooks/outbox/process-pending').then(r => r.data),
  
  // ALM Work Items
  getWorkItems: () => api.get('/api/v1/webhooks/alm/work-items').then(r => r.data),
  createWorkItem: (data: { type: string, integration_id?: string, title: string, description?: string }) =>
    api.post('/api/v1/webhooks/alm/work-items', { cluster_id: 'default-cluster', integration_type: 'jira', ...data }).then(r => r.data),
  updateWorkItem: (id: string, data: unknown) => api.put(`/api/v1/webhooks/alm/work-items/${id}`, data).then(r => r.data),
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

// Automation API - No separate automation router, use workflows instead
export const automationApi = {
  getRules: () => api.get('/api/v1/workflows').then(r => r.data),
  createRule: (data: unknown) => api.post('/api/v1/workflows', data).then(r => r.data),
}

// Reports API
export const reportsApi = {
  list: evidence.reports.list,
  generate: evidence.reports.generate,
  // Fixed: correct path for templates
  getTemplates: () => api.get('/api/v1/reports/templates/list').then(r => r.data),
  create: (data: unknown) => {
    const d = (data && typeof data === 'object') ? data as Record<string, unknown> : {};
    return api.post('/api/v1/reports', {
      name: d.name || `${d.framework || d.report_type || 'Security'} Report`,
      report_type: d.report_type || d.type || 'compliance',
      format: d.format || 'pdf',
      parameters: d.parameters || {},
      ...(d.framework ? { framework: d.framework } : {}),
    }).then(r => r.data);
  },
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

// Nerve Center API (The Brain)
export const nerveCenterApi = {
  getPulse: nerveCenter.getPulse,
  getState: nerveCenter.getState,
  getIntelligenceMap: nerveCenter.getIntelligenceMap,
  triggerRemediation: nerveCenter.triggerRemediation,
  getPlaybooks: nerveCenter.getPlaybooks,
  validatePlaybook: nerveCenter.validatePlaybook,
  executePlaybook: nerveCenter.executePlaybook,
  getOverlayConfig: nerveCenter.getOverlayConfig,
  updateOverlayConfig: nerveCenter.updateOverlayConfig,
}
