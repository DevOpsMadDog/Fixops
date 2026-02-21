import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { updateApiKey as updateApiKeyGlobal } from '../lib/api'
import { api } from '../lib/api'

// ═══════════════════════════════════════════════════════════════════════════
// UI Store
// ═══════════════════════════════════════════════════════════════════════════

interface UIStore {
  sidebarCollapsed: boolean
  theme: 'dark' | 'light'
  copilotOpen: boolean
  toggleSidebar: () => void
  setTheme: (theme: 'dark' | 'light') => void
  toggleCopilot: () => void
  setCopilotOpen: (open: boolean) => void
}

export const useUIStore = create<UIStore>()(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      theme: 'dark',
      copilotOpen: false,
      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
      setTheme: (theme) => set({ theme }),
      toggleCopilot: () => set((s) => ({ copilotOpen: !s.copilotOpen })),
      setCopilotOpen: (open) => set({ copilotOpen: open }),
    }),
    { name: 'aldeci-ui' }
  )
)

// ═══════════════════════════════════════════════════════════════════════════
// Auth Store
// ═══════════════════════════════════════════════════════════════════════════

interface User {
  id: string
  name: string
  email: string
  role: 'admin' | 'analyst' | 'viewer'
}

interface AuthStore {
  user: User | null
  apiKey: string
  isAuthenticated: boolean
  setUser: (user: User | null) => void
  setApiKey: (key: string) => void
  logout: () => void
}

export const useAuthStore = create<AuthStore>()(
  persist(
    (set) => ({
      user: null,
      apiKey: import.meta.env.VITE_API_KEY || 'test-token-123',
      isAuthenticated: true,
      setUser: (user) => set({ user, isAuthenticated: !!user }),
      setApiKey: (key) => {
        updateApiKeyGlobal(key)
        set({ apiKey: key })
      },
      logout: () => {
        localStorage.removeItem('aldeci_api_key')
        set({ user: null, apiKey: '', isAuthenticated: false })
      },
    }),
    {
      name: 'aldeci-auth',
      version: 1,
      migrate: (persistedState: any, version: number) => {
        if (version === 0) {
          // v0 → v1: reset apiKey to env value (clear stale 'demo-token')
          const envKey = import.meta.env.VITE_API_KEY || 'test-token-123'
          return { ...persistedState, apiKey: envKey, isAuthenticated: true }
        }
        return persistedState as AuthStore
      },
    }
  )
)

// ═══════════════════════════════════════════════════════════════════════════
// Chat Store (for AI Copilot)
// ═══════════════════════════════════════════════════════════════════════════

export interface ChatMessage {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  timestamp: Date
  isLoading?: boolean
  actions?: Array<{
    type: string
    label: string
    data?: Record<string, unknown>
  }>
}

interface ChatStore {
  messages: ChatMessage[]
  isTyping: boolean
  isLoading: boolean
  sessionId: string | null
  addMessage: (msg: Omit<ChatMessage, 'id' | 'timestamp'>) => void
  setTyping: (typing: boolean) => void
  setLoading: (loading: boolean) => void
  setSessionId: (id: string | null) => void
  clearMessages: () => void
  removeLastMessage: () => void
}

export const useChatStore = create<ChatStore>((set) => ({
  messages: [],
  isTyping: false,
  isLoading: false,
  sessionId: null,
  addMessage: (msg) =>
    set((s) => ({
      messages: [
        ...s.messages,
        { ...msg, id: crypto.randomUUID(), timestamp: new Date() },
      ],
    })),
  setTyping: (typing) => set({ isTyping: typing }),
  setLoading: (loading) => set({ isLoading: loading }),
  setSessionId: (id) => set({ sessionId: id }),
  clearMessages: () => set({ messages: [], sessionId: null }),
  removeLastMessage: () =>
    set((s) => ({ messages: s.messages.slice(0, -1) })),
}))

// ═══════════════════════════════════════════════════════════════════════════
// Dashboard Store
// ═══════════════════════════════════════════════════════════════════════════

interface DashboardMetrics {
  totalFindings: number
  criticalFindings: number
  highFindings: number
  mediumFindings: number
  lowFindings: number
  clustersCount: number
  dedupRate: number
  mttrHours: number
  slaCompliance: number
}

interface DashboardStore {
  metrics: DashboardMetrics | null
  isLoading: boolean
  error: string | null
  setMetrics: (metrics: DashboardMetrics) => void
  setLoading: (loading: boolean) => void
  setError: (error: string | null) => void
}

export const useDashboardStore = create<DashboardStore>((set) => ({
  metrics: null,
  isLoading: false,
  error: null,
  setMetrics: (metrics) => set({ metrics, error: null }),
  setLoading: (loading) => set({ isLoading: loading }),
  setError: (error) => set({ error }),
}))

// ═══════════════════════════════════════════════════════════════════════════
// Selection Store (for bulk operations)
// ═══════════════════════════════════════════════════════════════════════════

interface SelectionStore {
  selectedIds: Set<string>
  select: (id: string) => void
  deselect: (id: string) => void
  toggle: (id: string) => void
  selectAll: (ids: string[]) => void
  clear: () => void
  isSelected: (id: string) => boolean
}

export const useSelectionStore = create<SelectionStore>((set, get) => ({
  selectedIds: new Set(),
  select: (id) => set((s) => ({ selectedIds: new Set([...s.selectedIds, id]) })),
  deselect: (id) =>
    set((s) => {
      const next = new Set(s.selectedIds)
      next.delete(id)
      return { selectedIds: next }
    }),
  toggle: (id) => {
    const { selectedIds } = get()
    if (selectedIds.has(id)) {
      get().deselect(id)
    } else {
      get().select(id)
    }
  },
  selectAll: (ids) => set({ selectedIds: new Set(ids) }),
  clear: () => set({ selectedIds: new Set() }),
  isSelected: (id) => get().selectedIds.has(id),
}))

// ═══════════════════════════════════════════════════════════════════════════
// Findings Store
// ═══════════════════════════════════════════════════════════════════════════

export interface Finding {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: 'open' | 'in_progress' | 'resolved' | 'ignored' | 'false_positive'
  source: string
  cve_id?: string
  asset?: string
  first_seen: string
  last_seen: string
  epss_score?: number
  kev_listed?: boolean
}

interface FindingsFilter {
  severity?: string[]
  status?: string[]
  source?: string[]
  search?: string
}

interface FindingsStore {
  findings: Finding[]
  filters: FindingsFilter
  total: number
  isLoading: boolean
  error: string | null
  setFindings: (findings: Finding[], total?: number) => void
  setFilters: (filters: Partial<FindingsFilter>) => void
  clearFilters: () => void
  setLoading: (loading: boolean) => void
  setError: (error: string | null) => void
  updateFinding: (id: string, updates: Partial<Finding>) => void
}

export const useFindingsStore = create<FindingsStore>((set) => ({
  findings: [],
  filters: {},
  total: 0,
  isLoading: false,
  error: null,
  setFindings: (findings, total) => set({ findings, total: total ?? findings.length, error: null }),
  setFilters: (filters) => set((s) => ({ filters: { ...s.filters, ...filters } })),
  clearFilters: () => set({ filters: {} }),
  setLoading: (loading) => set({ isLoading: loading }),
  setError: (error) => set({ error }),
  updateFinding: (id, updates) =>
    set((s) => ({
      findings: s.findings.map((f) => (f.id === id ? { ...f, ...updates } : f)),
    })),
}))

// ═══════════════════════════════════════════════════════════════════════════
// Assets Store
// ═══════════════════════════════════════════════════════════════════════════

export interface Asset {
  id: string
  name: string
  type: 'repository' | 'container' | 'cloud_resource' | 'endpoint' | 'service' | 'unknown'
  risk_score: number
  finding_count: number
  last_scanned?: string
  tags: string[]
}

interface AssetsStore {
  assets: Asset[]
  total: number
  isLoading: boolean
  error: string | null
  setAssets: (assets: Asset[], total?: number) => void
  setLoading: (loading: boolean) => void
  setError: (error: string | null) => void
}

export const useAssetsStore = create<AssetsStore>((set) => ({
  assets: [],
  total: 0,
  isLoading: false,
  error: null,
  setAssets: (assets, total) => set({ assets, total: total ?? assets.length, error: null }),
  setLoading: (loading) => set({ isLoading: loading }),
  setError: (error) => set({ error }),
}))

// ═══════════════════════════════════════════════════════════════════════════
// Pipeline Store (Brain Pipeline status)
// ═══════════════════════════════════════════════════════════════════════════

type PipelineStatus = 'idle' | 'running' | 'completed' | 'failed'

interface PipelineStage {
  name: string
  status: PipelineStatus
  progress: number
  message?: string
}

interface PipelineStore {
  status: PipelineStatus
  stages: PipelineStage[]
  currentStage: string | null
  progress: number
  lastRunId: string | null
  lastRunAt: string | null
  isLoading: boolean
  setStatus: (status: PipelineStatus) => void
  setStages: (stages: PipelineStage[]) => void
  setCurrentStage: (stage: string | null) => void
  setProgress: (progress: number) => void
  setLastRun: (runId: string, at: string) => void
  setLoading: (loading: boolean) => void
  reset: () => void
}

export const usePipelineStore = create<PipelineStore>((set) => ({
  status: 'idle',
  stages: [],
  currentStage: null,
  progress: 0,
  lastRunId: null,
  lastRunAt: null,
  isLoading: false,
  setStatus: (status) => set({ status }),
  setStages: (stages) => set({ stages }),
  setCurrentStage: (stage) => set({ currentStage: stage }),
  setProgress: (progress) => set({ progress }),
  setLastRun: (runId, at) => set({ lastRunId: runId, lastRunAt: at }),
  setLoading: (loading) => set({ isLoading: loading }),
  reset: () => set({ status: 'idle', stages: [], currentStage: null, progress: 0 }),
}))

// ═══════════════════════════════════════════════════════════════════════════
// Notifications Store
// ═══════════════════════════════════════════════════════════════════════════

export interface AppNotification {
  id: string
  type: 'info' | 'warning' | 'error' | 'success'
  title: string
  message: string
  timestamp: string
  read: boolean
  link?: string
}

interface NotificationsStore {
  notifications: AppNotification[]
  unreadCount: number
  addNotification: (n: Omit<AppNotification, 'id' | 'timestamp' | 'read'>) => void
  markRead: (id: string) => void
  markAllRead: () => void
  dismiss: (id: string) => void
  clearAll: () => void
}

// ═══════════════════════════════════════════════════════════════════════════
// Runtime Config Store — fetched from /api/v1/nerve-center/overlay on startup
// ═══════════════════════════════════════════════════════════════════════════

interface ServiceDef {
  port: number
  label: string
}

interface RuntimeFeatures {
  api_activity_logger: boolean
  overlay_editor: boolean
  ml_dashboard: boolean
  mpte_console: boolean
  copilot: boolean
  knowledge_graph: boolean
  attack_simulation: boolean
  compliance_evidence: boolean
}

interface ServiceHealth {
  key: string
  label: string
  port: number
  status: 'healthy' | 'unhealthy' | 'checking'
}

interface RuntimeConfigStore {
  apiUrl: string
  apiVersion: string
  apiKeyHint: string
  authMode: string
  mode: string
  features: RuntimeFeatures
  services: Record<string, ServiceDef>
  serviceHealth: ServiceHealth[]
  loaded: boolean
  loading: boolean
  error: string | null
  fetchConfig: () => Promise<void>
  checkServiceHealth: () => Promise<void>
}

const defaultFeatures: RuntimeFeatures = {
  api_activity_logger: true,
  overlay_editor: true,
  ml_dashboard: true,
  mpte_console: true,
  copilot: true,
  knowledge_graph: true,
  attack_simulation: true,
  compliance_evidence: true,
}

export const useRuntimeConfigStore = create<RuntimeConfigStore>((set, get) => ({
  apiUrl: '',
  apiVersion: '',
  apiKeyHint: '',
  authMode: 'dev',
  mode: '',
  features: defaultFeatures,
  services: {},
  serviceHealth: [],
  loaded: false,
  loading: false,
  error: null,

  fetchConfig: async () => {
    if (get().loading) return
    set({ loading: true, error: null })
    try {
      const { data } = await api.get('/api/v1/nerve-center/overlay')
      const cfg = data?.api_config
      if (cfg) {
        const svcEntries = Object.entries(cfg.services || {}) as [string, ServiceDef][]
        set({
          apiUrl: cfg.api_url || '',
          apiVersion: cfg.api_version || '',
          apiKeyHint: cfg.api_key_hint || '',
          authMode: cfg.auth_mode || 'dev',
          mode: cfg.mode || 'enterprise',
          features: { ...defaultFeatures, ...(cfg.features || {}) },
          services: cfg.services || {},
          serviceHealth: svcEntries.map(([key, svc]) => ({
            key,
            label: svc.label,
            port: svc.port,
            status: 'checking' as const,
          })),
          loaded: true,
          loading: false,
        })
        // Immediately fire health check
        get().checkServiceHealth()
      } else {
        set({ loaded: true, loading: false })
      }
    } catch (err: any) {
      set({ loading: false, error: err?.message || 'Failed to load config' })
    }
  },

  checkServiceHealth: async () => {
    // Check individual service health endpoints
    const healthChecks = [
      { key: 'api_gateway', endpoint: '/api/v1/health' },
      { key: 'core', endpoint: '/api/v1/nerve-center/pulse' },
      { key: 'attack', endpoint: '/api/v1/attack-sim/health' },
      { key: 'feeds', endpoint: '/api/v1/feeds/health' },
      { key: 'evidence_risk', endpoint: '/api/v1/evidence' },
      { key: 'integrations', endpoint: '/api/v1/integrations' },
    ]

    for (const check of healthChecks) {
      try {
        await api.get(check.endpoint, { timeout: 5000 })
        set((s) => ({
          serviceHealth: s.serviceHealth.map((svc) =>
            svc.key === check.key ? { ...svc, status: 'healthy' as const } : svc
          ),
        }))
      } catch {
        set((s) => ({
          serviceHealth: s.serviceHealth.map((svc) =>
            svc.key === check.key ? { ...svc, status: 'unhealthy' as const } : svc
          ),
        }))
      }
    }
  },
}))

export const useNotificationsStore = create<NotificationsStore>((set, _get) => ({
  notifications: [],
  unreadCount: 0,
  addNotification: (n) =>
    set((s) => {
      const notification: AppNotification = {
        ...n,
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        read: false,
      }
      const notifications = [notification, ...s.notifications].slice(0, 100)
      return { notifications, unreadCount: s.unreadCount + 1 }
    }),
  markRead: (id) =>
    set((s) => {
      const notifications = s.notifications.map((n) =>
        n.id === id ? { ...n, read: true } : n
      )
      return { notifications, unreadCount: notifications.filter((n) => !n.read).length }
    }),
  markAllRead: () =>
    set((s) => ({
      notifications: s.notifications.map((n) => ({ ...n, read: true })),
      unreadCount: 0,
    })),
  dismiss: (id) =>
    set((s) => {
      const notifications = s.notifications.filter((n) => n.id !== id)
      return { notifications, unreadCount: notifications.filter((n) => !n.read).length }
    }),
  clearAll: () => set({ notifications: [], unreadCount: 0 }),
}))
