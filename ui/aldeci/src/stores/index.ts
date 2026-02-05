import { create } from 'zustand'
import { persist } from 'zustand/middleware'

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
      apiKey: 'demo-token',
      isAuthenticated: true, // Demo mode
      setUser: (user) => set({ user, isAuthenticated: !!user }),
      setApiKey: (key) => {
        localStorage.setItem('aldeci_api_key', key)
        set({ apiKey: key })
      },
      logout: () => {
        localStorage.removeItem('aldeci_api_key')
        set({ user: null, apiKey: '', isAuthenticated: false })
      },
    }),
    { name: 'aldeci-auth' }
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
