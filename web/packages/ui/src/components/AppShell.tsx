'use client'

import { useState, useEffect, ReactNode, createContext, useContext } from 'react'
import { 
  Bell, 
  Search, 
  User, 
  Settings, 
  ChevronDown,
  ChevronRight,
  Shield, 
  BarChart3, 
  FileText, 
  Zap, 
  Archive, 
  GitBranch,
  Command,
  Menu,
  Users,
  Layers,
  Cloud,
  Key,
  Workflow,
  Package,
  Store,
  LucideIcon,
  AlertTriangle,
  Activity,
  Database,
  Lock,
  Globe,
  Cpu
} from 'lucide-react'

// ============================================================================
// TYPES
// ============================================================================

export interface AppUrls {
  dashboard: string
  triage: string
  risk: string
  compliance: string
  evidence: string
  findings: string
  'saved-views': string
  automations: string
  integrations: string
  settings: string
  users: string
  teams: string
  policies: string
  inventory: string
  reports: string
  audit: string
  workflows: string
  sso: string
  secrets: string
  iac: string
  bulk: string
  pentagi: string
  marketplace: string
  shell?: string
  showcase?: string
  [key: string]: string | undefined
}

export interface NavItem {
  name: string
  key: string
  icon: LucideIcon
}

export interface NavSection {
  title: string
  items: NavItem[]
}

export interface AppShellProps {
  children: ReactNode
  activeApp?: string
  title?: string
  subtitle?: string
  showTopbar?: boolean
  showSidebar?: boolean
  headerActions?: ReactNode
  tabs?: Array<{ id: string; label: string; count?: number }>
  activeTab?: string
  onTabChange?: (tabId: string) => void
  onAppUrlsLoaded?: (urls: AppUrls) => void
}

// ============================================================================
// NAVIGATION CONFIG - Grouped into sections like enterprise products
// ============================================================================

export const NAV_SECTIONS: NavSection[] = [
  {
    title: 'Security',
    items: [
      { name: 'Dashboard', key: 'dashboard', icon: BarChart3 },
      { name: 'Triage', key: 'triage', icon: AlertTriangle },
      { name: 'Findings', key: 'findings', icon: FileText },
      { name: 'Risk Graph', key: 'risk', icon: GitBranch },
    ]
  },
  {
    title: 'Compliance',
    items: [
      { name: 'Frameworks', key: 'compliance', icon: Shield },
      { name: 'Evidence', key: 'evidence', icon: Archive },
      { name: 'Policies', key: 'policies', icon: Lock },
      { name: 'Audit Logs', key: 'audit', icon: Activity },
    ]
  },
  {
    title: 'Assets',
    items: [
      { name: 'Inventory', key: 'inventory', icon: Database },
      { name: 'IaC Scanning', key: 'iac', icon: Cloud },
      { name: 'Secrets', key: 'secrets', icon: Key },
    ]
  },
  {
    title: 'Automation',
    items: [
      { name: 'Workflows', key: 'workflows', icon: Workflow },
      { name: 'Automations', key: 'automations', icon: Zap },
      { name: 'Integrations', key: 'integrations', icon: Cpu },
    ]
  },
  {
    title: 'Organization',
    items: [
      { name: 'Users', key: 'users', icon: User },
      { name: 'Teams', key: 'teams', icon: Users },
      { name: 'SSO', key: 'sso', icon: Globe },
      { name: 'Settings', key: 'settings', icon: Settings },
    ]
  },
]

// Flat list for backward compatibility
export const NAV_ITEMS: NavItem[] = NAV_SECTIONS.flatMap(section => section.items)

// ============================================================================
// DEMO MODE CONTEXT
// ============================================================================

interface DemoModeContextType {
  demoEnabled: boolean
  toggleDemoMode: () => void
}

const DemoModeContext = createContext<DemoModeContextType>({
  demoEnabled: true,
  toggleDemoMode: () => {}
})

export const useDemoModeContext = () => useContext(DemoModeContext)

// ============================================================================
// URL RESOLUTION
// ============================================================================

const CENTRAL_URL = 'https://raw.githubusercontent.com/DevOpsMadDog/Fixops/main/web/app-urls.json'
const LOCAL_URL = '/app-urls.json'

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export function AppShell({ 
  children, 
  activeApp,
  title,
  subtitle,
  showTopbar = true,
  showSidebar = true,
  headerActions,
  tabs,
  activeTab,
  onTabChange,
  onAppUrlsLoaded
}: AppShellProps) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false)
  const [notificationsOpen, setNotificationsOpen] = useState(false)
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const [appUrls, setAppUrls] = useState<AppUrls | null>(null)
  const [currentApp, setCurrentApp] = useState<string>(activeApp || '')
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(NAV_SECTIONS.map(s => s.title)))
  const [demoEnabled, setDemoEnabled] = useState(true)

  // Load demo mode from localStorage
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem('fixops_demo_mode')
      if (stored !== null) {
        setDemoEnabled(stored === 'true')
      }
    }
  }, [])

  const toggleDemoMode = () => {
    const newValue = !demoEnabled
    setDemoEnabled(newValue)
    if (typeof window !== 'undefined') {
      localStorage.setItem('fixops_demo_mode', String(newValue))
    }
  }

  // Load app URLs from central config or local fallback
  useEffect(() => {
    const loadUrls = async () => {
      let urls: AppUrls | null = null
      
      try {
        const res = await fetch(CENTRAL_URL)
        if (res.ok) {
          urls = await res.json()
        }
      } catch (err) {
        console.warn('Failed to fetch central app-urls.json:', err)
      }
      
      if (!urls) {
        try {
          const res = await fetch(LOCAL_URL)
          if (res.ok) {
            urls = await res.json()
          }
        } catch (err) {
          console.error('Failed to load app URLs:', err)
        }
      }
      
      if (urls) {
        setAppUrls(urls)
        onAppUrlsLoaded?.(urls)
        
        if (!activeApp && typeof window !== 'undefined') {
          const origin = window.location.origin
          const currentAppEntry = Object.entries(urls).find(([_, url]) => url === origin)
          if (currentAppEntry) {
            setCurrentApp(currentAppEntry[0])
          }
        }
      }
    }
    
    loadUrls()
  }, [activeApp, onAppUrlsLoaded])

  useEffect(() => {
    if (activeApp) {
      setCurrentApp(activeApp)
    }
  }, [activeApp])

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setCommandPaletteOpen(true)
      }
      if (e.key === 'Escape') {
        setCommandPaletteOpen(false)
        setNotificationsOpen(false)
        setUserMenuOpen(false)
        setMobileMenuOpen(false)
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [])

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      const target = e.target as HTMLElement
      if (!target.closest('[data-dropdown]')) {
        setNotificationsOpen(false)
        setUserMenuOpen(false)
      }
    }
    window.addEventListener('click', handleClick)
    return () => window.removeEventListener('click', handleClick)
  }, [])

  const toggleSection = (title: string) => {
    setExpandedSections(prev => {
      const next = new Set(prev)
      if (next.has(title)) {
        next.delete(title)
      } else {
        next.add(title)
      }
      return next
    })
  }

  const getNavHref = (key: string) => {
    if (key === currentApp) return '/'
    return appUrls?.[key] || '#'
  }

  const notifications = [
    { id: 1, title: 'Critical vulnerability detected', time: '2m ago', unread: true },
    { id: 2, title: 'Compliance scan completed', time: '15m ago', unread: true },
    { id: 3, title: 'Evidence bundle signed', time: '1h ago', unread: false },
  ]

  return (
    <DemoModeContext.Provider value={{ demoEnabled, toggleDemoMode }}>
      <div className="min-h-screen bg-slate-950 text-slate-100">
        {/* ================================================================ */}
        {/* TOP BAR - Clean, minimal, professional                          */}
        {/* ================================================================ */}
        {showTopbar && (
          <header className="fixed top-0 left-0 right-0 h-14 bg-slate-950 border-b border-slate-800/50 z-50">
            <div className="flex items-center justify-between h-full px-4">
              {/* Left: Logo + Menu Toggle */}
              <div className="flex items-center gap-3">
                {showSidebar && (
                  <button
                    onClick={() => {
                      if (window.innerWidth < 768) {
                        setMobileMenuOpen(!mobileMenuOpen)
                      } else {
                        setSidebarCollapsed(!sidebarCollapsed)
                      }
                    }}
                    className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 rounded-lg transition-colors"
                  >
                    <Menu size={18} />
                  </button>
                )}
                <a href="/" className="flex items-center gap-2.5">
                  <div className="w-7 h-7 rounded-lg bg-indigo-600 flex items-center justify-center">
                    <Shield size={14} className="text-white" />
                  </div>
                  <span className="text-[15px] font-semibold text-white tracking-tight">FixOps</span>
                </a>
              </div>

              {/* Center: Global Search */}
              <div className="hidden md:flex flex-1 max-w-xl mx-8">
                <button
                  onClick={() => setCommandPaletteOpen(true)}
                  className="w-full h-9 px-3 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-500 hover:border-slate-700 hover:text-slate-400 transition-colors flex items-center justify-between"
                >
                  <div className="flex items-center gap-2">
                    <Search size={14} />
                    <span>Search...</span>
                  </div>
                  <kbd className="hidden sm:inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] font-medium text-slate-500 bg-slate-800 rounded">
                    <Command size={10} />K
                  </kbd>
                </button>
              </div>

              {/* Right: Actions */}
              <div className="flex items-center gap-1">
                {/* Demo Mode Badge */}
                <button
                  onClick={toggleDemoMode}
                  className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                    demoEnabled 
                      ? 'bg-amber-500/10 text-amber-400 hover:bg-amber-500/20' 
                      : 'bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20'
                  }`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${demoEnabled ? 'bg-amber-400' : 'bg-emerald-400'}`} />
                  {demoEnabled ? 'Demo' : 'Live'}
                </button>

                {/* Notifications */}
                <div className="relative" data-dropdown>
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      setNotificationsOpen(!notificationsOpen)
                      setUserMenuOpen(false)
                    }}
                    className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 rounded-lg transition-colors relative"
                  >
                    <Bell size={18} />
                    <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-rose-500 rounded-full" />
                  </button>

                  {notificationsOpen && (
                    <div className="absolute right-0 top-12 w-80 bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
                      <div className="px-4 py-3 border-b border-slate-800">
                        <h3 className="text-sm font-medium text-white">Notifications</h3>
                      </div>
                      <div className="max-h-80 overflow-y-auto">
                        {notifications.map((n) => (
                          <div
                            key={n.id}
                            className={`px-4 py-3 border-b border-slate-800/50 hover:bg-slate-800/30 cursor-pointer transition-colors ${
                              n.unread ? 'bg-indigo-500/5' : ''
                            }`}
                          >
                            <div className="flex items-start gap-3">
                              <div className="flex-1 min-w-0">
                                <p className="text-sm text-slate-200 truncate">{n.title}</p>
                                <p className="text-xs text-slate-500 mt-0.5">{n.time}</p>
                              </div>
                              {n.unread && <span className="w-2 h-2 bg-indigo-500 rounded-full mt-1.5" />}
                            </div>
                          </div>
                        ))}
                      </div>
                      <div className="px-4 py-2.5 border-t border-slate-800">
                        <button className="text-xs text-indigo-400 hover:text-indigo-300 font-medium">
                          View all notifications
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                {/* User Menu */}
                <div className="relative" data-dropdown>
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      setUserMenuOpen(!userMenuOpen)
                      setNotificationsOpen(false)
                    }}
                    className="flex items-center gap-2 p-1.5 hover:bg-slate-800/50 rounded-lg transition-colors"
                  >
                    <div className="w-7 h-7 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-lg flex items-center justify-center text-xs font-medium text-white">
                      A
                    </div>
                    <ChevronDown size={14} className="text-slate-500 hidden sm:block" />
                  </button>

                  {userMenuOpen && (
                    <div className="absolute right-0 top-12 w-56 bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
                      <div className="px-4 py-3 border-b border-slate-800">
                        <p className="text-sm font-medium text-white">Admin User</p>
                        <p className="text-xs text-slate-500">admin@fixops.io</p>
                      </div>
                      <div className="py-1">
                        {['Profile', 'Organization', 'API Keys', 'Preferences'].map((item) => (
                          <button
                            key={item}
                            className="w-full px-4 py-2 text-sm text-slate-300 hover:bg-slate-800/50 text-left transition-colors"
                          >
                            {item}
                          </button>
                        ))}
                      </div>
                      <div className="py-1 border-t border-slate-800">
                        <button className="w-full px-4 py-2 text-sm text-rose-400 hover:bg-slate-800/50 text-left transition-colors">
                          Sign out
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </header>
        )}

        {/* ================================================================ */}
        {/* MOBILE MENU OVERLAY                                             */}
        {/* ================================================================ */}
        {mobileMenuOpen && (
          <div 
            className="fixed inset-0 bg-black/60 z-40 md:hidden"
            onClick={() => setMobileMenuOpen(false)}
          />
        )}

        {/* ================================================================ */}
        {/* SIDEBAR - Grouped navigation like Wiz/Datadog                   */}
        {/* ================================================================ */}
        {showSidebar && (
          <aside
            className={`fixed top-14 bottom-0 bg-slate-950 border-r border-slate-800/50 z-40 transition-all duration-200 ${
              sidebarCollapsed ? 'w-16' : 'w-56'
            } ${mobileMenuOpen ? 'left-0' : '-left-56 md:left-0'}`}
          >
            <nav className="h-full flex flex-col py-3 overflow-y-auto">
              {NAV_SECTIONS.map((section) => (
                <div key={section.title} className="mb-1">
                  {/* Section Header */}
                  {!sidebarCollapsed && (
                    <button
                      onClick={() => toggleSection(section.title)}
                      className="w-full flex items-center justify-between px-4 py-1.5 text-[10px] font-semibold text-slate-500 uppercase tracking-wider hover:text-slate-400 transition-colors"
                    >
                      {section.title}
                      <ChevronRight 
                        size={12} 
                        className={`transition-transform ${expandedSections.has(section.title) ? 'rotate-90' : ''}`}
                      />
                    </button>
                  )}
                  
                  {/* Section Items */}
                  {(sidebarCollapsed || expandedSections.has(section.title)) && (
                    <div className="space-y-0.5 px-2">
                      {section.items.map((item) => {
                        const Icon = item.icon
                        const isActive = item.key === currentApp
                        const href = getNavHref(item.key)
                        
                        return (
                          <a
                            key={item.key}
                            href={href}
                            onClick={() => setMobileMenuOpen(false)}
                            title={sidebarCollapsed ? item.name : undefined}
                            className={`flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-[13px] font-medium transition-colors ${
                              isActive
                                ? 'bg-indigo-500/10 text-indigo-400'
                                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                            }`}
                          >
                            <Icon size={16} className={isActive ? 'text-indigo-400' : ''} />
                            {!sidebarCollapsed && <span>{item.name}</span>}
                          </a>
                        )
                      })}
                    </div>
                  )}
                </div>
              ))}

              {/* Bottom section */}
              <div className="mt-auto pt-3 border-t border-slate-800/50 px-2">
                <a
                  href={getNavHref('marketplace')}
                  className="flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-[13px] font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 transition-colors"
                >
                  <Store size={16} />
                  {!sidebarCollapsed && <span>Marketplace</span>}
                </a>
              </div>
            </nav>
          </aside>
        )}

        {/* ================================================================ */}
        {/* MAIN CONTENT AREA                                               */}
        {/* ================================================================ */}
        <main
          className={`transition-all duration-200 ${showTopbar ? 'pt-14' : ''} ${
            showSidebar ? (sidebarCollapsed ? 'md:pl-16' : 'md:pl-56') : ''
          }`}
        >
          {/* Page Header - Consistent across all apps */}
          {(title || tabs || headerActions) && (
            <div className="sticky top-14 z-30 bg-slate-950 border-b border-slate-800/50">
              <div className="px-6 py-4">
                {/* Title Row */}
                {(title || headerActions) && (
                  <div className="flex items-center justify-between mb-3">
                    <div>
                      {subtitle && (
                        <p className="text-xs text-slate-500 mb-0.5">{subtitle}</p>
                      )}
                      {title && (
                        <h1 className="text-xl font-semibold text-white">{title}</h1>
                      )}
                    </div>
                    {headerActions && (
                      <div className="flex items-center gap-2">
                        {headerActions}
                      </div>
                    )}
                  </div>
                )}

                {/* Tabs Row */}
                {tabs && tabs.length > 0 && (
                  <div className="flex items-center gap-1 -mb-4 pt-1">
                    {tabs.map((tab) => (
                      <button
                        key={tab.id}
                        onClick={() => onTabChange?.(tab.id)}
                        className={`px-3 py-2.5 text-sm font-medium border-b-2 transition-colors ${
                          activeTab === tab.id
                            ? 'text-indigo-400 border-indigo-400'
                            : 'text-slate-400 border-transparent hover:text-slate-200 hover:border-slate-700'
                        }`}
                      >
                        {tab.label}
                        {tab.count !== undefined && (
                          <span className={`ml-1.5 px-1.5 py-0.5 text-xs rounded ${
                            activeTab === tab.id ? 'bg-indigo-500/20' : 'bg-slate-800'
                          }`}>
                            {tab.count}
                          </span>
                        )}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Page Content */}
          <div className="p-6">
            {children}
          </div>
        </main>

        {/* ================================================================ */}
        {/* COMMAND PALETTE                                                 */}
        {/* ================================================================ */}
        {commandPaletteOpen && (
          <div className="fixed inset-0 bg-black/60 z-50 flex items-start justify-center pt-24">
            <div className="w-full max-w-xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
              <div className="flex items-center gap-3 px-4 py-3 border-b border-slate-800">
                <Search size={16} className="text-slate-500" />
                <input
                  type="text"
                  placeholder="Search commands, pages, or issues..."
                  autoFocus
                  className="flex-1 bg-transparent text-white placeholder-slate-500 outline-none text-sm"
                />
                <button
                  onClick={() => setCommandPaletteOpen(false)}
                  className="px-2 py-1 text-xs text-slate-500 bg-slate-800 rounded hover:bg-slate-700 transition-colors"
                >
                  ESC
                </button>
              </div>
              <div className="max-h-80 overflow-y-auto p-2">
                <div className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider px-2 py-1.5">
                  Quick Actions
                </div>
                {[
                  { label: 'Go to Triage', icon: AlertTriangle },
                  { label: 'View Risk Graph', icon: GitBranch },
                  { label: 'Run Compliance Scan', icon: Shield },
                  { label: 'Generate Report', icon: FileText },
                ].map((action, i) => (
                  <button
                    key={i}
                    className="w-full flex items-center gap-3 px-3 py-2.5 text-sm text-slate-300 hover:bg-slate-800/50 rounded-lg transition-colors"
                  >
                    <action.icon size={16} className="text-slate-500" />
                    {action.label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </DemoModeContext.Provider>
  )
}
