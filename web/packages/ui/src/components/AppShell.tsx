'use client'

import { useState, useEffect, ReactNode } from 'react'
import { 
  Bell, 
  Search, 
  User, 
  Settings, 
  ChevronDown, 
  Shield, 
  BarChart3, 
  FileText, 
  Zap, 
  Archive, 
  GitBranch,
  Command,
  Menu,
  X,
  Users,
  Layers,
  Cloud,
  Key,
  Workflow,
  Package,
  Store,
  LucideIcon
} from 'lucide-react'

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

export interface AppShellProps {
  children: ReactNode
  activeApp?: string
  showTopbar?: boolean
  showSidebar?: boolean
  sidebarFooter?: ReactNode
  onAppUrlsLoaded?: (urls: AppUrls) => void
}

// Central navigation configuration - single source of truth
export const NAV_ITEMS: NavItem[] = [
  { name: 'Dashboard', key: 'dashboard', icon: BarChart3 },
  { name: 'Triage Inbox', key: 'triage', icon: Shield },
  { name: 'Risk Graph', key: 'risk', icon: GitBranch },
  { name: 'Findings', key: 'findings', icon: FileText },
  { name: 'Compliance', key: 'compliance', icon: Archive },
  { name: 'Evidence', key: 'evidence', icon: Shield },
  { name: 'Saved Views', key: 'saved-views', icon: FileText },
  { name: 'Automations', key: 'automations', icon: Zap },
  { name: 'Integrations', key: 'integrations', icon: GitBranch },
  { name: 'Users', key: 'users', icon: Users },
  { name: 'Teams', key: 'teams', icon: Users },
  { name: 'Policies', key: 'policies', icon: Shield },
  { name: 'Inventory', key: 'inventory', icon: Package },
  { name: 'Reports', key: 'reports', icon: FileText },
  { name: 'Audit Logs', key: 'audit', icon: FileText },
  { name: 'Workflows', key: 'workflows', icon: Workflow },
  { name: 'SSO Config', key: 'sso', icon: Shield },
  { name: 'Secrets', key: 'secrets', icon: Key },
  { name: 'IaC Scanning', key: 'iac', icon: Cloud },
  { name: 'Bulk Operations', key: 'bulk', icon: Layers },
  { name: 'Pentagi', key: 'pentagi', icon: Shield },
  { name: 'Marketplace', key: 'marketplace', icon: Store },
  { name: 'Settings', key: 'settings', icon: Settings },
]

// URL resolution with multiple fallback strategies
const CENTRAL_URL = 'https://raw.githubusercontent.com/DevOpsMadDog/Fixops/main/web/app-urls.json'
const LOCAL_URL = '/app-urls.json'

export function AppShell({ 
  children, 
  activeApp,
  showTopbar = true,
  showSidebar = true,
  sidebarFooter,
  onAppUrlsLoaded
}: AppShellProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false)
  const [notificationsOpen, setNotificationsOpen] = useState(false)
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const [appUrls, setAppUrls] = useState<AppUrls | null>(null)
  const [currentApp, setCurrentApp] = useState<string>(activeApp || '')
  const [isDesktop, setIsDesktop] = useState(false)

  // Load app URLs from central config or local fallback
  useEffect(() => {
    const loadUrls = async () => {
      let urls: AppUrls | null = null
      
      // Try central URL first
      try {
        const res = await fetch(CENTRAL_URL)
        if (res.ok) {
          urls = await res.json()
        }
      } catch (err) {
        console.warn('Failed to fetch central app-urls.json, trying local fallback:', err)
      }
      
      // Fallback to local
      if (!urls) {
        try {
          const res = await fetch(LOCAL_URL)
          if (res.ok) {
            urls = await res.json()
          }
        } catch (err) {
          console.error('Failed to load app URLs from both central and local:', err)
        }
      }
      
      if (urls) {
        setAppUrls(urls)
        onAppUrlsLoaded?.(urls)
        
        // Detect current app from URL or use provided activeApp
        if (!activeApp && typeof window !== 'undefined') {
          const origin = window.location.origin
          const currentAppEntry = Object.entries(urls).find(([_, url]) => url === origin)
          if (currentAppEntry) {
            setCurrentApp(currentAppEntry[0])
          } else {
            // Fallback: use APP_KEY from build-time env
            const appKey = process.env.NEXT_PUBLIC_APP_KEY
            if (appKey && appKey in urls) {
              setCurrentApp(appKey)
            }
          }
        }
      }
    }
    
    loadUrls()
  }, [activeApp, onAppUrlsLoaded])

  // Update currentApp when activeApp prop changes
  useEffect(() => {
    if (activeApp) {
      setCurrentApp(activeApp)
    }
  }, [activeApp])

  // Handle responsive behavior
  useEffect(() => {
    const handleResize = () => {
      const wasDesktop = isDesktop
      const nowDesktop = window.innerWidth >= 768
      setIsDesktop(nowDesktop)
      
      if (!wasDesktop && nowDesktop && sidebarOpen) {
        setSidebarOpen(false)
        document.body.style.overflow = ''
      }
    }
    
    handleResize()
    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [isDesktop, sidebarOpen])

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
        if (sidebarOpen && !isDesktop) {
          setSidebarOpen(false)
        }
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [sidebarOpen, isDesktop])

  // Body scroll lock when sidebar is open on mobile
  useEffect(() => {
    if (sidebarOpen && !isDesktop) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = ''
    }
    
    return () => {
      document.body.style.overflow = ''
    }
  }, [sidebarOpen, isDesktop])

  // Build navigation with resolved URLs
  const navigation = NAV_ITEMS.map(item => ({
    ...item,
    href: appUrls && item.key in appUrls 
      ? (item.key === currentApp ? '/' : appUrls[item.key as keyof AppUrls] || '#')
      : '#',
    current: item.key === currentApp,
    disabled: !appUrls
  }))

  const notifications = [
    { id: 1, title: 'New critical vulnerability detected', time: '2 min ago', unread: true },
    { id: 2, title: 'Compliance scan completed', time: '15 min ago', unread: true },
    { id: 3, title: 'Evidence bundle signed', time: '1 hour ago', unread: false },
  ]

  return (
    <div className="min-h-screen bg-[#0f172a] font-sans text-white">
      {/* Top Navigation Bar */}
      {showTopbar && (
        <div className="fixed top-0 left-0 right-0 h-16 bg-[#0f172a]/95 backdrop-blur-xl border-b border-white/[0.06] z-50">
          <div className="flex items-center justify-between h-full px-4">
            {/* Left: Logo + Sidebar Toggle */}
            <div className="flex items-center gap-4">
              <button
                onClick={() => setSidebarOpen(!sidebarOpen)}
                className="p-2 hover:bg-white/[0.04] rounded-xl transition-all duration-200"
              >
                {sidebarOpen ? <X size={20} /> : <Menu size={20} />}
              </button>
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-[#6B5AED] to-[#8B7CF7] flex items-center justify-center shadow-[0_0_20px_rgba(107,90,237,0.3)]">
                  <Shield size={16} className="text-white" />
                </div>
                <span className="text-lg font-semibold tracking-tight">FixOps</span>
              </div>
            </div>

            {/* Center: Global Search - Hidden on mobile */}
            <div className="hidden md:flex flex-1 max-w-2xl mx-8">
              <button
                onClick={() => setCommandPaletteOpen(true)}
                className="w-full px-4 py-2.5 bg-white/[0.03] ring-1 ring-white/[0.08] rounded-xl text-sm text-slate-400 hover:bg-white/[0.06] hover:ring-white/[0.12] transition-all duration-200 flex items-center justify-between"
              >
                <div className="flex items-center gap-2">
                  <Search size={16} />
                  <span>Search or jump to...</span>
                </div>
                <div className="flex items-center gap-1 text-xs bg-white/[0.06] px-2 py-1 rounded-lg">
                  <Command size={12} />
                  <span>K</span>
                </div>
              </button>
            </div>

            {/* Right: Notifications + User Menu */}
            <div className="flex items-center gap-2">
              {/* Notifications */}
              <div className="relative">
                <button
                  onClick={() => setNotificationsOpen(!notificationsOpen)}
                  className="p-2.5 hover:bg-white/[0.04] rounded-xl transition-all duration-200 relative"
                >
                  <Bell size={18} />
                  <span className="absolute top-2 right-2 w-2 h-2 bg-rose-500 rounded-full ring-2 ring-[#0f172a]"></span>
                </button>

                {notificationsOpen && (
                  <div className="absolute right-0 top-14 w-80 bg-[#1e293b]/95 backdrop-blur-xl ring-1 ring-white/[0.08] rounded-2xl shadow-[0_16px_48px_rgba(0,0,0,0.4)]">
                    <div className="p-4 border-b border-white/[0.06]">
                      <h3 className="text-sm font-semibold">Notifications</h3>
                    </div>
                    <div className="max-h-96 overflow-y-auto">
                      {notifications.map((notif) => (
                        <div
                          key={notif.id}
                          className={`p-4 border-b border-white/[0.04] hover:bg-white/[0.04] cursor-pointer transition-colors ${
                            notif.unread ? 'bg-[#6B5AED]/[0.04]' : ''
                          }`}
                        >
                          <div className="flex items-start justify-between">
                            <div className="flex-1">
                              <p className="text-sm font-medium">{notif.title}</p>
                              <p className="text-xs text-slate-500 mt-1">{notif.time}</p>
                            </div>
                            {notif.unread && (
                              <div className="w-2 h-2 bg-[#6B5AED] rounded-full mt-1"></div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                    <div className="p-3 border-t border-white/[0.06]">
                      <button className="text-sm text-[#A599FF] hover:text-white transition-colors">
                        View all notifications
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* User Menu */}
              <div className="relative">
                <button
                  onClick={() => setUserMenuOpen(!userMenuOpen)}
                  className="flex items-center gap-2 p-2 hover:bg-white/[0.04] rounded-xl transition-all duration-200"
                >
                  <div className="w-8 h-8 bg-gradient-to-br from-[#6B5AED] to-[#8B7CF7] rounded-xl flex items-center justify-center">
                    <User size={14} />
                  </div>
                  <ChevronDown size={14} className="text-slate-400" />
                </button>

                {userMenuOpen && (
                  <div className="absolute right-0 top-14 w-56 bg-[#1e293b]/95 backdrop-blur-xl ring-1 ring-white/[0.08] rounded-2xl shadow-[0_16px_48px_rgba(0,0,0,0.4)]">
                    <div className="p-4 border-b border-white/[0.06]">
                      <p className="text-sm font-semibold">Admin User</p>
                      <p className="text-xs text-slate-500">admin@fixops.io</p>
                    </div>
                    <div className="p-2">
                      <button className="w-full px-3 py-2.5 text-sm text-left hover:bg-white/[0.04] rounded-xl transition-colors">
                        Profile Settings
                      </button>
                      <button className="w-full px-3 py-2.5 text-sm text-left hover:bg-white/[0.04] rounded-xl transition-colors">
                        Organization
                      </button>
                      <button className="w-full px-3 py-2.5 text-sm text-left hover:bg-white/[0.04] rounded-xl transition-colors">
                        API Keys
                      </button>
                    </div>
                    <div className="p-2 border-t border-white/[0.06]">
                      <button className="w-full px-3 py-2.5 text-sm text-left text-rose-400 hover:bg-white/[0.04] rounded-xl transition-colors">
                        Sign Out
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Mobile Overlay */}
      {sidebarOpen && showSidebar && (
        <div
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-30 md:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      {showSidebar && (
        <div
          className="fixed top-16 left-0 bottom-0 w-64 bg-[#0f172a]/95 backdrop-blur-xl border-r border-white/[0.06] transition-all duration-200 z-40 flex flex-col"
          style={{
            display: isDesktop || sidebarOpen ? 'flex' : 'none',
            transform: isDesktop || sidebarOpen ? 'translateX(0)' : 'translateX(-100%)'
          }}
        >
          <div className="flex-1 p-3 space-y-1 overflow-y-auto">
            {navigation.map((item) => {
              const Icon = item.icon
              return (
                <a
                  key={item.name}
                  href={item.href}
                  onClick={() => {
                    if (window.innerWidth < 768) {
                      setSidebarOpen(false)
                    }
                  }}
                  className={`flex items-center gap-3 px-3 py-2.5 rounded-xl text-[13px] font-medium transition-all duration-200 ${
                    item.current
                      ? 'bg-white/[0.08] text-white ring-1 ring-white/[0.1]'
                      : 'text-slate-400 hover:bg-white/[0.04] hover:text-slate-200'
                  }`}
                >
                  <Icon size={16} />
                  {item.name}
                </a>
              )
            })}
          </div>
          {sidebarFooter && (
            <div className="p-3 border-t border-white/[0.06]">
              {sidebarFooter}
            </div>
          )}
        </div>
      )}

      {/* Main Content */}
      <div
        className={`transition-all duration-200 ${showTopbar ? 'pt-16' : ''} ${showSidebar ? 'pl-0 md:pl-64' : ''}`}
      >
        {children}
      </div>

      {/* Command Palette Modal */}
      {commandPaletteOpen && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-start justify-center pt-32">
          <div className="w-full max-w-2xl bg-[#1e293b]/95 backdrop-blur-xl ring-1 ring-white/[0.08] rounded-2xl shadow-[0_16px_48px_rgba(0,0,0,0.4)]">
            <div className="p-4 border-b border-white/[0.06]">
              <div className="flex items-center gap-3">
                <Search size={18} className="text-slate-400" />
                <input
                  type="text"
                  placeholder="Type a command or search..."
                  autoFocus
                  className="flex-1 bg-transparent text-white placeholder-slate-500 outline-none text-[15px]"
                />
                <button
                  onClick={() => setCommandPaletteOpen(false)}
                  className="text-xs text-slate-500 hover:text-white px-2 py-1 rounded-lg bg-white/[0.04] transition-colors"
                >
                  ESC
                </button>
              </div>
            </div>
            <div className="p-2 max-h-96 overflow-y-auto">
              <div className="text-[11px] text-slate-500 uppercase tracking-wider px-3 py-2">Quick Actions</div>
              {navigation.map((item) => {
                const Icon = item.icon
                return (
                  <a
                    key={item.name}
                    href={item.href}
                    className="flex items-center gap-3 px-3 py-2.5 hover:bg-white/[0.04] rounded-xl transition-colors"
                    onClick={() => setCommandPaletteOpen(false)}
                  >
                    <Icon size={16} className="text-slate-400" />
                    <span className="text-[13px]">{item.name}</span>
                  </a>
                )
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default AppShell
