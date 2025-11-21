'use client'

import { useState, useEffect } from 'react'
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
  X
} from 'lucide-react'

interface EnterpriseShellProps {
  children: React.ReactNode
}

export default function EnterpriseShell({ children }: EnterpriseShellProps) {
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false)
  const [notificationsOpen, setNotificationsOpen] = useState(false)
  const [userMenuOpen, setUserMenuOpen] = useState(false)

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
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [])

  const navigation = [
    { name: 'Dashboard', href: '/dashboard', icon: BarChart3, current: false },
    { name: 'Triage Inbox', href: '/triage', icon: Shield, current: false },
    { name: 'Risk Graph', href: '/risk', icon: GitBranch, current: false },
    { name: 'Findings', href: '/findings', icon: FileText, current: false },
    { name: 'Compliance', href: '/compliance', icon: Archive, current: false },
    { name: 'Evidence', href: '/evidence', icon: Shield, current: false },
    { name: 'Saved Views', href: '/saved-views', icon: FileText, current: false },
    { name: 'Automations', href: '/automations', icon: Zap, current: false },
    { name: 'Integrations', href: '/integrations', icon: GitBranch, current: false },
    { name: 'Settings', href: '/settings', icon: Settings, current: false },
  ]

  const notifications = [
    { id: 1, title: 'New critical vulnerability detected', time: '2 min ago', unread: true },
    { id: 2, title: 'Compliance scan completed', time: '15 min ago', unread: true },
    { id: 3, title: 'Evidence bundle signed', time: '1 hour ago', unread: false },
  ]

  return (
    <div className="min-h-screen bg-[#0f172a] font-sans text-white">
      {/* Top Navigation Bar */}
      <div className="fixed top-0 left-0 right-0 h-16 bg-[#0f172a]/95 backdrop-blur-sm border-b border-white/10 z-50">
        <div className="flex items-center justify-between h-full px-4">
          {/* Left: Logo + Sidebar Toggle */}
          <div className="flex items-center gap-4">
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="p-2 hover:bg-white/5 rounded-md transition-colors"
            >
              {sidebarOpen ? <X size={20} /> : <Menu size={20} />}
            </button>
            <div className="flex items-center gap-2">
              <Shield size={24} className="text-[#6B5AED]" />
              <span className="text-xl font-semibold">FixOps</span>
            </div>
          </div>

          {/* Center: Global Search */}
          <div className="flex-1 max-w-2xl mx-8">
            <button
              onClick={() => setCommandPaletteOpen(true)}
              className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-slate-400 hover:bg-white/10 transition-all flex items-center justify-between"
            >
              <div className="flex items-center gap-2">
                <Search size={16} />
                <span>Search or jump to...</span>
              </div>
              <div className="flex items-center gap-1 text-xs bg-white/10 px-2 py-1 rounded">
                <Command size={12} />
                <span>K</span>
              </div>
            </button>
          </div>

          {/* Right: Notifications + User Menu */}
          <div className="flex items-center gap-3">
            {/* Notifications */}
            <div className="relative">
              <button
                onClick={() => setNotificationsOpen(!notificationsOpen)}
                className="p-2 hover:bg-white/5 rounded-md transition-colors relative"
              >
                <Bell size={20} />
                <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full"></span>
              </button>

              {notificationsOpen && (
                <div className="absolute right-0 top-12 w-80 bg-[#1e293b] border border-white/10 rounded-lg shadow-xl">
                  <div className="p-4 border-b border-white/10">
                    <h3 className="text-sm font-semibold">Notifications</h3>
                  </div>
                  <div className="max-h-96 overflow-y-auto">
                    {notifications.map((notif) => (
                      <div
                        key={notif.id}
                        className={`p-4 border-b border-white/5 hover:bg-white/5 cursor-pointer ${
                          notif.unread ? 'bg-[#6B5AED]/5' : ''
                        }`}
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <p className="text-sm font-medium">{notif.title}</p>
                            <p className="text-xs text-slate-400 mt-1">{notif.time}</p>
                          </div>
                          {notif.unread && (
                            <div className="w-2 h-2 bg-[#6B5AED] rounded-full mt-1"></div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                  <div className="p-3 border-t border-white/10">
                    <button className="text-sm text-[#6B5AED] hover:text-[#5B4ADD] transition-colors">
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
                className="flex items-center gap-2 p-2 hover:bg-white/5 rounded-md transition-colors"
              >
                <div className="w-8 h-8 bg-[#6B5AED] rounded-full flex items-center justify-center">
                  <User size={16} />
                </div>
                <ChevronDown size={16} />
              </button>

              {userMenuOpen && (
                <div className="absolute right-0 top-12 w-56 bg-[#1e293b] border border-white/10 rounded-lg shadow-xl">
                  <div className="p-3 border-b border-white/10">
                    <p className="text-sm font-semibold">Admin User</p>
                    <p className="text-xs text-slate-400">admin@fixops.io</p>
                  </div>
                  <div className="p-2">
                    <button className="w-full px-3 py-2 text-sm text-left hover:bg-white/5 rounded-md transition-colors">
                      Profile Settings
                    </button>
                    <button className="w-full px-3 py-2 text-sm text-left hover:bg-white/5 rounded-md transition-colors">
                      Organization
                    </button>
                    <button className="w-full px-3 py-2 text-sm text-left hover:bg-white/5 rounded-md transition-colors">
                      API Keys
                    </button>
                  </div>
                  <div className="p-2 border-t border-white/10">
                    <button className="w-full px-3 py-2 text-sm text-left text-red-400 hover:bg-white/5 rounded-md transition-colors">
                      Sign Out
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Sidebar */}
      <div
        className={`fixed top-16 left-0 bottom-0 w-64 bg-[#0f172a]/95 backdrop-blur-sm border-r border-white/10 transition-transform duration-200 z-40 ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="p-4 space-y-1">
          {navigation.map((item) => {
            const Icon = item.icon
            return (
              <a
                key={item.name}
                href={item.href}
                className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                  item.current
                    ? 'bg-[#6B5AED]/10 text-[#6B5AED]'
                    : 'text-slate-300 hover:bg-white/5 hover:text-white'
                }`}
              >
                <Icon size={18} />
                {item.name}
              </a>
            )
          })}
        </div>
      </div>

      {/* Main Content */}
      <div
        className={`pt-16 transition-all duration-200 ${
          sidebarOpen ? 'pl-64' : 'pl-0'
        }`}
      >
        {children}
      </div>

      {/* Command Palette Modal */}
      {commandPaletteOpen && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-start justify-center pt-32">
          <div className="w-full max-w-2xl bg-[#1e293b] border border-white/10 rounded-lg shadow-2xl">
            <div className="p-4 border-b border-white/10">
              <div className="flex items-center gap-3">
                <Search size={20} className="text-slate-400" />
                <input
                  type="text"
                  placeholder="Type a command or search..."
                  autoFocus
                  className="flex-1 bg-transparent text-white placeholder-slate-400 outline-none"
                />
                <button
                  onClick={() => setCommandPaletteOpen(false)}
                  className="text-xs text-slate-400 hover:text-white"
                >
                  ESC
                </button>
              </div>
            </div>
            <div className="p-2 max-h-96 overflow-y-auto">
              <div className="text-xs text-slate-500 px-3 py-2">Quick Actions</div>
              {navigation.map((item) => {
                const Icon = item.icon
                return (
                  <a
                    key={item.name}
                    href={item.href}
                    className="flex items-center gap-3 px-3 py-2 hover:bg-white/5 rounded-md transition-colors"
                    onClick={() => setCommandPaletteOpen(false)}
                  >
                    <Icon size={16} className="text-slate-400" />
                    <span className="text-sm">{item.name}</span>
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
