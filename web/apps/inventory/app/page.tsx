'use client'

import { useState } from 'react'
import { Package, Search, Plus, Edit2, Trash2, GitBranch, Code, Server, Box, Filter, ExternalLink, Calendar, Users } from 'lucide-react'
import EnterpriseShell from './components/EnterpriseShell'

const DEMO_APPLICATIONS = [
  {
    id: '1',
    name: 'Payment API',
    description: 'Core payment processing service',
    type: 'service',
    owner: 'Platform Team',
    repository: 'github.com/fixops/payment-api',
    language: 'Java',
    framework: 'Spring Boot',
    criticality: 'mission_critical',
    services: 3,
    components: 12,
    dependencies: 45,
    last_scan: '2024-11-22T08:00:00Z',
    status: 'active',
  },
  {
    id: '2',
    name: 'User Service',
    description: 'User authentication and profile management',
    type: 'service',
    owner: 'Backend Team',
    repository: 'github.com/fixops/user-service',
    language: 'Python',
    framework: 'FastAPI',
    criticality: 'high',
    services: 2,
    components: 8,
    dependencies: 32,
    last_scan: '2024-11-22T07:30:00Z',
    status: 'active',
  },
  {
    id: '3',
    name: 'Web Dashboard',
    description: 'Customer-facing web application',
    type: 'application',
    owner: 'Frontend Team',
    repository: 'github.com/fixops/web-dashboard',
    language: 'TypeScript',
    framework: 'Next.js',
    criticality: 'high',
    services: 1,
    components: 24,
    dependencies: 156,
    last_scan: '2024-11-22T09:00:00Z',
    status: 'active',
  },
  {
    id: '4',
    name: 'API Gateway',
    description: 'Central API gateway and routing',
    type: 'service',
    owner: 'Platform Team',
    repository: 'github.com/fixops/api-gateway',
    language: 'Go',
    framework: 'Gin',
    criticality: 'mission_critical',
    services: 1,
    components: 6,
    dependencies: 28,
    last_scan: '2024-11-22T08:15:00Z',
    status: 'active',
  },
  {
    id: '5',
    name: 'Notification Service',
    description: 'Email and SMS notification delivery',
    type: 'service',
    owner: 'Backend Team',
    repository: 'github.com/fixops/notification-service',
    language: 'Node.js',
    framework: 'Express',
    criticality: 'medium',
    services: 2,
    components: 10,
    dependencies: 42,
    last_scan: '2024-11-22T06:45:00Z',
    status: 'active',
  },
  {
    id: '6',
    name: 'Analytics Engine',
    description: 'Real-time analytics and reporting',
    type: 'service',
    owner: 'Data Team',
    repository: 'github.com/fixops/analytics-engine',
    language: 'Python',
    framework: 'Django',
    criticality: 'medium',
    services: 1,
    components: 15,
    dependencies: 67,
    last_scan: '2024-11-22T05:30:00Z',
    status: 'active',
  },
  {
    id: '7',
    name: 'Mobile App',
    description: 'iOS and Android mobile application',
    type: 'application',
    owner: 'Mobile Team',
    repository: 'github.com/fixops/mobile-app',
    language: 'Dart',
    framework: 'Flutter',
    criticality: 'high',
    services: 0,
    components: 18,
    dependencies: 89,
    last_scan: '2024-11-21T22:00:00Z',
    status: 'active',
  },
  {
    id: '8',
    name: 'Legacy Admin Portal',
    description: 'Deprecated admin interface',
    type: 'application',
    owner: 'Backend Team',
    repository: 'github.com/fixops/admin-portal',
    language: 'PHP',
    framework: 'Laravel',
    criticality: 'low',
    services: 1,
    components: 22,
    dependencies: 54,
    last_scan: '2024-11-20T10:00:00Z',
    status: 'deprecated',
  },
]

export default function InventoryPage() {
  const [applications, setApplications] = useState(DEMO_APPLICATIONS)
  const [filteredApplications, setFilteredApplications] = useState(DEMO_APPLICATIONS)
  const [selectedApp, setSelectedApp] = useState<typeof DEMO_APPLICATIONS[0] | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [criticalityFilter, setCriticalityFilter] = useState<string>('all')
  const [languageFilter, setLanguageFilter] = useState<string>('all')
  const [showCreateModal, setShowCreateModal] = useState(false)

  const getCriticalityColor = (criticality: string) => {
    const colors = {
      mission_critical: '#dc2626',
      high: '#f97316',
      medium: '#eab308',
      low: '#10b981',
    }
    return colors[criticality as keyof typeof colors] || colors.low
  }

  const getTypeIcon = (type: string) => {
    return type === 'application' ? <Box size={16} /> : <Server size={16} />
  }

  const formatDate = (isoString: string) => {
    const date = new Date(isoString)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60))
    
    if (diffHours < 1) return 'Just now'
    if (diffHours < 24) return `${diffHours}h ago`
    const diffDays = Math.floor(diffHours / 24)
    if (diffDays < 7) return `${diffDays}d ago`
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
  }

  const applyFilters = () => {
    let filtered = [...applications]

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(app =>
        app.name.toLowerCase().includes(query) ||
        app.description.toLowerCase().includes(query) ||
        app.owner.toLowerCase().includes(query)
      )
    }

    if (typeFilter !== 'all') {
      filtered = filtered.filter(app => app.type === typeFilter)
    }

    if (criticalityFilter !== 'all') {
      filtered = filtered.filter(app => app.criticality === criticalityFilter)
    }

    if (languageFilter !== 'all') {
      filtered = filtered.filter(app => app.language === languageFilter)
    }

    setFilteredApplications(filtered)
  }

  useState(() => {
    applyFilters()
  })

  const summary = {
    total: applications.length,
    services: applications.filter(a => a.type === 'service').length,
    applications_count: applications.filter(a => a.type === 'application').length,
    mission_critical: applications.filter(a => a.criticality === 'mission_critical').length,
    high: applications.filter(a => a.criticality === 'high').length,
    active: applications.filter(a => a.status === 'active').length,
    deprecated: applications.filter(a => a.status === 'deprecated').length,
  }

  const languages = Array.from(new Set(applications.map(a => a.language)))

  return (
    <EnterpriseShell>
      <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
        {/* Left Sidebar - Filters */}
        <div className="w-72 bg-[#0f172a]/80 border-r border-white/10 flex flex-col sticky top-0 h-screen">
          {/* Header */}
          <div className="p-6 border-b border-white/10">
            <div className="flex items-center gap-3 mb-4">
              <Package size={24} className="text-[#6B5AED]" />
              <h2 className="text-lg font-semibold">Application Inventory</h2>
            </div>
            <p className="text-xs text-slate-500">Track applications, services, and components</p>
          </div>

          {/* Summary Stats */}
          <div className="p-4 border-b border-white/10">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Total</div>
                <div className="text-xl font-semibold text-[#6B5AED]">{summary.total}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Services</div>
                <div className="text-xl font-semibold text-blue-500">{summary.services}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Apps</div>
                <div className="text-xl font-semibold text-green-500">{summary.applications_count}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Critical</div>
                <div className="text-xl font-semibold text-red-500">{summary.mission_critical}</div>
              </div>
            </div>
          </div>

          {/* Filters */}
          <div className="p-4 flex-1 overflow-auto">
            <div className="mb-6">
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Filter size={12} />
                Filter by Type
              </div>
              <div className="space-y-2">
                {['all', 'service', 'application'].map((type) => (
                  <button
                    key={type}
                    onClick={() => { setTypeFilter(type); applyFilters(); }}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      typeFilter === type
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="capitalize">{type}</span>
                    {type !== 'all' && (
                      <span className="ml-2 text-xs">
                        ({applications.filter(a => a.type === type).length})
                      </span>
                    )}
                    {type === 'all' && (
                      <span className="ml-2 text-xs">({applications.length})</span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            <div className="mb-6">
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Filter size={12} />
                Filter by Criticality
              </div>
              <div className="space-y-2">
                {['all', 'mission_critical', 'high', 'medium', 'low'].map((crit) => (
                  <button
                    key={crit}
                    onClick={() => { setCriticalityFilter(crit); applyFilters(); }}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      criticalityFilter === crit
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="capitalize">{crit.replace('_', ' ')}</span>
                    {crit !== 'all' && (
                      <span className="ml-2 text-xs">
                        ({applications.filter(a => a.criticality === crit).length})
                      </span>
                    )}
                    {crit === 'all' && (
                      <span className="ml-2 text-xs">({applications.length})</span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Code size={12} />
                Filter by Language
              </div>
              <div className="space-y-2">
                <button
                  onClick={() => { setLanguageFilter('all'); applyFilters(); }}
                  className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                    languageFilter === 'all'
                      ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                      : 'text-slate-400 hover:bg-white/5'
                  }`}
                >
                  All Languages
                  <span className="ml-2 text-xs">({applications.length})</span>
                </button>
                {languages.map((lang) => (
                  <button
                    key={lang}
                    onClick={() => { setLanguageFilter(lang); applyFilters(); }}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      languageFilter === lang
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    {lang}
                    <span className="ml-2 text-xs">
                      ({applications.filter(a => a.language === lang).length})
                    </span>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1 flex flex-col">
          {/* Top Bar */}
          <div className="p-5 border-b border-white/10 bg-[#0f172a]/80 backdrop-blur-sm">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h1 className="text-2xl font-semibold mb-1">Application Inventory</h1>
                <p className="text-sm text-slate-500">
                  Showing {filteredApplications.length} application{filteredApplications.length !== 1 ? 's' : ''}
                </p>
              </div>
              <button
                onClick={() => setShowCreateModal(true)}
                className="px-4 py-2 bg-[#6B5AED] hover:bg-[#5B4ADD] rounded-md text-white text-sm font-medium transition-all flex items-center gap-2"
              >
                <Plus size={16} />
                Add Application
              </button>
            </div>

            {/* Search Bar */}
            <div className="relative">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search by name, description, or owner..."
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); applyFilters(); }}
                className="w-full pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-[#6B5AED]/50"
              />
            </div>
          </div>

          {/* Applications Grid */}
          <div className="flex-1 overflow-auto p-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
              {filteredApplications.map((app) => (
                <div
                  key={app.id}
                  onClick={() => setSelectedApp(app)}
                  className="bg-white/2 border border-white/5 rounded-lg p-5 hover:bg-white/5 hover:border-[#6B5AED]/30 cursor-pointer transition-all"
                >
                  {/* Header */}
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-[#6B5AED]/20 flex items-center justify-center">
                        {getTypeIcon(app.type)}
                      </div>
                      <div>
                        <h3 className="text-sm font-semibold text-white">{app.name}</h3>
                        <p className="text-xs text-slate-400">{app.type}</p>
                      </div>
                    </div>
                    <span
                      className="px-2 py-1 rounded text-xs font-medium"
                      style={{ 
                        backgroundColor: `${getCriticalityColor(app.criticality)}20`,
                        color: getCriticalityColor(app.criticality)
                      }}
                    >
                      {app.criticality.replace('_', ' ')}
                    </span>
                  </div>

                  {/* Description */}
                  <p className="text-sm text-slate-300 mb-4 line-clamp-2">{app.description}</p>

                  {/* Stats */}
                  <div className="grid grid-cols-3 gap-3 mb-4">
                    <div className="text-center p-2 bg-white/5 rounded">
                      <div className="text-xs text-slate-400 mb-1">Services</div>
                      <div className="text-lg font-semibold text-[#6B5AED]">{app.services}</div>
                    </div>
                    <div className="text-center p-2 bg-white/5 rounded">
                      <div className="text-xs text-slate-400 mb-1">Components</div>
                      <div className="text-lg font-semibold text-blue-500">{app.components}</div>
                    </div>
                    <div className="text-center p-2 bg-white/5 rounded">
                      <div className="text-xs text-slate-400 mb-1">Dependencies</div>
                      <div className="text-lg font-semibold text-green-500">{app.dependencies}</div>
                    </div>
                  </div>

                  {/* Footer */}
                  <div className="flex items-center justify-between pt-3 border-t border-white/5">
                    <div className="flex items-center gap-2 text-xs text-slate-400">
                      <Users size={12} />
                      {app.owner}
                    </div>
                    <div className="flex items-center gap-2 text-xs text-slate-400">
                      <Calendar size={12} />
                      {formatDate(app.last_scan)}
                    </div>
                  </div>

                  {/* Tech Stack */}
                  <div className="flex items-center gap-2 mt-3">
                    <span className="px-2 py-1 bg-white/5 rounded text-xs text-slate-300">
                      {app.language}
                    </span>
                    <span className="px-2 py-1 bg-white/5 rounded text-xs text-slate-300">
                      {app.framework}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Application Detail Drawer */}
        {selectedApp && (
          <div
            onClick={() => setSelectedApp(null)}
            className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex justify-end"
          >
            <div
              onClick={(e) => e.stopPropagation()}
              className="w-[600px] h-full bg-[#1e293b] border-l border-white/10 flex flex-col animate-slide-in overflow-auto"
            >
              {/* Drawer Header */}
              <div className="p-6 border-b border-white/10 sticky top-0 bg-[#1e293b] z-10">
                <div className="flex justify-between items-start mb-4">
                  <div className="flex items-center gap-3">
                    <div className="w-12 h-12 rounded-lg bg-[#6B5AED]/20 flex items-center justify-center">
                      {getTypeIcon(selectedApp.type)}
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold">{selectedApp.name}</h3>
                      <p className="text-sm text-slate-400">{selectedApp.description}</p>
                    </div>
                  </div>
                  <button
                    onClick={() => setSelectedApp(null)}
                    className="text-slate-400 hover:text-white transition-colors"
                  >
                    ✕
                  </button>
                </div>

                <div className="flex gap-2">
                  <span
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium"
                    style={{ 
                      backgroundColor: `${getCriticalityColor(selectedApp.criticality)}20`,
                      color: getCriticalityColor(selectedApp.criticality)
                    }}
                  >
                    {selectedApp.criticality.replace('_', ' ')}
                  </span>
                  <span className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium bg-white/5 text-slate-300">
                    {getTypeIcon(selectedApp.type)}
                    {selectedApp.type}
                  </span>
                </div>
              </div>

              {/* Drawer Content */}
              <div className="flex-1 p-6 space-y-6">
                {/* Overview */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
                    <Package size={16} />
                    Overview
                  </h4>
                  <div className="space-y-3 bg-white/5 rounded-lg p-4">
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Application ID</span>
                      <span className="text-sm text-white font-mono">{selectedApp.id}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Owner</span>
                      <span className="text-sm text-white">{selectedApp.owner}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Status</span>
                      <span className="text-sm text-white capitalize">{selectedApp.status}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Last Scan</span>
                      <span className="text-sm text-white">{formatDate(selectedApp.last_scan)}</span>
                    </div>
                  </div>
                </div>

                {/* Tech Stack */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
                    <Code size={16} />
                    Tech Stack
                  </h4>
                  <div className="space-y-3 bg-white/5 rounded-lg p-4">
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Language</span>
                      <span className="text-sm text-white">{selectedApp.language}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Framework</span>
                      <span className="text-sm text-white">{selectedApp.framework}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Repository</span>
                      <a 
                        href={`https://${selectedApp.repository}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-[#6B5AED] hover:underline flex items-center gap-1"
                      >
                        {selectedApp.repository.split('/').slice(-1)[0]}
                        <ExternalLink size={12} />
                      </a>
                    </div>
                  </div>
                </div>

                {/* Inventory Stats */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
                    <GitBranch size={16} />
                    Inventory
                  </h4>
                  <div className="grid grid-cols-3 gap-3">
                    <div className="p-4 bg-white/5 rounded-lg text-center">
                      <div className="text-2xl font-semibold text-[#6B5AED] mb-1">{selectedApp.services}</div>
                      <div className="text-xs text-slate-400">Services</div>
                    </div>
                    <div className="p-4 bg-white/5 rounded-lg text-center">
                      <div className="text-2xl font-semibold text-blue-500 mb-1">{selectedApp.components}</div>
                      <div className="text-xs text-slate-400">Components</div>
                    </div>
                    <div className="p-4 bg-white/5 rounded-lg text-center">
                      <div className="text-2xl font-semibold text-green-500 mb-1">{selectedApp.dependencies}</div>
                      <div className="text-xs text-slate-400">Dependencies</div>
                    </div>
                  </div>
                </div>

                {/* Actions */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Actions</h4>
                  <div className="space-y-2">
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <GitBranch size={16} />
                      View Dependency Graph
                    </button>
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <Code size={16} />
                      View Components
                    </button>
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <Search size={16} />
                      Run Security Scan
                    </button>
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <Edit2 size={16} />
                      Edit Application
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </EnterpriseShell>
  )
}
