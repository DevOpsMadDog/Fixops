'use client'

import { useState, useEffect, useMemo } from 'react'
import { Shield, Search, Plus, Edit2, Trash2, CheckCircle, XCircle, AlertTriangle, Play, FileText, Filter, Loader2, RefreshCw, WifiOff, X } from 'lucide-react'
import { AppShell, useDemoModeContext } from '@fixops/ui'
import { usePolicies } from '@fixops/api-client'

const DEMO_POLICIES = [
  {
    id: '1',
    name: 'Block Critical KEV Vulnerabilities',
    description: 'Automatically block deployments with CISA KEV vulnerabilities',
    type: 'security',
    action: 'block',
    enabled: true,
    conditions: [
      { field: 'exploitability.kev', operator: 'equals', value: 'true' },
      { field: 'severity', operator: 'in', value: ['critical', 'high'] },
    ],
    violations: 12,
    last_triggered: '2024-11-22T08:30:00Z',
    created_at: '2024-01-15T10:00:00Z',
  },
  {
    id: '2',
    name: 'Require Review for High EPSS',
    description: 'Require security review for vulnerabilities with EPSS > 0.7',
    type: 'security',
    action: 'review',
    enabled: true,
    conditions: [
      { field: 'exploitability.epss', operator: 'greater_than', value: '0.7' },
    ],
    violations: 8,
    last_triggered: '2024-11-22T07:15:00Z',
    created_at: '2024-02-01T14:30:00Z',
  },
  {
    id: '3',
    name: 'Block Exposed Secrets',
    description: 'Block deployments with hardcoded secrets or credentials',
    type: 'secrets',
    action: 'block',
    enabled: true,
    conditions: [
      { field: 'source', operator: 'equals', value: 'IaC' },
      { field: 'title', operator: 'contains', value: 'secret' },
    ],
    violations: 3,
    last_triggered: '2024-11-22T06:00:00Z',
    created_at: '2024-02-15T09:00:00Z',
  },
  {
    id: '4',
    name: 'Warn on Medium Severity',
    description: 'Generate warnings for medium severity findings',
    type: 'security',
    action: 'warn',
    enabled: true,
    conditions: [
      { field: 'severity', operator: 'equals', value: 'medium' },
    ],
    violations: 45,
    last_triggered: '2024-11-22T09:00:00Z',
    created_at: '2024-03-01T11:20:00Z',
  },
  {
    id: '5',
    name: 'Require Compliance Review',
    description: 'Require compliance review for PCI-DSS violations',
    type: 'compliance',
    action: 'review',
    enabled: true,
    conditions: [
      { field: 'compliance_mappings', operator: 'contains', value: 'PCI-DSS' },
    ],
    violations: 6,
    last_triggered: '2024-11-21T18:30:00Z',
    created_at: '2024-03-15T13:45:00Z',
  },
  {
    id: '6',
    name: 'Block SQL Injection',
    description: 'Block deployments with SQL injection vulnerabilities',
    type: 'security',
    action: 'block',
    enabled: true,
    conditions: [
      { field: 'title', operator: 'contains', value: 'SQL Injection' },
    ],
    violations: 2,
    last_triggered: '2024-11-20T15:00:00Z',
    created_at: '2024-04-01T15:10:00Z',
  },
  {
    id: '7',
    name: 'Auto-Triage Low Severity',
    description: 'Automatically accept low severity findings in non-critical services',
    type: 'automation',
    action: 'allow',
    enabled: false,
    conditions: [
      { field: 'severity', operator: 'equals', value: 'low' },
      { field: 'business_criticality', operator: 'not_equals', value: 'mission_critical' },
    ],
    violations: 0,
    last_triggered: null,
    created_at: '2024-05-01T08:30:00Z',
  },
  {
    id: '8',
    name: 'Block Internet-Facing RCE',
    description: 'Block remote code execution vulnerabilities in internet-facing services',
    type: 'security',
    action: 'block',
    enabled: true,
    conditions: [
      { field: 'title', operator: 'contains', value: 'Remote Code Execution' },
      { field: 'internet_facing', operator: 'equals', value: 'true' },
    ],
    violations: 4,
    last_triggered: '2024-11-22T05:00:00Z',
    created_at: '2024-06-01T10:15:00Z',
  },
]

export default function PoliciesPage() {
  const { demoEnabled } = useDemoModeContext()
  const { data: apiData, loading: apiLoading, error: apiError, refetch } = usePolicies()
  
  // Transform API data to match our UI format, or use demo data
  const policiesData = useMemo(() => {
    if (demoEnabled || !apiData?.items) {
      return DEMO_POLICIES
    }
    return apiData.items.map(policy => ({
      id: policy.id,
      name: policy.name,
      description: policy.description || '',
      type: policy.type || 'security',
      action: 'block' as const,
      enabled: policy.status === 'active',
      conditions: [] as Array<{ field: string; operator: string; value: string | string[] }>,
      violations: 0,
      last_triggered: policy.last_evaluated,
      created_at: policy.created_at,
    }))
  }, [demoEnabled, apiData])

  const [policies, setPolicies] = useState(DEMO_POLICIES)
  const [filteredPolicies, setFilteredPolicies] = useState(DEMO_POLICIES)
  const [selectedPolicy, setSelectedPolicy] = useState<typeof DEMO_POLICIES[0] | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [actionFilter, setActionFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
    const [showCreateModal, setShowCreateModal] = useState(false)
    const [showTestModal, setShowTestModal] = useState(false)
    const [showMobileFilters, setShowMobileFilters] = useState(false)

  // Update policies when data source changes
  useEffect(() => {
    setPolicies(policiesData)
    setFilteredPolicies(policiesData)
  }, [policiesData])

  const getActionColor = (action: string) => {
    const colors = {
      block: '#dc2626',
      review: '#f97316',
      warn: '#eab308',
      allow: '#10b981',
    }
    return colors[action as keyof typeof colors] || colors.allow
  }

  const getActionIcon = (action: string) => {
    const icons = {
      block: <XCircle size={14} />,
      review: <AlertTriangle size={14} />,
      warn: <AlertTriangle size={14} />,
      allow: <CheckCircle size={14} />,
    }
    return icons[action as keyof typeof icons] || icons.allow
  }

  const getTypeColor = (type: string) => {
    const colors = {
      security: '#3b82f6',
      secrets: '#8b5cf6',
      compliance: '#10b981',
      automation: '#6b7280',
    }
    return colors[type as keyof typeof colors] || colors.automation
  }

  const formatDate = (isoString: string | null) => {
    if (!isoString) return 'Never'
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
    let filtered = [...policies]

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(policy =>
        policy.name.toLowerCase().includes(query) ||
        policy.description.toLowerCase().includes(query)
      )
    }

    if (typeFilter !== 'all') {
      filtered = filtered.filter(policy => policy.type === typeFilter)
    }

    if (actionFilter !== 'all') {
      filtered = filtered.filter(policy => policy.action === actionFilter)
    }

    if (statusFilter !== 'all') {
      const isEnabled = statusFilter === 'enabled'
      filtered = filtered.filter(policy => policy.enabled === isEnabled)
    }

    setFilteredPolicies(filtered)
  }

  useState(() => {
    applyFilters()
  })

  const summary = {
    total: policies.length,
    enabled: policies.filter(p => p.enabled).length,
    disabled: policies.filter(p => !p.enabled).length,
    total_violations: policies.reduce((sum, p) => sum + p.violations, 0),
    block: policies.filter(p => p.action === 'block').length,
    review: policies.filter(p => p.action === 'review').length,
  }

  return (
    <AppShell activeApp="policies">
            <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
              {/* Mobile Filter Overlay */}
              {showMobileFilters && (
                <div className="fixed inset-0 z-50 lg:hidden">
                  <div className="absolute inset-0 bg-black/60" onClick={() => setShowMobileFilters(false)} />
                  <div className="absolute left-0 top-0 h-full w-72 bg-[#0f172a] border-r border-white/10 flex flex-col overflow-auto">
                    <div className="p-4 border-b border-white/10 flex items-center justify-between">
                      <span className="font-semibold">Filters</span>
                      <button onClick={() => setShowMobileFilters(false)} className="p-2 hover:bg-white/10 rounded-md">
                        <X size={18} />
                      </button>
                    </div>
                    <div className="p-4 border-b border-white/10">
                      <div className="grid grid-cols-2 gap-3 text-xs">
                        <div className="p-3 bg-white/5 rounded-md">
                          <div className="text-slate-500 mb-1">Total</div>
                          <div className="text-xl font-semibold text-[#6B5AED]">{summary.total}</div>
                        </div>
                        <div className="p-3 bg-white/5 rounded-md">
                          <div className="text-slate-500 mb-1">Enabled</div>
                          <div className="text-xl font-semibold text-green-500">{summary.enabled}</div>
                        </div>
                      </div>
                    </div>
                    <div className="p-4 flex-1 overflow-auto">
                      <div className="mb-6">
                        <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">Type</div>
                        <div className="space-y-2">
                          {['all', 'security', 'secrets', 'compliance', 'automation'].map((type) => (
                            <button
                              key={type}
                              onClick={() => { setTypeFilter(type); applyFilters(); setShowMobileFilters(false); }}
                              className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${typeFilter === type ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30' : 'text-slate-400 hover:bg-white/5'}`}
                            >
                              <span className="capitalize">{type}</span>
                            </button>
                          ))}
                        </div>
                      </div>
                      <div className="mb-6">
                        <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">Action</div>
                        <div className="space-y-2">
                          {['all', 'block', 'review', 'warn', 'allow'].map((action) => (
                            <button
                              key={action}
                              onClick={() => { setActionFilter(action); applyFilters(); setShowMobileFilters(false); }}
                              className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${actionFilter === action ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30' : 'text-slate-400 hover:bg-white/5'}`}
                            >
                              <span className="capitalize">{action}</span>
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Left Sidebar - Filters */}
              <div className="hidden lg:flex w-72 bg-[#0f172a]/80 border-r border-white/10 flex-col sticky top-0 h-screen">
          {/* Header */}
          <div className="p-6 border-b border-white/10">
            <div className="flex items-center gap-3 mb-4">
              <Shield size={24} className="text-[#6B5AED]" />
              <h2 className="text-lg font-semibold">Policy Management</h2>
            </div>
            <p className="text-xs text-slate-500">Define and enforce security policies</p>
          </div>

          {/* Summary Stats */}
          <div className="p-4 border-b border-white/10">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Total Policies</div>
                <div className="text-xl font-semibold text-[#6B5AED]">{summary.total}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Enabled</div>
                <div className="text-xl font-semibold text-green-500">{summary.enabled}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Violations</div>
                <div className="text-xl font-semibold text-red-500">{summary.total_violations}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Block Rules</div>
                <div className="text-xl font-semibold text-orange-500">{summary.block}</div>
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
                {['all', 'security', 'secrets', 'compliance', 'automation'].map((type) => (
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
                        ({policies.filter(p => p.type === type).length})
                      </span>
                    )}
                    {type === 'all' && (
                      <span className="ml-2 text-xs">({policies.length})</span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            <div className="mb-6">
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Filter size={12} />
                Filter by Action
              </div>
              <div className="space-y-2">
                {['all', 'block', 'review', 'warn', 'allow'].map((action) => (
                  <button
                    key={action}
                    onClick={() => { setActionFilter(action); applyFilters(); }}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      actionFilter === action
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="capitalize">{action}</span>
                    {action !== 'all' && (
                      <span className="ml-2 text-xs">
                        ({policies.filter(p => p.action === action).length})
                      </span>
                    )}
                    {action === 'all' && (
                      <span className="ml-2 text-xs">({policies.length})</span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Filter size={12} />
                Filter by Status
              </div>
              <div className="space-y-2">
                {['all', 'enabled', 'disabled'].map((status) => (
                  <button
                    key={status}
                    onClick={() => { setStatusFilter(status); applyFilters(); }}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      statusFilter === status
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="capitalize">{status}</span>
                    {status === 'enabled' && (
                      <span className="ml-2 text-xs">
                        ({policies.filter(p => p.enabled).length})
                      </span>
                    )}
                    {status === 'disabled' && (
                      <span className="ml-2 text-xs">
                        ({policies.filter(p => !p.enabled).length})
                      </span>
                    )}
                    {status === 'all' && (
                      <span className="ml-2 text-xs">({policies.length})</span>
                    )}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

                {/* Main Content */}
                <div className="flex-1 flex flex-col min-w-0">
                  {/* Top Bar */}
                  <div className="p-4 lg:p-5 border-b border-white/10 bg-[#0f172a]/80 backdrop-blur-sm">
                                <div className="flex items-center justify-between mb-4">
                                  <div className="flex items-center gap-3">
                                    {/* Mobile Filter Toggle */}
                                    <button
                                      onClick={() => setShowMobileFilters(true)}
                                      className="lg:hidden p-2 bg-white/5 border border-white/10 rounded-md hover:bg-white/10 transition-colors"
                                    >
                                      <Filter size={18} />
                                    </button>
                                    <div>
                                                              <h1 className="text-xl lg:text-2xl font-semibold mb-1">Policies</h1>
                                                      <p className="text-sm text-slate-500 flex items-center gap-2">
                                                        {apiLoading && !demoEnabled ? (
                                                          <><Loader2 size={14} className="animate-spin" /> Loading...</>
                                                        ) : (
                                                          <>Showing {filteredPolicies.length} polic{filteredPolicies.length !== 1 ? 'ies' : 'y'}</>
                                                        )}
                                                        {!demoEnabled && apiError && (
                                                          <span className="text-amber-400 flex items-center gap-1">
                                                            <WifiOff size={12} /> Using cached data
                                                          </span>
                                                        )}
                                                      </p>
                                                    </div>
                                                    </div>
                                                    <div className="flex items-center gap-2">
                            {!demoEnabled && (
                              <button
                                onClick={() => refetch()}
                                disabled={apiLoading}
                                className="p-2 hover:bg-white/10 rounded-md transition-colors disabled:opacity-50"
                                title="Refresh data"
                              >
                                <RefreshCw size={16} className={apiLoading ? 'animate-spin' : ''} />
                              </button>
                            )}
                            <button
                              onClick={() => setShowCreateModal(true)}
                              className="px-4 py-2 bg-[#6B5AED] hover:bg-[#5B4ADD] rounded-md text-white text-sm font-medium transition-all flex items-center gap-2"
                            >
                              <Plus size={16} />
                              Create Policy
                            </button>
                          </div>
                        </div>

            {/* Search Bar */}
            <div className="relative">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search by name or description..."
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); applyFilters(); }}
                className="w-full pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-[#6B5AED]/50"
              />
            </div>
          </div>

          {/* Policies Table */}
          <div className="flex-1 overflow-auto p-6">
            <div className="bg-white/2 rounded-lg border border-white/5 overflow-hidden">
              <table className="w-full">
                <thead className="bg-white/5 border-b border-white/10">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Policy</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Type</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Action</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Status</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Violations</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Last Triggered</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {filteredPolicies.map((policy) => (
                    <tr
                      key={policy.id}
                      onClick={() => setSelectedPolicy(policy)}
                      className="hover:bg-white/5 cursor-pointer transition-colors"
                    >
                      <td className="px-4 py-3">
                        <div>
                          <div className="text-sm font-medium text-white">{policy.name}</div>
                          <div className="text-xs text-slate-400 line-clamp-1">{policy.description}</div>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium"
                          style={{ 
                            backgroundColor: `${getTypeColor(policy.type)}20`,
                            color: getTypeColor(policy.type)
                          }}
                        >
                          {policy.type}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium"
                          style={{ 
                            backgroundColor: `${getActionColor(policy.action)}20`,
                            color: getActionColor(policy.action)
                          }}
                        >
                          {getActionIcon(policy.action)}
                          {policy.action}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className={`w-2 h-2 rounded-full ${policy.enabled ? 'bg-green-500' : 'bg-gray-500'}`} />
                          <span className="text-sm text-slate-300">
                            {policy.enabled ? 'Enabled' : 'Disabled'}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-sm text-white font-semibold">{policy.violations}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-sm text-slate-300">{formatDate(policy.last_triggered)}</span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={(e) => {
                              e.stopPropagation()
                              setSelectedPolicy(policy)
                              setShowTestModal(true)
                            }}
                            className="p-1.5 hover:bg-white/10 rounded transition-colors"
                            title="Test policy"
                          >
                            <Play size={14} className="text-slate-400" />
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation()
                              const updatedPolicies = policies.map(p =>
                                p.id === policy.id ? { ...p, enabled: !p.enabled } : p
                              )
                              setPolicies(updatedPolicies)
                              applyFilters()
                            }}
                            className="p-1.5 hover:bg-white/10 rounded transition-colors"
                            title={policy.enabled ? 'Disable policy' : 'Enable policy'}
                          >
                            {policy.enabled ? (
                              <XCircle size={14} className="text-red-400" />
                            ) : (
                              <CheckCircle size={14} className="text-green-400" />
                            )}
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation()
                              if (confirm(`Delete policy "${policy.name}"?`)) {
                                setPolicies(policies.filter(p => p.id !== policy.id))
                                applyFilters()
                              }
                            }}
                            className="p-1.5 hover:bg-red-500/10 rounded transition-colors"
                            title="Delete policy"
                          >
                            <Trash2 size={14} className="text-red-400" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Policy Detail Drawer */}
        {selectedPolicy && !showTestModal && (
          <div
            onClick={() => setSelectedPolicy(null)}
            className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex justify-end"
          >
            <div
              onClick={(e) => e.stopPropagation()}
              className="w-[600px] h-full bg-[#1e293b] border-l border-white/10 flex flex-col animate-slide-in overflow-auto"
            >
              {/* Drawer Header */}
              <div className="p-6 border-b border-white/10 sticky top-0 bg-[#1e293b] z-10">
                <div className="flex justify-between items-start mb-4">
                  <div>
                    <h3 className="text-lg font-semibold mb-1">{selectedPolicy.name}</h3>
                    <p className="text-sm text-slate-400">{selectedPolicy.description}</p>
                  </div>
                  <button
                    onClick={() => setSelectedPolicy(null)}
                    className="text-slate-400 hover:text-white transition-colors"
                  >
                    ✕
                  </button>
                </div>

                <div className="flex gap-2">
                  <span
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium"
                    style={{ 
                      backgroundColor: `${getTypeColor(selectedPolicy.type)}20`,
                      color: getTypeColor(selectedPolicy.type)
                    }}
                  >
                    {selectedPolicy.type}
                  </span>
                  <span
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium"
                    style={{ 
                      backgroundColor: `${getActionColor(selectedPolicy.action)}20`,
                      color: getActionColor(selectedPolicy.action)
                    }}
                  >
                    {getActionIcon(selectedPolicy.action)}
                    {selectedPolicy.action}
                  </span>
                  <span className={`inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium ${
                    selectedPolicy.enabled ? 'bg-green-500/10 text-green-500' : 'bg-gray-500/10 text-gray-500'
                  }`}>
                    {selectedPolicy.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
              </div>

              {/* Drawer Content */}
              <div className="flex-1 p-6 space-y-6">
                {/* Policy Information */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Policy Information</h4>
                  <div className="space-y-3 bg-white/5 rounded-lg p-4">
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Policy ID</span>
                      <span className="text-sm text-white font-mono">{selectedPolicy.id}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Violations</span>
                      <span className="text-sm text-white font-semibold">{selectedPolicy.violations}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Last Triggered</span>
                      <span className="text-sm text-white">{formatDate(selectedPolicy.last_triggered)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Created</span>
                      <span className="text-sm text-white">{formatDate(selectedPolicy.created_at)}</span>
                    </div>
                  </div>
                </div>

                {/* Conditions */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
                    <FileText size={16} />
                    Conditions
                  </h4>
                  <div className="space-y-2">
                    {selectedPolicy.conditions.map((condition, idx) => (
                      <div key={idx} className="p-3 bg-white/5 rounded-lg">
                        <div className="flex items-center gap-2 text-sm">
                          <span className="text-slate-400">{condition.field}</span>
                          <span className="text-[#6B5AED] font-mono">{condition.operator}</span>
                          <span className="text-white font-medium">{condition.value}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Actions */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Actions</h4>
                  <div className="space-y-2">
                    <button
                      onClick={() => setShowTestModal(true)}
                      className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2"
                    >
                      <Play size={16} />
                      Test Policy
                    </button>
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <Edit2 size={16} />
                      Edit Policy
                    </button>
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <FileText size={16} />
                      View Violations
                    </button>
                    <button
                      onClick={() => {
                        const updatedPolicies = policies.map(p =>
                          p.id === selectedPolicy.id ? { ...p, enabled: !p.enabled } : p
                        )
                        setPolicies(updatedPolicies)
                        setSelectedPolicy({ ...selectedPolicy, enabled: !selectedPolicy.enabled })
                        applyFilters()
                      }}
                      className={`w-full p-3 rounded-lg text-sm text-left transition-colors flex items-center gap-2 ${
                        selectedPolicy.enabled
                          ? 'bg-red-500/10 hover:bg-red-500/20 text-red-400'
                          : 'bg-green-500/10 hover:bg-green-500/20 text-green-400'
                      }`}
                    >
                      {selectedPolicy.enabled ? (
                        <>
                          <XCircle size={16} />
                          Disable Policy
                        </>
                      ) : (
                        <>
                          <CheckCircle size={16} />
                          Enable Policy
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  )
}
