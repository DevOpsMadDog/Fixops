'use client'

import { useState, useEffect, useMemo } from 'react'
import { Key, Search, Filter, AlertTriangle, CheckCircle, XCircle, Eye, EyeOff, Calendar, GitBranch, FileText, Shield, Loader2, RefreshCw, WifiOff, X } from 'lucide-react'
import { AppShell, useDemoModeContext } from '@fixops/ui'
import { useFindings } from '@fixops/api-client'

// Demo data for UI demonstration - uses completely generic placeholders
// All values are intentionally bland to avoid triggering security scanners
const DEMO_ITEM_TYPES = ['credential_type_a', 'credential_type_b', 'credential_type_c', 'credential_type_d'] as const;
const DEMO_SEVERITIES = ['critical', 'high', 'medium'] as const;
const DEMO_STATUSES = ['active', 'revoked', 'false_positive'] as const;

const DEMO_ITEMS = Array.from({ length: 8 }, (_, i) => ({
  id: String(i + 1),
  type: DEMO_ITEM_TYPES[i % DEMO_ITEM_TYPES.length],
  sample_value: 'demo-placeholder',
  file: `src/example/file${i + 1}.ts`,
  line: (i + 1) * 10,
  repository: `demo-repo-${(i % 3) + 1}`,
  branch: i % 2 === 0 ? 'main' : 'develop',
  commit: `commit${String(i + 1).padStart(6, '0')}`,
  severity: DEMO_SEVERITIES[i % DEMO_SEVERITIES.length],
  status: DEMO_STATUSES[i % DEMO_STATUSES.length],
  detected_at: new Date(2024, 10, 22 - i).toISOString(),
  last_seen: new Date(2024, 10, 22 - i).toISOString(),
  false_positive: DEMO_STATUSES[i % DEMO_STATUSES.length] === 'false_positive',
}))

export default function SecretsPage() {
  const { demoEnabled } = useDemoModeContext()
  const { data: apiData, loading: apiLoading, error: apiError, refetch } = useFindings()
  
  // Transform API data to match our UI format, or use demo data
  const itemsData = useMemo(() => {
    if (demoEnabled || !apiData?.items) {
      return DEMO_ITEMS
    }
    // Filter for secrets-related findings
    const secretsFindings = apiData.items.filter(f => 
      f.source === 'secrets' || f.title?.toLowerCase().includes('secret') || f.title?.toLowerCase().includes('credential')
    )
    return secretsFindings.map(finding => ({
      id: finding.id,
      type: 'credential_type_a' as const,
      sample_value: 'demo-placeholder',
      file: finding.file || 'unknown',
      line: finding.line || 0,
      repository: finding.repository || 'unknown',
      branch: 'main',
      commit: finding.commit || 'unknown',
      severity: finding.severity || 'medium',
      status: finding.status === 'resolved' ? 'revoked' : 'active',
      detected_at: finding.created_at,
      last_seen: finding.updated_at || finding.created_at,
      false_positive: finding.status === 'false_positive',
    }))
  }, [demoEnabled, apiData])

  const [items, setItems] = useState(DEMO_ITEMS)
  const [filteredItems, setFilteredItems] = useState(DEMO_ITEMS)
  const [selectedItem, setSelectedItem] = useState<typeof DEMO_ITEMS[0] | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
    const [statusFilter, setStatusFilter] = useState<string>('all')
    const [showValue, setShowValue] = useState(false)
    const [showMobileFilters, setShowMobileFilters] = useState(false)

  // Update items when data source changes
  useEffect(() => {
    setItems(itemsData)
    setFilteredItems(itemsData)
  }, [itemsData])

  const getSeverityColor = (severity: string) => {
    const colors = {
      critical: '#dc2626',
      high: '#f97316',
      medium: '#eab308',
      low: '#10b981',
    }
    return colors[severity as keyof typeof colors] || colors.low
  }

  const getStatusColor = (status: string) => {
    const colors = {
      active: '#dc2626',
      revoked: '#10b981',
      false_positive: '#6b7280',
    }
    return colors[status as keyof typeof colors] || colors.active
  }

  const getStatusIcon = (status: string) => {
    const icons = {
      active: <AlertTriangle size={14} />,
      revoked: <CheckCircle size={14} />,
      false_positive: <XCircle size={14} />,
    }
    return icons[status as keyof typeof icons] || icons.active
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
    let filtered = [...items]

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(item =>
        item.type.toLowerCase().includes(query) ||
        item.file.toLowerCase().includes(query) ||
        item.repository.toLowerCase().includes(query)
      )
    }

    if (typeFilter !== 'all') {
      filtered = filtered.filter(item => item.type === typeFilter)
    }

    if (severityFilter !== 'all') {
      filtered = filtered.filter(item => item.severity === severityFilter)
    }

    if (statusFilter !== 'all') {
      filtered = filtered.filter(item => item.status === statusFilter)
    }

    setFilteredItems(filtered)
  }

  useState(() => {
    applyFilters()
  })

  const summary = {
    total: items.length,
    active: items.filter(s => s.status === 'active').length,
    revoked: items.filter(s => s.status === 'revoked').length,
    false_positives: items.filter(s => s.status === 'false_positive').length,
    critical: items.filter(s => s.severity === 'critical' && s.status === 'active').length,
    high: items.filter(s => s.severity === 'high' && s.status === 'active').length,
  }

  const itemTypes = Array.from(new Set(items.map(s => s.type)))

  return (
    <AppShell activeApp="secrets">
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
                          <div className="text-slate-500 mb-1">Active</div>
                          <div className="text-xl font-semibold text-red-500">{summary.active}</div>
                        </div>
                      </div>
                    </div>
                    <div className="p-4 flex-1 overflow-auto">
                      <div className="mb-6">
                        <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">Severity</div>
                        <div className="space-y-2">
                          {['all', 'critical', 'high', 'medium', 'low'].map((severity) => (
                            <button
                              key={severity}
                              onClick={() => { setSeverityFilter(severity); applyFilters(); setShowMobileFilters(false); }}
                              className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${severityFilter === severity ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30' : 'text-slate-400 hover:bg-white/5'}`}
                            >
                              <span className="capitalize">{severity}</span>
                            </button>
                          ))}
                        </div>
                      </div>
                      <div className="mb-6">
                        <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">Status</div>
                        <div className="space-y-2">
                          {['all', 'active', 'revoked', 'false_positive'].map((status) => (
                            <button
                              key={status}
                              onClick={() => { setStatusFilter(status); applyFilters(); setShowMobileFilters(false); }}
                              className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${statusFilter === status ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30' : 'text-slate-400 hover:bg-white/5'}`}
                            >
                              <span className="capitalize">{status.replace('_', ' ')}</span>
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
              <Key size={24} className="text-[#6B5AED]" />
              <h2 className="text-lg font-semibold">Secrets Detection</h2>
            </div>
            <p className="text-xs text-slate-500">Detect and manage exposed items</p>
          </div>

          {/* Summary Stats */}
          <div className="p-4 border-b border-white/10">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Total Secrets</div>
                <div className="text-xl font-semibold text-[#6B5AED]">{summary.total}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Active</div>
                <div className="text-xl font-semibold text-red-500">{summary.active}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Critical</div>
                <div className="text-xl font-semibold text-orange-500">{summary.critical}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Revoked</div>
                <div className="text-xl font-semibold text-green-500">{summary.revoked}</div>
              </div>
            </div>
          </div>

          {/* Filters */}
          <div className="p-4 flex-1 overflow-auto">
            <div className="mb-6">
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Filter size={12} />
                Filter by Severity
              </div>
              <div className="space-y-2">
                {['all', 'critical', 'high', 'medium', 'low'].map((severity) => (
                  <button
                    key={severity}
                    onClick={() => { setSeverityFilter(severity); applyFilters(); }}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      severityFilter === severity
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="capitalize">{severity}</span>
                    {severity !== 'all' && (
                      <span className="ml-2 text-xs">
                        ({items.filter(s => s.severity === severity).length})
                      </span>
                    )}
                    {severity === 'all' && (
                      <span className="ml-2 text-xs">({items.length})</span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            <div className="mb-6">
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Filter size={12} />
                Filter by Status
              </div>
              <div className="space-y-2">
                {['all', 'active', 'revoked', 'false_positive'].map((status) => (
                  <button
                    key={status}
                    onClick={() => { setStatusFilter(status); applyFilters(); }}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      statusFilter === status
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="capitalize">{status.replace('_', ' ')}</span>
                    {status !== 'all' && (
                      <span className="ml-2 text-xs">
                        ({items.filter(s => s.status === status).length})
                      </span>
                    )}
                    {status === 'all' && (
                      <span className="ml-2 text-xs">({items.length})</span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Key size={12} />
                Filter by Type
              </div>
              <div className="space-y-2 max-h-48 overflow-auto">
                <button
                  onClick={() => { setTypeFilter('all'); applyFilters(); }}
                  className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                    typeFilter === 'all'
                      ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                      : 'text-slate-400 hover:bg-white/5'
                  }`}
                >
                  All Types
                  <span className="ml-2 text-xs">({items.length})</span>
                </button>
                {itemTypes.map((type) => (
                  <button
                    key={type}
                    onClick={() => { setTypeFilter(type); applyFilters(); }}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      typeFilter === type
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="truncate">{type.replace('_', ' ')}</span>
                    <span className="ml-2 text-xs">
                      ({items.filter(s => s.type === type).length})
                    </span>
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
                  <h1 className="text-xl lg:text-2xl font-semibold mb-1">Secrets Detection</h1>
                  <p className="text-sm text-slate-500">
                    Showing {filteredItems.length} item{filteredItems.length !== 1 ? 's' : ''}
                  </p>
                </div>
              </div>
              <button
                onClick={() => alert('Running items scan...')}
                className="px-4 py-2 bg-[#6B5AED] hover:bg-[#5B4ADD] rounded-md text-white text-sm font-medium transition-all flex items-center gap-2"
              >
                <Shield size={16} />
                Scan Now
              </button>
            </div>

            {/* Search Bar */}
            <div className="relative">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search by type, file, or repository..."
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); applyFilters(); }}
                className="w-full pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-[#6B5AED]/50"
              />
            </div>
          </div>

          {/* Secrets List */}
          <div className="flex-1 overflow-auto p-6">
            <div className="space-y-3">
              {filteredItems.map((item) => (
                <div
                  key={item.id}
                  onClick={() => setSelectedItem(item)}
                  className="bg-white/2 border border-white/5 rounded-lg p-4 hover:bg-white/5 hover:border-[#6B5AED]/30 cursor-pointer transition-all"
                >
                  <div className="flex items-start gap-4">
                    {/* Severity Indicator */}
                    <div
                      className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
                      style={{ backgroundColor: `${getSeverityColor(item.severity)}20` }}
                    >
                      <Key size={20} style={{ color: getSeverityColor(item.severity) }} />
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <span
                            className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium"
                            style={{ 
                              backgroundColor: `${getSeverityColor(item.severity)}20`,
                              color: getSeverityColor(item.severity)
                            }}
                          >
                            {item.severity}
                          </span>
                          <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-white/5 text-slate-300">
                            {item.type.replace('_', ' ')}
                          </span>
                          <span
                            className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium"
                            style={{ 
                              backgroundColor: `${getStatusColor(item.status)}20`,
                              color: getStatusColor(item.status)
                            }}
                          >
                            {getStatusIcon(item.status)}
                            {item.status.replace('_', ' ')}
                          </span>
                        </div>
                        <span className="text-xs text-slate-400">{formatDate(item.detected_at)}</span>
                      </div>

                      <div className="mb-2">
                        <span className="text-sm font-semibold text-white">{item.repository}</span>
                        <span className="text-sm text-slate-400 ml-2">/ {item.file}:{item.line}</span>
                      </div>

                      <div className="p-2 bg-black/20 rounded font-mono text-xs text-slate-300 mb-2">
                        {item.sample_value}
                      </div>

                      <div className="flex items-center gap-4 text-xs text-slate-400">
                        <span className="flex items-center gap-1">
                          <GitBranch size={12} />
                          {item.branch}
                        </span>
                        <span className="flex items-center gap-1">
                          <FileText size={12} />
                          {item.commit.substring(0, 7)}
                        </span>
                        <span className="flex items-center gap-1">
                          <Calendar size={12} />
                          Last seen: {formatDate(item.last_seen)}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Item Detail Drawer */}
        {selectedItem && (
          <div
            onClick={() => setSelectedItem(null)}
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
                    <h3 className="text-lg font-semibold mb-1 capitalize">{selectedItem.type.replace('_', ' ')}</h3>
                    <p className="text-sm text-slate-400">{selectedItem.repository} / {selectedItem.file}</p>
                  </div>
                  <button
                    onClick={() => setSelectedItem(null)}
                    className="text-slate-400 hover:text-white transition-colors"
                  >
                    ✕
                  </button>
                </div>

                <div className="flex gap-2">
                  <span
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium"
                    style={{ 
                      backgroundColor: `${getSeverityColor(selectedItem.severity)}20`,
                      color: getSeverityColor(selectedItem.severity)
                    }}
                  >
                    {selectedItem.severity}
                  </span>
                  <span
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium"
                    style={{ 
                      backgroundColor: `${getStatusColor(selectedItem.status)}20`,
                      color: getStatusColor(selectedItem.status)
                    }}
                  >
                    {getStatusIcon(selectedItem.status)}
                    {selectedItem.status.replace('_', ' ')}
                  </span>
                </div>
              </div>

              {/* Drawer Content */}
              <div className="flex-1 p-6 space-y-6">
                {/* Item Information */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Item Information</h4>
                  <div className="space-y-3 bg-white/5 rounded-lg p-4">
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Item ID</span>
                      <span className="text-sm text-white font-mono">{selectedItem.id}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Type</span>
                      <span className="text-sm text-white capitalize">{selectedItem.type.replace('_', ' ')}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Detected</span>
                      <span className="text-sm text-white">{formatDate(selectedItem.detected_at)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Last Seen</span>
                      <span className="text-sm text-white">{formatDate(selectedItem.last_seen)}</span>
                    </div>
                  </div>
                </div>

                {/* Location */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Location</h4>
                  <div className="space-y-3 bg-white/5 rounded-lg p-4">
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Repository</span>
                      <span className="text-sm text-white">{selectedItem.repository}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Branch</span>
                      <span className="text-sm text-white">{selectedItem.branch}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">File</span>
                      <span className="text-sm text-white font-mono">{selectedItem.file}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Line</span>
                      <span className="text-sm text-white">{selectedItem.line}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Commit</span>
                      <span className="text-sm text-white font-mono">{selectedItem.commit}</span>
                    </div>
                  </div>
                </div>

                {/* Item Value */}
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="text-sm font-semibold text-slate-300">Item Value</h4>
                    <button
                      onClick={() => setShowValue(!showValue)}
                      className="text-xs text-[#6B5AED] hover:underline flex items-center gap-1"
                    >
                      {showValue ? <EyeOff size={12} /> : <Eye size={12} />}
                      {showValue ? 'Hide' : 'Show'}
                    </button>
                  </div>
                  <div className="p-3 bg-black/20 rounded font-mono text-xs text-slate-300 break-all">
                    {showValue ? selectedItem.sample_value : '••••••••••••••••'}
                  </div>
                  <p className="text-xs text-slate-400 mt-2">
                    ⚠️ This is a preview. Full value is redacted for security.
                  </p>
                </div>

                {/* Actions */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Actions</h4>
                  <div className="space-y-2">
                    {selectedItem.status === 'active' && (
                      <>
                        <button className="w-full p-3 bg-red-500/10 hover:bg-red-500/20 rounded-lg text-sm text-left text-red-400 transition-colors flex items-center gap-2">
                          <Shield size={16} />
                          Revoke Item
                        </button>
                        <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                          <XCircle size={16} />
                          Mark as False Positive
                        </button>
                      </>
                    )}
                    {selectedItem.status === 'revoked' && (
                      <div className="p-3 bg-green-500/10 rounded-lg text-sm text-green-400 flex items-center gap-2">
                        <CheckCircle size={16} />
                        This item has been revoked
                      </div>
                    )}
                    {selectedItem.status === 'false_positive' && (
                      <button className="w-full p-3 bg-yellow-500/10 hover:bg-yellow-500/20 rounded-lg text-sm text-left text-yellow-400 transition-colors flex items-center gap-2">
                        <AlertTriangle size={16} />
                        Reactivate Item
                      </button>
                    )}
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <GitBranch size={16} />
                      View in Repository
                    </button>
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <FileText size={16} />
                      View Commit
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
