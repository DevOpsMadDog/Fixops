'use client'

import { useState, useEffect, useMemo } from 'react'
import { Star, Plus, Trash2, Edit2, ArrowLeft, Filter, Clock, Loader2, RefreshCw, WifiOff, X } from 'lucide-react'
import { AppShell, useDemoModeContext } from '@fixops/ui'
import { useFindings } from '@fixops/api-client'

const SAVED_VIEWS = [
  {
    id: 'view1',
    name: 'Critical & KEV',
    description: 'Critical vulnerabilities in CISA KEV catalog',
    filters: {
      severity: ['critical'],
      kev: true,
      internet_facing: null,
      new_7d: null,
    },
    count: 12,
    created: '2024-10-15',
    last_used: '2024-11-21',
    is_default: true,
  },
  {
    id: 'view2',
    name: 'Internet-Facing High/Critical',
    description: 'High and critical issues in internet-facing services',
    filters: {
      severity: ['critical', 'high'],
      kev: null,
      internet_facing: true,
      new_7d: null,
    },
    count: 87,
    created: '2024-09-20',
    last_used: '2024-11-20',
    is_default: false,
  },
  {
    id: 'view3',
    name: 'New This Week',
    description: 'All issues discovered in the last 7 days',
    filters: {
      severity: null,
      kev: null,
      internet_facing: null,
      new_7d: true,
    },
    count: 87,
    created: '2024-08-10',
    last_used: '2024-11-19',
    is_default: false,
  },
  {
    id: 'view4',
    name: 'Payment API Issues',
    description: 'All security findings in payment-api service',
    filters: {
      severity: null,
      kev: null,
      internet_facing: null,
      new_7d: null,
      service: 'payment-api',
    },
    count: 45,
    created: '2024-07-05',
    last_used: '2024-11-18',
    is_default: false,
  },
  {
    id: 'view5',
    name: 'Compliance Gaps',
    description: 'Issues affecting compliance framework controls',
    filters: {
      severity: ['high', 'critical'],
      kev: null,
      internet_facing: null,
      new_7d: null,
      has_compliance_mapping: true,
    },
    count: 156,
    created: '2024-06-12',
    last_used: '2024-11-17',
    is_default: false,
  },
]

export default function SavedViewsPage() {
  const { demoEnabled } = useDemoModeContext()
  const { data: apiData, loading: apiLoading, error: apiError, refetch } = useFindings()
  
  // Transform API data to match our UI format, or use demo data
  const viewsData = useMemo(() => {
    if (demoEnabled || !apiData?.items) {
      return SAVED_VIEWS
    }
    // In real mode, we would fetch saved views from an API
    // For now, return demo data with updated counts from real findings
    return SAVED_VIEWS.map(view => ({
      ...view,
      count: apiData.items.filter(f => {
        if (view.filters.severity && !view.filters.severity.includes(f.severity)) return false
        if (view.filters.kev && !f.kev_listed) return false
        return true
      }).length
    }))
  }, [demoEnabled, apiData])

    const [views, setViews] = useState(SAVED_VIEWS)
    const [selectedView, setSelectedView] = useState<typeof SAVED_VIEWS[0] | null>(null)
    const [isCreating, setIsCreating] = useState(false)
    const [showMobileFilters, setShowMobileFilters] = useState(false)

  // Update views when data source changes
  useEffect(() => {
    setViews(viewsData)
  }, [viewsData])

  const getSeverityColor = (severity: string) => {
    const colors = {
      critical: '#dc2626',
      high: '#f97316',
      medium: '#f59e0b',
      low: '#3b82f6',
    }
    return colors[severity as keyof typeof colors] || colors.low
  }

  return (
    <AppShell activeApp="saved-views">
        <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
          {/* Mobile Filter Overlay */}
          {showMobileFilters && (
            <div className="fixed inset-0 z-50 lg:hidden">
              <div className="absolute inset-0 bg-black/60" onClick={() => setShowMobileFilters(false)} />
              <div className="absolute left-0 top-0 h-full w-80 bg-[#0f172a] border-r border-white/10 flex flex-col overflow-auto">
                <div className="p-4 border-b border-white/10 flex items-center justify-between">
                  <span className="font-semibold">Saved Views</span>
                  <button onClick={() => setShowMobileFilters(false)} className="p-2 hover:bg-white/10 rounded-md">
                    <X size={18} />
                  </button>
                </div>
                <div className="p-4 border-b border-white/10">
                  <button
                    onClick={() => setIsCreating(true)}
                    className="w-full px-4 py-2.5 bg-[#6B5AED] rounded-md text-white text-sm font-medium flex items-center justify-center gap-2 hover:bg-[#5B4ADD] transition-all"
                  >
                    <Plus size={16} />
                    Create New View
                  </button>
                </div>
                <div className="p-4 flex-1 overflow-auto">
                  <div className="space-y-2">
                    {views.map((view) => (
                      <button
                        key={view.id}
                        onClick={() => { setSelectedView(view); setShowMobileFilters(false); }}
                        className={`w-full p-3 rounded-lg text-left transition-all ${selectedView?.id === view.id ? 'bg-[#6B5AED]/10 border border-[#6B5AED]/30' : 'bg-white/5 hover:bg-white/10'}`}
                      >
                        <div className="flex items-center gap-3">
                          <Star size={16} className={view.is_default ? 'text-amber-400 fill-amber-400' : 'text-slate-500'} />
                          <div className="flex-1 min-w-0">
                            <div className="font-medium text-sm truncate">{view.name}</div>
                            <div className="text-xs text-slate-500">{view.count} findings</div>
                          </div>
                        </div>
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Left Sidebar - Views List */}
          <div className="hidden lg:flex w-80 bg-[#0f172a]/80 border-r border-white/10 flex-col sticky top-0 h-screen">
        {/* Header */}
        <div className="p-6 border-b border-white/10">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-[#6B5AED]">Saved Views</h2>
            <button
              onClick={() => window.location.href = '/triage'}
              className="p-2 rounded-md border border-white/10 text-slate-400 hover:bg-white/5 transition-all"
              title="Back to Triage"
            >
              <ArrowLeft size={16} />
            </button>
          </div>
          <p className="text-xs text-slate-500">Custom filters and queries</p>
        </div>

        {/* Create New Button */}
        <div className="p-4 border-b border-white/10">
          <button
            onClick={() => setIsCreating(true)}
            className="w-full px-4 py-2.5 bg-[#6B5AED] rounded-md text-white text-sm font-medium flex items-center justify-center gap-2 hover:bg-[#5B4ADD] transition-all"
          >
            <Plus size={16} />
            Create New View
          </button>
        </div>

        {/* Views List */}
        <div className="p-4 flex-1 overflow-auto">
          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">
            My Views ({SAVED_VIEWS.length})
          </div>
          <div className="space-y-2">
            {SAVED_VIEWS.map((view) => (
              <button
                key={view.id}
                onClick={() => setSelectedView(view)}
                className={`w-full p-3 rounded-md text-left transition-all ${
                  selectedView?.id === view.id
                    ? 'bg-[#6B5AED]/10 border border-[#6B5AED]/30'
                    : 'bg-white/5 border border-white/10 hover:bg-white/10'
                }`}
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-2">
                    {view.is_default && <Star size={14} className="text-amber-500 fill-amber-500" />}
                    <span className="text-sm font-semibold text-white">{view.name}</span>
                  </div>
                  <span className="text-xs font-semibold text-[#6B5AED]">{view.count}</span>
                </div>
                <p className="text-xs text-slate-400 mb-2">{view.description}</p>
                <div className="flex items-center gap-2 text-[10px] text-slate-500">
                  <Clock size={10} />
                  Used {new Date(view.last_used).toLocaleDateString()}
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

            {/* Main Content */}
            <div className="flex-1 flex flex-col min-w-0">
              {/* Top Bar */}
              <div className="p-4 lg:p-5 border-b border-white/10 bg-[#0f172a]/80 backdrop-blur-sm">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    {/* Mobile Filter Toggle */}
                    <button
                      onClick={() => setShowMobileFilters(true)}
                      className="lg:hidden p-2 bg-white/5 border border-white/10 rounded-md hover:bg-white/10 transition-colors"
                    >
                      <Filter size={18} />
                    </button>
                    <div>
                    <h1 className="text-xl lg:text-2xl font-semibold mb-1">
                      {selectedView ? selectedView.name : 'Saved Views'}
                    </h1>
                          <p className="text-sm text-slate-500">
                            {selectedView ? selectedView.description : 'Select a view to see details'}
                          </p>
                        </div>
                        </div>
                        {selectedView && (
              <div className="flex gap-2">
                <button
                  onClick={() => window.location.href = `/triage?view=${selectedView.id}`}
                  className="px-4 py-2 bg-[#6B5AED] rounded-md text-white text-sm font-medium hover:bg-[#5B4ADD] transition-all"
                >
                  Apply View
                </button>
                <button className="px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all">
                  <Edit2 size={14} />
                </button>
                <button className="px-4 py-2 bg-white/5 border border-white/10 rounded-md text-red-400 text-sm font-medium hover:bg-red-500/10 transition-all">
                  <Trash2 size={14} />
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-auto p-6">
          {!selectedView && !isCreating ? (
            /* Empty State */
            <div className="flex items-center justify-center h-full">
              <div className="text-center max-w-md">
                <Filter size={48} className="text-slate-600 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-white mb-2">No View Selected</h3>
                <p className="text-sm text-slate-400 mb-6">
                  Select a saved view from the sidebar or create a new one to get started.
                </p>
                <button
                  onClick={() => setIsCreating(true)}
                  className="px-4 py-2 bg-[#6B5AED] rounded-md text-white text-sm font-medium hover:bg-[#5B4ADD] transition-all"
                >
                  Create New View
                </button>
              </div>
            </div>
          ) : isCreating ? (
            /* Create View Form */
            <div className="max-w-3xl mx-auto">
              <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                <h3 className="text-lg font-semibold mb-6">Create New View</h3>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      View Name
                    </label>
                    <input
                      type="text"
                      placeholder="e.g., Critical Internet-Facing Issues"
                      className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      Description
                    </label>
                    <textarea
                      placeholder="Describe what this view shows..."
                      rows={3}
                      className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                    />
                  </div>

                  <div className="border-t border-white/10 pt-4">
                    <h4 className="text-sm font-semibold text-slate-300 mb-4">Filters</h4>
                    
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-slate-300 mb-2">
                          Severity
                        </label>
                        <div className="flex gap-2">
                          {['critical', 'high', 'medium', 'low'].map((severity) => (
                            <label
                              key={severity}
                              className="flex items-center gap-2 px-3 py-2 bg-white/5 border border-white/10 rounded-md cursor-pointer hover:bg-white/10 transition-all"
                            >
                              <input type="checkbox" className="cursor-pointer" />
                              <span
                                className="text-xs font-semibold uppercase tracking-wider"
                                style={{ color: getSeverityColor(severity) }}
                              >
                                {severity}
                              </span>
                            </label>
                          ))}
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-4">
                        <label className="flex items-center gap-2 p-3 bg-white/5 border border-white/10 rounded-md cursor-pointer hover:bg-white/10 transition-all">
                          <input type="checkbox" className="cursor-pointer" />
                          <span className="text-sm text-slate-300">KEV Only</span>
                        </label>
                        <label className="flex items-center gap-2 p-3 bg-white/5 border border-white/10 rounded-md cursor-pointer hover:bg-white/10 transition-all">
                          <input type="checkbox" className="cursor-pointer" />
                          <span className="text-sm text-slate-300">Internet-Facing</span>
                        </label>
                        <label className="flex items-center gap-2 p-3 bg-white/5 border border-white/10 rounded-md cursor-pointer hover:bg-white/10 transition-all">
                          <input type="checkbox" className="cursor-pointer" />
                          <span className="text-sm text-slate-300">New (7 days)</span>
                        </label>
                        <label className="flex items-center gap-2 p-3 bg-white/5 border border-white/10 rounded-md cursor-pointer hover:bg-white/10 transition-all">
                          <input type="checkbox" className="cursor-pointer" />
                          <span className="text-sm text-slate-300">Has Compliance Mapping</span>
                        </label>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-slate-300 mb-2">
                          Service (optional)
                        </label>
                        <input
                          type="text"
                          placeholder="e.g., payment-api"
                          className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                        />
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-slate-300 mb-2">
                          Min EPSS Score (optional)
                        </label>
                        <input
                          type="number"
                          min="0"
                          max="1"
                          step="0.01"
                          placeholder="0.0 - 1.0"
                          className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                        />
                      </div>
                    </div>
                  </div>

                  <div className="flex gap-3 pt-4">
                    <button
                      onClick={() => setIsCreating(false)}
                      className="flex-1 px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all"
                    >
                      Cancel
                    </button>
                    <button className="flex-1 px-4 py-2 bg-[#6B5AED] rounded-md text-white text-sm font-medium hover:bg-[#5B4ADD] transition-all">
                      Create View
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ) : selectedView ? (
            /* View Details */
            <div className="max-w-4xl mx-auto space-y-6">
              {/* View Info */}
              <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      {selectedView.is_default && (
                        <Star size={18} className="text-amber-500 fill-amber-500" />
                      )}
                      <h3 className="text-xl font-semibold">{selectedView.name}</h3>
                    </div>
                    <p className="text-sm text-slate-400">{selectedView.description}</p>
                  </div>
                  <div className="text-right">
                    <div className="text-3xl font-bold text-[#6B5AED] mb-1">{selectedView.count}</div>
                    <div className="text-xs text-slate-500">matching issues</div>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4 mt-4 pt-4 border-t border-white/10">
                  <div>
                    <div className="text-xs text-slate-500 mb-1">Created</div>
                    <div className="text-sm text-slate-300">
                      {new Date(selectedView.created).toLocaleDateString()}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 mb-1">Last Used</div>
                    <div className="text-sm text-slate-300">
                      {new Date(selectedView.last_used).toLocaleDateString()}
                    </div>
                  </div>
                </div>
              </div>

              {/* Active Filters */}
              <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                <h4 className="text-sm font-semibold text-slate-300 mb-4">Active Filters</h4>
                <div className="flex flex-wrap gap-2">
                  {selectedView.filters.severity && selectedView.filters.severity.map((sev) => (
                    <span
                      key={sev}
                      className="px-3 py-1.5 bg-white/5 border border-white/10 rounded-md text-xs font-semibold uppercase tracking-wider"
                      style={{ color: getSeverityColor(sev) }}
                    >
                      {sev}
                    </span>
                  ))}
                  {selectedView.filters.kev && (
                    <span className="px-3 py-1.5 bg-amber-500/20 border border-amber-500/30 rounded-md text-xs font-semibold text-amber-300">
                      KEV Only
                    </span>
                  )}
                  {selectedView.filters.internet_facing && (
                    <span className="px-3 py-1.5 bg-red-500/20 border border-red-500/30 rounded-md text-xs font-semibold text-red-300">
                      Internet-Facing
                    </span>
                  )}
                  {selectedView.filters.new_7d && (
                    <span className="px-3 py-1.5 bg-blue-500/20 border border-blue-500/30 rounded-md text-xs font-semibold text-blue-300">
                      New (7 days)
                    </span>
                  )}
                  {selectedView.filters.service && (
                    <span className="px-3 py-1.5 bg-purple-500/20 border border-purple-500/30 rounded-md text-xs font-semibold text-purple-300 font-mono">
                      Service: {selectedView.filters.service}
                    </span>
                  )}
                  {selectedView.filters.has_compliance_mapping && (
                    <span className="px-3 py-1.5 bg-green-500/20 border border-green-500/30 rounded-md text-xs font-semibold text-green-300">
                      Has Compliance Mapping
                    </span>
                  )}
                </div>
              </div>

              {/* Quick Actions */}
              <div className="grid grid-cols-2 gap-4">
                <button
                  onClick={() => window.location.href = `/triage?view=${selectedView.id}`}
                  className="p-4 bg-[#6B5AED]/10 border border-[#6B5AED]/30 rounded-md hover:bg-[#6B5AED]/20 transition-all text-left"
                >
                  <div className="text-sm font-semibold text-[#6B5AED] mb-1">Apply to Triage</div>
                  <div className="text-xs text-slate-400">View {selectedView.count} matching issues</div>
                </button>
                <button
                  onClick={() => setIsCreating(true)}
                  className="p-4 bg-white/5 border border-white/10 rounded-md hover:bg-white/10 transition-all text-left"
                >
                  <div className="text-sm font-semibold text-white mb-1">Duplicate View</div>
                  <div className="text-xs text-slate-400">Create a copy with these filters</div>
                </button>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
    </AppShell>
  )
}
