'use client'

import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { FileText, Search, Plus, Download, Calendar, Clock, Filter, Play, Edit2, Trash2, CheckCircle, XCircle, RefreshCw, Settings, ToggleLeft, ToggleRight } from 'lucide-react'
import { AppShell } from '@fixops/ui'
import { useReports, useSystemMode, useReportDownload } from '@fixops/api-client'

// Fallback demo data for when API is unavailable
const FALLBACK_REPORTS = [
  {
    id: 'demo-1',
    name: 'Weekly Security Summary',
    description: 'Weekly summary of security findings and remediation progress',
    type: 'security',
    format: 'PDF',
    schedule: 'weekly',
    recipients: ['security-team@fixops.io', 'cto@fixops.io'],
    last_generated: '2024-11-18T09:00:00Z',
    next_scheduled: '2024-11-25T09:00:00Z',
    status: 'active',
    created_at: '2024-01-15T10:00:00Z',
  },
  {
    id: 'demo-2',
    name: 'Compliance Audit Report',
    description: 'SOC2 and ISO27001 compliance status and gaps',
    type: 'compliance',
    format: 'HTML',
    schedule: 'monthly',
    recipients: ['compliance@fixops.io', 'audit@fixops.io'],
    last_generated: '2024-11-01T08:00:00Z',
    next_scheduled: '2024-12-01T08:00:00Z',
    status: 'active',
    created_at: '2024-02-01T14:30:00Z',
  },
  {
    id: 'demo-3',
    name: 'Critical Vulnerabilities Report',
    description: 'All critical and high severity vulnerabilities with KEV status',
    type: 'security',
    format: 'JSON',
    schedule: 'daily',
    recipients: ['security-team@fixops.io'],
    last_generated: '2024-11-22T06:00:00Z',
    next_scheduled: '2024-11-23T06:00:00Z',
    status: 'active',
    created_at: '2024-03-10T09:00:00Z',
  },
  {
    id: 'demo-4',
    name: 'SARIF Export for CI/CD',
    description: 'SARIF format export for integration with CI/CD pipelines',
    type: 'integration',
    format: 'SARIF',
    schedule: 'on_demand',
    recipients: [],
    last_generated: '2024-11-21T15:30:00Z',
    next_scheduled: null,
    status: 'active',
    created_at: '2024-04-05T11:20:00Z',
  },
  {
    id: 'demo-5',
    name: 'Executive Dashboard',
    description: 'High-level metrics and trends for executive leadership',
    type: 'executive',
    format: 'PDF',
    schedule: 'monthly',
    recipients: ['ceo@fixops.io', 'cto@fixops.io', 'ciso@fixops.io'],
    last_generated: '2024-11-01T10:00:00Z',
    next_scheduled: '2024-12-01T10:00:00Z',
    status: 'active',
    created_at: '2024-05-12T13:45:00Z',
  },
  {
    id: 'demo-6',
    name: 'Team Performance Report',
    description: 'Team-level metrics for remediation velocity and SLA compliance',
    type: 'operational',
    format: 'CSV',
    schedule: 'weekly',
    recipients: ['team-leads@fixops.io'],
    last_generated: '2024-11-18T10:00:00Z',
    next_scheduled: '2024-11-25T10:00:00Z',
    status: 'active',
    created_at: '2024-06-18T15:10:00Z',
  },
  {
    id: 'demo-7',
    name: 'Secrets Detection Report',
    description: 'All detected secrets and credentials in code repositories',
    type: 'security',
    format: 'HTML',
    schedule: 'on_demand',
    recipients: ['security-team@fixops.io'],
    last_generated: '2024-11-20T14:00:00Z',
    next_scheduled: null,
    status: 'paused',
    created_at: '2024-07-22T08:30:00Z',
  },
  {
    id: 'demo-8',
    name: 'IaC Security Findings',
    description: 'Infrastructure as Code security misconfigurations',
    type: 'security',
    format: 'JSON',
    schedule: 'daily',
    recipients: ['infra-team@fixops.io', 'security-team@fixops.io'],
    last_generated: '2024-11-22T05:00:00Z',
    next_scheduled: '2024-11-23T05:00:00Z',
    status: 'active',
    created_at: '2024-08-30T10:15:00Z',
  },
]

interface Report {
  id: string
  name: string
  description?: string
  type?: string
  report_type?: string
  format: string
  schedule?: string
  recipients?: string[]
  last_generated?: string
  next_scheduled?: string | null
  status: string
  created_at: string
  file_path?: string
  file_size?: number
}

export default function ReportsPage() {
  // API hooks
  const { data: apiReports, loading: apiLoading, error: apiError, refetch } = useReports()
  const { mode, toggleMode, loading: modeLoading } = useSystemMode()
  const { downloadReport: download, downloading } = useReportDownload()

  // Transform API data to match UI format
  const transformReport = useCallback((r: Record<string, unknown>): Report => ({
    id: String(r.id || ''),
    name: String(r.name || ''),
    description: String(r.description || `${r.report_type || r.type || 'General'} report`),
    type: String(r.report_type || r.type || 'security'),
    format: String(r.format || 'PDF').toUpperCase(),
    schedule: String(r.schedule || 'on_demand'),
    recipients: Array.isArray(r.recipients) ? r.recipients.map(String) : [],
    last_generated: r.completed_at ? String(r.completed_at) : r.last_generated ? String(r.last_generated) : undefined,
    next_scheduled: r.next_scheduled ? String(r.next_scheduled) : null,
    status: String(r.status || 'active'),
    created_at: String(r.created_at || new Date().toISOString()),
    file_path: r.file_path ? String(r.file_path) : undefined,
    file_size: typeof r.file_size === 'number' ? r.file_size : undefined,
  }), [])

  // Use API data if available, otherwise use fallback - memoized to prevent unnecessary re-renders
  const reports = useMemo(() => 
    apiReports?.items?.map(transformReport) || FALLBACK_REPORTS,
    [apiReports?.items, transformReport]
  )
  const [filteredReports, setFilteredReports] = useState<Report[]>(reports)
  const [selectedReport, setSelectedReport] = useState<Report | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [formatFilter, setFormatFilter] = useState<string>('all')
  const [scheduleFilter, setScheduleFilter] = useState<string>('all')
  const [showCreateModal, setShowCreateModal] = useState(false)

  // Refresh data when mode changes - using ref to track if this is initial mount
  const isInitialMount = useRef(true)
  useEffect(() => {
    if (isInitialMount.current) {
      isInitialMount.current = false
      return // Skip initial mount since useApi already fetches on mount
    }
    refetch()
  }, [mode, refetch])

  // Sync filtered reports when API data changes
  useEffect(() => {
    setFilteredReports(reports)
  }, [reports])

  // Handle report download
  const handleDownload = async (reportId: string, reportName: string, reportFormat: string) => {
    try {
      const extension = reportFormat.toLowerCase()
      await download(reportId, `${reportName.replace(/\s+/g, '_')}.${extension}`)
    } catch (err) {
      console.error('Download failed:', err)
      alert('Download failed. Please try again.')
    }
  }

  const getTypeColor = (type: string | undefined) => {
    const colors = {
      security: '#dc2626',
      compliance: '#10b981',
      executive: '#8b5cf6',
      operational: '#3b82f6',
      integration: '#6b7280',
    }
    return colors[(type || 'integration') as keyof typeof colors] || colors.integration
  }

  const getFormatColor = (format: string | undefined) => {
    const colors = {
      PDF: '#dc2626',
      HTML: '#f97316',
      JSON: '#3b82f6',
      CSV: '#10b981',
      SARIF: '#8b5cf6',
    }
    return colors[(format || 'JSON') as keyof typeof colors] || colors.JSON
  }

  const formatDate = (isoString: string | null | undefined) => {
    if (!isoString) return 'N/A'
    const date = new Date(isoString)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60))
    
    if (diffHours < 1) return 'Just now'
    if (diffHours < 24) return `${diffHours}h ago`
    const diffDays = Math.floor(diffHours / 24)
    if (diffDays < 7) return `${diffDays}d ago`
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
  }

  // Use useEffect to apply filters whenever filter state changes
  useEffect(() => {
    let filtered = [...reports]

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(report =>
        report.name.toLowerCase().includes(query) ||
        (report.description?.toLowerCase().includes(query) ?? false)
      )
    }

    if (typeFilter !== 'all') {
      filtered = filtered.filter(report => report.type === typeFilter)
    }

    if (formatFilter !== 'all') {
      filtered = filtered.filter(report => report.format === formatFilter)
    }

    if (scheduleFilter !== 'all') {
      filtered = filtered.filter(report => report.schedule === scheduleFilter)
    }

    setFilteredReports(filtered)
  }, [reports, searchQuery, typeFilter, formatFilter, scheduleFilter])

  const summary = {
    total: reports.length,
    active: reports.filter(r => r.status === 'active').length,
    paused: reports.filter(r => r.status === 'paused').length,
    scheduled: reports.filter(r => r.schedule !== 'on_demand').length,
    on_demand: reports.filter(r => r.schedule === 'on_demand').length,
  }

  return (
    <AppShell activeApp="reports">
      <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
        {/* Left Sidebar - Filters */}
        <div className="w-72 bg-[#0f172a]/80 border-r border-white/10 flex flex-col sticky top-0 h-screen">
          {/* Header */}
          <div className="p-6 border-b border-white/10">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <FileText size={24} className="text-[#6B5AED]" />
                <h2 className="text-lg font-semibold">Reports</h2>
              </div>
              <button
                onClick={refetch}
                disabled={apiLoading}
                className="p-2 hover:bg-white/10 rounded-md transition-colors"
                title="Refresh reports"
              >
                <RefreshCw size={16} className={apiLoading ? 'animate-spin' : ''} />
              </button>
            </div>
            <p className="text-xs text-slate-500 mb-3">Generate and schedule reports</p>
            
            {/* Mode Toggle */}
            <div className="flex items-center justify-between p-2 bg-white/5 rounded-md">
              <span className="text-xs text-slate-400">Mode:</span>
              <button
                onClick={toggleMode}
                disabled={modeLoading}
                className="flex items-center gap-2 text-xs font-medium"
              >
                {mode === 'demo' ? (
                  <>
                    <ToggleLeft size={18} className="text-orange-400" />
                    <span className="text-orange-400">Demo</span>
                  </>
                ) : (
                  <>
                    <ToggleRight size={18} className="text-green-400" />
                    <span className="text-green-400">Enterprise</span>
                  </>
                )}
              </button>
            </div>
            {apiError && (
              <div className="mt-2 p-2 bg-red-500/10 rounded-md text-xs text-red-400">
                API unavailable - showing demo data
              </div>
            )}
          </div>

          {/* Summary Stats */}
          <div className="p-4 border-b border-white/10">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Total Reports</div>
                <div className="text-xl font-semibold text-[#6B5AED]">{summary.total}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Active</div>
                <div className="text-xl font-semibold text-green-500">{summary.active}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Scheduled</div>
                <div className="text-xl font-semibold text-blue-500">{summary.scheduled}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">On-Demand</div>
                <div className="text-xl font-semibold text-orange-500">{summary.on_demand}</div>
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
                {['all', 'security', 'compliance', 'executive', 'operational', 'integration'].map((type) => (
                  <button
                    key={type}
                    onClick={() => setTypeFilter(type)}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      typeFilter === type
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="capitalize">{type}</span>
                    {type !== 'all' && (
                      <span className="ml-2 text-xs">
                        ({reports.filter(r => r.type === type).length})
                      </span>
                    )}
                    {type === 'all' && (
                      <span className="ml-2 text-xs">({reports.length})</span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            <div className="mb-6">
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Filter size={12} />
                Filter by Format
              </div>
              <div className="space-y-2">
                {['all', 'PDF', 'HTML', 'JSON', 'CSV', 'SARIF'].map((format) => (
                  <button
                    key={format}
                    onClick={() => setFormatFilter(format)}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      formatFilter === format
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    {format}
                    {format !== 'all' && (
                      <span className="ml-2 text-xs">
                        ({reports.filter(r => r.format === format).length})
                      </span>
                    )}
                    {format === 'all' && (
                      <span className="ml-2 text-xs">({reports.length})</span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Clock size={12} />
                Filter by Schedule
              </div>
              <div className="space-y-2">
                {['all', 'daily', 'weekly', 'monthly', 'on_demand'].map((schedule) => (
                  <button
                    key={schedule}
                    onClick={() => setScheduleFilter(schedule)}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      scheduleFilter === schedule
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="capitalize">{schedule.replace('_', ' ')}</span>
                    {schedule !== 'all' && (
                      <span className="ml-2 text-xs">
                        ({reports.filter(r => r.schedule === schedule).length})
                      </span>
                    )}
                    {schedule === 'all' && (
                      <span className="ml-2 text-xs">({reports.length})</span>
                    )}
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
                <h1 className="text-2xl font-semibold mb-1">Reports</h1>
                <p className="text-sm text-slate-500">
                  Showing {filteredReports.length} report{filteredReports.length !== 1 ? 's' : ''}
                </p>
              </div>
              <button
                onClick={() => setShowCreateModal(true)}
                className="px-4 py-2 bg-[#6B5AED] hover:bg-[#5B4ADD] rounded-md text-white text-sm font-medium transition-all flex items-center gap-2"
              >
                <Plus size={16} />
                Create Report
              </button>
            </div>

            {/* Search Bar */}
            <div className="relative">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search by name or description..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-[#6B5AED]/50"
              />
            </div>
          </div>

          {/* Reports Grid */}
          <div className="flex-1 overflow-auto p-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {filteredReports.map((report) => (
                <div
                  key={report.id}
                  onClick={() => setSelectedReport(report)}
                  className="bg-white/2 border border-white/5 rounded-lg p-5 hover:bg-white/5 hover:border-[#6B5AED]/30 cursor-pointer transition-all"
                >
                  {/* Header */}
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-[#6B5AED]/20 flex items-center justify-center">
                        <FileText size={20} className="text-[#6B5AED]" />
                      </div>
                      <div>
                        <h3 className="text-sm font-semibold text-white">{report.name}</h3>
                        <p className="text-xs text-slate-400">{(report.schedule || 'on_demand').replace('_', ' ')}</p>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <span
                        className="px-2 py-1 rounded text-xs font-medium"
                        style={{ 
                          backgroundColor: `${getFormatColor(report.format)}20`,
                          color: getFormatColor(report.format)
                        }}
                      >
                        {report.format}
                      </span>
                    </div>
                  </div>

                  {/* Description */}
                  <p className="text-sm text-slate-300 mb-4">{report.description}</p>

                  {/* Type Badge */}
                  <div className="mb-4">
                    <span
                      className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium"
                      style={{ 
                        backgroundColor: `${getTypeColor(report.type || 'compliance')}20`,
                        color: getTypeColor(report.type || 'compliance')
                      }}
                    >
                      {report.type || 'compliance'}
                    </span>
                  </div>

                  {/* Stats */}
                  <div className="grid grid-cols-2 gap-3 mb-4">
                    <div className="p-3 bg-white/5 rounded-lg">
                      <div className="text-xs text-slate-400 mb-1">Last Generated</div>
                      <div className="text-sm text-white">{formatDate(report.last_generated)}</div>
                    </div>
                    <div className="p-3 bg-white/5 rounded-lg">
                      <div className="text-xs text-slate-400 mb-1">Next Scheduled</div>
                      <div className="text-sm text-white">{formatDate(report.next_scheduled)}</div>
                    </div>
                  </div>

                  {/* Footer */}
                  <div className="flex items-center justify-between pt-3 border-t border-white/5">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${report.status === 'active' ? 'bg-green-500' : 'bg-gray-500'}`} />
                      <span className="text-xs text-slate-400 capitalize">{report.status}</span>
                    </div>
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        alert(`Generating ${report.name}...`)
                      }}
                      className="text-xs text-[#6B5AED] hover:underline flex items-center gap-1"
                    >
                      <Play size={12} />
                      Generate Now
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Report Detail Drawer */}
        {selectedReport && (
          <div
            onClick={() => setSelectedReport(null)}
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
                    <h3 className="text-lg font-semibold mb-1">{selectedReport.name}</h3>
                    <p className="text-sm text-slate-400">{selectedReport.description}</p>
                  </div>
                  <button
                    onClick={() => setSelectedReport(null)}
                    className="text-slate-400 hover:text-white transition-colors"
                  >
                    ✕
                  </button>
                </div>

                <div className="flex gap-2">
                  <span
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium"
                    style={{ 
                      backgroundColor: `${getTypeColor(selectedReport.type)}20`,
                      color: getTypeColor(selectedReport.type)
                    }}
                  >
                    {selectedReport.type}
                  </span>
                  <span
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium"
                    style={{ 
                      backgroundColor: `${getFormatColor(selectedReport.format)}20`,
                      color: getFormatColor(selectedReport.format)
                    }}
                  >
                    {selectedReport.format}
                  </span>
                  <span className={`inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium ${
                    selectedReport.status === 'active' ? 'bg-green-500/10 text-green-500' : 'bg-gray-500/10 text-gray-500'
                  }`}>
                    {selectedReport.status === 'active' ? <CheckCircle size={14} /> : <XCircle size={14} />}
                    {selectedReport.status}
                  </span>
                </div>
              </div>

              {/* Drawer Content */}
              <div className="flex-1 p-6 space-y-6">
                {/* Report Information */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Report Information</h4>
                  <div className="space-y-3 bg-white/5 rounded-lg p-4">
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Report ID</span>
                      <span className="text-sm text-white font-mono">{selectedReport.id}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Schedule</span>
                      <span className="text-sm text-white capitalize">{(selectedReport.schedule || 'on_demand').replace('_', ' ')}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Last Generated</span>
                      <span className="text-sm text-white">{formatDate(selectedReport.last_generated)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Next Scheduled</span>
                      <span className="text-sm text-white">{formatDate(selectedReport.next_scheduled)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Created</span>
                      <span className="text-sm text-white">{formatDate(selectedReport.created_at)}</span>
                    </div>
                  </div>
                </div>

                {/* Recipients */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Recipients</h4>
                  {(selectedReport.recipients?.length || 0) > 0 ? (
                    <div className="space-y-2">
                      {(selectedReport.recipients || []).map((recipient, idx) => (
                        <div key={idx} className="p-3 bg-white/5 rounded-lg flex items-center justify-between">
                          <span className="text-sm text-white">{recipient}</span>
                          <button className="text-xs text-slate-400 hover:text-white transition-colors">
                            Remove
                          </button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-4 bg-white/5 rounded-lg text-center text-sm text-slate-400">
                      No recipients configured (on-demand report)
                    </div>
                  )}
                </div>

                {/* Actions */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Actions</h4>
                  <div className="space-y-2">
                    <button
                      onClick={() => alert(`Generating ${selectedReport.name}...`)}
                      className="w-full p-3 bg-[#6B5AED]/10 hover:bg-[#6B5AED]/20 rounded-lg text-sm text-left text-[#6B5AED] transition-colors flex items-center gap-2"
                    >
                      <Play size={16} />
                      Generate Now
                    </button>
                    <button 
                      onClick={() => handleDownload(selectedReport.id, selectedReport.name, selectedReport.format)}
                      disabled={downloading}
                      className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2 disabled:opacity-50"
                    >
                      <Download size={16} className={downloading ? 'animate-pulse' : ''} />
                      {downloading ? 'Downloading...' : 'Download Last Report'}
                    </button>
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <Edit2 size={16} />
                      Edit Report
                    </button>
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <Calendar size={16} />
                      Change Schedule
                    </button>
                    {selectedReport.status === 'active' ? (
                      <button className="w-full p-3 bg-yellow-500/10 hover:bg-yellow-500/20 rounded-lg text-sm text-left text-yellow-400 transition-colors flex items-center gap-2">
                        <XCircle size={16} />
                        Pause Report
                      </button>
                    ) : (
                      <button className="w-full p-3 bg-green-500/10 hover:bg-green-500/20 rounded-lg text-sm text-left text-green-400 transition-colors flex items-center gap-2">
                        <CheckCircle size={16} />
                        Resume Report
                      </button>
                    )}
                    <button className="w-full p-3 bg-red-500/10 hover:bg-red-500/20 rounded-lg text-sm text-left text-red-400 transition-colors flex items-center gap-2">
                      <Trash2 size={16} />
                      Delete Report
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
