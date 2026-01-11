'use client'

import { useState, useEffect, useMemo } from 'react'
import { Layers, Search, Filter, CheckSquare, XSquare, UserPlus, Tag, Calendar, Download, Upload, AlertTriangle, CheckCircle, Loader2, RefreshCw, WifiOff } from 'lucide-react'
import { AppShell, useDemoModeContext } from '@fixops/ui'
import { useFindings } from '@fixops/api-client'

const DEMO_FINDINGS = [
  {
    id: '1',
    title: 'Apache Struts Remote Code Execution (CVE-2023-50164)',
    severity: 'critical',
    source: 'CVE',
    service: 'payment-api',
    assignee: null as string | null,
    tags: [] as string[],
    status: 'open',
    selected: false,
  },
  {
    id: '2',
    title: 'SQL Injection in User Authentication',
    severity: 'high',
    source: 'SAST',
    service: 'user-service',
    assignee: null,
    tags: [],
    status: 'open',
    selected: false,
  },
  {
    id: '3',
    title: 'Hardcoded AWS Credentials',
    severity: 'critical',
    source: 'IaC',
    service: 'infrastructure',
    assignee: null,
    tags: [],
    status: 'open',
    selected: false,
  },
  {
    id: '4',
    title: 'Cross-Site Scripting (XSS) in Dashboard',
    severity: 'medium',
    source: 'SAST',
    service: 'web-dashboard',
    assignee: null,
    tags: [],
    status: 'open',
    selected: false,
  },
  {
    id: '5',
    title: 'Insecure Deserialization',
    severity: 'high',
    source: 'SAST',
    service: 'api-gateway',
    assignee: null,
    tags: [],
    status: 'open',
    selected: false,
  },
  {
    id: '6',
    title: 'Missing Authentication on Admin Endpoint',
    severity: 'critical',
    source: 'SAST',
    service: 'admin-panel',
    assignee: null,
    tags: [],
    status: 'open',
    selected: false,
  },
  {
    id: '7',
    title: 'Outdated OpenSSL Library',
    severity: 'high',
    source: 'CVE',
    service: 'payment-api',
    assignee: null,
    tags: [],
    status: 'open',
    selected: false,
  },
  {
    id: '8',
    title: 'S3 Bucket Public Access Enabled',
    severity: 'high',
    source: 'IaC',
    service: 'infrastructure',
    assignee: null,
    tags: [],
    status: 'open',
    selected: false,
  },
]

export default function BulkOperationsPage() {
  const { demoEnabled } = useDemoModeContext()
  const { data: apiData, loading: apiLoading, error: apiError, refetch } = useFindings()
  
  // Transform API data to match our UI format, or use demo data
  const findingsData = useMemo(() => {
    if (demoEnabled || !apiData?.items) {
      return DEMO_FINDINGS
    }
    return apiData.items.map(finding => ({
      id: finding.id,
      title: finding.title,
      severity: finding.severity || 'medium',
      source: finding.source || 'CVE',
      service: finding.service || 'unknown',
      assignee: finding.assignee || null,
      tags: finding.tags || [],
      status: finding.status || 'open',
      selected: false,
    }))
  }, [demoEnabled, apiData])

  const [findings, setFindings] = useState(DEMO_FINDINGS)
  const [filteredFindings, setFilteredFindings] = useState(DEMO_FINDINGS)
  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [sourceFilter, setSourceFilter] = useState<string>('all')
  const [selectAll, setSelectAll] = useState(false)
  const [bulkAction, setBulkAction] = useState<string>('')
  const [showAssignModal, setShowAssignModal] = useState(false)
  const [showTagModal, setShowTagModal] = useState(false)
  const [showExportModal, setShowExportModal] = useState(false)

  // Update findings when data source changes
  useEffect(() => {
    setFindings(findingsData)
    setFilteredFindings(findingsData)
  }, [findingsData])

  const getSeverityColor = (severity: string) => {
    const colors = {
      critical: '#dc2626',
      high: '#f97316',
      medium: '#eab308',
      low: '#10b981',
    }
    return colors[severity as keyof typeof colors] || colors.low
  }

  const applyFilters = () => {
    let filtered = [...findings]

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(finding =>
        finding.title.toLowerCase().includes(query) ||
        finding.service.toLowerCase().includes(query)
      )
    }

    if (severityFilter !== 'all') {
      filtered = filtered.filter(finding => finding.severity === severityFilter)
    }

    if (sourceFilter !== 'all') {
      filtered = filtered.filter(finding => finding.source === sourceFilter)
    }

    setFilteredFindings(filtered)
  }

  useState(() => {
    applyFilters()
  })

  const handleSelectAll = () => {
    const newSelectAll = !selectAll
    setSelectAll(newSelectAll)
    setFindings(findings.map(f => ({ ...f, selected: newSelectAll })))
    setFilteredFindings(filteredFindings.map(f => ({ ...f, selected: newSelectAll })))
  }

  const handleSelectFinding = (id: string) => {
    const updatedFindings = findings.map(f =>
      f.id === id ? { ...f, selected: !f.selected } : f
    )
    setFindings(updatedFindings)
    setFilteredFindings(filteredFindings.map(f =>
      f.id === id ? { ...f, selected: !f.selected } : f
    ))
    setSelectAll(updatedFindings.every(f => f.selected))
  }

  const selectedCount = findings.filter(f => f.selected).length

  const handleBulkAssign = (assignee: string) => {
    const updatedFindings = findings.map(f =>
      f.selected ? { ...f, assignee, selected: false } : f
    )
    setFindings(updatedFindings)
    setFilteredFindings(filteredFindings.map(f =>
      f.selected ? { ...f, assignee, selected: false } : f
    ))
    setSelectAll(false)
    setShowAssignModal(false)
    alert(`Assigned ${selectedCount} findings to ${assignee}`)
  }

  const handleBulkTag = (tag: string) => {
    const updatedFindings = findings.map(f =>
      f.selected ? { ...f, tags: [...f.tags, tag], selected: false } : f
    )
    setFindings(updatedFindings)
    setFilteredFindings(filteredFindings.map(f =>
      f.selected ? { ...f, tags: [...f.tags, tag], selected: false } : f
    ))
    setSelectAll(false)
    setShowTagModal(false)
    alert(`Added tag "${tag}" to ${selectedCount} findings`)
  }

  const handleBulkAcceptRisk = () => {
    if (confirm(`Accept risk for ${selectedCount} findings?`)) {
      const updatedFindings = findings.map(f =>
        f.selected ? { ...f, status: 'accepted', selected: false } : f
      )
      setFindings(updatedFindings)
      setFilteredFindings(filteredFindings.map(f =>
        f.selected ? { ...f, status: 'accepted', selected: false } : f
      ))
      setSelectAll(false)
      alert(`Accepted risk for ${selectedCount} findings`)
    }
  }

  const handleBulkDelete = () => {
    if (confirm(`Delete ${selectedCount} findings? This action cannot be undone.`)) {
      const updatedFindings = findings.filter(f => !f.selected)
      setFindings(updatedFindings)
      setFilteredFindings(filteredFindings.filter(f => !f.selected))
      setSelectAll(false)
      alert(`Deleted ${selectedCount} findings`)
    }
  }

  const handleBulkExport = (format: string) => {
    alert(`Exporting ${selectedCount} findings as ${format}...`)
    setShowExportModal(false)
  }

  const summary = {
    total: findings.length,
    selected: selectedCount,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
  }

  return (
    <AppShell activeApp="bulk">
      <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
        {/* Left Sidebar - Filters */}
        <div className="w-72 bg-[#0f172a]/80 border-r border-white/10 flex flex-col sticky top-0 h-screen">
          {/* Header */}
          <div className="p-6 border-b border-white/10">
            <div className="flex items-center gap-3 mb-4">
              <Layers size={24} className="text-[#6B5AED]" />
              <h2 className="text-lg font-semibold">Bulk Operations</h2>
            </div>
            <p className="text-xs text-slate-500">Manage multiple findings at once</p>
          </div>

          {/* Summary Stats */}
          <div className="p-4 border-b border-white/10">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Total Findings</div>
                <div className="text-xl font-semibold text-[#6B5AED]">{summary.total}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Selected</div>
                <div className="text-xl font-semibold text-green-500">{summary.selected}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Critical</div>
                <div className="text-xl font-semibold text-red-500">{summary.critical}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">High</div>
                <div className="text-xl font-semibold text-orange-500">{summary.high}</div>
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
                        ({findings.filter(f => f.severity === severity).length})
                      </span>
                    )}
                    {severity === 'all' && (
                      <span className="ml-2 text-xs">({findings.length})</span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Filter size={12} />
                Filter by Source
              </div>
              <div className="space-y-2">
                {['all', 'CVE', 'SAST', 'IaC'].map((source) => (
                  <button
                    key={source}
                    onClick={() => { setSourceFilter(source); applyFilters(); }}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      sourceFilter === source
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    {source}
                    {source !== 'all' && (
                      <span className="ml-2 text-xs">
                        ({findings.filter(f => f.source === source).length})
                      </span>
                    )}
                    {source === 'all' && (
                      <span className="ml-2 text-xs">({findings.length})</span>
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
                <h1 className="text-2xl font-semibold mb-1">Bulk Operations</h1>
                <p className="text-sm text-slate-500">
                  {selectedCount > 0 ? `${selectedCount} finding${selectedCount !== 1 ? 's' : ''} selected` : `Showing ${filteredFindings.length} finding${filteredFindings.length !== 1 ? 's' : ''}`}
                </p>
              </div>
            </div>

            {/* Search Bar */}
            <div className="relative mb-4">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search by title or service..."
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); applyFilters(); }}
                className="w-full pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-[#6B5AED]/50"
              />
            </div>

            {/* Bulk Actions Bar */}
            {selectedCount > 0 && (
              <div className="flex items-center gap-2 p-3 bg-[#6B5AED]/10 border border-[#6B5AED]/30 rounded-lg">
                <span className="text-sm text-white font-medium">{selectedCount} selected</span>
                <div className="flex-1" />
                <button
                  onClick={() => setShowAssignModal(true)}
                  className="px-3 py-1.5 bg-white/10 hover:bg-white/20 rounded text-xs text-white transition-colors flex items-center gap-1"
                >
                  <UserPlus size={14} />
                  Assign
                </button>
                <button
                  onClick={() => setShowTagModal(true)}
                  className="px-3 py-1.5 bg-white/10 hover:bg-white/20 rounded text-xs text-white transition-colors flex items-center gap-1"
                >
                  <Tag size={14} />
                  Tag
                </button>
                <button
                  onClick={handleBulkAcceptRisk}
                  className="px-3 py-1.5 bg-white/10 hover:bg-white/20 rounded text-xs text-white transition-colors flex items-center gap-1"
                >
                  <CheckCircle size={14} />
                  Accept Risk
                </button>
                <button
                  onClick={() => setShowExportModal(true)}
                  className="px-3 py-1.5 bg-white/10 hover:bg-white/20 rounded text-xs text-white transition-colors flex items-center gap-1"
                >
                  <Download size={14} />
                  Export
                </button>
                <button
                  onClick={handleBulkDelete}
                  className="px-3 py-1.5 bg-red-500/20 hover:bg-red-500/30 rounded text-xs text-red-400 transition-colors flex items-center gap-1"
                >
                  <XSquare size={14} />
                  Delete
                </button>
              </div>
            )}
          </div>

          {/* Findings Table */}
          <div className="flex-1 overflow-auto p-6">
            <div className="bg-white/2 rounded-lg border border-white/5 overflow-hidden">
              <table className="w-full">
                <thead className="bg-white/5 border-b border-white/10">
                  <tr>
                    <th className="px-4 py-3 text-left">
                      <input
                        type="checkbox"
                        checked={selectAll}
                        onChange={handleSelectAll}
                        className="w-4 h-4 rounded border-white/20 bg-white/5 text-[#6B5AED] focus:ring-[#6B5AED]/50"
                      />
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Severity</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Title</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Source</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Service</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Assignee</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Tags</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {filteredFindings.map((finding) => (
                    <tr
                      key={finding.id}
                      className={`hover:bg-white/5 transition-colors ${finding.selected ? 'bg-[#6B5AED]/10' : ''}`}
                    >
                      <td className="px-4 py-3">
                        <input
                          type="checkbox"
                          checked={finding.selected}
                          onChange={() => handleSelectFinding(finding.id)}
                          className="w-4 h-4 rounded border-white/20 bg-white/5 text-[#6B5AED] focus:ring-[#6B5AED]/50"
                        />
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium"
                          style={{ 
                            backgroundColor: `${getSeverityColor(finding.severity)}20`,
                            color: getSeverityColor(finding.severity)
                          }}
                        >
                          {finding.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-sm text-white">{finding.title}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-sm text-slate-300">{finding.source}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-sm text-slate-300">{finding.service}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-sm text-slate-300">{finding.assignee || '—'}</span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex gap-1">
                          {finding.tags.length > 0 ? (
                            finding.tags.map((tag, idx) => (
                              <span key={idx} className="px-2 py-0.5 bg-white/10 rounded text-xs text-slate-300">
                                {tag}
                              </span>
                            ))
                          ) : (
                            <span className="text-sm text-slate-400">—</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Assign Modal */}
        {showAssignModal && (
          <div
            onClick={() => setShowAssignModal(false)}
            className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center"
          >
            <div
              onClick={(e) => e.stopPropagation()}
              className="w-[400px] bg-[#1e293b] border border-white/10 rounded-lg p-6"
            >
              <h3 className="text-lg font-semibold mb-4">Assign to Team/User</h3>
              <div className="space-y-2 mb-4">
                {['security-team', 'infra-team', 'dev-team', 'john.doe@fixops.io', 'sarah.chen@fixops.io'].map((assignee) => (
                  <button
                    key={assignee}
                    onClick={() => handleBulkAssign(assignee)}
                    className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors"
                  >
                    {assignee}
                  </button>
                ))}
              </div>
              <button
                onClick={() => setShowAssignModal(false)}
                className="w-full p-2 bg-white/10 hover:bg-white/20 rounded text-sm text-white transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Tag Modal */}
        {showTagModal && (
          <div
            onClick={() => setShowTagModal(false)}
            className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center"
          >
            <div
              onClick={(e) => e.stopPropagation()}
              className="w-[400px] bg-[#1e293b] border border-white/10 rounded-lg p-6"
            >
              <h3 className="text-lg font-semibold mb-4">Add Tag</h3>
              <div className="space-y-2 mb-4">
                {['urgent', 'reviewed', 'false-positive', 'production', 'needs-verification'].map((tag) => (
                  <button
                    key={tag}
                    onClick={() => handleBulkTag(tag)}
                    className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors"
                  >
                    {tag}
                  </button>
                ))}
              </div>
              <button
                onClick={() => setShowTagModal(false)}
                className="w-full p-2 bg-white/10 hover:bg-white/20 rounded text-sm text-white transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Export Modal */}
        {showExportModal && (
          <div
            onClick={() => setShowExportModal(false)}
            className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center"
          >
            <div
              onClick={(e) => e.stopPropagation()}
              className="w-[400px] bg-[#1e293b] border border-white/10 rounded-lg p-6"
            >
              <h3 className="text-lg font-semibold mb-4">Export Format</h3>
              <div className="space-y-2 mb-4">
                {['CSV', 'JSON', 'PDF', 'SARIF'].map((format) => (
                  <button
                    key={format}
                    onClick={() => handleBulkExport(format)}
                    className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors"
                  >
                    {format}
                  </button>
                ))}
              </div>
              <button
                onClick={() => setShowExportModal(false)}
                className="w-full p-2 bg-white/10 hover:bg-white/20 rounded text-sm text-white transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  )
}
