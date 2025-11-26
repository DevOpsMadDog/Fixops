'use client'

import { useState } from 'react'
import { Shield, Search, Plus, Play, XCircle, Calendar, Clock, CheckCircle, AlertTriangle, Filter, FileText, Settings } from 'lucide-react'
import EnterpriseShell from './components/EnterpriseShell'

const DEMO_PENTEST_REQUESTS = [
  {
    id: '1',
    name: 'Payment API Security Assessment',
    target: 'payment-api.fixops.com',
    type: 'web_application',
    scope: 'Full API endpoints, authentication, authorization',
    status: 'completed',
    severity_found: 'high',
    findings_count: 12,
    created_at: '2024-11-15T10:00:00Z',
    started_at: '2024-11-16T09:00:00Z',
    completed_at: '2024-11-18T17:00:00Z',
    requested_by: 'sarah.chen@fixops.io',
  },
  {
    id: '2',
    name: 'Infrastructure Penetration Test',
    target: 'prod.fixops.com',
    type: 'infrastructure',
    scope: 'Network perimeter, cloud infrastructure, VPN access',
    status: 'in_progress',
    severity_found: null,
    findings_count: 0,
    created_at: '2024-11-20T08:00:00Z',
    started_at: '2024-11-21T10:00:00Z',
    completed_at: null,
    requested_by: 'john.doe@fixops.io',
  },
  {
    id: '3',
    name: 'Mobile App Security Review',
    target: 'FixOps Mobile App v2.1',
    type: 'mobile_application',
    scope: 'iOS and Android apps, API communication, data storage',
    status: 'pending',
    severity_found: null,
    findings_count: 0,
    created_at: '2024-11-22T07:00:00Z',
    started_at: null,
    completed_at: null,
    requested_by: 'emily.rodriguez@fixops.io',
  },
  {
    id: '4',
    name: 'Admin Panel Security Audit',
    target: 'admin.fixops.com',
    type: 'web_application',
    scope: 'Authentication, RBAC, sensitive operations',
    status: 'completed',
    severity_found: 'critical',
    findings_count: 8,
    created_at: '2024-11-10T14:00:00Z',
    started_at: '2024-11-11T09:00:00Z',
    completed_at: '2024-11-13T16:00:00Z',
    requested_by: 'michael.kim@fixops.io',
  },
  {
    id: '5',
    name: 'API Gateway Security Test',
    target: 'api.fixops.com',
    type: 'api',
    scope: 'Rate limiting, authentication, input validation',
    status: 'cancelled',
    severity_found: null,
    findings_count: 0,
    created_at: '2024-11-08T11:00:00Z',
    started_at: null,
    completed_at: null,
    requested_by: 'anna.patel@fixops.io',
  },
]

const DEMO_FINDINGS = [
  {
    id: 'f1',
    request_id: '1',
    title: 'SQL Injection in Payment Endpoint',
    severity: 'critical',
    cvss_score: 9.8,
    description: 'SQL injection vulnerability in /api/payments endpoint allows unauthorized data access',
    remediation: 'Use parameterized queries and input validation',
    status: 'open',
  },
  {
    id: 'f2',
    request_id: '1',
    title: 'Broken Authentication',
    severity: 'high',
    cvss_score: 8.1,
    description: 'JWT tokens do not expire and can be reused indefinitely',
    remediation: 'Implement token expiration and refresh mechanism',
    status: 'open',
  },
  {
    id: 'f3',
    request_id: '4',
    title: 'Privilege Escalation',
    severity: 'critical',
    cvss_score: 9.1,
    description: 'Regular users can escalate privileges to admin through API manipulation',
    remediation: 'Implement proper authorization checks on all admin endpoints',
    status: 'resolved',
  },
]

export default function PentagiPage() {
  const [requests, setRequests] = useState(DEMO_PENTEST_REQUESTS)
  const [filteredRequests, setFilteredRequests] = useState(DEMO_PENTEST_REQUESTS)
  const [selectedRequest, setSelectedRequest] = useState<typeof DEMO_PENTEST_REQUESTS[0] | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showFindings, setShowFindings] = useState(false)

  const getStatusColor = (status: string) => {
    const colors = {
      pending: '#eab308',
      in_progress: '#3b82f6',
      completed: '#10b981',
      cancelled: '#6b7280',
    }
    return colors[status as keyof typeof colors] || colors.pending
  }

  const getStatusIcon = (status: string) => {
    const icons = {
      pending: <Clock size={14} />,
      in_progress: <Play size={14} />,
      completed: <CheckCircle size={14} />,
      cancelled: <XCircle size={14} />,
    }
    return icons[status as keyof typeof icons] || icons.pending
  }

  const getSeverityColor = (severity: string | null) => {
    if (!severity) return '#6b7280'
    const colors = {
      critical: '#dc2626',
      high: '#f97316',
      medium: '#eab308',
      low: '#10b981',
    }
    return colors[severity as keyof typeof colors] || colors.low
  }

  const formatDate = (isoString: string | null) => {
    if (!isoString) return 'N/A'
    const date = new Date(isoString)
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
  }

  const formatDuration = (start: string | null, end: string | null) => {
    if (!start || !end) return 'N/A'
    const startDate = new Date(start)
    const endDate = new Date(end)
    const diffMs = endDate.getTime() - startDate.getTime()
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24))
    return `${diffDays} day${diffDays !== 1 ? 's' : ''}`
  }

  const applyFilters = () => {
    let filtered = [...requests]

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(request =>
        request.name.toLowerCase().includes(query) ||
        request.target.toLowerCase().includes(query)
      )
    }

    if (typeFilter !== 'all') {
      filtered = filtered.filter(request => request.type === typeFilter)
    }

    if (statusFilter !== 'all') {
      filtered = filtered.filter(request => request.status === statusFilter)
    }

    setFilteredRequests(filtered)
  }

  useState(() => {
    applyFilters()
  })

  const summary = {
    total: requests.length,
    pending: requests.filter(r => r.status === 'pending').length,
    in_progress: requests.filter(r => r.status === 'in_progress').length,
    completed: requests.filter(r => r.status === 'completed').length,
    total_findings: requests.reduce((sum, r) => sum + r.findings_count, 0),
  }

  const requestTypes = Array.from(new Set(requests.map(r => r.type)))
  const requestFindings = DEMO_FINDINGS.filter(f => f.request_id === selectedRequest?.id)

  return (
    <EnterpriseShell>
      <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
        {/* Left Sidebar - Filters */}
        <div className="w-72 bg-[#0f172a]/80 border-r border-white/10 flex flex-col sticky top-0 h-screen">
          {/* Header */}
          <div className="p-6 border-b border-white/10">
            <div className="flex items-center gap-3 mb-4">
              <Shield size={24} className="text-[#6B5AED]" />
              <h2 className="text-lg font-semibold">Pentagi Integration</h2>
            </div>
            <p className="text-xs text-slate-500">Penetration testing requests</p>
          </div>

          {/* Summary Stats */}
          <div className="p-4 border-b border-white/10">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Total Requests</div>
                <div className="text-xl font-semibold text-[#6B5AED]">{summary.total}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">In Progress</div>
                <div className="text-xl font-semibold text-blue-500">{summary.in_progress}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Completed</div>
                <div className="text-xl font-semibold text-green-500">{summary.completed}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Findings</div>
                <div className="text-xl font-semibold text-orange-500">{summary.total_findings}</div>
              </div>
            </div>
          </div>

          {/* Filters */}
          <div className="p-4 flex-1 overflow-auto">
            <div className="mb-6">
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Filter size={12} />
                Filter by Status
              </div>
              <div className="space-y-2">
                {['all', 'pending', 'in_progress', 'completed', 'cancelled'].map((status) => (
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
                        ({requests.filter(r => r.status === status).length})
                      </span>
                    )}
                    {status === 'all' && (
                      <span className="ml-2 text-xs">({requests.length})</span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Filter size={12} />
                Filter by Type
              </div>
              <div className="space-y-2">
                <button
                  onClick={() => { setTypeFilter('all'); applyFilters(); }}
                  className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                    typeFilter === 'all'
                      ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                      : 'text-slate-400 hover:bg-white/5'
                  }`}
                >
                  All Types
                  <span className="ml-2 text-xs">({requests.length})</span>
                </button>
                {requestTypes.map((type) => (
                  <button
                    key={type}
                    onClick={() => { setTypeFilter(type); applyFilters(); }}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      typeFilter === type
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="capitalize">{type.replace('_', ' ')}</span>
                    <span className="ml-2 text-xs">
                      ({requests.filter(r => r.type === type).length})
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
                <h1 className="text-2xl font-semibold mb-1">Penetration Testing</h1>
                <p className="text-sm text-slate-500">
                  Showing {filteredRequests.length} request{filteredRequests.length !== 1 ? 's' : ''}
                </p>
              </div>
              <button
                onClick={() => setShowCreateModal(true)}
                className="px-4 py-2 bg-[#6B5AED] hover:bg-[#5B4ADD] rounded-md text-white text-sm font-medium transition-all flex items-center gap-2"
              >
                <Plus size={16} />
                New Request
              </button>
            </div>

            {/* Search Bar */}
            <div className="relative">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search by name or target..."
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); applyFilters(); }}
                className="w-full pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-[#6B5AED]/50"
              />
            </div>
          </div>

          {/* Requests Grid */}
          <div className="flex-1 overflow-auto p-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {filteredRequests.map((request) => (
                <div
                  key={request.id}
                  onClick={() => setSelectedRequest(request)}
                  className="bg-white/2 border border-white/5 rounded-lg p-5 hover:bg-white/5 hover:border-[#6B5AED]/30 cursor-pointer transition-all"
                >
                  {/* Header */}
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-[#6B5AED]/20 flex items-center justify-center">
                        <Shield size={20} className="text-[#6B5AED]" />
                      </div>
                      <div>
                        <h3 className="text-sm font-semibold text-white">{request.name}</h3>
                        <p className="text-xs text-slate-400 capitalize">{request.type.replace('_', ' ')}</p>
                      </div>
                    </div>
                    <span
                      className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium"
                      style={{ 
                        backgroundColor: `${getStatusColor(request.status)}20`,
                        color: getStatusColor(request.status)
                      }}
                    >
                      {getStatusIcon(request.status)}
                      {request.status.replace('_', ' ')}
                    </span>
                  </div>

                  {/* Target */}
                  <div className="mb-4 p-3 bg-white/5 rounded-lg">
                    <div className="text-xs text-slate-400 mb-1">Target</div>
                    <div className="text-sm text-white font-mono">{request.target}</div>
                  </div>

                  {/* Stats */}
                  <div className="grid grid-cols-2 gap-3 mb-4">
                    <div className="p-3 bg-white/5 rounded-lg text-center">
                      <div className="text-xs text-slate-400 mb-1">Findings</div>
                      <div className="text-lg font-semibold text-orange-500">{request.findings_count}</div>
                    </div>
                    <div className="p-3 bg-white/5 rounded-lg text-center">
                      <div className="text-xs text-slate-400 mb-1">Duration</div>
                      <div className="text-sm font-semibold text-blue-500">
                        {formatDuration(request.started_at, request.completed_at)}
                      </div>
                    </div>
                  </div>

                  {/* Severity Badge */}
                  {request.severity_found && (
                    <div className="mb-4">
                      <span
                        className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium"
                        style={{ 
                          backgroundColor: `${getSeverityColor(request.severity_found)}20`,
                          color: getSeverityColor(request.severity_found)
                        }}
                      >
                        <AlertTriangle size={12} />
                        Highest: {request.severity_found}
                      </span>
                    </div>
                  )}

                  {/* Footer */}
                  <div className="flex items-center justify-between pt-3 border-t border-white/5">
                    <div className="flex items-center gap-2 text-xs text-slate-400">
                      <Calendar size={12} />
                      {formatDate(request.created_at)}
                    </div>
                    <span className="text-xs text-slate-400">{request.requested_by}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Request Detail Drawer */}
        {selectedRequest && (
          <div
            onClick={() => setSelectedRequest(null)}
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
                    <h3 className="text-lg font-semibold mb-1">{selectedRequest.name}</h3>
                    <p className="text-sm text-slate-400 capitalize">{selectedRequest.type.replace('_', ' ')}</p>
                  </div>
                  <button
                    onClick={() => setSelectedRequest(null)}
                    className="text-slate-400 hover:text-white transition-colors"
                  >
                    ✕
                  </button>
                </div>

                <div className="flex gap-2">
                  <span
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium"
                    style={{ 
                      backgroundColor: `${getStatusColor(selectedRequest.status)}20`,
                      color: getStatusColor(selectedRequest.status)
                    }}
                  >
                    {getStatusIcon(selectedRequest.status)}
                    {selectedRequest.status.replace('_', ' ')}
                  </span>
                  {selectedRequest.severity_found && (
                    <span
                      className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium"
                      style={{ 
                        backgroundColor: `${getSeverityColor(selectedRequest.severity_found)}20`,
                        color: getSeverityColor(selectedRequest.severity_found)
                      }}
                    >
                      <AlertTriangle size={14} />
                      {selectedRequest.severity_found}
                    </span>
                  )}
                </div>
              </div>

              {/* Drawer Content */}
              <div className="flex-1 p-6 space-y-6">
                {/* Request Information */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Request Information</h4>
                  <div className="space-y-3 bg-white/5 rounded-lg p-4">
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Request ID</span>
                      <span className="text-sm text-white font-mono">{selectedRequest.id}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Target</span>
                      <span className="text-sm text-white">{selectedRequest.target}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Type</span>
                      <span className="text-sm text-white capitalize">{selectedRequest.type.replace('_', ' ')}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Requested By</span>
                      <span className="text-sm text-white">{selectedRequest.requested_by}</span>
                    </div>
                  </div>
                </div>

                {/* Scope */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Scope</h4>
                  <div className="p-4 bg-white/5 rounded-lg">
                    <p className="text-sm text-white">{selectedRequest.scope}</p>
                  </div>
                </div>

                {/* Timeline */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Timeline</h4>
                  <div className="space-y-3 bg-white/5 rounded-lg p-4">
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Created</span>
                      <span className="text-sm text-white">{formatDate(selectedRequest.created_at)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Started</span>
                      <span className="text-sm text-white">{formatDate(selectedRequest.started_at)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Completed</span>
                      <span className="text-sm text-white">{formatDate(selectedRequest.completed_at)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Duration</span>
                      <span className="text-sm text-white">
                        {formatDuration(selectedRequest.started_at, selectedRequest.completed_at)}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Findings */}
                {selectedRequest.findings_count > 0 && (
                  <div>
                    <div className="flex items-center justify-between mb-3">
                      <h4 className="text-sm font-semibold text-slate-300">Findings ({selectedRequest.findings_count})</h4>
                      <button
                        onClick={() => setShowFindings(!showFindings)}
                        className="text-xs text-[#6B5AED] hover:underline"
                      >
                        {showFindings ? 'Hide' : 'Show'} Details
                      </button>
                    </div>
                    {showFindings && (
                      <div className="space-y-2">
                        {requestFindings.map((finding) => (
                          <div key={finding.id} className="p-3 bg-white/5 rounded-lg">
                            <div className="flex items-start justify-between mb-2">
                              <span className="text-sm font-medium text-white">{finding.title}</span>
                              <span
                                className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium"
                                style={{ 
                                  backgroundColor: `${getSeverityColor(finding.severity)}20`,
                                  color: getSeverityColor(finding.severity)
                                }}
                              >
                                {finding.severity}
                              </span>
                            </div>
                            <p className="text-xs text-slate-400 mb-2">{finding.description}</p>
                            <div className="text-xs text-slate-500">CVSS: {finding.cvss_score}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Actions */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Actions</h4>
                  <div className="space-y-2">
                    {selectedRequest.status === 'pending' && (
                      <button className="w-full p-3 bg-[#6B5AED]/10 hover:bg-[#6B5AED]/20 rounded-lg text-sm text-left text-[#6B5AED] transition-colors flex items-center gap-2">
                        <Play size={16} />
                        Start Test
                      </button>
                    )}
                    {selectedRequest.status === 'in_progress' && (
                      <button className="w-full p-3 bg-yellow-500/10 hover:bg-yellow-500/20 rounded-lg text-sm text-left text-yellow-400 transition-colors flex items-center gap-2">
                        <XCircle size={16} />
                        Cancel Test
                      </button>
                    )}
                    {selectedRequest.status === 'completed' && (
                      <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                        <FileText size={16} />
                        Download Report
                      </button>
                    )}
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <Settings size={16} />
                      Configure Pentagi
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
