'use client'

import { useState, useEffect, useMemo } from 'react'
import { FileText, Search, Filter, Calendar, User, Activity, Shield, AlertTriangle, CheckCircle, XCircle, Download, Loader2, RefreshCw, WifiOff, X } from 'lucide-react'
import { AppShell, useDemoModeContext } from '@fixops/ui'
import { useAuditLogs } from '@fixops/api-client'

const DEMO_AUDIT_LOGS = [
  {
    id: '1',
    timestamp: '2024-11-22T09:15:00Z',
    event_type: 'policy.triggered',
    severity: 'high',
    user: 'security-team',
    action: 'Block deployment',
    resource: 'payment-api:v2.3.1',
    details: 'Policy "Block Critical KEV Vulnerabilities" triggered for CVE-2023-50164',
    ip_address: '192.168.1.100',
    user_agent: 'FixOps CLI v1.2.0',
  },
  {
    id: '2',
    timestamp: '2024-11-22T08:45:00Z',
    event_type: 'user.login',
    severity: 'info',
    user: 'sarah.chen@fixops.io',
    action: 'User login',
    resource: 'web-ui',
    details: 'Successful login via SSO',
    ip_address: '10.0.1.50',
    user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
  },
  {
    id: '3',
    timestamp: '2024-11-22T08:30:00Z',
    event_type: 'finding.accepted',
    severity: 'medium',
    user: 'john.doe@fixops.io',
    action: 'Accept risk',
    resource: 'user-service:finding-123',
    details: 'Risk accepted for SQL Injection finding with business justification',
    ip_address: '10.0.1.51',
    user_agent: 'FixOps Web UI v2.0.0',
  },
  {
    id: '4',
    timestamp: '2024-11-22T08:00:00Z',
    event_type: 'scan.completed',
    severity: 'info',
    user: 'system',
    action: 'Scan completed',
    resource: 'payment-api',
    details: 'Security scan completed: 12 findings (3 critical, 5 high, 4 medium)',
    ip_address: '172.16.0.10',
    user_agent: 'FixOps Scanner v3.1.0',
  },
  {
    id: '5',
    timestamp: '2024-11-22T07:30:00Z',
    event_type: 'policy.created',
    severity: 'info',
    user: 'admin@fixops.io',
    action: 'Create policy',
    resource: 'policy-9',
    details: 'Created new policy "Block Internet-Facing RCE"',
    ip_address: '10.0.1.100',
    user_agent: 'FixOps Web UI v2.0.0',
  },
  {
    id: '6',
    timestamp: '2024-11-22T07:00:00Z',
    event_type: 'user.created',
    severity: 'info',
    user: 'admin@fixops.io',
    action: 'Create user',
    resource: 'user-15',
    details: 'Created new user account for anna.patel@fixops.io with role: security_analyst',
    ip_address: '10.0.1.100',
    user_agent: 'FixOps Web UI v2.0.0',
  },
  {
    id: '7',
    timestamp: '2024-11-22T06:45:00Z',
    event_type: 'integration.sync',
    severity: 'info',
    user: 'system',
    action: 'Sync integration',
    resource: 'jira-integration',
    details: 'Synced 45 issues with Jira',
    ip_address: '172.16.0.10',
    user_agent: 'FixOps Integration Service v1.5.0',
  },
  {
    id: '8',
    timestamp: '2024-11-22T06:30:00Z',
    event_type: 'policy.violated',
    severity: 'critical',
    user: 'system',
    action: 'Policy violation',
    resource: 'api-gateway:v1.8.2',
    details: 'Policy violation detected: Exposed AWS credentials in Terraform configuration',
    ip_address: '172.16.0.10',
    user_agent: 'FixOps Scanner v3.1.0',
  },
  {
    id: '9',
    timestamp: '2024-11-22T06:00:00Z',
    event_type: 'report.generated',
    severity: 'info',
    user: 'system',
    action: 'Generate report',
    resource: 'report-3',
    details: 'Generated "Critical Vulnerabilities Report" and sent to security-team@fixops.io',
    ip_address: '172.16.0.10',
    user_agent: 'FixOps Report Service v1.0.0',
  },
  {
    id: '10',
    timestamp: '2024-11-22T05:30:00Z',
    event_type: 'user.logout',
    severity: 'info',
    user: 'emily.rodriguez@fixops.io',
    action: 'User logout',
    resource: 'web-ui',
    details: 'User logged out',
    ip_address: '10.0.1.52',
    user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
  },
  {
    id: '11',
    timestamp: '2024-11-22T05:00:00Z',
    event_type: 'finding.remediated',
    severity: 'info',
    user: 'michael.kim@fixops.io',
    action: 'Remediate finding',
    resource: 'web-dashboard:finding-456',
    details: 'Marked XSS vulnerability as remediated with fix commit SHA: abc123def',
    ip_address: '10.0.1.53',
    user_agent: 'FixOps Web UI v2.0.0',
  },
  {
    id: '12',
    timestamp: '2024-11-22T04:30:00Z',
    event_type: 'api.key.created',
    severity: 'medium',
    user: 'admin@fixops.io',
    action: 'Create API key',
    resource: 'api-key-789',
    details: 'Created new API key for CI/CD integration with read-only permissions',
    ip_address: '10.0.1.100',
    user_agent: 'FixOps Web UI v2.0.0',
  },
]

export default function AuditLogsPage() {
  const { demoEnabled } = useDemoModeContext()
  const { data: apiData, loading: apiLoading, error: apiError, refetch } = useAuditLogs()
  
  // Transform API data to match our UI format, or use demo data
  const logsData = useMemo(() => {
    if (demoEnabled || !apiData?.items) {
      return DEMO_AUDIT_LOGS
    }
    return apiData.items.map(log => ({
      id: log.id,
      timestamp: log.timestamp,
      event_type: log.event_type || 'system.event',
      severity: log.severity || 'info',
      user: log.user || 'system',
      action: log.action || 'Unknown action',
      resource: log.resource || '',
      details: log.details || '',
      ip_address: log.ip_address || '',
      user_agent: log.user_agent || '',
    }))
  }, [demoEnabled, apiData])

  const [logs, setLogs] = useState(DEMO_AUDIT_LOGS)
  const [filteredLogs, setFilteredLogs] = useState(DEMO_AUDIT_LOGS)
  const [selectedLog, setSelectedLog] = useState<typeof DEMO_AUDIT_LOGS[0] | null>(null)
    const [searchQuery, setSearchQuery] = useState('')
    const [eventTypeFilter, setEventTypeFilter] = useState<string>('all')
    const [severityFilter, setSeverityFilter] = useState<string>('all')
    const [userFilter, setUserFilter] = useState<string>('all')
    const [showMobileFilters, setShowMobileFilters] = useState(false)

  // Update logs when data source changes
  useEffect(() => {
    setLogs(logsData)
    setFilteredLogs(logsData)
  }, [logsData])

  const getSeverityColor = (severity: string) => {
    const colors = {
      critical: '#dc2626',
      high: '#f97316',
      medium: '#eab308',
      low: '#10b981',
      info: '#3b82f6',
    }
    return colors[severity as keyof typeof colors] || colors.info
  }

  const getSeverityIcon = (severity: string) => {
    const icons = {
      critical: <XCircle size={14} />,
      high: <AlertTriangle size={14} />,
      medium: <AlertTriangle size={14} />,
      low: <CheckCircle size={14} />,
      info: <Activity size={14} />,
    }
    return icons[severity as keyof typeof icons] || icons.info
  }

  const getEventTypeIcon = (eventType: string) => {
    if (eventType.startsWith('policy')) return <Shield size={14} />
    if (eventType.startsWith('user')) return <User size={14} />
    if (eventType.startsWith('scan') || eventType.startsWith('finding')) return <Activity size={14} />
    return <FileText size={14} />
  }

  const formatDateTime = (isoString: string) => {
    const date = new Date(isoString)
    return date.toLocaleString('en-US', { 
      month: 'short', 
      day: 'numeric', 
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    })
  }

  const formatTimeAgo = (isoString: string) => {
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
    let filtered = [...logs]

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(log =>
        log.action.toLowerCase().includes(query) ||
        log.details.toLowerCase().includes(query) ||
        log.user.toLowerCase().includes(query) ||
        log.resource.toLowerCase().includes(query)
      )
    }

    if (eventTypeFilter !== 'all') {
      filtered = filtered.filter(log => log.event_type === eventTypeFilter)
    }

    if (severityFilter !== 'all') {
      filtered = filtered.filter(log => log.severity === severityFilter)
    }

    if (userFilter !== 'all') {
      filtered = filtered.filter(log => log.user === userFilter)
    }

    setFilteredLogs(filtered)
  }

  useState(() => {
    applyFilters()
  })

  const summary = {
    total: logs.length,
    critical: logs.filter(l => l.severity === 'critical').length,
    high: logs.filter(l => l.severity === 'high').length,
    medium: logs.filter(l => l.severity === 'medium').length,
    policy_events: logs.filter(l => l.event_type.startsWith('policy')).length,
    user_events: logs.filter(l => l.event_type.startsWith('user')).length,
  }

  const eventTypes = Array.from(new Set(logs.map(l => l.event_type)))
  const users = Array.from(new Set(logs.map(l => l.user)))

  return (
    <AppShell activeApp="audit">
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
                    {/* Mobile sidebar content */}
                    <div className="p-4 border-b border-white/10">
                      <div className="grid grid-cols-2 gap-3 text-xs">
                        <div className="p-3 bg-white/5 rounded-md">
                          <div className="text-slate-500 mb-1">Total Events</div>
                          <div className="text-xl font-semibold text-[#6B5AED]">{summary.total}</div>
                        </div>
                        <div className="p-3 bg-white/5 rounded-md">
                          <div className="text-slate-500 mb-1">Critical</div>
                          <div className="text-xl font-semibold text-red-500">{summary.critical}</div>
                        </div>
                      </div>
                    </div>
                    <div className="p-4 flex-1 overflow-auto">
                      <div className="mb-6">
                        <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">Severity</div>
                        <div className="space-y-2">
                          {['all', 'critical', 'high', 'medium', 'low', 'info'].map((severity) => (
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
                    </div>
                  </div>
                </div>
              )}

              {/* Desktop Sidebar - Filters */}
              <div className="hidden lg:flex w-72 bg-[#0f172a]/80 border-r border-white/10 flex-col sticky top-0 h-screen">
                {/* Header */}
                <div className="p-6 border-b border-white/10">
            <div className="flex items-center gap-3 mb-4">
              <FileText size={24} className="text-[#6B5AED]" />
              <h2 className="text-lg font-semibold">Audit Logs</h2>
            </div>
            <p className="text-xs text-slate-500">Track all system events and actions</p>
          </div>

          {/* Summary Stats */}
          <div className="p-4 border-b border-white/10">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Total Events</div>
                <div className="text-xl font-semibold text-[#6B5AED]">{summary.total}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Critical</div>
                <div className="text-xl font-semibold text-red-500">{summary.critical}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Policy Events</div>
                <div className="text-xl font-semibold text-orange-500">{summary.policy_events}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">User Events</div>
                <div className="text-xl font-semibold text-blue-500">{summary.user_events}</div>
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
                {['all', 'critical', 'high', 'medium', 'low', 'info'].map((severity) => (
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
                        ({logs.filter(l => l.severity === severity).length})
                      </span>
                    )}
                    {severity === 'all' && (
                      <span className="ml-2 text-xs">({logs.length})</span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            <div className="mb-6">
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Filter size={12} />
                Filter by Event Type
              </div>
              <div className="space-y-2 max-h-48 overflow-auto">
                <button
                  onClick={() => { setEventTypeFilter('all'); applyFilters(); }}
                  className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                    eventTypeFilter === 'all'
                      ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                      : 'text-slate-400 hover:bg-white/5'
                  }`}
                >
                  All Events
                  <span className="ml-2 text-xs">({logs.length})</span>
                </button>
                {eventTypes.map((type) => (
                  <button
                    key={type}
                    onClick={() => { setEventTypeFilter(type); applyFilters(); }}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      eventTypeFilter === type
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    {type.replace('.', ' ')}
                    <span className="ml-2 text-xs">
                      ({logs.filter(l => l.event_type === type).length})
                    </span>
                  </button>
                ))}
              </div>
            </div>

            <div>
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <User size={12} />
                Filter by User
              </div>
              <div className="space-y-2 max-h-48 overflow-auto">
                <button
                  onClick={() => { setUserFilter('all'); applyFilters(); }}
                  className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                    userFilter === 'all'
                      ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                      : 'text-slate-400 hover:bg-white/5'
                  }`}
                >
                  All Users
                  <span className="ml-2 text-xs">({logs.length})</span>
                </button>
                {users.map((user) => (
                  <button
                    key={user}
                    onClick={() => { setUserFilter(user); applyFilters(); }}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      userFilter === user
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="truncate">{user}</span>
                    <span className="ml-2 text-xs">
                      ({logs.filter(l => l.user === user).length})
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
                                      <h1 className="text-xl lg:text-2xl font-semibold mb-1">Audit Logs</h1>
                            <p className="text-sm text-slate-500 flex items-center gap-2">
                              {apiLoading && !demoEnabled ? (
                                <><Loader2 size={14} className="animate-spin" /> Loading...</>
                              ) : (
                                <>Showing {filteredLogs.length} event{filteredLogs.length !== 1 ? 's' : ''}</>
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
                                                      onClick={() => alert('Exporting audit logs...')}
                                                      className="hidden sm:flex px-4 py-2 bg-[#6B5AED] hover:bg-[#5B4ADD] rounded-md text-white text-sm font-medium transition-all items-center gap-2"
                                                    >
                                                      <Download size={16} />
                                                      <span className="hidden md:inline">Export Logs</span>
                                                    </button>
                                                  </div>
                                                </div>

            {/* Search Bar */}
            <div className="relative">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search by action, user, resource, or details..."
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); applyFilters(); }}
                className="w-full pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-[#6B5AED]/50"
              />
            </div>
          </div>

          {/* Audit Logs Timeline */}
          <div className="flex-1 overflow-auto p-6">
            <div className="space-y-3">
              {filteredLogs.map((log) => (
                <div
                  key={log.id}
                  onClick={() => setSelectedLog(log)}
                  className="bg-white/2 border border-white/5 rounded-lg p-4 hover:bg-white/5 hover:border-[#6B5AED]/30 cursor-pointer transition-all"
                >
                  <div className="flex items-start gap-4">
                    {/* Severity Indicator */}
                    <div
                      className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
                      style={{ backgroundColor: `${getSeverityColor(log.severity)}20` }}
                    >
                      <span style={{ color: getSeverityColor(log.severity) }}>
                        {getSeverityIcon(log.severity)}
                      </span>
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <span
                            className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium"
                            style={{ 
                              backgroundColor: `${getSeverityColor(log.severity)}20`,
                              color: getSeverityColor(log.severity)
                            }}
                          >
                            {getSeverityIcon(log.severity)}
                            {log.severity}
                          </span>
                          <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-white/5 text-slate-300">
                            {getEventTypeIcon(log.event_type)}
                            {log.event_type.replace('.', ' ')}
                          </span>
                        </div>
                        <span className="text-xs text-slate-400">{formatTimeAgo(log.timestamp)}</span>
                      </div>

                      <div className="mb-2">
                        <span className="text-sm font-semibold text-white">{log.action}</span>
                        <span className="text-sm text-slate-400 ml-2">by {log.user}</span>
                      </div>

                      <p className="text-sm text-slate-300 mb-2">{log.details}</p>

                      <div className="flex items-center gap-4 text-xs text-slate-400">
                        <span className="flex items-center gap-1">
                          <Activity size={12} />
                          {log.resource}
                        </span>
                        <span className="flex items-center gap-1">
                          <Calendar size={12} />
                          {formatDateTime(log.timestamp)}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Log Detail Drawer */}
        {selectedLog && (
          <div
            onClick={() => setSelectedLog(null)}
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
                    <h3 className="text-lg font-semibold mb-1">{selectedLog.action}</h3>
                    <p className="text-sm text-slate-400">{selectedLog.event_type.replace('.', ' ')}</p>
                  </div>
                  <button
                    onClick={() => setSelectedLog(null)}
                    className="text-slate-400 hover:text-white transition-colors"
                  >
                    ✕
                  </button>
                </div>

                <div className="flex gap-2">
                  <span
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium"
                    style={{ 
                      backgroundColor: `${getSeverityColor(selectedLog.severity)}20`,
                      color: getSeverityColor(selectedLog.severity)
                    }}
                  >
                    {getSeverityIcon(selectedLog.severity)}
                    {selectedLog.severity}
                  </span>
                  <span className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium bg-white/5 text-slate-300">
                    {getEventTypeIcon(selectedLog.event_type)}
                    {selectedLog.event_type.replace('.', ' ')}
                  </span>
                </div>
              </div>

              {/* Drawer Content */}
              <div className="flex-1 p-6 space-y-6">
                {/* Event Details */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Event Details</h4>
                  <div className="space-y-3 bg-white/5 rounded-lg p-4">
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Event ID</span>
                      <span className="text-sm text-white font-mono">{selectedLog.id}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Timestamp</span>
                      <span className="text-sm text-white">{formatDateTime(selectedLog.timestamp)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">User</span>
                      <span className="text-sm text-white">{selectedLog.user}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Resource</span>
                      <span className="text-sm text-white font-mono">{selectedLog.resource}</span>
                    </div>
                  </div>
                </div>

                {/* Description */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Description</h4>
                  <div className="p-4 bg-white/5 rounded-lg">
                    <p className="text-sm text-white">{selectedLog.details}</p>
                  </div>
                </div>

                {/* Technical Details */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Technical Details</h4>
                  <div className="space-y-3 bg-white/5 rounded-lg p-4">
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">IP Address</span>
                      <span className="text-sm text-white font-mono">{selectedLog.ip_address}</span>
                    </div>
                    <div>
                      <div className="text-sm text-slate-400 mb-1">User Agent</div>
                      <div className="text-xs text-white font-mono break-all">{selectedLog.user_agent}</div>
                    </div>
                  </div>
                </div>

                {/* Actions */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Actions</h4>
                  <div className="space-y-2">
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <Download size={16} />
                      Export Event Details
                    </button>
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <User size={16} />
                      View User Activity
                    </button>
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <Activity size={16} />
                      View Related Events
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
