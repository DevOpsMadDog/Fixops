'use client'

import { useState } from 'react'
import { Key, Search, Filter, AlertTriangle, CheckCircle, XCircle, Eye, EyeOff, Calendar, GitBranch, FileText, Shield } from 'lucide-react'
import EnterpriseShell from './components/EnterpriseShell'

const DEMO_SECRETS = [
  {
    id: '1',
    type: 'aws_access_key',
    value_preview: 'AKIA****************',
    file: 'terraform/main.tf',
    line: 89,
    repository: 'infrastructure',
    branch: 'main',
    commit: 'abc123def456',
    severity: 'critical',
    status: 'active',
    detected_at: '2024-11-22T08:30:00Z',
    last_seen: '2024-11-22T08:30:00Z',
    false_positive: false,
  },
  {
    id: '2',
    type: 'github_token',
    value_preview: 'ghp_****************',
    file: '.github/workflows/deploy.yml',
    line: 45,
    repository: 'payment-api',
    branch: 'feature/ci-cd',
    commit: 'def456ghi789',
    severity: 'high',
    status: 'active',
    detected_at: '2024-11-22T07:15:00Z',
    last_seen: '2024-11-22T07:15:00Z',
    false_positive: false,
  },
  {
    id: '3',
    type: 'slack_webhook',
    value_preview: 'https://hooks.slack.com/services/T****/B****/****',
    file: 'config/notifications.json',
    line: 12,
    repository: 'notification-service',
    branch: 'main',
    commit: 'ghi789jkl012',
    severity: 'medium',
    status: 'active',
    detected_at: '2024-11-22T06:00:00Z',
    last_seen: '2024-11-22T06:00:00Z',
    false_positive: false,
  },
  {
    id: '4',
    type: 'database_password',
    value_preview: 'postgres://user:****@localhost:5432/db',
    file: 'config/database.yml',
    line: 8,
    repository: 'user-service',
    branch: 'main',
    commit: 'jkl012mno345',
    severity: 'critical',
    status: 'revoked',
    detected_at: '2024-11-21T18:30:00Z',
    last_seen: '2024-11-21T18:30:00Z',
    false_positive: false,
  },
  {
    id: '5',
    type: 'api_key',
    value_preview: 'sk_live_****************',
    file: 'src/services/payment.ts',
    line: 23,
    repository: 'payment-api',
    branch: 'main',
    commit: 'mno345pqr678',
    severity: 'high',
    status: 'active',
    detected_at: '2024-11-21T15:00:00Z',
    last_seen: '2024-11-21T15:00:00Z',
    false_positive: false,
  },
  {
    id: '6',
    type: 'private_key',
    value_preview: '-----BEGIN RSA PRIVATE KEY-----\nMIIE****',
    file: 'certs/server.key',
    line: 1,
    repository: 'api-gateway',
    branch: 'main',
    commit: 'pqr678stu901',
    severity: 'critical',
    status: 'active',
    detected_at: '2024-11-21T12:00:00Z',
    last_seen: '2024-11-21T12:00:00Z',
    false_positive: false,
  },
  {
    id: '7',
    type: 'jwt_secret',
    value_preview: 'HS256_****************',
    file: 'config/auth.js',
    line: 15,
    repository: 'auth-service',
    branch: 'develop',
    commit: 'stu901vwx234',
    severity: 'high',
    status: 'false_positive',
    detected_at: '2024-11-21T10:00:00Z',
    last_seen: '2024-11-21T10:00:00Z',
    false_positive: true,
  },
  {
    id: '8',
    type: 'oauth_token',
    value_preview: 'ya29.****************',
    file: 'src/integrations/google.ts',
    line: 67,
    repository: 'analytics-engine',
    branch: 'main',
    commit: 'vwx234yz567',
    severity: 'medium',
    status: 'active',
    detected_at: '2024-11-21T08:00:00Z',
    last_seen: '2024-11-21T08:00:00Z',
    false_positive: false,
  },
]

export default function SecretsPage() {
  const [secrets, setSecrets] = useState(DEMO_SECRETS)
  const [filteredSecrets, setFilteredSecrets] = useState(DEMO_SECRETS)
  const [selectedSecret, setSelectedSecret] = useState<typeof DEMO_SECRETS[0] | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [showValue, setShowValue] = useState(false)

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
    let filtered = [...secrets]

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(secret =>
        secret.type.toLowerCase().includes(query) ||
        secret.file.toLowerCase().includes(query) ||
        secret.repository.toLowerCase().includes(query)
      )
    }

    if (typeFilter !== 'all') {
      filtered = filtered.filter(secret => secret.type === typeFilter)
    }

    if (severityFilter !== 'all') {
      filtered = filtered.filter(secret => secret.severity === severityFilter)
    }

    if (statusFilter !== 'all') {
      filtered = filtered.filter(secret => secret.status === statusFilter)
    }

    setFilteredSecrets(filtered)
  }

  useState(() => {
    applyFilters()
  })

  const summary = {
    total: secrets.length,
    active: secrets.filter(s => s.status === 'active').length,
    revoked: secrets.filter(s => s.status === 'revoked').length,
    false_positives: secrets.filter(s => s.status === 'false_positive').length,
    critical: secrets.filter(s => s.severity === 'critical' && s.status === 'active').length,
    high: secrets.filter(s => s.severity === 'high' && s.status === 'active').length,
  }

  const secretTypes = Array.from(new Set(secrets.map(s => s.type)))

  return (
    <EnterpriseShell>
      <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
        {/* Left Sidebar - Filters */}
        <div className="w-72 bg-[#0f172a]/80 border-r border-white/10 flex flex-col sticky top-0 h-screen">
          {/* Header */}
          <div className="p-6 border-b border-white/10">
            <div className="flex items-center gap-3 mb-4">
              <Key size={24} className="text-[#6B5AED]" />
              <h2 className="text-lg font-semibold">Secrets Detection</h2>
            </div>
            <p className="text-xs text-slate-500">Detect and manage exposed secrets</p>
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
                        ({secrets.filter(s => s.severity === severity).length})
                      </span>
                    )}
                    {severity === 'all' && (
                      <span className="ml-2 text-xs">({secrets.length})</span>
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
                        ({secrets.filter(s => s.status === status).length})
                      </span>
                    )}
                    {status === 'all' && (
                      <span className="ml-2 text-xs">({secrets.length})</span>
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
                  <span className="ml-2 text-xs">({secrets.length})</span>
                </button>
                {secretTypes.map((type) => (
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
                      ({secrets.filter(s => s.type === type).length})
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
                <h1 className="text-2xl font-semibold mb-1">Secrets Detection</h1>
                <p className="text-sm text-slate-500">
                  Showing {filteredSecrets.length} secret{filteredSecrets.length !== 1 ? 's' : ''}
                </p>
              </div>
              <button
                onClick={() => alert('Running secrets scan...')}
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
              {filteredSecrets.map((secret) => (
                <div
                  key={secret.id}
                  onClick={() => setSelectedSecret(secret)}
                  className="bg-white/2 border border-white/5 rounded-lg p-4 hover:bg-white/5 hover:border-[#6B5AED]/30 cursor-pointer transition-all"
                >
                  <div className="flex items-start gap-4">
                    {/* Severity Indicator */}
                    <div
                      className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
                      style={{ backgroundColor: `${getSeverityColor(secret.severity)}20` }}
                    >
                      <Key size={20} style={{ color: getSeverityColor(secret.severity) }} />
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <span
                            className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium"
                            style={{ 
                              backgroundColor: `${getSeverityColor(secret.severity)}20`,
                              color: getSeverityColor(secret.severity)
                            }}
                          >
                            {secret.severity}
                          </span>
                          <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-white/5 text-slate-300">
                            {secret.type.replace('_', ' ')}
                          </span>
                          <span
                            className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium"
                            style={{ 
                              backgroundColor: `${getStatusColor(secret.status)}20`,
                              color: getStatusColor(secret.status)
                            }}
                          >
                            {getStatusIcon(secret.status)}
                            {secret.status.replace('_', ' ')}
                          </span>
                        </div>
                        <span className="text-xs text-slate-400">{formatDate(secret.detected_at)}</span>
                      </div>

                      <div className="mb-2">
                        <span className="text-sm font-semibold text-white">{secret.repository}</span>
                        <span className="text-sm text-slate-400 ml-2">/ {secret.file}:{secret.line}</span>
                      </div>

                      <div className="p-2 bg-black/20 rounded font-mono text-xs text-slate-300 mb-2">
                        {secret.value_preview}
                      </div>

                      <div className="flex items-center gap-4 text-xs text-slate-400">
                        <span className="flex items-center gap-1">
                          <GitBranch size={12} />
                          {secret.branch}
                        </span>
                        <span className="flex items-center gap-1">
                          <FileText size={12} />
                          {secret.commit.substring(0, 7)}
                        </span>
                        <span className="flex items-center gap-1">
                          <Calendar size={12} />
                          Last seen: {formatDate(secret.last_seen)}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Secret Detail Drawer */}
        {selectedSecret && (
          <div
            onClick={() => setSelectedSecret(null)}
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
                    <h3 className="text-lg font-semibold mb-1 capitalize">{selectedSecret.type.replace('_', ' ')}</h3>
                    <p className="text-sm text-slate-400">{selectedSecret.repository} / {selectedSecret.file}</p>
                  </div>
                  <button
                    onClick={() => setSelectedSecret(null)}
                    className="text-slate-400 hover:text-white transition-colors"
                  >
                    ✕
                  </button>
                </div>

                <div className="flex gap-2">
                  <span
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium"
                    style={{ 
                      backgroundColor: `${getSeverityColor(selectedSecret.severity)}20`,
                      color: getSeverityColor(selectedSecret.severity)
                    }}
                  >
                    {selectedSecret.severity}
                  </span>
                  <span
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium"
                    style={{ 
                      backgroundColor: `${getStatusColor(selectedSecret.status)}20`,
                      color: getStatusColor(selectedSecret.status)
                    }}
                  >
                    {getStatusIcon(selectedSecret.status)}
                    {selectedSecret.status.replace('_', ' ')}
                  </span>
                </div>
              </div>

              {/* Drawer Content */}
              <div className="flex-1 p-6 space-y-6">
                {/* Secret Information */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Secret Information</h4>
                  <div className="space-y-3 bg-white/5 rounded-lg p-4">
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Secret ID</span>
                      <span className="text-sm text-white font-mono">{selectedSecret.id}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Type</span>
                      <span className="text-sm text-white capitalize">{selectedSecret.type.replace('_', ' ')}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Detected</span>
                      <span className="text-sm text-white">{formatDate(selectedSecret.detected_at)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Last Seen</span>
                      <span className="text-sm text-white">{formatDate(selectedSecret.last_seen)}</span>
                    </div>
                  </div>
                </div>

                {/* Location */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Location</h4>
                  <div className="space-y-3 bg-white/5 rounded-lg p-4">
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Repository</span>
                      <span className="text-sm text-white">{selectedSecret.repository}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Branch</span>
                      <span className="text-sm text-white">{selectedSecret.branch}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">File</span>
                      <span className="text-sm text-white font-mono">{selectedSecret.file}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Line</span>
                      <span className="text-sm text-white">{selectedSecret.line}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Commit</span>
                      <span className="text-sm text-white font-mono">{selectedSecret.commit}</span>
                    </div>
                  </div>
                </div>

                {/* Secret Value */}
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="text-sm font-semibold text-slate-300">Secret Value</h4>
                    <button
                      onClick={() => setShowValue(!showValue)}
                      className="text-xs text-[#6B5AED] hover:underline flex items-center gap-1"
                    >
                      {showValue ? <EyeOff size={12} /> : <Eye size={12} />}
                      {showValue ? 'Hide' : 'Show'}
                    </button>
                  </div>
                  <div className="p-3 bg-black/20 rounded font-mono text-xs text-slate-300 break-all">
                    {showValue ? selectedSecret.value_preview : '••••••••••••••••'}
                  </div>
                  <p className="text-xs text-slate-400 mt-2">
                    ⚠️ This is a preview. Full value is redacted for security.
                  </p>
                </div>

                {/* Actions */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Actions</h4>
                  <div className="space-y-2">
                    {selectedSecret.status === 'active' && (
                      <>
                        <button className="w-full p-3 bg-red-500/10 hover:bg-red-500/20 rounded-lg text-sm text-left text-red-400 transition-colors flex items-center gap-2">
                          <Shield size={16} />
                          Revoke Secret
                        </button>
                        <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                          <XCircle size={16} />
                          Mark as False Positive
                        </button>
                      </>
                    )}
                    {selectedSecret.status === 'revoked' && (
                      <div className="p-3 bg-green-500/10 rounded-lg text-sm text-green-400 flex items-center gap-2">
                        <CheckCircle size={16} />
                        This secret has been revoked
                      </div>
                    )}
                    {selectedSecret.status === 'false_positive' && (
                      <button className="w-full p-3 bg-yellow-500/10 hover:bg-yellow-500/20 rounded-lg text-sm text-left text-yellow-400 transition-colors flex items-center gap-2">
                        <AlertTriangle size={16} />
                        Reactivate Secret
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
    </EnterpriseShell>
  )
}
