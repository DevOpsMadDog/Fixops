'use client'

import { useState } from 'react'
import { Cloud, Search, Filter, AlertTriangle, CheckCircle, XCircle, FileText, GitBranch, Calendar, Shield, Settings } from 'lucide-react'
import EnterpriseShell from './components/EnterpriseShell'

const DEMO_IAC_FINDINGS = [
  {
    id: '1',
    title: 'S3 Bucket Public Access Enabled',
    description: 'S3 bucket allows public read access which may expose sensitive data',
    severity: 'critical',
    category: 'storage',
    provider: 'aws',
    resource_type: 's3_bucket',
    resource_name: 'user-uploads-prod',
    file: 'terraform/s3.tf',
    line: 45,
    repository: 'infrastructure',
    branch: 'main',
    commit: 'abc123def456',
    status: 'open',
    detected_at: '2024-11-22T08:30:00Z',
    remediation: 'Set block_public_acls = true and block_public_policy = true',
  },
  {
    id: '2',
    title: 'Security Group Allows Unrestricted Ingress',
    description: 'Security group allows ingress from 0.0.0.0/0 on port 22 (SSH)',
    severity: 'high',
    category: 'network',
    provider: 'aws',
    resource_type: 'security_group',
    resource_name: 'web-server-sg',
    file: 'terraform/security_groups.tf',
    line: 23,
    repository: 'infrastructure',
    branch: 'main',
    commit: 'def456ghi789',
    status: 'open',
    detected_at: '2024-11-22T07:15:00Z',
    remediation: 'Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager',
  },
  {
    id: '3',
    title: 'RDS Instance Not Encrypted',
    description: 'RDS database instance does not have encryption at rest enabled',
    severity: 'high',
    category: 'database',
    provider: 'aws',
    resource_type: 'rds_instance',
    resource_name: 'postgres-prod',
    file: 'terraform/rds.tf',
    line: 67,
    repository: 'infrastructure',
    branch: 'main',
    commit: 'ghi789jkl012',
    status: 'open',
    detected_at: '2024-11-22T06:00:00Z',
    remediation: 'Set storage_encrypted = true and specify kms_key_id',
  },
  {
    id: '4',
    title: 'IAM Policy Allows Wildcard Actions',
    description: 'IAM policy grants overly permissive access with wildcard actions',
    severity: 'medium',
    category: 'iam',
    provider: 'aws',
    resource_type: 'iam_policy',
    resource_name: 'developer-policy',
    file: 'terraform/iam.tf',
    line: 89,
    repository: 'infrastructure',
    branch: 'develop',
    commit: 'jkl012mno345',
    status: 'resolved',
    detected_at: '2024-11-21T18:30:00Z',
    remediation: 'Use least privilege principle and specify exact actions needed',
  },
  {
    id: '5',
    title: 'Azure Storage Account Allows HTTP',
    description: 'Storage account allows insecure HTTP connections',
    severity: 'high',
    category: 'storage',
    provider: 'azure',
    resource_type: 'storage_account',
    resource_name: 'appstorageprod',
    file: 'terraform/azure_storage.tf',
    line: 34,
    repository: 'infrastructure',
    branch: 'main',
    commit: 'mno345pqr678',
    status: 'open',
    detected_at: '2024-11-21T15:00:00Z',
    remediation: 'Set enable_https_traffic_only = true',
  },
  {
    id: '6',
    title: 'GCP Compute Instance No OS Login',
    description: 'Compute instance does not have OS Login enabled for SSH access management',
    severity: 'medium',
    category: 'compute',
    provider: 'gcp',
    resource_type: 'compute_instance',
    resource_name: 'web-server-01',
    file: 'terraform/gcp_compute.tf',
    line: 56,
    repository: 'infrastructure',
    branch: 'main',
    commit: 'pqr678stu901',
    status: 'open',
    detected_at: '2024-11-21T12:00:00Z',
    remediation: 'Enable OS Login in project metadata and instance metadata',
  },
  {
    id: '7',
    title: 'Kubernetes Secret Not Encrypted',
    description: 'Kubernetes secret is stored in plain text in the manifest',
    severity: 'critical',
    category: 'kubernetes',
    provider: 'kubernetes',
    resource_type: 'secret',
    resource_name: 'db-credentials',
    file: 'k8s/secrets.yaml',
    line: 12,
    repository: 'k8s-manifests',
    branch: 'main',
    commit: 'stu901vwx234',
    status: 'open',
    detected_at: '2024-11-21T10:00:00Z',
    remediation: 'Use sealed-secrets, external-secrets, or a secrets management solution like Vault',
  },
  {
    id: '8',
    title: 'CloudFormation Stack Missing Termination Protection',
    description: 'CloudFormation stack does not have termination protection enabled',
    severity: 'low',
    category: 'management',
    provider: 'aws',
    resource_type: 'cloudformation_stack',
    resource_name: 'production-stack',
    file: 'cloudformation/stack.yaml',
    line: 5,
    repository: 'infrastructure',
    branch: 'main',
    commit: 'vwx234yz567',
    status: 'false_positive',
    detected_at: '2024-11-21T08:00:00Z',
    remediation: 'Enable termination protection for production stacks',
  },
]

export default function IaCPage() {
  const [findings, setFindings] = useState(DEMO_IAC_FINDINGS)
  const [filteredFindings, setFilteredFindings] = useState(DEMO_IAC_FINDINGS)
  const [selectedFinding, setSelectedFinding] = useState<typeof DEMO_IAC_FINDINGS[0] | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [categoryFilter, setCategoryFilter] = useState<string>('all')
  const [providerFilter, setProviderFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')

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
      open: '#dc2626',
      resolved: '#10b981',
      false_positive: '#6b7280',
    }
    return colors[status as keyof typeof colors] || colors.open
  }

  const getStatusIcon = (status: string) => {
    const icons = {
      open: <AlertTriangle size={14} />,
      resolved: <CheckCircle size={14} />,
      false_positive: <XCircle size={14} />,
    }
    return icons[status as keyof typeof icons] || icons.open
  }

  const getProviderColor = (provider: string) => {
    const colors = {
      aws: '#ff9900',
      azure: '#0078d4',
      gcp: '#4285f4',
      kubernetes: '#326ce5',
    }
    return colors[provider as keyof typeof colors] || '#6b7280'
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
    let filtered = [...findings]

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(finding =>
        finding.title.toLowerCase().includes(query) ||
        finding.description.toLowerCase().includes(query) ||
        finding.resource_name.toLowerCase().includes(query)
      )
    }

    if (severityFilter !== 'all') {
      filtered = filtered.filter(finding => finding.severity === severityFilter)
    }

    if (categoryFilter !== 'all') {
      filtered = filtered.filter(finding => finding.category === categoryFilter)
    }

    if (providerFilter !== 'all') {
      filtered = filtered.filter(finding => finding.provider === providerFilter)
    }

    if (statusFilter !== 'all') {
      filtered = filtered.filter(finding => finding.status === statusFilter)
    }

    setFilteredFindings(filtered)
  }

  useState(() => {
    applyFilters()
  })

  const summary = {
    total: findings.length,
    open: findings.filter(f => f.status === 'open').length,
    resolved: findings.filter(f => f.status === 'resolved').length,
    critical: findings.filter(f => f.severity === 'critical' && f.status === 'open').length,
    high: findings.filter(f => f.severity === 'high' && f.status === 'open').length,
  }

  const categories = Array.from(new Set(findings.map(f => f.category)))
  const providers = Array.from(new Set(findings.map(f => f.provider)))

  return (
    <EnterpriseShell>
      <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
        {/* Left Sidebar - Filters */}
        <div className="w-72 bg-[#0f172a]/80 border-r border-white/10 flex flex-col sticky top-0 h-screen">
          {/* Header */}
          <div className="p-6 border-b border-white/10">
            <div className="flex items-center gap-3 mb-4">
              <Cloud size={24} className="text-[#6B5AED]" />
              <h2 className="text-lg font-semibold">IaC Scanning</h2>
            </div>
            <p className="text-xs text-slate-500">Infrastructure security findings</p>
          </div>

          {/* Summary Stats */}
          <div className="p-4 border-b border-white/10">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Total Findings</div>
                <div className="text-xl font-semibold text-[#6B5AED]">{summary.total}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Open</div>
                <div className="text-xl font-semibold text-red-500">{summary.open}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Critical</div>
                <div className="text-xl font-semibold text-orange-500">{summary.critical}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Resolved</div>
                <div className="text-xl font-semibold text-green-500">{summary.resolved}</div>
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

            <div className="mb-6">
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Filter size={12} />
                Filter by Provider
              </div>
              <div className="space-y-2">
                <button
                  onClick={() => { setProviderFilter('all'); applyFilters(); }}
                  className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                    providerFilter === 'all'
                      ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                      : 'text-slate-400 hover:bg-white/5'
                  }`}
                >
                  All Providers
                  <span className="ml-2 text-xs">({findings.length})</span>
                </button>
                {providers.map((provider) => (
                  <button
                    key={provider}
                    onClick={() => { setProviderFilter(provider); applyFilters(); }}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      providerFilter === provider
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="uppercase">{provider}</span>
                    <span className="ml-2 text-xs">
                      ({findings.filter(f => f.provider === provider).length})
                    </span>
                  </button>
                ))}
              </div>
            </div>

            <div className="mb-6">
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Filter size={12} />
                Filter by Category
              </div>
              <div className="space-y-2">
                <button
                  onClick={() => { setCategoryFilter('all'); applyFilters(); }}
                  className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                    categoryFilter === 'all'
                      ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                      : 'text-slate-400 hover:bg-white/5'
                  }`}
                >
                  All Categories
                  <span className="ml-2 text-xs">({findings.length})</span>
                </button>
                {categories.map((category) => (
                  <button
                    key={category}
                    onClick={() => { setCategoryFilter(category); applyFilters(); }}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      categoryFilter === category
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="capitalize">{category}</span>
                    <span className="ml-2 text-xs">
                      ({findings.filter(f => f.category === category).length})
                    </span>
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
                {['all', 'open', 'resolved', 'false_positive'].map((status) => (
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
                        ({findings.filter(f => f.status === status).length})
                      </span>
                    )}
                    {status === 'all' && (
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
                <h1 className="text-2xl font-semibold mb-1">IaC Security Findings</h1>
                <p className="text-sm text-slate-500">
                  Showing {filteredFindings.length} finding{filteredFindings.length !== 1 ? 's' : ''}
                </p>
              </div>
              <button
                onClick={() => alert('Running IaC scan...')}
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
                placeholder="Search by title, description, or resource..."
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); applyFilters(); }}
                className="w-full pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-[#6B5AED]/50"
              />
            </div>
          </div>

          {/* Findings List */}
          <div className="flex-1 overflow-auto p-6">
            <div className="space-y-3">
              {filteredFindings.map((finding) => (
                <div
                  key={finding.id}
                  onClick={() => setSelectedFinding(finding)}
                  className="bg-white/2 border border-white/5 rounded-lg p-4 hover:bg-white/5 hover:border-[#6B5AED]/30 cursor-pointer transition-all"
                >
                  <div className="flex items-start gap-4">
                    {/* Severity Indicator */}
                    <div
                      className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
                      style={{ backgroundColor: `${getSeverityColor(finding.severity)}20` }}
                    >
                      <Cloud size={20} style={{ color: getSeverityColor(finding.severity) }} />
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span
                            className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium"
                            style={{ 
                              backgroundColor: `${getSeverityColor(finding.severity)}20`,
                              color: getSeverityColor(finding.severity)
                            }}
                          >
                            {finding.severity}
                          </span>
                          <span
                            className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium"
                            style={{ 
                              backgroundColor: `${getProviderColor(finding.provider)}20`,
                              color: getProviderColor(finding.provider)
                            }}
                          >
                            {finding.provider.toUpperCase()}
                          </span>
                          <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-white/5 text-slate-300 capitalize">
                            {finding.category}
                          </span>
                          <span
                            className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium"
                            style={{ 
                              backgroundColor: `${getStatusColor(finding.status)}20`,
                              color: getStatusColor(finding.status)
                            }}
                          >
                            {getStatusIcon(finding.status)}
                            {finding.status.replace('_', ' ')}
                          </span>
                        </div>
                        <span className="text-xs text-slate-400">{formatDate(finding.detected_at)}</span>
                      </div>

                      <div className="mb-2">
                        <span className="text-sm font-semibold text-white">{finding.title}</span>
                      </div>

                      <p className="text-sm text-slate-300 mb-2">{finding.description}</p>

                      <div className="flex items-center gap-4 text-xs text-slate-400">
                        <span className="flex items-center gap-1">
                          <Settings size={12} />
                          {finding.resource_type}: {finding.resource_name}
                        </span>
                        <span className="flex items-center gap-1">
                          <FileText size={12} />
                          {finding.file}:{finding.line}
                        </span>
                        <span className="flex items-center gap-1">
                          <GitBranch size={12} />
                          {finding.branch}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Finding Detail Drawer */}
        {selectedFinding && (
          <div
            onClick={() => setSelectedFinding(null)}
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
                    <h3 className="text-lg font-semibold mb-1">{selectedFinding.title}</h3>
                    <p className="text-sm text-slate-400">{selectedFinding.resource_type}: {selectedFinding.resource_name}</p>
                  </div>
                  <button
                    onClick={() => setSelectedFinding(null)}
                    className="text-slate-400 hover:text-white transition-colors"
                  >
                    ✕
                  </button>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <span
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium"
                    style={{ 
                      backgroundColor: `${getSeverityColor(selectedFinding.severity)}20`,
                      color: getSeverityColor(selectedFinding.severity)
                    }}
                  >
                    {selectedFinding.severity}
                  </span>
                  <span
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium"
                    style={{ 
                      backgroundColor: `${getProviderColor(selectedFinding.provider)}20`,
                      color: getProviderColor(selectedFinding.provider)
                    }}
                  >
                    {selectedFinding.provider.toUpperCase()}
                  </span>
                  <span className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium bg-white/5 text-slate-300 capitalize">
                    {selectedFinding.category}
                  </span>
                  <span
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium"
                    style={{ 
                      backgroundColor: `${getStatusColor(selectedFinding.status)}20`,
                      color: getStatusColor(selectedFinding.status)
                    }}
                  >
                    {getStatusIcon(selectedFinding.status)}
                    {selectedFinding.status.replace('_', ' ')}
                  </span>
                </div>
              </div>

              {/* Drawer Content */}
              <div className="flex-1 p-6 space-y-6">
                {/* Description */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Description</h4>
                  <div className="p-4 bg-white/5 rounded-lg">
                    <p className="text-sm text-white">{selectedFinding.description}</p>
                  </div>
                </div>

                {/* Resource Information */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Resource Information</h4>
                  <div className="space-y-3 bg-white/5 rounded-lg p-4">
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Resource Type</span>
                      <span className="text-sm text-white">{selectedFinding.resource_type}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Resource Name</span>
                      <span className="text-sm text-white">{selectedFinding.resource_name}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Provider</span>
                      <span className="text-sm text-white uppercase">{selectedFinding.provider}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Category</span>
                      <span className="text-sm text-white capitalize">{selectedFinding.category}</span>
                    </div>
                  </div>
                </div>

                {/* Location */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Location</h4>
                  <div className="space-y-3 bg-white/5 rounded-lg p-4">
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Repository</span>
                      <span className="text-sm text-white">{selectedFinding.repository}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Branch</span>
                      <span className="text-sm text-white">{selectedFinding.branch}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">File</span>
                      <span className="text-sm text-white font-mono">{selectedFinding.file}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Line</span>
                      <span className="text-sm text-white">{selectedFinding.line}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Commit</span>
                      <span className="text-sm text-white font-mono">{selectedFinding.commit}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Detected</span>
                      <span className="text-sm text-white">{formatDate(selectedFinding.detected_at)}</span>
                    </div>
                  </div>
                </div>

                {/* Remediation */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Remediation</h4>
                  <div className="p-4 bg-[#6B5AED]/10 rounded-lg border border-[#6B5AED]/30">
                    <p className="text-sm text-white">{selectedFinding.remediation}</p>
                  </div>
                </div>

                {/* Actions */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Actions</h4>
                  <div className="space-y-2">
                    {selectedFinding.status === 'open' && (
                      <>
                        <button className="w-full p-3 bg-green-500/10 hover:bg-green-500/20 rounded-lg text-sm text-left text-green-400 transition-colors flex items-center gap-2">
                          <CheckCircle size={16} />
                          Mark as Resolved
                        </button>
                        <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                          <XCircle size={16} />
                          Mark as False Positive
                        </button>
                      </>
                    )}
                    {selectedFinding.status === 'resolved' && (
                      <div className="p-3 bg-green-500/10 rounded-lg text-sm text-green-400 flex items-center gap-2">
                        <CheckCircle size={16} />
                        This finding has been resolved
                      </div>
                    )}
                    {selectedFinding.status === 'false_positive' && (
                      <button className="w-full p-3 bg-yellow-500/10 hover:bg-yellow-500/20 rounded-lg text-sm text-left text-yellow-400 transition-colors flex items-center gap-2">
                        <AlertTriangle size={16} />
                        Reopen Finding
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
