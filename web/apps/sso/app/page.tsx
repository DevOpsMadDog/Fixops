'use client'

import { useState, useEffect, useMemo } from 'react'
import { Shield, Search, Plus, Edit2, Trash2, CheckCircle, XCircle, Key, Globe, Users, Settings, Filter, Calendar, Loader2, RefreshCw, WifiOff } from 'lucide-react'
import { AppShell, useDemoModeContext } from '@fixops/ui'
import { useIntegrations } from '@fixops/api-client'

const DEMO_SSO_PROVIDERS = [
  {
    id: '1',
    name: 'Okta Corporate',
    provider: 'okta',
    domain: 'fixops.okta.com',
    entity_id: 'https://fixops.okta.com/saml2/idp',
    sso_url: 'https://fixops.okta.com/app/fixops/sso/saml',
    certificate: '-----BEGIN CERTIFICATE-----\nMIIDpDCCAoygAwIBAgIGAXxyz...',
    status: 'active',
    users_count: 145,
    last_login: '2024-11-22T09:15:00Z',
    created_at: '2024-01-15T10:00:00Z',
  },
  {
    id: '2',
    name: 'Azure AD',
    provider: 'azure',
    domain: 'fixops.onmicrosoft.com',
    entity_id: 'https://sts.windows.net/abc123/',
    sso_url: 'https://login.microsoftonline.com/abc123/saml2',
    certificate: '-----BEGIN CERTIFICATE-----\nMIIDpDCCAoygAwIBAgIGAXxyz...',
    status: 'active',
    users_count: 89,
    last_login: '2024-11-22T08:45:00Z',
    created_at: '2024-02-01T14:30:00Z',
  },
  {
    id: '3',
    name: 'Google Workspace',
    provider: 'google',
    domain: 'fixops.com',
    entity_id: 'https://accounts.google.com/o/saml2?idpid=C01abc123',
    sso_url: 'https://accounts.google.com/o/saml2/idp?idpid=C01abc123',
    certificate: '-----BEGIN CERTIFICATE-----\nMIIDpDCCAoygAwIBAgIGAXxyz...',
    status: 'active',
    users_count: 67,
    last_login: '2024-11-22T07:30:00Z',
    created_at: '2024-03-10T09:00:00Z',
  },
  {
    id: '4',
    name: 'OneLogin',
    provider: 'onelogin',
    domain: 'fixops.onelogin.com',
    entity_id: 'https://app.onelogin.com/saml/metadata/123456',
    sso_url: 'https://fixops.onelogin.com/trust/saml2/http-post/sso/123456',
    certificate: '-----BEGIN CERTIFICATE-----\nMIIDpDCCAoygAwIBAgIGAXxyz...',
    status: 'inactive',
    users_count: 0,
    last_login: null,
    created_at: '2024-04-05T11:20:00Z',
  },
]

export default function SSOPage() {
  const { demoEnabled } = useDemoModeContext()
  const { data: apiData, loading: apiLoading, error: apiError, refetch } = useIntegrations()
  
  // Transform API data to match our UI format, or use demo data
  const providersData = useMemo(() => {
    if (demoEnabled || !apiData?.items) {
      return DEMO_SSO_PROVIDERS
    }
    // Filter for SSO-related integrations
    const ssoIntegrations = apiData.items.filter(i => 
      i.type === 'sso' || i.category === 'authentication'
    )
    return ssoIntegrations.map(integration => ({
      id: integration.id,
      name: integration.name,
      provider: integration.provider || 'okta',
      domain: integration.domain || 'unknown',
      entity_id: integration.entity_id || '',
      sso_url: integration.sso_url || '',
      certificate: integration.certificate || '',
      status: integration.status || 'inactive',
      users_count: integration.users_count || 0,
      last_login: integration.last_login,
      created_at: integration.created_at,
    }))
  }, [demoEnabled, apiData])

  const [providers, setProviders] = useState(DEMO_SSO_PROVIDERS)
  const [filteredProviders, setFilteredProviders] = useState(DEMO_SSO_PROVIDERS)
  const [selectedProvider, setSelectedProvider] = useState<typeof DEMO_SSO_PROVIDERS[0] | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [providerFilter, setProviderFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [showCreateModal, setShowCreateModal] = useState(false)

  // Update providers when data source changes
  useEffect(() => {
    setProviders(providersData)
    setFilteredProviders(providersData)
  }, [providersData])

  const getProviderColor = (provider: string) => {
    const colors = {
      okta: '#007dc1',
      azure: '#0078d4',
      google: '#4285f4',
      onelogin: '#2c3e50',
    }
    return colors[provider as keyof typeof colors] || '#6b7280'
  }

  const getProviderIcon = (provider: string) => {
    return <Shield size={20} />
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
    let filtered = [...providers]

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(provider =>
        provider.name.toLowerCase().includes(query) ||
        provider.domain.toLowerCase().includes(query)
      )
    }

    if (providerFilter !== 'all') {
      filtered = filtered.filter(provider => provider.provider === providerFilter)
    }

    if (statusFilter !== 'all') {
      filtered = filtered.filter(provider => provider.status === statusFilter)
    }

    setFilteredProviders(filtered)
  }

  useState(() => {
    applyFilters()
  })

  const summary = {
    total: providers.length,
    active: providers.filter(p => p.status === 'active').length,
    inactive: providers.filter(p => p.status === 'inactive').length,
    total_users: providers.reduce((sum, p) => sum + p.users_count, 0),
  }

  const providerTypes = Array.from(new Set(providers.map(p => p.provider)))

  return (
    <AppShell activeApp="sso">
      <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
        {/* Left Sidebar - Filters */}
        <div className="w-72 bg-[#0f172a]/80 border-r border-white/10 flex flex-col sticky top-0 h-screen">
          {/* Header */}
          <div className="p-6 border-b border-white/10">
            <div className="flex items-center gap-3 mb-4">
              <Shield size={24} className="text-[#6B5AED]" />
              <h2 className="text-lg font-semibold">SSO Configuration</h2>
            </div>
            <p className="text-xs text-slate-500">Manage SAML identity providers</p>
          </div>

          {/* Summary Stats */}
          <div className="p-4 border-b border-white/10">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Total Providers</div>
                <div className="text-xl font-semibold text-[#6B5AED]">{summary.total}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Active</div>
                <div className="text-xl font-semibold text-green-500">{summary.active}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Total Users</div>
                <div className="text-xl font-semibold text-blue-500">{summary.total_users}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Inactive</div>
                <div className="text-xl font-semibold text-gray-500">{summary.inactive}</div>
              </div>
            </div>
          </div>

          {/* Filters */}
          <div className="p-4 flex-1 overflow-auto">
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
                  <span className="ml-2 text-xs">({providers.length})</span>
                </button>
                {providerTypes.map((type) => (
                  <button
                    key={type}
                    onClick={() => { setProviderFilter(type); applyFilters(); }}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      providerFilter === type
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="capitalize">{type}</span>
                    <span className="ml-2 text-xs">
                      ({providers.filter(p => p.provider === type).length})
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
                {['all', 'active', 'inactive'].map((status) => (
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
                    {status !== 'all' && (
                      <span className="ml-2 text-xs">
                        ({providers.filter(p => p.status === status).length})
                      </span>
                    )}
                    {status === 'all' && (
                      <span className="ml-2 text-xs">({providers.length})</span>
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
                <h1 className="text-2xl font-semibold mb-1">SSO Providers</h1>
                <p className="text-sm text-slate-500">
                  Showing {filteredProviders.length} provider{filteredProviders.length !== 1 ? 's' : ''}
                </p>
              </div>
              <button
                onClick={() => setShowCreateModal(true)}
                className="px-4 py-2 bg-[#6B5AED] hover:bg-[#5B4ADD] rounded-md text-white text-sm font-medium transition-all flex items-center gap-2"
              >
                <Plus size={16} />
                Add Provider
              </button>
            </div>

            {/* Search Bar */}
            <div className="relative">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search by name or domain..."
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); applyFilters(); }}
                className="w-full pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-[#6B5AED]/50"
              />
            </div>
          </div>

          {/* Providers Grid */}
          <div className="flex-1 overflow-auto p-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {filteredProviders.map((provider) => (
                <div
                  key={provider.id}
                  onClick={() => setSelectedProvider(provider)}
                  className="bg-white/2 border border-white/5 rounded-lg p-5 hover:bg-white/5 hover:border-[#6B5AED]/30 cursor-pointer transition-all"
                >
                  {/* Header */}
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div
                        className="w-10 h-10 rounded-lg flex items-center justify-center"
                        style={{ backgroundColor: `${getProviderColor(provider.provider)}20` }}
                      >
                        <span style={{ color: getProviderColor(provider.provider) }}>
                          {getProviderIcon(provider.provider)}
                        </span>
                      </div>
                      <div>
                        <h3 className="text-sm font-semibold text-white">{provider.name}</h3>
                        <p className="text-xs text-slate-400 capitalize">{provider.provider}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${provider.status === 'active' ? 'bg-green-500' : 'bg-gray-500'}`} />
                      <span className="text-xs text-slate-400 capitalize">{provider.status}</span>
                    </div>
                  </div>

                  {/* Domain */}
                  <div className="mb-4 p-3 bg-white/5 rounded-lg">
                    <div className="text-xs text-slate-400 mb-1">Domain</div>
                    <div className="text-sm text-white font-mono flex items-center gap-2">
                      <Globe size={14} />
                      {provider.domain}
                    </div>
                  </div>

                  {/* Stats */}
                  <div className="grid grid-cols-2 gap-3 mb-4">
                    <div className="p-3 bg-white/5 rounded-lg text-center">
                      <div className="text-xs text-slate-400 mb-1">Users</div>
                      <div className="text-lg font-semibold text-[#6B5AED]">{provider.users_count}</div>
                    </div>
                    <div className="p-3 bg-white/5 rounded-lg text-center">
                      <div className="text-xs text-slate-400 mb-1">Last Login</div>
                      <div className="text-sm font-semibold text-green-500">{formatDate(provider.last_login)}</div>
                    </div>
                  </div>

                  {/* Footer */}
                  <div className="flex items-center justify-between pt-3 border-t border-white/5">
                    <div className="flex items-center gap-2 text-xs text-slate-400">
                      <Calendar size={12} />
                      Created {formatDate(provider.created_at)}
                    </div>
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        alert(`Testing SSO connection for ${provider.name}...`)
                      }}
                      className="text-xs text-[#6B5AED] hover:underline"
                    >
                      Test Connection
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Provider Detail Drawer */}
        {selectedProvider && (
          <div
            onClick={() => setSelectedProvider(null)}
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
                    <div
                      className="w-12 h-12 rounded-lg flex items-center justify-center"
                      style={{ backgroundColor: `${getProviderColor(selectedProvider.provider)}20` }}
                    >
                      <span style={{ color: getProviderColor(selectedProvider.provider) }}>
                        {getProviderIcon(selectedProvider.provider)}
                      </span>
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold">{selectedProvider.name}</h3>
                      <p className="text-sm text-slate-400 capitalize">{selectedProvider.provider}</p>
                    </div>
                  </div>
                  <button
                    onClick={() => setSelectedProvider(null)}
                    className="text-slate-400 hover:text-white transition-colors"
                  >
                    ✕
                  </button>
                </div>

                <div className="flex gap-2">
                  <span
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium"
                    style={{ 
                      backgroundColor: `${getProviderColor(selectedProvider.provider)}20`,
                      color: getProviderColor(selectedProvider.provider)
                    }}
                  >
                    <Shield size={14} />
                    {selectedProvider.provider}
                  </span>
                  <span className={`inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium ${
                    selectedProvider.status === 'active' ? 'bg-green-500/10 text-green-500' : 'bg-gray-500/10 text-gray-500'
                  }`}>
                    {selectedProvider.status === 'active' ? <CheckCircle size={14} /> : <XCircle size={14} />}
                    {selectedProvider.status}
                  </span>
                </div>
              </div>

              {/* Drawer Content */}
              <div className="flex-1 p-6 space-y-6">
                {/* Provider Information */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Provider Information</h4>
                  <div className="space-y-3 bg-white/5 rounded-lg p-4">
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Provider ID</span>
                      <span className="text-sm text-white font-mono">{selectedProvider.id}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Domain</span>
                      <span className="text-sm text-white">{selectedProvider.domain}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Users</span>
                      <span className="text-sm text-white">{selectedProvider.users_count}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Last Login</span>
                      <span className="text-sm text-white">{formatDate(selectedProvider.last_login)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Created</span>
                      <span className="text-sm text-white">{formatDate(selectedProvider.created_at)}</span>
                    </div>
                  </div>
                </div>

                {/* SAML Configuration */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
                    <Key size={16} />
                    SAML Configuration
                  </h4>
                  <div className="space-y-3 bg-white/5 rounded-lg p-4">
                    <div>
                      <div className="text-sm text-slate-400 mb-1">Entity ID</div>
                      <div className="text-xs text-white font-mono break-all bg-black/20 p-2 rounded">
                        {selectedProvider.entity_id}
                      </div>
                    </div>
                    <div>
                      <div className="text-sm text-slate-400 mb-1">SSO URL</div>
                      <div className="text-xs text-white font-mono break-all bg-black/20 p-2 rounded">
                        {selectedProvider.sso_url}
                      </div>
                    </div>
                    <div>
                      <div className="text-sm text-slate-400 mb-1">Certificate</div>
                      <div className="text-xs text-white font-mono break-all bg-black/20 p-2 rounded max-h-32 overflow-auto">
                        {selectedProvider.certificate}...
                      </div>
                    </div>
                  </div>
                </div>

                {/* Actions */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Actions</h4>
                  <div className="space-y-2">
                    <button
                      onClick={() => alert(`Testing SSO connection for ${selectedProvider.name}...`)}
                      className="w-full p-3 bg-[#6B5AED]/10 hover:bg-[#6B5AED]/20 rounded-lg text-sm text-left text-[#6B5AED] transition-colors flex items-center gap-2"
                    >
                      <Settings size={16} />
                      Test Connection
                    </button>
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <Edit2 size={16} />
                      Edit Configuration
                    </button>
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <Users size={16} />
                      View Users
                    </button>
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <Key size={16} />
                      Download Metadata
                    </button>
                    {selectedProvider.status === 'active' ? (
                      <button className="w-full p-3 bg-yellow-500/10 hover:bg-yellow-500/20 rounded-lg text-sm text-left text-yellow-400 transition-colors flex items-center gap-2">
                        <XCircle size={16} />
                        Disable Provider
                      </button>
                    ) : (
                      <button className="w-full p-3 bg-green-500/10 hover:bg-green-500/20 rounded-lg text-sm text-left text-green-400 transition-colors flex items-center gap-2">
                        <CheckCircle size={16} />
                        Enable Provider
                      </button>
                    )}
                    <button className="w-full p-3 bg-red-500/10 hover:bg-red-500/20 rounded-lg text-sm text-left text-red-400 transition-colors flex items-center gap-2">
                      <Trash2 size={16} />
                      Delete Provider
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
