'use client'

import { useState, useMemo } from 'react'
import { Search, Check, Plus, RefreshCw, Settings, ArrowLeft, Shield, Code, Cloud, Database, AlertCircle, Download, Upload, Filter, X } from 'lucide-react'
import { AppShell, useDemoModeContext } from '@fixops/ui'
import { useInventory } from '@fixops/api-client'

interface Scanner {
  id: string
  name: string
  description: string
  category: 'infrastructure' | 'application' | 'cloud' | 'cmdb'
  status: 'connected' | 'available' | 'error'
  icon: string
  config?: {
    url?: string
    api_key_configured?: boolean
    last_sync?: string
  }
  stats?: {
    assets: number
    vulnerabilities: number
    last_scan?: string
  }
}

const DEMO_SCANNERS: Scanner[] = [
  {
    id: 'qualys',
    name: 'Qualys VM',
    description: 'Enterprise vulnerability management and compliance',
    category: 'infrastructure',
    status: 'connected',
    icon: '🛡️',
    config: {
      url: 'https://qualysapi.qualys.com',
      api_key_configured: true,
      last_sync: '2024-11-21T10:30:00Z',
    },
    stats: {
      assets: 2847,
      vulnerabilities: 12453,
      last_scan: '2024-11-21T08:00:00Z',
    },
  },
  {
    id: 'tenable-nessus',
    name: 'Tenable Nessus',
    description: 'Network vulnerability scanner',
    category: 'infrastructure',
    status: 'connected',
    icon: '🔍',
    config: {
      url: 'https://nessus.company.com',
      api_key_configured: true,
      last_sync: '2024-11-21T09:15:00Z',
    },
    stats: {
      assets: 1523,
      vulnerabilities: 8721,
      last_scan: '2024-11-21T06:00:00Z',
    },
  },
  {
    id: 'tenable-io',
    name: 'Tenable.io',
    description: 'Cloud-based vulnerability management',
    category: 'infrastructure',
    status: 'connected',
    icon: '☁️',
    config: {
      url: 'https://cloud.tenable.com',
      api_key_configured: true,
      last_sync: '2024-11-21T11:00:00Z',
    },
    stats: {
      assets: 3421,
      vulnerabilities: 15234,
      last_scan: '2024-11-21T10:00:00Z',
    },
  },
  {
    id: 'rapid7',
    name: 'Rapid7 InsightVM',
    description: 'Vulnerability risk management',
    category: 'infrastructure',
    status: 'available',
    icon: '⚡',
  },
  {
    id: 'crowdstrike',
    name: 'CrowdStrike Spotlight',
    description: 'Endpoint vulnerability assessment',
    category: 'infrastructure',
    status: 'available',
    icon: '🦅',
  },
  {
    id: 'checkmarx',
    name: 'Checkmarx SAST',
    description: 'Static application security testing',
    category: 'application',
    status: 'connected',
    icon: '🔐',
    config: {
      url: 'https://checkmarx.company.com',
      api_key_configured: true,
      last_sync: '2024-11-21T07:30:00Z',
    },
    stats: {
      assets: 156,
      vulnerabilities: 2341,
      last_scan: '2024-11-21T06:00:00Z',
    },
  },
  {
    id: 'veracode-static',
    name: 'Veracode Static',
    description: 'Static analysis security testing',
    category: 'application',
    status: 'connected',
    icon: '📊',
    config: {
      url: 'https://analysiscenter.veracode.com',
      api_key_configured: true,
      last_sync: '2024-11-21T08:45:00Z',
    },
    stats: {
      assets: 89,
      vulnerabilities: 1876,
      last_scan: '2024-11-21T07:00:00Z',
    },
  },
  {
    id: 'veracode-dynamic',
    name: 'Veracode Dynamic',
    description: 'Dynamic application security testing',
    category: 'application',
    status: 'available',
    icon: '🌐',
  },
  {
    id: 'sonarqube',
    name: 'SonarQube',
    description: 'Code quality and security analysis',
    category: 'application',
    status: 'connected',
    icon: '📈',
    config: {
      url: 'https://sonar.company.com',
      api_key_configured: true,
      last_sync: '2024-11-21T10:00:00Z',
    },
    stats: {
      assets: 234,
      vulnerabilities: 4521,
      last_scan: '2024-11-21T09:30:00Z',
    },
  },
  {
    id: 'burp-suite',
    name: 'Burp Suite Pro',
    description: 'Web application security testing',
    category: 'application',
    status: 'available',
    icon: '🕷️',
  },
  {
    id: 'github-sast',
    name: 'GitHub Advanced Security',
    description: 'Native GitHub code scanning',
    category: 'application',
    status: 'connected',
    icon: '🐙',
    config: {
      url: 'https://github.com',
      api_key_configured: true,
      last_sync: '2024-11-21T11:15:00Z',
    },
    stats: {
      assets: 312,
      vulnerabilities: 1234,
      last_scan: '2024-11-21T11:00:00Z',
    },
  },
  {
    id: 'aws-inspector',
    name: 'AWS Inspector',
    description: 'AWS workload vulnerability assessment',
    category: 'cloud',
    status: 'connected',
    icon: '🔶',
    config: {
      url: 'https://inspector.us-east-1.amazonaws.com',
      api_key_configured: true,
      last_sync: '2024-11-21T10:45:00Z',
    },
    stats: {
      assets: 1247,
      vulnerabilities: 3892,
      last_scan: '2024-11-21T10:00:00Z',
    },
  },
  {
    id: 'prisma-cloud',
    name: 'Prisma Cloud',
    description: 'Cloud security posture management',
    category: 'cloud',
    status: 'connected',
    icon: '🔷',
    config: {
      url: 'https://api.prismacloud.io',
      api_key_configured: true,
      last_sync: '2024-11-21T09:30:00Z',
    },
    stats: {
      assets: 2156,
      vulnerabilities: 5678,
      last_scan: '2024-11-21T09:00:00Z',
    },
  },
  {
    id: 'wiz',
    name: 'Wiz',
    description: 'Cloud infrastructure security',
    category: 'cloud',
    status: 'available',
    icon: '✨',
  },
  {
    id: 'snyk',
    name: 'Snyk',
    description: 'Developer-first security platform',
    category: 'cloud',
    status: 'connected',
    icon: '🐍',
    config: {
      url: 'https://snyk.io',
      api_key_configured: true,
      last_sync: '2024-11-21T11:30:00Z',
    },
    stats: {
      assets: 456,
      vulnerabilities: 2134,
      last_scan: '2024-11-21T11:00:00Z',
    },
  },
  {
    id: 'snyk-container',
    name: 'Snyk Container',
    description: 'Container image vulnerability scanning',
    category: 'cloud',
    status: 'available',
    icon: '📦',
  },
  {
    id: 'jfrog',
    name: 'JFrog Xray',
    description: 'Universal artifact analysis',
    category: 'cloud',
    status: 'available',
    icon: '🐸',
  },
  {
    id: 'servicenow',
    name: 'ServiceNow CMDB',
    description: 'IT service management and CMDB',
    category: 'cmdb',
    status: 'connected',
    icon: '📋',
    config: {
      url: 'https://company.service-now.com',
      api_key_configured: true,
      last_sync: '2024-11-21T08:00:00Z',
    },
    stats: {
      assets: 8934,
      vulnerabilities: 0,
      last_scan: '2024-11-21T07:00:00Z',
    },
  },
  {
    id: 'bmc-remedy',
    name: 'BMC Remedy',
    description: 'IT service management platform',
    category: 'cmdb',
    status: 'available',
    icon: '🔧',
  },
  {
    id: 'active-directory',
    name: 'Active Directory',
    description: 'Microsoft directory services',
    category: 'cmdb',
    status: 'connected',
    icon: '🏢',
    config: {
      url: 'ldap://ad.company.com',
      api_key_configured: true,
      last_sync: '2024-11-21T06:00:00Z',
    },
    stats: {
      assets: 12456,
      vulnerabilities: 0,
      last_scan: '2024-11-21T05:00:00Z',
    },
  },
  {
    id: 'aws-cloud',
    name: 'AWS Cloud',
    description: 'Amazon Web Services asset discovery',
    category: 'cmdb',
    status: 'connected',
    icon: '🔶',
    config: {
      url: 'https://aws.amazon.com',
      api_key_configured: true,
      last_sync: '2024-11-21T10:00:00Z',
    },
    stats: {
      assets: 3421,
      vulnerabilities: 0,
      last_scan: '2024-11-21T09:30:00Z',
    },
  },
  {
    id: 'azure-cloud',
    name: 'Azure Cloud',
    description: 'Microsoft Azure asset discovery',
    category: 'cmdb',
    status: 'available',
    icon: '🔵',
  },
]

const CATEGORY_INFO = {
  infrastructure: { label: 'Infrastructure', icon: Shield, color: 'text-blue-400' },
  application: { label: 'Application (SAST/DAST)', icon: Code, color: 'text-purple-400' },
  cloud: { label: 'Cloud / Container', icon: Cloud, color: 'text-cyan-400' },
  cmdb: { label: 'CMDB / Asset Sources', icon: Database, color: 'text-orange-400' },
}

function formatTimeAgo(dateString: string): string {
  const date = new Date(dateString)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60))
  const diffDays = Math.floor(diffHours / 24)
  
  if (diffDays > 0) return `${diffDays}d ago`
  if (diffHours > 0) return `${diffHours}h ago`
  return 'Just now'
}

function formatNumber(num: number): string {
  if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`
  return num.toString()
}

export default function ScannersPage() {
  const { demoEnabled } = useDemoModeContext()
  const { data: apiData, loading: apiLoading, error: apiError, refetch } = useInventory()
    const [selectedCategory, setSelectedCategory] = useState<string>('all')
    const [searchQuery, setSearchQuery] = useState('')
    const [selectedScanner, setSelectedScanner] = useState<Scanner | null>(null)
    const [isConfiguring, setIsConfiguring] = useState(false)
    const [configForm, setConfigForm] = useState({ url: '', apiKey: '' })
    const [showMobileFilters, setShowMobileFilters] = useState(false)

    // Transform API data to match our UI format, or use demo data
    // Note: Inventory API doesn't have scanner-specific fields, so we use demo data
    const scannersData = useMemo(() => {
      // Always use demo data since inventory API doesn't have scanner-specific fields
      return DEMO_SCANNERS
    }, [])

  // Use scannersData directly instead of storing in state to avoid lint errors
  const scanners = scannersData.length > 0 ? scannersData : DEMO_SCANNERS

  const filteredScanners = useMemo(() => {
    return scanners.filter(scanner => {
      const matchesCategory = selectedCategory === 'all' || scanner.category === selectedCategory
      const matchesSearch = scanner.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                           scanner.description.toLowerCase().includes(searchQuery.toLowerCase())
      return matchesCategory && matchesSearch
    })
  }, [scanners, selectedCategory, searchQuery])

  const connectedCount = scanners.filter(s => s.status === 'connected').length
  const totalAssets = scanners.reduce((sum, s) => sum + (s.stats?.assets || 0), 0)
  const totalVulns = scanners.reduce((sum, s) => sum + (s.stats?.vulnerabilities || 0), 0)

  const handleConnect = (scanner: Scanner) => {
    setSelectedScanner(scanner)
    setIsConfiguring(true)
    setConfigForm({ url: scanner.config?.url || '', apiKey: '' })
  }

  const handleSaveConfig = () => {
    setIsConfiguring(false)
    setSelectedScanner(null)
  }

  const handleSync = (scanner: Scanner) => {
    console.log('Syncing scanner:', scanner.id)
  }

  const handleExportCSV = () => {
    const headers = ['Name', 'Category', 'Status', 'Assets', 'Vulnerabilities', 'Last Sync']
    const rows = scanners.map(s => [
      s.name,
      CATEGORY_INFO[s.category].label,
      s.status,
      s.stats?.assets || 0,
      s.stats?.vulnerabilities || 0,
      s.config?.last_sync || 'N/A'
    ])
    const csv = [headers, ...rows].map(row => row.join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'scanners-export.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <AppShell activeApp="scanners">
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
                      <div className="relative">
                        <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                        <input
                          type="text"
                          placeholder="Search scanners..."
                          value={searchQuery}
                          onChange={(e) => setSearchQuery(e.target.value)}
                          className="w-full pl-9 pr-4 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                        />
                      </div>
                    </div>
                    <div className="p-4 flex-1 overflow-auto">
                      <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">Categories</div>
                      <div className="space-y-1">
                        <button
                          onClick={() => { setSelectedCategory('all'); setShowMobileFilters(false); }}
                          className={`w-full px-3 py-2 rounded-md text-left text-sm transition-all ${selectedCategory === 'all' ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30' : 'text-slate-400 hover:bg-white/5'}`}
                        >
                          All Scanners
                        </button>
                        {Object.entries(CATEGORY_INFO).map(([key, info]) => (
                          <button
                            key={key}
                            onClick={() => { setSelectedCategory(key); setShowMobileFilters(false); }}
                            className={`w-full px-3 py-2 rounded-md text-left text-sm transition-all ${selectedCategory === key ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30' : 'text-slate-400 hover:bg-white/5'}`}
                          >
                            {info.label}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Desktop Sidebar */}
              <div className="hidden lg:flex w-72 bg-[#0f172a]/80 border-r border-white/10 flex-col sticky top-0 h-screen">
                <div className="p-6 border-b border-white/10">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-[#6B5AED]">Security Scanners</h2>
              <button
                onClick={() => window.location.href = '/triage'}
                className="p-2 rounded-md border border-white/10 text-slate-400 hover:bg-white/5 transition-all"
                title="Back to Triage"
              >
                <ArrowLeft size={16} />
              </button>
            </div>
            <p className="text-xs text-slate-500">Connect vulnerability scanners</p>
          </div>

          <div className="p-4 border-b border-white/10">
            <div className="relative">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search scanners..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-4 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
              />
            </div>
          </div>

          <div className="p-4 border-b border-white/10">
            <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">
              Categories
            </div>
            <div className="space-y-1">
              <button
                onClick={() => setSelectedCategory('all')}
                className={`w-full px-3 py-2 rounded-md text-left text-sm transition-all flex items-center justify-between ${
                  selectedCategory === 'all'
                    ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                    : 'text-slate-400 hover:bg-white/5'
                }`}
              >
                <span>All Scanners</span>
                <span className="text-xs">{scanners.length}</span>
              </button>
              {Object.entries(CATEGORY_INFO).map(([key, info]) => {
                const Icon = info.icon
                const count = scanners.filter(s => s.category === key).length
                return (
                  <button
                    key={key}
                    onClick={() => setSelectedCategory(key)}
                    className={`w-full px-3 py-2 rounded-md text-left text-sm transition-all flex items-center justify-between ${
                      selectedCategory === key
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="flex items-center gap-2">
                      <Icon size={14} className={info.color} />
                      {info.label}
                    </span>
                    <span className="text-xs">{count}</span>
                  </button>
                )
              })}
            </div>
          </div>

          <div className="p-4 flex-1">
            <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">
              Summary
            </div>
            <div className="space-y-3">
              <div className="p-3 bg-white/5 rounded-md border border-white/10">
                <div className="text-2xl font-bold text-green-400">{connectedCount}</div>
                <div className="text-xs text-slate-500">Connected Scanners</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md border border-white/10">
                <div className="text-2xl font-bold text-blue-400">{formatNumber(totalAssets)}</div>
                <div className="text-xs text-slate-500">Total Assets</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md border border-white/10">
                <div className="text-2xl font-bold text-orange-400">{formatNumber(totalVulns)}</div>
                <div className="text-xs text-slate-500">Total Vulnerabilities</div>
              </div>
            </div>
          </div>
        </div>

                <div className="flex-1 flex flex-col min-w-0">
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
                            {selectedCategory === 'all' ? 'All Scanners' : CATEGORY_INFO[selectedCategory as keyof typeof CATEGORY_INFO]?.label}
                          </h1>
                          <p className="text-sm text-slate-500">
                            {filteredScanners.length} scanners {selectedCategory !== 'all' && `in ${CATEGORY_INFO[selectedCategory as keyof typeof CATEGORY_INFO]?.label}`}
                          </p>
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <button
                          onClick={handleExportCSV}
                          className="hidden sm:flex px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all items-center gap-2"
                        >
                          <Download size={14} />
                          <span className="hidden md:inline">Export CSV</span>
                        </button>
                        <button className="hidden sm:flex px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all items-center gap-2">
                          <Upload size={14} />
                          <span className="hidden md:inline">Import SARIF</span>
                        </button>
                      </div>
                    </div>
                  </div>

          <div className="flex-1 overflow-auto p-6">
            {!demoEnabled ? (
              <div className="flex items-center justify-center h-full">
                <div className="text-center max-w-md">
                  <AlertCircle size={48} className="mx-auto mb-4 text-slate-500" />
                  <h3 className="text-lg font-semibold text-white mb-2">No Scanner Data</h3>
                  <p className="text-sm text-slate-400 mb-4">
                    Enable demo mode to see sample scanner data, or connect your scanners to see real data.
                  </p>
                </div>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredScanners.map((scanner) => {
                  const categoryInfo = CATEGORY_INFO[scanner.category]
                  return (
                    <div
                      key={scanner.id}
                      className={`p-4 rounded-lg border transition-all ${
                        scanner.status === 'connected'
                          ? 'bg-white/5 border-green-500/30 hover:border-green-500/50'
                          : scanner.status === 'error'
                          ? 'bg-white/5 border-red-500/30 hover:border-red-500/50'
                          : 'bg-white/5 border-white/10 hover:border-white/20'
                      }`}
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center gap-3">
                          <span className="text-2xl">{scanner.icon}</span>
                          <div>
                            <h3 className="font-semibold text-white">{scanner.name}</h3>
                            <span className={`text-xs ${categoryInfo.color}`}>{categoryInfo.label}</span>
                          </div>
                        </div>
                        {scanner.status === 'connected' ? (
                          <Check size={16} className="text-green-500" />
                        ) : scanner.status === 'error' ? (
                          <AlertCircle size={16} className="text-red-500" />
                        ) : (
                          <Plus size={16} className="text-slate-500" />
                        )}
                      </div>
                      
                      <p className="text-xs text-slate-400 mb-4">{scanner.description}</p>
                      
                      {scanner.status === 'connected' && scanner.stats && (
                        <div className="grid grid-cols-2 gap-2 mb-4">
                          <div className="p-2 bg-white/5 rounded">
                            <div className="text-sm font-semibold text-white">{formatNumber(scanner.stats.assets)}</div>
                            <div className="text-[10px] text-slate-500">Assets</div>
                          </div>
                          <div className="p-2 bg-white/5 rounded">
                            <div className="text-sm font-semibold text-white">{formatNumber(scanner.stats.vulnerabilities)}</div>
                            <div className="text-[10px] text-slate-500">Vulnerabilities</div>
                          </div>
                        </div>
                      )}
                      
                      {scanner.config?.last_sync && (
                        <div className="text-[10px] text-slate-500 mb-3">
                          Last sync: {formatTimeAgo(scanner.config.last_sync)}
                        </div>
                      )}
                      
                      <div className="flex gap-2">
                        {scanner.status === 'connected' ? (
                          <>
                            <button
                              onClick={() => handleSync(scanner)}
                              className="flex-1 px-3 py-1.5 bg-white/5 border border-white/10 rounded text-xs text-slate-300 hover:bg-white/10 transition-all flex items-center justify-center gap-1"
                            >
                              <RefreshCw size={12} />
                              Sync
                            </button>
                            <button
                              onClick={() => handleConnect(scanner)}
                              className="flex-1 px-3 py-1.5 bg-white/5 border border-white/10 rounded text-xs text-slate-300 hover:bg-white/10 transition-all flex items-center justify-center gap-1"
                            >
                              <Settings size={12} />
                              Configure
                            </button>
                          </>
                        ) : (
                          <button
                            onClick={() => handleConnect(scanner)}
                            className="w-full px-3 py-1.5 bg-[#6B5AED] rounded text-xs text-white hover:bg-[#5B4ADD] transition-all flex items-center justify-center gap-1"
                          >
                            <Plus size={12} />
                            Connect
                          </button>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>

        {isConfiguring && selectedScanner && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-[#1e293b] rounded-lg border border-white/10 w-full max-w-md p-6">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-lg font-semibold">Configure {selectedScanner.name}</h3>
                <button
                  onClick={() => setIsConfiguring(false)}
                  className="p-1 rounded hover:bg-white/10 transition-all"
                >
                  <Plus size={16} className="rotate-45" />
                </button>
              </div>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    API URL
                  </label>
                  <input
                    type="text"
                    placeholder={`https://${selectedScanner.id}.example.com`}
                    value={configForm.url}
                    onChange={(e) => setConfigForm({ ...configForm, url: e.target.value })}
                    className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    API Key
                  </label>
                  <input
                    type="password"
                    placeholder="Enter API key"
                    value={configForm.apiKey}
                    onChange={(e) => setConfigForm({ ...configForm, apiKey: e.target.value })}
                    className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                  />
                </div>
              </div>
              
              <div className="flex gap-3 mt-6">
                <button
                  onClick={() => setIsConfiguring(false)}
                  className="flex-1 px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSaveConfig}
                  className="flex-1 px-4 py-2 bg-[#6B5AED] rounded-md text-white text-sm font-medium hover:bg-[#5B4ADD] transition-all"
                >
                  Save & Connect
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  )
}
