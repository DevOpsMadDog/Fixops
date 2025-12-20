'use client'

import { useState, useEffect } from 'react'
import { Network, Search, AlertTriangle, CheckCircle, Clock, Filter, RefreshCw, Download, Target, Shield, Activity } from 'lucide-react'
import EnterpriseShell from './components/EnterpriseShell'

interface ReachabilityResult {
  id: string
  cve_id: string
  component: string
  version: string
  is_reachable: boolean
  confidence: number
  attack_path: string[]
  epss_score: number
  kev_listed: boolean
  severity: string
  analyzed_at: string
  business_impact: string
}

const DEMO_RESULTS: ReachabilityResult[] = [
  {
    id: '1',
    cve_id: 'CVE-2024-1234',
    component: 'log4j-core',
    version: '2.14.1',
    is_reachable: true,
    confidence: 0.95,
    attack_path: ['Internet', 'API Gateway', 'payment-service', 'log4j-core'],
    epss_score: 0.89,
    kev_listed: true,
    severity: 'critical',
    analyzed_at: '2024-12-20T10:00:00Z',
    business_impact: 'high'
  },
  {
    id: '2',
    cve_id: 'CVE-2024-5678',
    component: 'openssl',
    version: '1.1.1k',
    is_reachable: true,
    confidence: 0.78,
    attack_path: ['Internet', 'Load Balancer', 'auth-service', 'openssl'],
    epss_score: 0.72,
    kev_listed: true,
    severity: 'high',
    analyzed_at: '2024-12-20T09:30:00Z',
    business_impact: 'high'
  },
  {
    id: '3',
    cve_id: 'CVE-2024-9012',
    component: 'express',
    version: '4.17.1',
    is_reachable: false,
    confidence: 0.92,
    attack_path: [],
    epss_score: 0.23,
    kev_listed: false,
    severity: 'medium',
    analyzed_at: '2024-12-20T09:00:00Z',
    business_impact: 'low'
  },
  {
    id: '4',
    cve_id: 'CVE-2024-3456',
    component: 'struts-core',
    version: '2.5.30',
    is_reachable: true,
    confidence: 0.88,
    attack_path: ['Internet', 'CDN', 'web-frontend', 'struts-core'],
    epss_score: 0.67,
    kev_listed: false,
    severity: 'high',
    analyzed_at: '2024-12-20T08:30:00Z',
    business_impact: 'medium'
  },
  {
    id: '5',
    cve_id: 'CVE-2024-7890',
    component: 'jackson-databind',
    version: '2.9.8',
    is_reachable: false,
    confidence: 0.85,
    attack_path: [],
    epss_score: 0.15,
    kev_listed: false,
    severity: 'low',
    analyzed_at: '2024-12-20T08:00:00Z',
    business_impact: 'low'
  }
]

export default function ReachabilityPage() {
  const [results, setResults] = useState<ReachabilityResult[]>(DEMO_RESULTS)
  const [filteredResults, setFilteredResults] = useState<ReachabilityResult[]>(DEMO_RESULTS)
  const [selectedResult, setSelectedResult] = useState<ReachabilityResult | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [reachabilityFilter, setReachabilityFilter] = useState<string>('all')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [newCveInput, setNewCveInput] = useState('')

  useEffect(() => {
    applyFilters()
  }, [searchQuery, reachabilityFilter, severityFilter, results])

  const applyFilters = () => {
    let filtered = [...results]

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(r =>
        r.cve_id.toLowerCase().includes(query) ||
        r.component.toLowerCase().includes(query)
      )
    }

    if (reachabilityFilter !== 'all') {
      const isReachable = reachabilityFilter === 'reachable'
      filtered = filtered.filter(r => r.is_reachable === isReachable)
    }

    if (severityFilter !== 'all') {
      filtered = filtered.filter(r => r.severity === severityFilter)
    }

    setFilteredResults(filtered)
  }

  const getSeverityColor = (severity: string) => {
    const colors = {
      critical: '#dc2626',
      high: '#f97316',
      medium: '#eab308',
      low: '#10b981',
    }
    return colors[severity as keyof typeof colors] || colors.low
  }

  const formatDate = (isoString: string) => {
    const date = new Date(isoString)
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
  }

  const handleAnalyze = async () => {
    if (!newCveInput.trim()) return
    
    setIsAnalyzing(true)
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 2000))
    
    const newResult: ReachabilityResult = {
      id: String(results.length + 1),
      cve_id: newCveInput.toUpperCase(),
      component: 'analyzed-component',
      version: '1.0.0',
      is_reachable: Math.random() > 0.5,
      confidence: Math.random() * 0.3 + 0.7,
      attack_path: Math.random() > 0.5 ? ['Internet', 'Gateway', 'Service', 'Component'] : [],
      epss_score: Math.random(),
      kev_listed: Math.random() > 0.7,
      severity: ['critical', 'high', 'medium', 'low'][Math.floor(Math.random() * 4)],
      analyzed_at: new Date().toISOString(),
      business_impact: ['high', 'medium', 'low'][Math.floor(Math.random() * 3)]
    }
    
    setResults([newResult, ...results])
    setNewCveInput('')
    setIsAnalyzing(false)
  }

  const summary = {
    total: results.length,
    reachable: results.filter(r => r.is_reachable).length,
    not_reachable: results.filter(r => !r.is_reachable).length,
    kev_count: results.filter(r => r.kev_listed).length,
    critical: results.filter(r => r.severity === 'critical').length,
  }

  return (
    <EnterpriseShell>
      <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
        {/* Left Sidebar - Filters */}
        <div className="w-72 bg-[#0f172a]/80 border-r border-white/10 flex flex-col sticky top-0 h-screen">
          {/* Header */}
          <div className="p-6 border-b border-white/10">
            <div className="flex items-center gap-3 mb-4">
              <Network size={24} className="text-[#6B5AED]" />
              <h2 className="text-lg font-semibold">Reachability Analysis</h2>
            </div>
            <p className="text-xs text-slate-500">CVE attack path analysis</p>
          </div>

          {/* Summary Stats */}
          <div className="p-4 border-b border-white/10">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Total Analyzed</div>
                <div className="text-xl font-semibold text-[#6B5AED]">{summary.total}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Reachable</div>
                <div className="text-xl font-semibold text-red-500">{summary.reachable}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Not Reachable</div>
                <div className="text-xl font-semibold text-green-500">{summary.not_reachable}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">KEV Listed</div>
                <div className="text-xl font-semibold text-amber-500">{summary.kev_count}</div>
              </div>
            </div>
          </div>

          {/* Filters */}
          <div className="p-4 flex-1 overflow-auto">
            <div className="mb-6">
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Filter size={12} />
                Reachability Status
              </div>
              <div className="space-y-2">
                {['all', 'reachable', 'not_reachable'].map((status) => (
                  <button
                    key={status}
                    onClick={() => setReachabilityFilter(status)}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      reachabilityFilter === status
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="capitalize">{status.replace('_', ' ')}</span>
                  </button>
                ))}
              </div>
            </div>

            <div>
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Filter size={12} />
                Severity
              </div>
              <div className="space-y-2">
                {['all', 'critical', 'high', 'medium', 'low'].map((severity) => (
                  <button
                    key={severity}
                    onClick={() => setSeverityFilter(severity)}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      severityFilter === severity
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="capitalize">{severity}</span>
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
                <h1 className="text-2xl font-semibold mb-1">Reachability Analysis</h1>
                <p className="text-sm text-slate-500">
                  Showing {filteredResults.length} result{filteredResults.length !== 1 ? 's' : ''}
                </p>
              </div>
              <div className="flex items-center gap-3">
                <input
                  type="text"
                  placeholder="CVE-2024-XXXX"
                  value={newCveInput}
                  onChange={(e) => setNewCveInput(e.target.value)}
                  className="px-3 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-[#6B5AED]/50 w-40"
                />
                <button
                  onClick={handleAnalyze}
                  disabled={isAnalyzing || !newCveInput.trim()}
                  className="px-4 py-2 bg-[#6B5AED] hover:bg-[#5B4ADD] disabled:opacity-50 rounded-md text-white text-sm font-medium transition-all flex items-center gap-2"
                >
                  {isAnalyzing ? (
                    <>
                      <RefreshCw size={16} className="animate-spin" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <Target size={16} />
                      Analyze
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Search Bar */}
            <div className="relative">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search by CVE or component..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-[#6B5AED]/50"
              />
            </div>
          </div>

          {/* Results Grid */}
          <div className="flex-1 overflow-auto p-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {filteredResults.map((result) => (
                <div
                  key={result.id}
                  onClick={() => setSelectedResult(result)}
                  className="bg-white/2 border border-white/5 rounded-lg p-5 hover:bg-white/5 hover:border-[#6B5AED]/30 cursor-pointer transition-all"
                >
                  {/* Header */}
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                        result.is_reachable ? 'bg-red-500/20' : 'bg-green-500/20'
                      }`}>
                        {result.is_reachable ? (
                          <AlertTriangle size={20} className="text-red-500" />
                        ) : (
                          <CheckCircle size={20} className="text-green-500" />
                        )}
                      </div>
                      <div>
                        <h3 className="text-sm font-semibold text-white">{result.cve_id}</h3>
                        <p className="text-xs text-slate-400">{result.component}@{result.version}</p>
                      </div>
                    </div>
                    <span
                      className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium"
                      style={{ 
                        backgroundColor: `${getSeverityColor(result.severity)}20`,
                        color: getSeverityColor(result.severity)
                      }}
                    >
                      {result.severity}
                    </span>
                  </div>

                  {/* Reachability Status */}
                  <div className="mb-4 p-3 bg-white/5 rounded-lg">
                    <div className="flex items-center justify-between">
                      <div className="text-xs text-slate-400">Reachability</div>
                      <div className={`text-sm font-semibold ${result.is_reachable ? 'text-red-500' : 'text-green-500'}`}>
                        {result.is_reachable ? 'REACHABLE' : 'NOT REACHABLE'}
                      </div>
                    </div>
                    <div className="mt-2 flex items-center gap-2">
                      <div className="flex-1 h-2 bg-white/10 rounded-full overflow-hidden">
                        <div 
                          className={`h-full rounded-full ${result.is_reachable ? 'bg-red-500' : 'bg-green-500'}`}
                          style={{ width: `${result.confidence * 100}%` }}
                        />
                      </div>
                      <span className="text-xs text-slate-400">{Math.round(result.confidence * 100)}% confidence</span>
                    </div>
                  </div>

                  {/* Stats */}
                  <div className="grid grid-cols-3 gap-3 mb-4">
                    <div className="p-2 bg-white/5 rounded-lg text-center">
                      <div className="text-xs text-slate-400 mb-1">EPSS</div>
                      <div className="text-sm font-semibold text-orange-500">{(result.epss_score * 100).toFixed(1)}%</div>
                    </div>
                    <div className="p-2 bg-white/5 rounded-lg text-center">
                      <div className="text-xs text-slate-400 mb-1">KEV</div>
                      <div className={`text-sm font-semibold ${result.kev_listed ? 'text-amber-500' : 'text-slate-500'}`}>
                        {result.kev_listed ? 'YES' : 'NO'}
                      </div>
                    </div>
                    <div className="p-2 bg-white/5 rounded-lg text-center">
                      <div className="text-xs text-slate-400 mb-1">Impact</div>
                      <div className="text-sm font-semibold text-blue-500 capitalize">{result.business_impact}</div>
                    </div>
                  </div>

                  {/* Attack Path Preview */}
                  {result.is_reachable && result.attack_path.length > 0 && (
                    <div className="mb-4">
                      <div className="text-xs text-slate-400 mb-2">Attack Path</div>
                      <div className="flex items-center gap-1 text-xs overflow-x-auto">
                        {result.attack_path.map((node, idx) => (
                          <span key={idx} className="flex items-center gap-1">
                            <span className="px-2 py-1 bg-white/10 rounded">{node}</span>
                            {idx < result.attack_path.length - 1 && <span className="text-slate-500">→</span>}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Footer */}
                  <div className="flex items-center justify-between pt-3 border-t border-white/5">
                    <div className="flex items-center gap-2 text-xs text-slate-400">
                      <Clock size={12} />
                      {formatDate(result.analyzed_at)}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Detail Drawer */}
        {selectedResult && (
          <div
            onClick={() => setSelectedResult(null)}
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
                    <h3 className="text-lg font-semibold mb-1">{selectedResult.cve_id}</h3>
                    <p className="text-sm text-slate-400">{selectedResult.component}@{selectedResult.version}</p>
                  </div>
                  <button
                    onClick={() => setSelectedResult(null)}
                    className="text-slate-400 hover:text-white transition-colors"
                  >
                    X
                  </button>
                </div>

                <div className="flex gap-2">
                  <span
                    className={`inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium ${
                      selectedResult.is_reachable 
                        ? 'bg-red-500/20 text-red-500' 
                        : 'bg-green-500/20 text-green-500'
                    }`}
                  >
                    {selectedResult.is_reachable ? <AlertTriangle size={14} /> : <CheckCircle size={14} />}
                    {selectedResult.is_reachable ? 'Reachable' : 'Not Reachable'}
                  </span>
                  <span
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium"
                    style={{ 
                      backgroundColor: `${getSeverityColor(selectedResult.severity)}20`,
                      color: getSeverityColor(selectedResult.severity)
                    }}
                  >
                    {selectedResult.severity}
                  </span>
                  {selectedResult.kev_listed && (
                    <span className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium bg-amber-500/20 text-amber-500">
                      <Shield size={14} />
                      KEV
                    </span>
                  )}
                </div>
              </div>

              {/* Drawer Content */}
              <div className="flex-1 p-6 space-y-6">
                {/* Confidence Score */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Analysis Confidence</h4>
                  <div className="bg-white/5 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-slate-400">Confidence Score</span>
                      <span className="text-lg font-semibold text-[#6B5AED]">{Math.round(selectedResult.confidence * 100)}%</span>
                    </div>
                    <div className="h-3 bg-white/10 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-[#6B5AED] rounded-full"
                        style={{ width: `${selectedResult.confidence * 100}%` }}
                      />
                    </div>
                  </div>
                </div>

                {/* Attack Path */}
                {selectedResult.is_reachable && selectedResult.attack_path.length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold text-slate-300 mb-3">Attack Path</h4>
                    <div className="bg-white/5 rounded-lg p-4">
                      <div className="space-y-3">
                        {selectedResult.attack_path.map((node, idx) => (
                          <div key={idx} className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-full bg-[#6B5AED]/20 flex items-center justify-center text-xs font-semibold text-[#6B5AED]">
                              {idx + 1}
                            </div>
                            <div className="flex-1 p-3 bg-white/5 rounded-lg">
                              <span className="text-sm text-white">{node}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {/* Risk Metrics */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Risk Metrics</h4>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-white/5 rounded-lg p-4">
                      <div className="text-xs text-slate-400 mb-1">EPSS Score</div>
                      <div className="text-2xl font-semibold text-orange-500">{(selectedResult.epss_score * 100).toFixed(1)}%</div>
                      <div className="text-xs text-slate-500 mt-1">Exploitation probability</div>
                    </div>
                    <div className="bg-white/5 rounded-lg p-4">
                      <div className="text-xs text-slate-400 mb-1">Business Impact</div>
                      <div className="text-2xl font-semibold text-blue-500 capitalize">{selectedResult.business_impact}</div>
                      <div className="text-xs text-slate-500 mt-1">Organizational risk</div>
                    </div>
                  </div>
                </div>

                {/* CLI Command */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">CLI Command</h4>
                  <div className="bg-black/30 rounded-lg p-4 font-mono text-sm">
                    <code className="text-green-400">python -m core.cli reachability analyze {selectedResult.cve_id}</code>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex gap-3">
                  <button className="flex-1 px-4 py-2 bg-[#6B5AED] hover:bg-[#5B4ADD] rounded-md text-white text-sm font-medium transition-all flex items-center justify-center gap-2">
                    <Activity size={16} />
                    Run Micro Pentest
                  </button>
                  <button className="px-4 py-2 bg-white/5 hover:bg-white/10 border border-white/10 rounded-md text-white text-sm font-medium transition-all flex items-center gap-2">
                    <Download size={16} />
                    Export
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </EnterpriseShell>
  )
}
