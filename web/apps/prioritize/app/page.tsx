'use client'

import { useState, useMemo } from 'react'
import { Search, ArrowLeft, AlertCircle, TrendingUp, TrendingDown, Shield, Zap, Globe, Filter, Download, ChevronDown, ChevronUp, X, Plus, Brain, Target } from 'lucide-react'
import { AppShell, useDemoModeContext } from '@fixops/ui'

interface RiskFactor {
  name: string
  impact: number
  direction: 'increase' | 'decrease'
  description: string
}

interface Vulnerability {
  id: string
  cve_id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  risk_score: number
  epss_score: number
  kev_listed: boolean
  exploit_available: boolean
  internet_facing: boolean
  asset_criticality: 'mission_critical' | 'business_critical' | 'standard' | 'low'
  affected_assets: number
  age_days: number
  risk_factors: RiskFactor[]
  threat_intel: {
    campaigns: string[]
    threat_actors: string[]
    malware: string[]
  }
  mitigating_controls: string[]
}

interface QueryCondition {
  id: string
  field: string
  operator: string
  value: string
  connector: 'AND' | 'OR'
}

const DEMO_VULNERABILITIES: Vulnerability[] = [
  {
    id: 'vuln-1',
    cve_id: 'CVE-2024-3094',
    title: 'XZ Utils Backdoor - Malicious Code in Compression Library',
    severity: 'critical',
    risk_score: 98,
    epss_score: 0.97,
    kev_listed: true,
    exploit_available: true,
    internet_facing: true,
    asset_criticality: 'mission_critical',
    affected_assets: 234,
    age_days: 5,
    risk_factors: [
      { name: 'KEV Listed', impact: 25, direction: 'increase', description: 'Listed in CISA Known Exploited Vulnerabilities catalog' },
      { name: 'Active Exploitation', impact: 20, direction: 'increase', description: 'Currently being exploited in the wild' },
      { name: 'Internet Facing', impact: 15, direction: 'increase', description: 'Affected assets are exposed to the internet' },
      { name: 'Mission Critical Assets', impact: 15, direction: 'increase', description: 'Affects mission critical business systems' },
      { name: 'High EPSS Score', impact: 10, direction: 'increase', description: 'EPSS score indicates high exploitation probability' },
    ],
    threat_intel: {
      campaigns: ['Operation Backdoor', 'Supply Chain Attack 2024'],
      threat_actors: ['APT-Unknown', 'Lazarus Group'],
      malware: ['XZ Backdoor'],
    },
    mitigating_controls: [],
  },
  {
    id: 'vuln-2',
    cve_id: 'CVE-2024-21762',
    title: 'Fortinet FortiOS SSL VPN Remote Code Execution',
    severity: 'critical',
    risk_score: 95,
    epss_score: 0.94,
    kev_listed: true,
    exploit_available: true,
    internet_facing: true,
    asset_criticality: 'business_critical',
    affected_assets: 12,
    age_days: 14,
    risk_factors: [
      { name: 'KEV Listed', impact: 25, direction: 'increase', description: 'Listed in CISA Known Exploited Vulnerabilities catalog' },
      { name: 'Active Exploitation', impact: 20, direction: 'increase', description: 'Currently being exploited in the wild' },
      { name: 'Internet Facing', impact: 15, direction: 'increase', description: 'VPN endpoints are internet-exposed' },
      { name: 'Business Critical', impact: 10, direction: 'increase', description: 'Affects business critical infrastructure' },
      { name: 'WAF Protection', impact: -5, direction: 'decrease', description: 'Web Application Firewall provides partial protection' },
    ],
    threat_intel: {
      campaigns: ['VPN Exploitation Campaign'],
      threat_actors: ['Volt Typhoon', 'APT28'],
      malware: ['COATHANGER'],
    },
    mitigating_controls: ['WAF Rules', 'Network Segmentation'],
  },
  {
    id: 'vuln-3',
    cve_id: 'CVE-2023-50164',
    title: 'Apache Struts Remote Code Execution',
    severity: 'critical',
    risk_score: 89,
    epss_score: 0.89,
    kev_listed: true,
    exploit_available: true,
    internet_facing: true,
    asset_criticality: 'mission_critical',
    affected_assets: 8,
    age_days: 45,
    risk_factors: [
      { name: 'KEV Listed', impact: 25, direction: 'increase', description: 'Listed in CISA Known Exploited Vulnerabilities catalog' },
      { name: 'Public Exploit', impact: 15, direction: 'increase', description: 'Exploit code publicly available' },
      { name: 'Internet Facing', impact: 15, direction: 'increase', description: 'Web applications exposed to internet' },
      { name: 'EDR Coverage', impact: -10, direction: 'decrease', description: 'Endpoint Detection and Response provides monitoring' },
      { name: 'IDS Signatures', impact: -5, direction: 'decrease', description: 'Intrusion Detection signatures deployed' },
    ],
    threat_intel: {
      campaigns: ['Struts Exploitation Wave'],
      threat_actors: ['Various'],
      malware: [],
    },
    mitigating_controls: ['EDR', 'IDS/IPS', 'WAF'],
  },
  {
    id: 'vuln-4',
    cve_id: 'CVE-2024-1709',
    title: 'ConnectWise ScreenConnect Authentication Bypass',
    severity: 'critical',
    risk_score: 92,
    epss_score: 0.91,
    kev_listed: true,
    exploit_available: true,
    internet_facing: true,
    asset_criticality: 'business_critical',
    affected_assets: 3,
    age_days: 21,
    risk_factors: [
      { name: 'KEV Listed', impact: 25, direction: 'increase', description: 'Listed in CISA Known Exploited Vulnerabilities catalog' },
      { name: 'Active Ransomware', impact: 20, direction: 'increase', description: 'Used in active ransomware campaigns' },
      { name: 'Internet Facing', impact: 15, direction: 'increase', description: 'Remote access tool exposed to internet' },
      { name: 'Low Asset Count', impact: -5, direction: 'decrease', description: 'Limited number of affected assets' },
    ],
    threat_intel: {
      campaigns: ['ScreenConnect Ransomware Wave'],
      threat_actors: ['Black Basta', 'LockBit'],
      malware: ['Cobalt Strike', 'Ransomware'],
    },
    mitigating_controls: [],
  },
  {
    id: 'vuln-5',
    cve_id: 'CVE-2023-46747',
    title: 'F5 BIG-IP Configuration Utility Authentication Bypass',
    severity: 'high',
    risk_score: 78,
    epss_score: 0.72,
    kev_listed: false,
    exploit_available: true,
    internet_facing: false,
    asset_criticality: 'business_critical',
    affected_assets: 6,
    age_days: 90,
    risk_factors: [
      { name: 'Public Exploit', impact: 15, direction: 'increase', description: 'Exploit code publicly available' },
      { name: 'Business Critical', impact: 10, direction: 'increase', description: 'Affects load balancer infrastructure' },
      { name: 'Internal Only', impact: -15, direction: 'decrease', description: 'Not exposed to internet' },
      { name: 'Network Segmentation', impact: -10, direction: 'decrease', description: 'Isolated network segment' },
    ],
    threat_intel: {
      campaigns: [],
      threat_actors: [],
      malware: [],
    },
    mitigating_controls: ['Network Segmentation', 'Access Controls'],
  },
  {
    id: 'vuln-6',
    cve_id: 'CVE-2024-0012',
    title: 'Palo Alto PAN-OS Management Interface Authentication Bypass',
    severity: 'high',
    risk_score: 75,
    epss_score: 0.68,
    kev_listed: false,
    exploit_available: false,
    internet_facing: false,
    asset_criticality: 'mission_critical',
    affected_assets: 4,
    age_days: 30,
    risk_factors: [
      { name: 'Mission Critical', impact: 15, direction: 'increase', description: 'Affects firewall infrastructure' },
      { name: 'No Public Exploit', impact: -15, direction: 'decrease', description: 'No known public exploit' },
      { name: 'Internal Only', impact: -15, direction: 'decrease', description: 'Management interface not internet-exposed' },
      { name: 'MFA Enabled', impact: -10, direction: 'decrease', description: 'Multi-factor authentication required' },
    ],
    threat_intel: {
      campaigns: [],
      threat_actors: [],
      malware: [],
    },
    mitigating_controls: ['MFA', 'Jump Server', 'Audit Logging'],
  },
  {
    id: 'vuln-7',
    cve_id: 'CVE-2023-44487',
    title: 'HTTP/2 Rapid Reset Attack (DoS)',
    severity: 'medium',
    risk_score: 55,
    epss_score: 0.45,
    kev_listed: false,
    exploit_available: true,
    internet_facing: true,
    asset_criticality: 'standard',
    affected_assets: 156,
    age_days: 120,
    risk_factors: [
      { name: 'Wide Exposure', impact: 10, direction: 'increase', description: 'Many affected assets' },
      { name: 'DoS Only', impact: -15, direction: 'decrease', description: 'Denial of service, no data breach risk' },
      { name: 'CDN Protection', impact: -10, direction: 'decrease', description: 'CDN provides DDoS mitigation' },
      { name: 'Rate Limiting', impact: -5, direction: 'decrease', description: 'Rate limiting configured' },
    ],
    threat_intel: {
      campaigns: ['HTTP/2 DDoS Campaign'],
      threat_actors: ['Various'],
      malware: [],
    },
    mitigating_controls: ['CDN', 'Rate Limiting', 'WAF'],
  },
]

const QUERY_FIELDS = [
  { value: 'severity', label: 'Severity' },
  { value: 'risk_score', label: 'Risk Score' },
  { value: 'epss_score', label: 'EPSS Score' },
  { value: 'kev_listed', label: 'KEV Listed' },
  { value: 'exploit_available', label: 'Exploit Available' },
  { value: 'internet_facing', label: 'Internet Facing' },
  { value: 'asset_criticality', label: 'Asset Criticality' },
  { value: 'affected_assets', label: 'Affected Assets' },
  { value: 'age_days', label: 'Age (Days)' },
]

const QUERY_OPERATORS = {
  string: ['equals', 'not equals', 'contains'],
  number: ['equals', 'greater than', 'less than', 'between'],
  boolean: ['is true', 'is false'],
}

export default function PrioritizePage() {
  const { demoEnabled } = useDemoModeContext()
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null)
  const [showQueryBuilder, setShowQueryBuilder] = useState(false)
  const [queryConditions, setQueryConditions] = useState<QueryCondition[]>([])
  const [sortBy, setSortBy] = useState<'risk_score' | 'epss_score' | 'affected_assets'>('risk_score')
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc')

  const vulnerabilities = useMemo(() => demoEnabled ? DEMO_VULNERABILITIES : [], [demoEnabled])

  const filteredVulns = useMemo(() => {
    const filtered = vulnerabilities.filter(vuln => {
      const matchesSearch = vuln.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                           vuln.cve_id.toLowerCase().includes(searchQuery.toLowerCase())
      return matchesSearch
    })

    filtered.sort((a, b) => {
      const aVal = a[sortBy]
      const bVal = b[sortBy]
      if (sortOrder === 'desc') return bVal - aVal
      return aVal - bVal
    })

    return filtered
  }, [vulnerabilities, searchQuery, sortBy, sortOrder])

  const stats = useMemo(() => ({
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length,
    kevListed: vulnerabilities.filter(v => v.kev_listed).length,
    exploitable: vulnerabilities.filter(v => v.exploit_available).length,
    avgRiskScore: vulnerabilities.length > 0 
      ? Math.round(vulnerabilities.reduce((sum, v) => sum + v.risk_score, 0) / vulnerabilities.length)
      : 0,
  }), [vulnerabilities])

  const handleExportCSV = () => {
    const headers = ['CVE ID', 'Title', 'Severity', 'Risk Score', 'EPSS', 'KEV', 'Exploit', 'Internet Facing', 'Affected Assets']
    const rows = vulnerabilities.map(v => [
      v.cve_id,
      v.title,
      v.severity,
      v.risk_score,
      v.epss_score,
      v.kev_listed ? 'Yes' : 'No',
      v.exploit_available ? 'Yes' : 'No',
      v.internet_facing ? 'Yes' : 'No',
      v.affected_assets
    ])
    const csv = [headers, ...rows].map(row => row.join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'prioritized-vulnerabilities.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  const addQueryCondition = () => {
    setQueryConditions([...queryConditions, {
      id: Date.now().toString(),
      field: 'severity',
      operator: 'equals',
      value: '',
      connector: 'AND'
    }])
  }

  const removeQueryCondition = (id: string) => {
    setQueryConditions(queryConditions.filter(c => c.id !== id))
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-500/10 border-red-500/30'
      case 'high': return 'text-orange-400 bg-orange-500/10 border-orange-500/30'
      case 'medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30'
      case 'low': return 'text-green-400 bg-green-500/10 border-green-500/30'
      default: return 'text-slate-400 bg-slate-500/10 border-slate-500/30'
    }
  }

  const getRiskScoreColor = (score: number) => {
    if (score >= 90) return 'text-red-400'
    if (score >= 70) return 'text-orange-400'
    if (score >= 50) return 'text-yellow-400'
    return 'text-green-400'
  }

  return (
    <AppShell activeApp="prioritize">
      <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
        <div className="w-72 bg-[#0f172a]/80 border-r border-white/10 flex flex-col sticky top-0 h-screen">
          <div className="p-6 border-b border-white/10">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-[#6B5AED]">Prioritize</h2>
              <button
                onClick={() => window.location.href = '/triage'}
                className="p-2 rounded-md border border-white/10 text-slate-400 hover:bg-white/5 transition-all"
                title="Back to Triage"
              >
                <ArrowLeft size={16} />
              </button>
            </div>
            <p className="text-xs text-slate-500">ML-powered risk prioritization</p>
          </div>

          <div className="p-4 border-b border-white/10">
            <div className="flex items-center gap-2 p-3 bg-gradient-to-r from-[#6B5AED]/10 to-purple-500/10 rounded-lg border border-[#6B5AED]/20">
              <Brain size={20} className="text-[#6B5AED]" />
              <div>
                <div className="text-sm font-medium text-white">ML Risk Engine</div>
                <div className="text-xs text-slate-400">30+ threat intel feeds</div>
              </div>
            </div>
          </div>

          <div className="p-4 flex-1">
            <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">
              Risk Summary
            </div>
            <div className="space-y-3">
              <div className="p-3 bg-white/5 rounded-md border border-white/10">
                <div className="text-2xl font-bold text-[#6B5AED]">{stats.avgRiskScore}</div>
                <div className="text-xs text-slate-500">Avg Risk Score</div>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div className="p-2 bg-red-500/10 rounded border border-red-500/20">
                  <div className="text-lg font-bold text-red-400">{stats.critical}</div>
                  <div className="text-[10px] text-red-400/70">Critical</div>
                </div>
                <div className="p-2 bg-orange-500/10 rounded border border-orange-500/20">
                  <div className="text-lg font-bold text-orange-400">{stats.high}</div>
                  <div className="text-[10px] text-orange-400/70">High</div>
                </div>
                <div className="p-2 bg-yellow-500/10 rounded border border-yellow-500/20">
                  <div className="text-lg font-bold text-yellow-400">{stats.medium}</div>
                  <div className="text-[10px] text-yellow-400/70">Medium</div>
                </div>
                <div className="p-2 bg-green-500/10 rounded border border-green-500/20">
                  <div className="text-lg font-bold text-green-400">{stats.low}</div>
                  <div className="text-[10px] text-green-400/70">Low</div>
                </div>
              </div>
              <div className="p-3 bg-white/5 rounded-md border border-white/10">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-slate-500">KEV Listed</span>
                  <span className="text-sm font-semibold text-red-400">{stats.kevListed}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-500">Exploitable</span>
                  <span className="text-sm font-semibold text-orange-400">{stats.exploitable}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="flex-1 flex flex-col">
          <div className="p-5 border-b border-white/10 bg-[#0f172a]/80 backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-2xl font-semibold mb-1">Vulnerability Prioritization</h1>
                <p className="text-sm text-slate-500">{filteredVulns.length} vulnerabilities ranked by risk</p>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => setShowQueryBuilder(!showQueryBuilder)}
                  className={`px-4 py-2 border rounded-md text-sm font-medium transition-all flex items-center gap-2 ${
                    showQueryBuilder 
                      ? 'bg-[#6B5AED]/10 border-[#6B5AED]/30 text-[#6B5AED]' 
                      : 'bg-white/5 border-white/10 text-slate-300 hover:bg-white/10'
                  }`}
                >
                  <Filter size={14} />
                  Query Builder
                </button>
                <button
                  onClick={handleExportCSV}
                  className="px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all flex items-center gap-2"
                >
                  <Download size={14} />
                  Export CSV
                </button>
              </div>
            </div>
          </div>

          {showQueryBuilder && (
            <div className="p-4 border-b border-white/10 bg-[#1e293b]/50">
              <div className="flex items-center justify-between mb-3">
                <span className="text-sm font-medium text-white">Query Builder</span>
                <button
                  onClick={addQueryCondition}
                  className="px-3 py-1 bg-[#6B5AED]/20 border border-[#6B5AED]/30 rounded text-xs text-[#6B5AED] hover:bg-[#6B5AED]/30 transition-all flex items-center gap-1"
                >
                  <Plus size={12} />
                  Add Condition
                </button>
              </div>
              {queryConditions.length === 0 ? (
                <p className="text-xs text-slate-500">No conditions added. Click &quot;Add Condition&quot; to build a query.</p>
              ) : (
                <div className="space-y-2">
                  {queryConditions.map((condition, index) => (
                    <div key={condition.id} className="flex items-center gap-2">
                      {index > 0 && (
                        <select
                          value={condition.connector}
                          onChange={(e) => {
                            const updated = [...queryConditions]
                            updated[index].connector = e.target.value as 'AND' | 'OR'
                            setQueryConditions(updated)
                          }}
                          className="px-2 py-1 bg-white/5 border border-white/10 rounded text-xs text-white"
                        >
                          <option value="AND">AND</option>
                          <option value="OR">OR</option>
                        </select>
                      )}
                      <select
                        value={condition.field}
                        onChange={(e) => {
                          const updated = [...queryConditions]
                          updated[index].field = e.target.value
                          setQueryConditions(updated)
                        }}
                        className="px-2 py-1 bg-white/5 border border-white/10 rounded text-xs text-white"
                      >
                        {QUERY_FIELDS.map(f => (
                          <option key={f.value} value={f.value}>{f.label}</option>
                        ))}
                      </select>
                      <select
                        value={condition.operator}
                        onChange={(e) => {
                          const updated = [...queryConditions]
                          updated[index].operator = e.target.value
                          setQueryConditions(updated)
                        }}
                        className="px-2 py-1 bg-white/5 border border-white/10 rounded text-xs text-white"
                      >
                        <option value="equals">equals</option>
                        <option value="not equals">not equals</option>
                        <option value="greater than">greater than</option>
                        <option value="less than">less than</option>
                      </select>
                      <input
                        type="text"
                        value={condition.value}
                        onChange={(e) => {
                          const updated = [...queryConditions]
                          updated[index].value = e.target.value
                          setQueryConditions(updated)
                        }}
                        placeholder="Value"
                        className="px-2 py-1 bg-white/5 border border-white/10 rounded text-xs text-white placeholder-slate-500 w-32"
                      />
                      <button
                        onClick={() => removeQueryCondition(condition.id)}
                        className="p-1 text-slate-500 hover:text-red-400 transition-all"
                      >
                        <X size={14} />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          <div className="p-4 border-b border-white/10 flex gap-4">
            <div className="relative flex-1 max-w-md">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search by CVE or title..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-4 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
              />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-500">Sort by:</span>
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as typeof sortBy)}
                className="px-3 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white focus:outline-none"
              >
                <option value="risk_score">Risk Score</option>
                <option value="epss_score">EPSS Score</option>
                <option value="affected_assets">Affected Assets</option>
              </select>
              <button
                onClick={() => setSortOrder(sortOrder === 'desc' ? 'asc' : 'desc')}
                className="p-2 bg-white/5 border border-white/10 rounded-md text-slate-300 hover:bg-white/10 transition-all"
              >
                {sortOrder === 'desc' ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
              </button>
            </div>
          </div>

          <div className="flex-1 overflow-auto">
            {!demoEnabled ? (
              <div className="flex items-center justify-center h-full">
                <div className="text-center max-w-md">
                  <AlertCircle size={48} className="mx-auto mb-4 text-slate-500" />
                  <h3 className="text-lg font-semibold text-white mb-2">No Vulnerability Data</h3>
                  <p className="text-sm text-slate-400 mb-4">
                    Enable demo mode to see sample prioritization data, or connect your scanners to see real data.
                  </p>
                </div>
              </div>
            ) : (
              <div className="flex">
                <div className={`flex-1 p-6 ${selectedVuln ? 'border-r border-white/10' : ''}`}>
                  <div className="space-y-3">
                    {filteredVulns.map((vuln, index) => (
                      <div
                        key={vuln.id}
                        onClick={() => setSelectedVuln(vuln)}
                        className={`p-4 rounded-lg border transition-all cursor-pointer ${
                          selectedVuln?.id === vuln.id
                            ? 'bg-[#6B5AED]/10 border-[#6B5AED]/30'
                            : 'bg-white/5 border-white/10 hover:border-white/20'
                        }`}
                      >
                        <div className="flex items-start gap-4">
                          <div className="flex flex-col items-center">
                            <div className={`text-2xl font-bold ${getRiskScoreColor(vuln.risk_score)}`}>
                              {vuln.risk_score}
                            </div>
                            <div className="text-[10px] text-slate-500">Risk</div>
                          </div>
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-xs font-mono text-slate-400">#{index + 1}</span>
                              <span className="text-xs font-mono text-[#6B5AED]">{vuln.cve_id}</span>
                              <span className={`px-2 py-0.5 rounded text-xs font-medium border ${getSeverityColor(vuln.severity)}`}>
                                {vuln.severity}
                              </span>
                              {vuln.kev_listed && (
                                <span className="px-2 py-0.5 bg-red-500/10 border border-red-500/30 rounded text-xs text-red-400 flex items-center gap-1">
                                  <Shield size={10} />
                                  KEV
                                </span>
                              )}
                              {vuln.exploit_available && (
                                <span className="px-2 py-0.5 bg-orange-500/10 border border-orange-500/30 rounded text-xs text-orange-400 flex items-center gap-1">
                                  <Zap size={10} />
                                  Exploit
                                </span>
                              )}
                              {vuln.internet_facing && (
                                <span className="px-2 py-0.5 bg-blue-500/10 border border-blue-500/30 rounded text-xs text-blue-400 flex items-center gap-1">
                                  <Globe size={10} />
                                  Internet
                                </span>
                              )}
                            </div>
                            <h3 className="font-medium text-white mb-2">{vuln.title}</h3>
                            <div className="flex items-center gap-4 text-xs text-slate-500">
                              <span>EPSS: {(vuln.epss_score * 100).toFixed(0)}%</span>
                              <span>{vuln.affected_assets} assets</span>
                              <span>{vuln.age_days}d old</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {selectedVuln && (
                  <div className="w-96 p-6 bg-[#0f172a]/50 sticky top-0 h-screen overflow-auto">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-lg font-semibold">Risk Breakdown</h3>
                      <button
                        onClick={() => setSelectedVuln(null)}
                        className="p-1 text-slate-500 hover:text-white transition-all"
                      >
                        <X size={16} />
                      </button>
                    </div>

                    <div className="mb-6">
                      <div className="text-xs text-slate-500 mb-2">{selectedVuln.cve_id}</div>
                      <div className="text-sm text-white mb-4">{selectedVuln.title}</div>
                      <div className="flex items-center gap-4">
                        <div className="text-center">
                          <div className={`text-3xl font-bold ${getRiskScoreColor(selectedVuln.risk_score)}`}>
                            {selectedVuln.risk_score}
                          </div>
                          <div className="text-xs text-slate-500">Risk Score</div>
                        </div>
                        <div className="text-center">
                          <div className="text-3xl font-bold text-blue-400">
                            {(selectedVuln.epss_score * 100).toFixed(0)}%
                          </div>
                          <div className="text-xs text-slate-500">EPSS</div>
                        </div>
                      </div>
                    </div>

                    <div className="mb-6">
                      <div className="text-sm font-medium text-white mb-3 flex items-center gap-2">
                        <TrendingUp size={14} className="text-red-400" />
                        Factors Increasing Risk
                      </div>
                      <div className="space-y-2">
                        {selectedVuln.risk_factors.filter(f => f.direction === 'increase').map((factor, i) => (
                          <div key={i} className="p-2 bg-red-500/10 rounded border border-red-500/20">
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-xs font-medium text-red-400">{factor.name}</span>
                              <span className="text-xs text-red-400">+{factor.impact}%</span>
                            </div>
                            <p className="text-[10px] text-slate-400">{factor.description}</p>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="mb-6">
                      <div className="text-sm font-medium text-white mb-3 flex items-center gap-2">
                        <TrendingDown size={14} className="text-green-400" />
                        Factors Decreasing Risk
                      </div>
                      <div className="space-y-2">
                        {selectedVuln.risk_factors.filter(f => f.direction === 'decrease').length > 0 ? (
                          selectedVuln.risk_factors.filter(f => f.direction === 'decrease').map((factor, i) => (
                            <div key={i} className="p-2 bg-green-500/10 rounded border border-green-500/20">
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-xs font-medium text-green-400">{factor.name}</span>
                                <span className="text-xs text-green-400">{factor.impact}%</span>
                              </div>
                              <p className="text-[10px] text-slate-400">{factor.description}</p>
                            </div>
                          ))
                        ) : (
                          <p className="text-xs text-slate-500">No mitigating factors identified</p>
                        )}
                      </div>
                    </div>

                    {selectedVuln.threat_intel.campaigns.length > 0 && (
                      <div className="mb-6">
                        <div className="text-sm font-medium text-white mb-3 flex items-center gap-2">
                          <Target size={14} className="text-orange-400" />
                          Threat Intelligence
                        </div>
                        <div className="space-y-2">
                          {selectedVuln.threat_intel.campaigns.length > 0 && (
                            <div>
                              <div className="text-[10px] text-slate-500 mb-1">Campaigns</div>
                              <div className="flex flex-wrap gap-1">
                                {selectedVuln.threat_intel.campaigns.map((c, i) => (
                                  <span key={i} className="px-2 py-0.5 bg-orange-500/10 rounded text-xs text-orange-400">{c}</span>
                                ))}
                              </div>
                            </div>
                          )}
                          {selectedVuln.threat_intel.threat_actors.length > 0 && (
                            <div>
                              <div className="text-[10px] text-slate-500 mb-1">Threat Actors</div>
                              <div className="flex flex-wrap gap-1">
                                {selectedVuln.threat_intel.threat_actors.map((a, i) => (
                                  <span key={i} className="px-2 py-0.5 bg-red-500/10 rounded text-xs text-red-400">{a}</span>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {selectedVuln.mitigating_controls.length > 0 && (
                      <div>
                        <div className="text-sm font-medium text-white mb-3 flex items-center gap-2">
                          <Shield size={14} className="text-green-400" />
                          Mitigating Controls
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {selectedVuln.mitigating_controls.map((c, i) => (
                            <span key={i} className="px-2 py-0.5 bg-green-500/10 rounded text-xs text-green-400">{c}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </AppShell>
  )
}
