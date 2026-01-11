'use client'

import { useState, useMemo } from 'react'
import { ArrowLeft, AlertCircle, TrendingUp, TrendingDown, Download, BarChart3, PieChart, Activity, Shield, Target, FileText } from 'lucide-react'
import { AppShell, useDemoModeContext } from '@fixops/ui'

interface MetricCard {
  id: string
  title: string
  value: number | string
  change: number
  changeType: 'increase' | 'decrease'
  unit?: string
  trend: number[]
}

interface VulnerabilityTrend {
  date: string
  critical: number
  high: number
  medium: number
  low: number
}

interface RemediationMetric {
  period: string
  fixed: number
  new: number
  net: number
}

interface AssetRisk {
  id: string
  name: string
  type: string
  risk_score: number
  vulnerabilities: number
  last_scan: string
}

interface ScannerCoverage {
  name: string
  coverage: number
  assets_scanned: number
  total_assets: number
}

const DEMO_METRICS: MetricCard[] = [
  {
    id: 'risk-score',
    title: 'Overall Risk Score',
    value: 72,
    change: -8,
    changeType: 'decrease',
    trend: [85, 82, 78, 75, 72],
  },
  {
    id: 'mttr',
    title: 'Mean Time to Remediate',
    value: '12.4',
    change: -2.3,
    changeType: 'decrease',
    unit: 'days',
    trend: [18, 16, 14, 13, 12.4],
  },
  {
    id: 'mttd',
    title: 'Mean Time to Detect',
    value: '4.2',
    change: -0.8,
    changeType: 'decrease',
    unit: 'hours',
    trend: [6, 5.5, 5, 4.5, 4.2],
  },
  {
    id: 'open-vulns',
    title: 'Open Vulnerabilities',
    value: 1247,
    change: -156,
    changeType: 'decrease',
    trend: [1500, 1420, 1350, 1300, 1247],
  },
  {
    id: 'critical-vulns',
    title: 'Critical Vulnerabilities',
    value: 23,
    change: -7,
    changeType: 'decrease',
    trend: [45, 38, 32, 28, 23],
  },
  {
    id: 'compliance',
    title: 'Compliance Score',
    value: '94%',
    change: 3,
    changeType: 'increase',
    trend: [88, 90, 91, 93, 94],
  },
]

const DEMO_VULN_TRENDS: VulnerabilityTrend[] = [
  { date: 'Week 1', critical: 45, high: 234, medium: 567, low: 890 },
  { date: 'Week 2', critical: 38, high: 212, medium: 534, low: 856 },
  { date: 'Week 3', critical: 32, high: 198, medium: 512, low: 823 },
  { date: 'Week 4', critical: 28, high: 178, medium: 489, low: 798 },
  { date: 'Week 5', critical: 23, high: 156, medium: 456, low: 768 },
]

const DEMO_REMEDIATION: RemediationMetric[] = [
  { period: 'Week 1', fixed: 89, new: 67, net: -22 },
  { period: 'Week 2', fixed: 112, new: 78, net: -34 },
  { period: 'Week 3', fixed: 98, new: 56, net: -42 },
  { period: 'Week 4', fixed: 134, new: 89, net: -45 },
  { period: 'Week 5', fixed: 156, new: 98, net: -58 },
]

const DEMO_TOP_ASSETS: AssetRisk[] = [
  { id: 'a1', name: 'payment-api-prod', type: 'Application', risk_score: 95, vulnerabilities: 23, last_scan: '2024-11-21T10:00:00Z' },
  { id: 'a2', name: 'customer-db-primary', type: 'Database', risk_score: 92, vulnerabilities: 8, last_scan: '2024-11-21T08:00:00Z' },
  { id: 'a3', name: 'auth-service-prod', type: 'Application', risk_score: 88, vulnerabilities: 15, last_scan: '2024-11-21T09:30:00Z' },
  { id: 'a4', name: 'vpn-gateway-01', type: 'Network', risk_score: 85, vulnerabilities: 4, last_scan: '2024-11-21T06:00:00Z' },
  { id: 'a5', name: 'k8s-control-plane', type: 'Infrastructure', risk_score: 82, vulnerabilities: 12, last_scan: '2024-11-21T07:00:00Z' },
]

const DEMO_SCANNER_COVERAGE: ScannerCoverage[] = [
  { name: 'Infrastructure', coverage: 92, assets_scanned: 2847, total_assets: 3095 },
  { name: 'Application (SAST)', coverage: 85, assets_scanned: 312, total_assets: 367 },
  { name: 'Application (DAST)', coverage: 78, assets_scanned: 156, total_assets: 200 },
  { name: 'Cloud/Container', coverage: 88, assets_scanned: 1247, total_assets: 1417 },
  { name: 'CMDB', coverage: 95, assets_scanned: 8934, total_assets: 9404 },
]

const BUSINESS_LINES = [
  { id: 'all', name: 'All Business Lines' },
  { id: 'payments', name: 'Payments' },
  { id: 'customer', name: 'Customer Services' },
  { id: 'infrastructure', name: 'Infrastructure' },
  { id: 'data', name: 'Data Platform' },
]

function formatDate(dateString: string): string {
  return new Date(dateString).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export default function InsightPage() {
  const { demoEnabled } = useDemoModeContext()
  const [selectedBusinessLine, setSelectedBusinessLine] = useState('all')
  const [dateRange, setDateRange] = useState('30d')

  const metrics = useMemo(() => demoEnabled ? DEMO_METRICS : [], [demoEnabled])
  const vulnTrends = useMemo(() => demoEnabled ? DEMO_VULN_TRENDS : [], [demoEnabled])
  const remediation = useMemo(() => demoEnabled ? DEMO_REMEDIATION : [], [demoEnabled])
  const topAssets = useMemo(() => demoEnabled ? DEMO_TOP_ASSETS : [], [demoEnabled])
  const scannerCoverage = useMemo(() => demoEnabled ? DEMO_SCANNER_COVERAGE : [], [demoEnabled])

  const severityDistribution = useMemo(() => {
    if (!demoEnabled || vulnTrends.length === 0) return { critical: 0, high: 0, medium: 0, low: 0 }
    const latest = vulnTrends[vulnTrends.length - 1]
    return {
      critical: latest.critical,
      high: latest.high,
      medium: latest.medium,
      low: latest.low,
    }
  }, [demoEnabled, vulnTrends])

  const totalVulns = severityDistribution.critical + severityDistribution.high + severityDistribution.medium + severityDistribution.low

  const handleExportPDF = () => {
    console.log('Exporting PDF report...')
    alert('PDF export functionality - would generate a comprehensive security report')
  }

  const handleExportCSV = () => {
    const headers = ['Metric', 'Value', 'Change', 'Trend']
    const rows = metrics.map(m => [
      m.title,
      `${m.value}${m.unit ? ' ' + m.unit : ''}`,
      `${m.change > 0 ? '+' : ''}${m.change}`,
      m.trend.join(' -> ')
    ])
    const csv = [headers, ...rows].map(row => row.join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'security-metrics.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  const getRiskColor = (score: number) => {
    if (score >= 90) return 'text-red-400'
    if (score >= 70) return 'text-orange-400'
    if (score >= 50) return 'text-yellow-400'
    return 'text-green-400'
  }

  return (
    <AppShell activeApp="insight">
      <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
        <div className="w-72 bg-[#0f172a]/80 border-r border-white/10 flex flex-col sticky top-0 h-screen">
          <div className="p-6 border-b border-white/10">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-[#6B5AED]">Insight</h2>
              <button
                onClick={() => window.location.href = '/triage'}
                className="p-2 rounded-md border border-white/10 text-slate-400 hover:bg-white/5 transition-all"
                title="Back to Triage"
              >
                <ArrowLeft size={16} />
              </button>
            </div>
            <p className="text-xs text-slate-500">Security analytics dashboard</p>
          </div>

          <div className="p-4 border-b border-white/10">
            <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">
              Business Line
            </div>
            <select
              value={selectedBusinessLine}
              onChange={(e) => setSelectedBusinessLine(e.target.value)}
              className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white focus:outline-none focus:border-[#6B5AED]/50"
            >
              {BUSINESS_LINES.map(bl => (
                <option key={bl.id} value={bl.id}>{bl.name}</option>
              ))}
            </select>
          </div>

          <div className="p-4 border-b border-white/10">
            <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">
              Date Range
            </div>
            <div className="grid grid-cols-2 gap-2">
              {['7d', '30d', '90d', '1y'].map(range => (
                <button
                  key={range}
                  onClick={() => setDateRange(range)}
                  className={`px-3 py-2 rounded-md text-xs font-medium transition-all ${
                    dateRange === range
                      ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                      : 'bg-white/5 text-slate-400 border border-white/10 hover:bg-white/10'
                  }`}
                >
                  {range}
                </button>
              ))}
            </div>
          </div>

          <div className="p-4 flex-1">
            <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">
              Quick Stats
            </div>
            <div className="space-y-3">
              <div className="p-3 bg-gradient-to-r from-green-500/10 to-emerald-500/10 rounded-md border border-green-500/20">
                <div className="flex items-center gap-2 mb-1">
                  <TrendingDown size={14} className="text-green-400" />
                  <span className="text-xs text-green-400">Risk Trending Down</span>
                </div>
                <div className="text-lg font-bold text-white">-8 points</div>
                <div className="text-[10px] text-slate-500">vs last month</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md border border-white/10">
                <div className="flex items-center gap-2 mb-1">
                  <Activity size={14} className="text-blue-400" />
                  <span className="text-xs text-slate-400">Remediation Velocity</span>
                </div>
                <div className="text-lg font-bold text-white">156/week</div>
                <div className="text-[10px] text-slate-500">vulns fixed</div>
              </div>
            </div>
          </div>
        </div>

        <div className="flex-1 flex flex-col">
          <div className="p-5 border-b border-white/10 bg-[#0f172a]/80 backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-2xl font-semibold mb-1">Security Dashboard</h1>
                <p className="text-sm text-slate-500">
                  {selectedBusinessLine === 'all' ? 'Organization-wide' : BUSINESS_LINES.find(b => b.id === selectedBusinessLine)?.name} security metrics
                </p>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={handleExportCSV}
                  className="px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all flex items-center gap-2"
                >
                  <Download size={14} />
                  Export CSV
                </button>
                <button
                  onClick={handleExportPDF}
                  className="px-4 py-2 bg-[#6B5AED] rounded-md text-white text-sm font-medium hover:bg-[#5B4ADD] transition-all flex items-center gap-2"
                >
                  <FileText size={14} />
                  Export PDF
                </button>
              </div>
            </div>
          </div>

          <div className="flex-1 overflow-auto p-6">
            {!demoEnabled ? (
              <div className="flex items-center justify-center h-full">
                <div className="text-center max-w-md">
                  <AlertCircle size={48} className="mx-auto mb-4 text-slate-500" />
                  <h3 className="text-lg font-semibold text-white mb-2">No Analytics Data</h3>
                  <p className="text-sm text-slate-400 mb-4">
                    Enable demo mode to see sample analytics, or connect your systems to see real data.
                  </p>
                </div>
              </div>
            ) : (
              <div className="space-y-6">
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                  {metrics.map((metric) => (
                    <div
                      key={metric.id}
                      className="p-4 bg-white/5 rounded-lg border border-white/10"
                    >
                      <div className="text-xs text-slate-500 mb-2">{metric.title}</div>
                      <div className="flex items-baseline gap-1 mb-2">
                        <span className="text-2xl font-bold text-white">{metric.value}</span>
                        {metric.unit && <span className="text-sm text-slate-400">{metric.unit}</span>}
                      </div>
                      <div className={`flex items-center gap-1 text-xs ${
                        metric.changeType === 'decrease' ? 'text-green-400' : 'text-red-400'
                      }`}>
                        {metric.changeType === 'decrease' ? (
                          <TrendingDown size={12} />
                        ) : (
                          <TrendingUp size={12} />
                        )}
                        <span>{metric.change > 0 ? '+' : ''}{metric.change}</span>
                      </div>
                    </div>
                  ))}
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="p-4 bg-white/5 rounded-lg border border-white/10">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="font-semibold text-white flex items-center gap-2">
                        <BarChart3 size={16} className="text-[#6B5AED]" />
                        Vulnerability Trend
                      </h3>
                    </div>
                    <div className="space-y-3">
                      {vulnTrends.map((week, index) => (
                        <div key={index} className="flex items-center gap-3">
                          <span className="text-xs text-slate-500 w-16">{week.date}</span>
                          <div className="flex-1 flex h-4 rounded overflow-hidden">
                            <div 
                              className="bg-red-500" 
                              style={{ width: `${(week.critical / (week.critical + week.high + week.medium + week.low)) * 100}%` }}
                              title={`Critical: ${week.critical}`}
                            />
                            <div 
                              className="bg-orange-500" 
                              style={{ width: `${(week.high / (week.critical + week.high + week.medium + week.low)) * 100}%` }}
                              title={`High: ${week.high}`}
                            />
                            <div 
                              className="bg-yellow-500" 
                              style={{ width: `${(week.medium / (week.critical + week.high + week.medium + week.low)) * 100}%` }}
                              title={`Medium: ${week.medium}`}
                            />
                            <div 
                              className="bg-green-500" 
                              style={{ width: `${(week.low / (week.critical + week.high + week.medium + week.low)) * 100}%` }}
                              title={`Low: ${week.low}`}
                            />
                          </div>
                          <span className="text-xs text-slate-400 w-12 text-right">
                            {week.critical + week.high + week.medium + week.low}
                          </span>
                        </div>
                      ))}
                    </div>
                    <div className="flex items-center gap-4 mt-4 text-xs">
                      <span className="flex items-center gap-1"><span className="w-2 h-2 bg-red-500 rounded" /> Critical</span>
                      <span className="flex items-center gap-1"><span className="w-2 h-2 bg-orange-500 rounded" /> High</span>
                      <span className="flex items-center gap-1"><span className="w-2 h-2 bg-yellow-500 rounded" /> Medium</span>
                      <span className="flex items-center gap-1"><span className="w-2 h-2 bg-green-500 rounded" /> Low</span>
                    </div>
                  </div>

                  <div className="p-4 bg-white/5 rounded-lg border border-white/10">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="font-semibold text-white flex items-center gap-2">
                        <Activity size={16} className="text-green-400" />
                        Remediation Velocity
                      </h3>
                    </div>
                    <div className="space-y-3">
                      {remediation.map((week, index) => (
                        <div key={index} className="flex items-center gap-3">
                          <span className="text-xs text-slate-500 w-16">{week.period}</span>
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <div className="flex-1 h-2 bg-white/10 rounded-full overflow-hidden">
                                <div 
                                  className="h-full bg-green-500 rounded-full"
                                  style={{ width: `${(week.fixed / 200) * 100}%` }}
                                />
                              </div>
                              <span className="text-xs text-green-400 w-8">{week.fixed}</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <div className="flex-1 h-2 bg-white/10 rounded-full overflow-hidden">
                                <div 
                                  className="h-full bg-red-500 rounded-full"
                                  style={{ width: `${(week.new / 200) * 100}%` }}
                                />
                              </div>
                              <span className="text-xs text-red-400 w-8">{week.new}</span>
                            </div>
                          </div>
                          <span className={`text-xs font-medium w-12 text-right ${week.net < 0 ? 'text-green-400' : 'text-red-400'}`}>
                            {week.net > 0 ? '+' : ''}{week.net}
                          </span>
                        </div>
                      ))}
                    </div>
                    <div className="flex items-center gap-4 mt-4 text-xs">
                      <span className="flex items-center gap-1"><span className="w-2 h-2 bg-green-500 rounded" /> Fixed</span>
                      <span className="flex items-center gap-1"><span className="w-2 h-2 bg-red-500 rounded" /> New</span>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  <div className="p-4 bg-white/5 rounded-lg border border-white/10">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="font-semibold text-white flex items-center gap-2">
                        <PieChart size={16} className="text-orange-400" />
                        Severity Distribution
                      </h3>
                    </div>
                    <div className="flex items-center justify-center mb-4">
                      <div className="relative w-32 h-32">
                        <svg viewBox="0 0 36 36" className="w-full h-full -rotate-90">
                          <circle cx="18" cy="18" r="15.915" fill="none" stroke="#1e293b" strokeWidth="3" />
                          <circle 
                            cx="18" cy="18" r="15.915" fill="none" 
                            stroke="#ef4444" strokeWidth="3"
                            strokeDasharray={`${(severityDistribution.critical / totalVulns) * 100} 100`}
                            strokeDashoffset="0"
                          />
                          <circle 
                            cx="18" cy="18" r="15.915" fill="none" 
                            stroke="#f97316" strokeWidth="3"
                            strokeDasharray={`${(severityDistribution.high / totalVulns) * 100} 100`}
                            strokeDashoffset={`-${(severityDistribution.critical / totalVulns) * 100}`}
                          />
                          <circle 
                            cx="18" cy="18" r="15.915" fill="none" 
                            stroke="#eab308" strokeWidth="3"
                            strokeDasharray={`${(severityDistribution.medium / totalVulns) * 100} 100`}
                            strokeDashoffset={`-${((severityDistribution.critical + severityDistribution.high) / totalVulns) * 100}`}
                          />
                          <circle 
                            cx="18" cy="18" r="15.915" fill="none" 
                            stroke="#22c55e" strokeWidth="3"
                            strokeDasharray={`${(severityDistribution.low / totalVulns) * 100} 100`}
                            strokeDashoffset={`-${((severityDistribution.critical + severityDistribution.high + severityDistribution.medium) / totalVulns) * 100}`}
                          />
                        </svg>
                        <div className="absolute inset-0 flex items-center justify-center">
                          <div className="text-center">
                            <div className="text-xl font-bold text-white">{totalVulns}</div>
                            <div className="text-[10px] text-slate-500">Total</div>
                          </div>
                        </div>
                      </div>
                    </div>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-red-400 flex items-center gap-2">
                          <span className="w-2 h-2 bg-red-500 rounded" /> Critical
                        </span>
                        <span className="text-xs text-white">{severityDistribution.critical}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-orange-400 flex items-center gap-2">
                          <span className="w-2 h-2 bg-orange-500 rounded" /> High
                        </span>
                        <span className="text-xs text-white">{severityDistribution.high}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-yellow-400 flex items-center gap-2">
                          <span className="w-2 h-2 bg-yellow-500 rounded" /> Medium
                        </span>
                        <span className="text-xs text-white">{severityDistribution.medium}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-green-400 flex items-center gap-2">
                          <span className="w-2 h-2 bg-green-500 rounded" /> Low
                        </span>
                        <span className="text-xs text-white">{severityDistribution.low}</span>
                      </div>
                    </div>
                  </div>

                  <div className="p-4 bg-white/5 rounded-lg border border-white/10">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="font-semibold text-white flex items-center gap-2">
                        <Shield size={16} className="text-blue-400" />
                        Scanner Coverage
                      </h3>
                    </div>
                    <div className="space-y-3">
                      {scannerCoverage.map((scanner, index) => (
                        <div key={index}>
                          <div className="flex items-center justify-between text-xs mb-1">
                            <span className="text-slate-400">{scanner.name}</span>
                            <span className="text-white">{scanner.coverage}%</span>
                          </div>
                          <div className="h-2 bg-white/10 rounded-full overflow-hidden">
                            <div 
                              className={`h-full rounded-full ${
                                scanner.coverage >= 90 ? 'bg-green-500' :
                                scanner.coverage >= 70 ? 'bg-yellow-500' : 'bg-red-500'
                              }`}
                              style={{ width: `${scanner.coverage}%` }}
                            />
                          </div>
                          <div className="text-[10px] text-slate-500 mt-1">
                            {scanner.assets_scanned.toLocaleString()} / {scanner.total_assets.toLocaleString()} assets
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="p-4 bg-white/5 rounded-lg border border-white/10">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="font-semibold text-white flex items-center gap-2">
                        <Target size={16} className="text-red-400" />
                        Top Risky Assets
                      </h3>
                    </div>
                    <div className="space-y-3">
                      {topAssets.map((asset, index) => (
                        <div key={asset.id} className="flex items-center gap-3">
                          <span className="text-xs text-slate-500 w-4">{index + 1}</span>
                          <div className="flex-1 min-w-0">
                            <div className="text-sm text-white truncate">{asset.name}</div>
                            <div className="text-[10px] text-slate-500">{asset.type} - {asset.vulnerabilities} vulns</div>
                          </div>
                          <div className={`text-sm font-bold ${getRiskColor(asset.risk_score)}`}>
                            {asset.risk_score}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </AppShell>
  )
}
