'use client'

import { useState } from 'react'
import { useDashboardData } from './hooks/useDashboardData'
import { TrendingUp, TrendingDown, Shield, AlertTriangle, CheckCircle, Clock, ArrowRight, Activity, Target, Zap, Users, Filter, Calendar, Download, RefreshCw, Wifi, WifiOff } from 'lucide-react'
import { LineChart, Line, AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import EnterpriseShell from './components/EnterpriseShell'


export default function DashboardPage() {
  // Use real-time data from API with fallback to demo data
  const { summary: SUMMARY_STATS, trends: TRENDS, topServices: TOP_SERVICES, mttrMetrics, teams: TEAM_DATA, issueTrends: ISSUE_TREND_DATA, resolutionTrends: RESOLUTION_TREND_DATA, complianceTrends: COMPLIANCE_TREND_DATA, recentFindings: RECENT_FINDINGS, isLoading, error, lastUpdated, refresh } = useDashboardData(30000)
  
  // Use MTTR trend data from API
  const MTTR_MTTD_DATA = mttrMetrics.mttr_trend
  
  // Compute severity distribution from dynamic data
  const SEVERITY_DISTRIBUTION = [
    { name: 'Critical', value: SUMMARY_STATS.critical, color: '#dc2626' },
    { name: 'High', value: SUMMARY_STATS.high, color: '#f97316' },
    { name: 'Medium', value: SUMMARY_STATS.medium, color: '#f59e0b' },
    { name: 'Low', value: SUMMARY_STATS.low, color: '#3b82f6' },
  ]
  const [selectedTeam, setSelectedTeam] = useState<string>('all')
  const [timeRange, setTimeRange] = useState<string>('7d')
  const [showDeltaMode, setShowDeltaMode] = useState(false)

  const getSeverityColor = (severity: string) => {
    const colors = {
      critical: '#dc2626',
      high: '#f97316',
      medium: '#f59e0b',
      low: '#3b82f6',
    }
    return colors[severity as keyof typeof colors] || colors.low
  }

  return (
    <EnterpriseShell>
      <div className="min-h-screen bg-[#0f172a] font-sans text-white">
        {/* Top Bar */}
        <div className="p-6 border-b border-white/10 bg-[#0f172a]/80 backdrop-blur-sm">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-semibold mb-2">FixOps Dashboard</h1>
            <p className="text-sm text-slate-400">
              Security posture overview and key metrics
            </p>
          </div>
          <div className="flex gap-3">
            <button
              onClick={() => setShowDeltaMode(!showDeltaMode)}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-all flex items-center gap-2 ${
                showDeltaMode 
                  ? 'bg-[#6B5AED] text-white' 
                  : 'bg-white/5 border border-white/10 text-slate-300 hover:bg-white/10'
              }`}
            >
              <RefreshCw size={14} />
              Delta Mode
            </button>
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all focus:outline-none focus:border-[#6B5AED]"
            >
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
              <option value="90d">Last 90 Days</option>
            </select>
            <select
              value={selectedTeam}
              onChange={(e) => setSelectedTeam(e.target.value)}
              className="px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all focus:outline-none focus:border-[#6B5AED]"
            >
              <option value="all">All Teams</option>
              {TEAM_DATA.map(team => (
                <option key={team.name} value={team.name}>{team.name}</option>
              ))}
            </select>
            <button
              className="px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all flex items-center gap-2"
            >
              <Download size={14} />
              Export
            </button>
            <button
              onClick={() => window.location.href = '/triage'}
              className="px-4 py-2 bg-[#6B5AED] rounded-md text-white text-sm font-medium hover:bg-[#5B4ADD] transition-all"
            >
              View Triage Inbox
            </button>
          </div>
        </div>
      </div>

      {/* Loading and Error States */}
        {isLoading && (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#6B5AED]"></div>
            <span className="ml-3 text-slate-400">Loading dashboard data...</span>
          </div>
        )}
        {error && (
          <div className="mx-6 mt-6 p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
            <div className="flex items-center gap-2 text-red-400">
              <AlertTriangle size={18} />
              <span className="font-medium">Error loading data</span>
            </div>
            <p className="mt-1 text-sm text-red-300">{error}</p>
            <button onClick={refresh} className="mt-2 px-3 py-1 bg-red-500/20 hover:bg-red-500/30 rounded text-sm text-red-300">Retry</button>
          </div>
        )}
        {/* Main Content */}
      <div className="p-6">
        <div className="max-w-7xl mx-auto space-y-6">
          {/* Key Metrics Grid */}
          <div className="grid grid-cols-4 gap-4">
            {/* Total Issues */}
            <div className="p-5 bg-white/2 rounded-lg border border-white/5">
              <div className="flex items-center justify-between mb-3">
                <span className="text-sm text-slate-400">Total Issues</span>
                <div className={`flex items-center gap-1 text-xs font-semibold ${
                  TRENDS.total_issues.direction === 'down' ? 'text-green-500' : 'text-red-500'
                }`}>
                  {TRENDS.total_issues.direction === 'down' ? <TrendingDown size={14} /> : <TrendingUp size={14} />}
                  {Math.abs(TRENDS.total_issues.change)}%
                </div>
              </div>
              <div className="text-3xl font-bold text-white mb-1">{SUMMARY_STATS.total_issues}</div>
              <div className="text-xs text-slate-500">
                {SUMMARY_STATS.new_7d} new, {SUMMARY_STATS.resolved_7d} resolved (7d)
              </div>
            </div>

            {/* Critical Issues */}
            <div className="p-5 bg-red-500/10 rounded-lg border border-red-500/20">
              <div className="flex items-center justify-between mb-3">
                <span className="text-sm text-red-300">Critical Issues</span>
                <div className={`flex items-center gap-1 text-xs font-semibold ${
                  TRENDS.critical.direction === 'down' ? 'text-green-500' : 'text-red-500'
                }`}>
                  {TRENDS.critical.direction === 'down' ? <TrendingDown size={14} /> : <TrendingUp size={14} />}
                  {Math.abs(TRENDS.critical.change)}%
                </div>
              </div>
              <div className="text-3xl font-bold text-red-500 mb-1">{SUMMARY_STATS.critical}</div>
              <div className="text-xs text-red-300/70">
                {SUMMARY_STATS.kev_count} KEV vulnerabilities
              </div>
            </div>

            {/* Avg Resolution Time */}
            <div className="p-5 bg-white/2 rounded-lg border border-white/5">
              <div className="flex items-center justify-between mb-3">
                <span className="text-sm text-slate-400">Avg Resolution</span>
                <div className={`flex items-center gap-1 text-xs font-semibold ${
                  TRENDS.avg_resolution_time.direction === 'down' ? 'text-green-500' : 'text-red-500'
                }`}>
                  {TRENDS.avg_resolution_time.direction === 'down' ? <TrendingDown size={14} /> : <TrendingUp size={14} />}
                  {Math.abs(TRENDS.avg_resolution_time.change)}%
                </div>
              </div>
              <div className="text-3xl font-bold text-white mb-1">
                {TRENDS.avg_resolution_time.value}
                <span className="text-lg text-slate-400 ml-1">days</span>
              </div>
              <div className="text-xs text-slate-500">
                Avg age: {SUMMARY_STATS.avg_age_days} days
              </div>
            </div>

            {/* Compliance Score */}
            <div className="p-5 bg-green-500/10 rounded-lg border border-green-500/20">
              <div className="flex items-center justify-between mb-3">
                <span className="text-sm text-green-300">Compliance Score</span>
                <div className={`flex items-center gap-1 text-xs font-semibold ${
                  TRENDS.compliance_score.direction === 'down' ? 'text-red-500' : 'text-green-500'
                }`}>
                  {TRENDS.compliance_score.direction === 'down' ? <TrendingDown size={14} /> : <TrendingUp size={14} />}
                  {Math.abs(TRENDS.compliance_score.change)}%
                </div>
              </div>
              <div className="text-3xl font-bold text-green-500 mb-1">
                {TRENDS.compliance_score.value}%
              </div>
              <div className="text-xs text-green-300/70">
                4 frameworks tracked
              </div>
            </div>
          </div>

          {/* MTTR/MTTD Metrics */}
          <div className="grid grid-cols-2 gap-4">
            <div className="p-5 bg-white/2 rounded-lg border border-white/5">
              <div className="flex items-center justify-between mb-3">
                <div>
                  <div className="text-sm text-slate-400 mb-1">Mean Time to Resolve (MTTR)</div>
                  <div className="text-3xl font-bold text-white">{mttrMetrics.mttr} <span className="text-lg text-slate-400">days</span></div>
                </div>
                <div className="p-3 bg-blue-500/10 rounded-lg">
                  <Clock size={24} className="text-blue-400" />
                </div>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <div className="flex items-center gap-1 text-green-500">
                  <TrendingDown size={12} />
                  <span className="font-semibold">-8.3%</span>
                </div>
                <span className="text-slate-500">vs last period</span>
              </div>
            </div>

            <div className="p-5 bg-white/2 rounded-lg border border-white/5">
              <div className="flex items-center justify-between mb-3">
                <div>
                  <div className="text-sm text-slate-400 mb-1">Mean Time to Detect (MTTD)</div>
                  <div className="text-3xl font-bold text-white">{mttrMetrics.mttd} <span className="text-lg text-slate-400">days</span></div>
                </div>
                <div className="p-3 bg-purple-500/10 rounded-lg">
                  <Activity size={24} className="text-purple-400" />
                </div>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <div className="flex items-center gap-1 text-green-500">
                  <TrendingDown size={12} />
                  <span className="font-semibold">-12.5%</span>
                </div>
                <span className="text-slate-500">vs last period</span>
              </div>
            </div>
          </div>

          {/* MTTR/MTTD Trend Chart */}
          <div className="p-6 bg-white/2 rounded-lg border border-white/5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">MTTR & MTTD Trend (10 Weeks)</h3>
              <div className="flex items-center gap-4 text-xs">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full bg-[#6B5AED]"></div>
                  <span className="text-slate-400">MTTR</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full bg-[#10b981]"></div>
                  <span className="text-slate-400">MTTD</span>
                </div>
              </div>
            </div>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={MTTR_MTTD_DATA}>
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" />
                <XAxis dataKey="week" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '6px' }}
                  labelStyle={{ color: '#e2e8f0' }}
                />
                <Line type="monotone" dataKey="mttr" stroke="#6B5AED" strokeWidth={2} dot={{ fill: '#6B5AED', r: 4 }} name="MTTR (days)" />
                <Line type="monotone" dataKey="mttd" stroke="#10b981" strokeWidth={2} dot={{ fill: '#10b981', r: 4 }} name="MTTD (days)" />
              </LineChart>
            </ResponsiveContainer>
            <div className="mt-3 text-xs text-slate-400">
              Both metrics trending down - faster detection and resolution
            </div>
          </div>

          {/* Team Performance */}
          <div className="p-6 bg-white/2 rounded-lg border border-white/5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Team Performance</h3>
              <Users size={18} className="text-[#6B5AED]" />
            </div>
            <div className="space-y-3">
              {TEAM_DATA.map((team, index) => (
                <div 
                  key={team.name}
                  className="p-4 bg-white/2 rounded-lg border border-white/5 hover:border-[#6B5AED]/30 transition-all cursor-pointer"
                  onClick={() => setSelectedTeam(team.name)}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="font-medium text-white">{team.name}</div>
                    <div className="flex items-center gap-3 text-xs">
                      <div className="flex items-center gap-1">
                        <div className="w-2 h-2 rounded-full bg-red-500"></div>
                        <span className="text-slate-400">{team.critical} critical</span>
                      </div>
                      <div className="text-slate-500">{team.issues} total</div>
                    </div>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-3">
                      <div className="text-slate-400">
                        Resolved: <span className="text-green-400 font-semibold">{team.resolved_7d}</span> (7d)
                      </div>
                      <div className="text-slate-400">
                        Avg Resolution: <span className="text-white font-semibold">{team.avg_resolution}d</span>
                      </div>
                    </div>
                    <ArrowRight size={14} className="text-slate-500" />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Charts Grid - 3 columns */}
          <div className="grid grid-cols-3 gap-6">
            {/* Issue Trend Chart */}
            <div className="p-6 bg-white/2 rounded-lg border border-white/5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Issue Trend (10 Days)</h3>
                <Activity size={18} className="text-[#6B5AED]" />
              </div>
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={ISSUE_TREND_DATA}>
                  <defs>
                    <linearGradient id="totalGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#6B5AED" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#6B5AED" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" />
                  <XAxis dataKey="day" stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={11} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '6px' }}
                    labelStyle={{ color: '#e2e8f0' }}
                  />
                  <Area type="monotone" dataKey="total" stroke="#6B5AED" fillOpacity={1} fill="url(#totalGradient)" />
                </AreaChart>
              </ResponsiveContainer>
              <div className="mt-3 text-xs text-slate-400">
                Trending down -5.2% from last period
              </div>
            </div>

            {/* Severity Distribution Pie Chart */}
            <div className="p-6 bg-white/2 rounded-lg border border-white/5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Severity Distribution</h3>
                <Target size={18} className="text-[#6B5AED]" />
              </div>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={SEVERITY_DISTRIBUTION}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={2}
                    dataKey="value"
                  >
                    {SEVERITY_DISTRIBUTION.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '6px' }}
                    labelStyle={{ color: '#e2e8f0' }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
                {SEVERITY_DISTRIBUTION.map((item) => (
                  <div key={item.name} className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }}></div>
                    <span className="text-slate-400">{item.name}: {item.value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Resolution Time Trend */}
            <div className="p-6 bg-white/2 rounded-lg border border-white/5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Resolution Time (10 Weeks)</h3>
                <Zap size={18} className="text-[#6B5AED]" />
              </div>
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={RESOLUTION_TREND_DATA}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" />
                  <XAxis dataKey="week" stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={11} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '6px' }}
                    labelStyle={{ color: '#e2e8f0' }}
                  />
                  <Line type="monotone" dataKey="avgDays" stroke="#6B5AED" strokeWidth={2} dot={{ fill: '#6B5AED', r: 4 }} />
                  <Line type="monotone" dataKey="target" stroke="#10b981" strokeWidth={2} strokeDasharray="5 5" dot={false} />
                </LineChart>
              </ResponsiveContainer>
              <div className="mt-3 text-xs text-slate-400">
                Target: 4.0 days • Current: 4.2 days
              </div>
            </div>
          </div>

          {/* Compliance Trend Chart - Full Width */}
          <div className="p-6 bg-white/2 rounded-lg border border-white/5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Compliance Score Trend (12 Months)</h3>
              <div className="flex items-center gap-2">
                <span className="text-2xl font-bold text-green-500">85%</span>
                <div className="flex items-center gap-1 text-xs font-semibold text-green-500">
                  <TrendingUp size={14} />
                  +3.1%
                </div>
              </div>
            </div>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={COMPLIANCE_TREND_DATA}>
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" />
                <XAxis dataKey="month" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} domain={[70, 90]} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '6px' }}
                  labelStyle={{ color: '#e2e8f0' }}
                />
                <Bar dataKey="score" fill="#10b981" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Two Column Layout */}
          <div className="grid grid-cols-2 gap-6">
            {/* Recent Critical Findings */}
            <div className="p-6 bg-white/2 rounded-lg border border-white/5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Recent Critical Findings</h3>
                <button
                  onClick={() => window.location.href = '/triage'}
                  className="text-sm text-[#6B5AED] hover:text-[#5B4ADD] transition-colors flex items-center gap-1"
                >
                  View All
                  <ArrowRight size={14} />
                </button>
              </div>
              <div className="space-y-3">
                {RECENT_FINDINGS.map((finding) => (
                  <div
                    key={finding.id}
                    className="p-4 bg-white/5 rounded-md border border-white/10 hover:bg-white/10 transition-all cursor-pointer"
                    onClick={() => window.location.href = `/findings?id=${finding.id}`}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <div
                            className="w-2 h-2 rounded-full"
                            style={{ backgroundColor: getSeverityColor(finding.severity) }}
                          ></div>
                          <span
                            className="text-xs font-semibold uppercase tracking-wider"
                            style={{ color: getSeverityColor(finding.severity) }}
                          >
                            {finding.severity}
                          </span>
                          {finding.kev && (
                            <span className="px-1.5 py-0.5 bg-amber-500/20 border border-amber-500/30 rounded text-[10px] font-semibold text-amber-300">
                              KEV
                            </span>
                          )}
                        </div>
                        <h4 className="text-sm font-semibold text-white mb-1">{finding.title}</h4>
                        <div className="flex items-center gap-2 text-xs text-slate-400">
                          <span className="font-mono">{finding.service}</span>
                          <span>•</span>
                          <span className="flex items-center gap-1">
                            <Clock size={10} />
                            {finding.age}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Top Affected Services */}
            <div className="p-6 bg-white/2 rounded-lg border border-white/5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Top Affected Services</h3>
                <button
                  onClick={() => window.location.href = '/risk'}
                  className="text-sm text-[#6B5AED] hover:text-[#5B4ADD] transition-colors flex items-center gap-1"
                >
                  View Graph
                  <ArrowRight size={14} />
                </button>
              </div>
              <div className="space-y-3">
                {TOP_SERVICES.map((service, idx) => (
                  <div
                    key={service.name}
                    className="p-4 bg-white/5 rounded-md border border-white/10"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-slate-500">#{idx + 1}</span>
                        <span className="text-sm font-mono text-white">{service.name}</span>
                      </div>
                      <span className="text-sm font-semibold text-slate-300">{service.issues} issues</span>
                    </div>
                    <div className="flex gap-3 text-xs">
                      <span className="text-red-400">{service.critical} critical</span>
                      <span className="text-orange-400">{service.high} high</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="grid grid-cols-4 gap-4">
            <button
              onClick={() => window.location.href = '/triage'}
              className="p-4 bg-white/5 border border-white/10 rounded-md hover:bg-white/10 transition-all text-left"
            >
              <Shield size={20} className="text-[#6B5AED] mb-2" />
              <div className="text-sm font-semibold text-white mb-1">Triage Inbox</div>
              <div className="text-xs text-slate-400">Review and prioritize findings</div>
            </button>
            <button
              onClick={() => window.location.href = '/compliance'}
              className="p-4 bg-white/5 border border-white/10 rounded-md hover:bg-white/10 transition-all text-left"
            >
              <CheckCircle size={20} className="text-green-500 mb-2" />
              <div className="text-sm font-semibold text-white mb-1">Compliance</div>
              <div className="text-xs text-slate-400">Framework coverage & gaps</div>
            </button>
            <button
              onClick={() => window.location.href = '/evidence'}
              className="p-4 bg-white/5 border border-white/10 rounded-md hover:bg-white/10 transition-all text-left"
            >
              <Shield size={20} className="text-amber-500 mb-2" />
              <div className="text-sm font-semibold text-white mb-1">Evidence</div>
              <div className="text-xs text-slate-400">Signed audit bundles</div>
            </button>
            <button
              onClick={() => window.location.href = '/settings'}
              className="p-4 bg-white/5 border border-white/10 rounded-md hover:bg-white/10 transition-all text-left"
            >
              <AlertTriangle size={20} className="text-slate-400 mb-2" />
              <div className="text-sm font-semibold text-white mb-1">Settings</div>
              <div className="text-xs text-slate-400">Configure organization</div>
            </button>
          </div>
        </div>
      </div>
    </div>
    </EnterpriseShell>
  )
}
