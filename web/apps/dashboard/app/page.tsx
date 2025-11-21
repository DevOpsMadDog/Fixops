'use client'

import { useState } from 'react'
import { TrendingUp, TrendingDown, Shield, AlertTriangle, CheckCircle, Clock, ArrowRight, Activity, Target, Zap } from 'lucide-react'
import { LineChart, Line, AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import EnterpriseShell from './components/EnterpriseShell'

const SUMMARY_STATS = {
  total_issues: 789,
  critical: 45,
  high: 123,
  medium: 298,
  low: 323,
  new_7d: 87,
  resolved_7d: 52,
  kev_count: 12,
  internet_facing: 234,
  avg_age_days: 23,
}

const TRENDS = {
  total_issues: { value: 789, change: -5.2, direction: 'down' },
  critical: { value: 45, change: 12.5, direction: 'up' },
  avg_resolution_time: { value: 4.2, change: -8.3, direction: 'down', unit: 'days' },
  compliance_score: { value: 85, change: 3.1, direction: 'up', unit: '%' },
}

const ISSUE_TREND_DATA = [
  { day: 'Day 1', total: 823, critical: 38, high: 115, medium: 312, low: 358 },
  { day: 'Day 2', total: 819, critical: 39, high: 117, medium: 310, low: 353 },
  { day: 'Day 3', total: 815, critical: 40, high: 118, medium: 308, low: 349 },
  { day: 'Day 4', total: 811, critical: 41, high: 119, medium: 306, low: 345 },
  { day: 'Day 5', total: 807, critical: 42, high: 120, medium: 304, low: 341 },
  { day: 'Day 6', total: 803, critical: 43, high: 121, medium: 302, low: 337 },
  { day: 'Day 7', total: 799, critical: 44, high: 122, medium: 300, low: 333 },
  { day: 'Day 8', total: 795, critical: 45, high: 123, medium: 298, low: 329 },
  { day: 'Day 9', total: 791, critical: 46, high: 124, medium: 296, low: 325 },
  { day: 'Day 10', total: 789, critical: 45, high: 123, medium: 298, low: 323 },
]

const RESOLUTION_TREND_DATA = [
  { week: 'W1', avgDays: 5.2, target: 4.0 },
  { week: 'W2', avgDays: 5.0, target: 4.0 },
  { week: 'W3', avgDays: 4.8, target: 4.0 },
  { week: 'W4', avgDays: 4.9, target: 4.0 },
  { week: 'W5', avgDays: 4.7, target: 4.0 },
  { week: 'W6', avgDays: 4.5, target: 4.0 },
  { week: 'W7', avgDays: 4.4, target: 4.0 },
  { week: 'W8', avgDays: 4.3, target: 4.0 },
  { week: 'W9', avgDays: 4.2, target: 4.0 },
  { week: 'W10', avgDays: 4.2, target: 4.0 },
]

const SEVERITY_DISTRIBUTION = [
  { name: 'Critical', value: SUMMARY_STATS.critical, color: '#dc2626' },
  { name: 'High', value: SUMMARY_STATS.high, color: '#f97316' },
  { name: 'Medium', value: SUMMARY_STATS.medium, color: '#f59e0b' },
  { name: 'Low', value: SUMMARY_STATS.low, color: '#3b82f6' },
]

const COMPLIANCE_TREND_DATA = [
  { month: 'Jan', score: 78 },
  { month: 'Feb', score: 79 },
  { month: 'Mar', score: 80 },
  { month: 'Apr', score: 81 },
  { month: 'May', score: 82 },
  { month: 'Jun', score: 82 },
  { month: 'Jul', score: 83 },
  { month: 'Aug', score: 83 },
  { month: 'Sep', score: 84 },
  { month: 'Oct', score: 84 },
  { month: 'Nov', score: 85 },
  { month: 'Dec', score: 85 },
]

const RECENT_FINDINGS = [
  {
    id: '1',
    title: 'Apache Struts RCE (CVE-2023-50164)',
    severity: 'critical',
    service: 'payment-api',
    age: '2 hours ago',
    kev: true,
  },
  {
    id: '3',
    title: 'Exposed AWS Credentials',
    severity: 'critical',
    service: 'config-service',
    age: '5 hours ago',
    kev: false,
  },
  {
    id: '9',
    title: 'Log4j RCE (CVE-2021-44228)',
    severity: 'critical',
    service: 'logging-service',
    age: '1 day ago',
    kev: true,
  },
]

const TOP_SERVICES = [
  { name: 'payment-api', issues: 45, critical: 8, high: 15 },
  { name: 'user-service', issues: 38, critical: 5, high: 12 },
  { name: 'auth-service', issues: 32, critical: 4, high: 10 },
  { name: 'logging-service', issues: 28, critical: 6, high: 8 },
  { name: 'api-gateway', issues: 24, critical: 3, high: 9 },
]

export default function DashboardPage() {
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
              onClick={() => window.location.href = '/triage'}
              className="px-4 py-2 bg-[#6B5AED] rounded-md text-white text-sm font-medium hover:bg-[#5B4ADD] transition-all"
            >
              View Triage Inbox
            </button>
            <button
              onClick={() => window.location.href = '/risk'}
              className="px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all"
            >
              Risk Graph
            </button>
          </div>
        </div>
      </div>

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
