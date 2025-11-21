'use client'

import { useState } from 'react'
import { TrendingUp, TrendingDown, Shield, AlertTriangle, CheckCircle, Clock, ArrowRight } from 'lucide-react'

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

          {/* Severity Breakdown */}
          <div className="p-6 bg-white/2 rounded-lg border border-white/5">
            <h3 className="text-lg font-semibold mb-4">Severity Distribution</h3>
            <div className="space-y-3">
              {[
                { label: 'Critical', count: SUMMARY_STATS.critical, color: '#dc2626', total: SUMMARY_STATS.total_issues },
                { label: 'High', count: SUMMARY_STATS.high, color: '#f97316', total: SUMMARY_STATS.total_issues },
                { label: 'Medium', count: SUMMARY_STATS.medium, color: '#f59e0b', total: SUMMARY_STATS.total_issues },
                { label: 'Low', count: SUMMARY_STATS.low, color: '#3b82f6', total: SUMMARY_STATS.total_issues },
              ].map(({ label, count, color, total }) => {
                const percentage = Math.round((count / total) * 100)
                return (
                  <div key={label}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium text-slate-300">{label}</span>
                      <span className="text-sm text-slate-400">{count} ({percentage}%)</span>
                    </div>
                    <div className="h-2 bg-white/10 rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all"
                        style={{ width: `${percentage}%`, backgroundColor: color }}
                      ></div>
                    </div>
                  </div>
                )
              })}
            </div>
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
  )
}
