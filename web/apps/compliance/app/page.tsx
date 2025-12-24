'use client'

import { useState, useEffect, useCallback, useMemo } from 'react'
import { Shield, CheckCircle, XCircle, AlertTriangle, ChevronRight, ArrowLeft, Loader2 } from 'lucide-react'
import { AppShell } from '@fixops/ui'
import { useCompliance, useSystemMode, useDemoMode } from '@fixops/api-client'
import { Switch, StatusBadge, StatCard } from '@fixops/ui'

interface Framework {
  id: string
  name: string
  description: string
  coverage: number
  controls_total: number
  controls_passing: number
  controls_failing: number
  last_audit: string
  next_audit: string
  status: string
}

interface ControlGap {
  id: string
  framework: string
  control_id: string
  control_name: string
  description: string
  severity: string
  affected_services: string[]
  remediation: string
}

const DEMO_FRAMEWORKS: Framework[] = [
  {
    id: 'soc2',
    name: 'SOC 2 Type II',
    description: 'Service Organization Control 2',
    coverage: 78,
    controls_total: 64,
    controls_passing: 50,
    controls_failing: 14,
    last_audit: '2024-09-15',
    next_audit: '2025-03-15',
    status: 'active',
  },
  {
    id: 'iso27001',
    name: 'ISO 27001:2022',
    description: 'Information Security Management',
    coverage: 85,
    controls_total: 93,
    controls_passing: 79,
    controls_failing: 14,
    last_audit: '2024-08-20',
    next_audit: '2025-02-20',
    status: 'active',
  },
  {
    id: 'pci-dss',
    name: 'PCI-DSS 4.0',
    description: 'Payment Card Industry Data Security Standard',
    coverage: 92,
    controls_total: 12,
    controls_passing: 11,
    controls_failing: 1,
    last_audit: '2024-10-01',
    next_audit: '2025-04-01',
    status: 'active',
  },
  {
    id: 'gdpr',
    name: 'GDPR',
    description: 'General Data Protection Regulation',
    coverage: 88,
    controls_total: 28,
    controls_passing: 25,
    controls_failing: 3,
    last_audit: '2024-07-10',
    next_audit: '2025-01-10',
    status: 'active',
  },
]

const DEMO_CONTROL_GAPS: ControlGap[] = [
  {
    id: 'gap1',
    framework: 'SOC 2',
    control_id: 'CC8.1',
    control_name: 'Vulnerability Management',
    description: '14 critical vulnerabilities unpatched for >30 days',
    severity: 'high',
    affected_services: ['payment-api', 'user-service', 'logging-service'],
    remediation: 'Apply security patches to Apache Struts, OpenSSL, and Log4j',
  },
  {
    id: 'gap2',
    framework: 'ISO 27001',
    control_id: 'A.12.6.1',
    control_name: 'Management of Technical Vulnerabilities',
    description: 'No automated vulnerability scanning in CI/CD pipeline',
    severity: 'medium',
    affected_services: ['All services'],
    remediation: 'Integrate SAST/DAST tools into deployment pipeline',
  },
  {
    id: 'gap3',
    framework: 'PCI-DSS',
    control_id: '6.2',
    control_name: 'Ensure all systems are protected from known vulnerabilities',
    description: 'Payment processing service has 1 critical CVE',
    severity: 'critical',
    affected_services: ['payment-api'],
    remediation: 'Upgrade payment processing library to latest secure version',
  },
  {
    id: 'gap4',
    framework: 'GDPR',
    control_id: 'Art. 32',
    control_name: 'Security of Processing',
    description: 'Unencrypted database connections exposing PII',
    severity: 'high',
    affected_services: ['user-service', 'auth-service'],
    remediation: 'Enable SSL/TLS for all database connections',
  },
  {
    id: 'gap5',
    framework: 'SOC 2',
    control_id: 'CC7.2',
    control_name: 'System Monitoring',
    description: 'Insufficient logging for security events',
    severity: 'medium',
    affected_services: ['api-gateway', 'auth-service'],
    remediation: 'Implement centralized logging with SIEM integration',
  },
]

export default function CompliancePage() {
  const { data: complianceData, loading: apiLoading, error: apiError } = useCompliance()
  const { mode } = useSystemMode()
  const { demoEnabled, toggleDemoMode } = useDemoMode()

  const transformApiData = useCallback((apiData: NonNullable<typeof complianceData>): { frameworks: Framework[]; gaps: ControlGap[] } => {
    const frameworksList = apiData.frameworks.map((f, index) => ({
      id: f.id || `framework-${index}`,
      name: f.name,
      description: f.description,
      coverage: Math.round((f.controls_passed / f.controls_total) * 100) || 0,
      controls_total: f.controls_total,
      controls_passing: f.controls_passed,
      controls_failing: f.controls_failed,
      last_audit: f.last_assessed || new Date().toISOString().split('T')[0],
      next_audit: new Date(Date.now() + 180 * 86400000).toISOString().split('T')[0],
      status: 'active',
    }))

    const gapsList = apiData.gaps.map((g, index) => ({
      id: `gap-${index}`,
      framework: g.framework,
      control_id: g.control_id,
      control_name: g.description.split(':')[0] || g.description,
      description: g.description,
      severity: g.severity,
      affected_services: ['Affected services'],
      remediation: g.remediation,
    }))

    return { frameworks: frameworksList, gaps: gapsList }
  }, [])

  // Demo mode: explicitly show demo data when toggle is ON
  // Live mode: show real API data (or empty state if no data)
  const hasApiData = complianceData?.frameworks && complianceData.frameworks.length > 0
  const { frameworks, controlGaps } = useMemo(() => {
    if (demoEnabled) {
      return { frameworks: DEMO_FRAMEWORKS, controlGaps: DEMO_CONTROL_GAPS }
    }
    if (hasApiData) {
      const data = transformApiData(complianceData)
      return { frameworks: data.frameworks, controlGaps: data.gaps }
    }
    return { frameworks: [], controlGaps: [] } // Empty state when no API data and demo mode is OFF
  }, [complianceData, transformApiData, demoEnabled, hasApiData])

  const [selectedFramework, setSelectedFramework] = useState<Framework | null>(null)
  const [selectedGap, setSelectedGap] = useState<ControlGap | null>(null)

  const getSeverityColor = (severity: string) => {
    const colors = {
      critical: '#dc2626',
      high: '#f97316',
      medium: '#f59e0b',
      low: '#3b82f6',
    }
    return colors[severity as keyof typeof colors] || colors.low
  }

  const getCoverageColor = (coverage: number) => {
    if (coverage >= 90) return '#10b981'
    if (coverage >= 75) return '#f59e0b'
    return '#dc2626'
  }

  return (
    <AppShell activeApp="compliance">
    <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
      {/* Left Sidebar - Framework List */}
      <div className="w-80 bg-white/[0.02] backdrop-blur-xl border-r border-white/[0.06] flex flex-col sticky top-0 h-screen">
        {/* Header */}
        <div className="p-5 border-b border-white/[0.06]">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-[#6B5AED] to-[#8B7CF7] flex items-center justify-center shadow-[0_0_20px_rgba(107,90,237,0.3)]">
                <Shield size={16} className="text-white" />
              </div>
              <div>
                <h2 className="text-[15px] font-semibold text-white tracking-tight">Compliance</h2>
                <p className="text-[11px] text-slate-500">Framework coverage & gaps</p>
              </div>
            </div>
            <button
              onClick={() => window.location.href = '/triage'}
              className="p-2 rounded-xl bg-white/[0.04] ring-1 ring-white/[0.08] text-slate-400 hover:bg-white/[0.08] hover:text-white transition-all"
              title="Back to Triage"
            >
              <ArrowLeft size={16} />
            </button>
          </div>
          
          {/* Demo Mode Toggle - Apple-like */}
          <div className="mt-4 p-3 rounded-xl bg-white/[0.03] ring-1 ring-white/[0.06]">
            <Switch
              checked={demoEnabled}
              onChange={toggleDemoMode}
              label={demoEnabled ? 'Demo Mode' : 'Live Mode'}
              size="sm"
            />
            {/* Status Badge */}
            <div className="mt-2">
              {apiLoading && !demoEnabled && (
                <StatusBadge status="loading" label="Loading..." />
              )}
              {apiError && !apiLoading && !demoEnabled && (
                <StatusBadge status="error" label="API Error" />
              )}
              {!apiLoading && !apiError && !hasApiData && !demoEnabled && (
                <StatusBadge status="warning" label="No Data" />
              )}
              {demoEnabled && (
                <StatusBadge status="demo" label="Demo Data" />
              )}
              {!demoEnabled && hasApiData && !apiLoading && !apiError && (
                <StatusBadge status="live" label={`Live (${mode})`} />
              )}
            </div>
          </div>
        </div>

        {/* Summary Stats */}
        <div className="p-4 border-b border-white/[0.06]">
          <div className="grid grid-cols-2 gap-2">
            <StatCard label="Frameworks" value={frameworks.length} color="purple" />
            <StatCard 
              label="Avg Coverage" 
              value={`${frameworks.length > 0 ? Math.round(frameworks.reduce((sum, f) => sum + f.coverage, 0) / frameworks.length) : 0}%`} 
              color="green" 
            />
            <StatCard 
              label="Total Controls" 
              value={frameworks.reduce((sum, f) => sum + f.controls_total, 0)} 
              color="default" 
            />
            <StatCard label="Control Gaps" value={controlGaps.length} color="red" />
          </div>
        </div>

        {/* Framework List */}
        <div className="p-4 flex-1 overflow-auto">
          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">
            Active Frameworks
          </div>
          <div className="space-y-2">
            {frameworks.map((framework) => (
              <button
                key={framework.id}
                onClick={() => setSelectedFramework(framework)}
                className={`w-full p-3 rounded-md text-left transition-all ${
                  selectedFramework?.id === framework.id
                    ? 'bg-[#6B5AED]/10 border border-[#6B5AED]/30'
                    : 'bg-white/5 border border-white/10 hover:bg-white/10'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-semibold text-white">{framework.name}</span>
                  <ChevronRight size={16} className="text-slate-400" />
                </div>
                <div className="text-xs text-slate-400 mb-2">{framework.description}</div>
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-2 bg-white/10 rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{
                        width: `${framework.coverage}%`,
                        backgroundColor: getCoverageColor(framework.coverage),
                      }}
                    ></div>
                  </div>
                  <span
                    className="text-xs font-semibold"
                    style={{ color: getCoverageColor(framework.coverage) }}
                  >
                    {framework.coverage}%
                  </span>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col">
        {/* Top Bar */}
        <div className="p-5 border-b border-white/10 bg-[#0f172a]/80 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-semibold mb-1">Compliance Dashboard</h1>
              <p className="text-sm text-slate-500">
                Framework coverage and control gap analysis
              </p>
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => window.location.href = '/triage'}
                className="px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all"
              >
                Triage View
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

        {/* Content Area */}
        <div className="flex-1 overflow-auto p-6">
          {!selectedFramework ? (
            /* Overview Grid */
            <div className="grid grid-cols-2 gap-6">
              {frameworks.map((framework) => (
                <div
                  key={framework.id}
                  onClick={() => setSelectedFramework(framework)}
                  className="p-6 bg-white/2 rounded-lg border border-white/5 cursor-pointer hover:bg-white/5 transition-all"
                >
                  <div className="flex items-start justify-between mb-4">
                    <div>
                      <h3 className="text-lg font-semibold mb-1">{framework.name}</h3>
                      <p className="text-sm text-slate-400">{framework.description}</p>
                    </div>
                    <Shield size={24} className="text-[#6B5AED]" />
                  </div>

                  {/* Coverage Bar */}
                  <div className="mb-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs text-slate-500">Coverage</span>
                      <span
                        className="text-sm font-semibold"
                        style={{ color: getCoverageColor(framework.coverage) }}
                      >
                        {framework.coverage}%
                      </span>
                    </div>
                    <div className="h-2 bg-white/10 rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all"
                        style={{
                          width: `${framework.coverage}%`,
                          backgroundColor: getCoverageColor(framework.coverage),
                        }}
                      ></div>
                    </div>
                  </div>

                  {/* Stats Grid */}
                  <div className="grid grid-cols-3 gap-3 text-xs">
                    <div>
                      <div className="text-slate-500 mb-1">Total</div>
                      <div className="text-lg font-semibold text-slate-300">
                        {framework.controls_total}
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-500 mb-1">Passing</div>
                      <div className="text-lg font-semibold text-green-500">
                        {framework.controls_passing}
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-500 mb-1">Failing</div>
                      <div className="text-lg font-semibold text-red-500">
                        {framework.controls_failing}
                      </div>
                    </div>
                  </div>

                  {/* Audit Info */}
                  <div className="mt-4 pt-4 border-t border-white/10 text-xs text-slate-400">
                    <div className="flex justify-between">
                      <span>Last Audit:</span>
                      <span>{new Date(framework.last_audit).toLocaleDateString()}</span>
                    </div>
                    <div className="flex justify-between mt-1">
                      <span>Next Audit:</span>
                      <span>{new Date(framework.next_audit).toLocaleDateString()}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            /* Framework Detail View */
            <div>
              {/* Framework Header */}
              <div className="mb-6">
                <button
                  onClick={() => setSelectedFramework(null)}
                  className="flex items-center gap-2 text-sm text-slate-400 hover:text-white transition-colors mb-4"
                >
                  <ArrowLeft size={16} />
                  Back to Overview
                </button>
                <div className="flex items-start justify-between">
                  <div>
                    <h2 className="text-2xl font-semibold mb-2">{selectedFramework.name}</h2>
                    <p className="text-sm text-slate-400">{selectedFramework.description}</p>
                  </div>
                  <div className="text-right">
                    <div
                      className="text-4xl font-bold mb-1"
                      style={{ color: getCoverageColor(selectedFramework.coverage) }}
                    >
                      {selectedFramework.coverage}%
                    </div>
                    <div className="text-xs text-slate-500">Coverage</div>
                  </div>
                </div>
              </div>

              {/* Control Stats */}
              <div className="grid grid-cols-3 gap-4 mb-6">
                <div className="p-4 bg-white/5 rounded-md border border-white/10">
                  <div className="text-sm text-slate-400 mb-2">Total Controls</div>
                  <div className="text-2xl font-semibold text-slate-300">
                    {selectedFramework.controls_total}
                  </div>
                </div>
                <div className="p-4 bg-green-500/10 rounded-md border border-green-500/20">
                  <div className="text-sm text-green-300 mb-2">Passing Controls</div>
                  <div className="text-2xl font-semibold text-green-500">
                    {selectedFramework.controls_passing}
                  </div>
                </div>
                <div className="p-4 bg-red-500/10 rounded-md border border-red-500/20">
                  <div className="text-sm text-red-300 mb-2">Failing Controls</div>
                  <div className="text-2xl font-semibold text-red-500">
                    {selectedFramework.controls_failing}
                  </div>
                </div>
              </div>

              {/* Control Gaps */}
              <div>
                <h3 className="text-lg font-semibold mb-4">Control Gaps</h3>
                <div className="space-y-3">
                  {controlGaps.filter(gap => gap.framework === selectedFramework.name).map((gap) => (
                    <div
                      key={gap.id}
                      onClick={() => setSelectedGap(gap)}
                      className="p-4 bg-white/2 rounded-lg border border-white/5 cursor-pointer hover:bg-white/5 transition-all"
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <div
                              className="w-2 h-2 rounded-full"
                              style={{ backgroundColor: getSeverityColor(gap.severity) }}
                            ></div>
                            <span
                              className="text-xs font-semibold uppercase tracking-wider"
                              style={{ color: getSeverityColor(gap.severity) }}
                            >
                              {gap.severity}
                            </span>
                            <span className="text-xs text-slate-500">•</span>
                            <span className="text-xs text-slate-400 font-mono">{gap.control_id}</span>
                          </div>
                          <h4 className="text-sm font-semibold text-white mb-1">{gap.control_name}</h4>
                          <p className="text-sm text-slate-400">{gap.description}</p>
                        </div>
                        <ChevronRight size={20} className="text-slate-400 flex-shrink-0 ml-4" />
                      </div>
                      <div className="flex items-center gap-2 text-xs text-slate-500">
                        <span>Affected:</span>
                        {gap.affected_services.slice(0, 2).map((service, idx) => (
                          <span key={idx} className="px-2 py-0.5 bg-white/5 rounded font-mono">
                            {service}
                          </span>
                        ))}
                        {gap.affected_services.length > 2 && (
                          <span className="text-slate-400">
                            +{gap.affected_services.length - 2} more
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Gap Detail Drawer */}
      {selectedGap && (
        <div
          onClick={() => setSelectedGap(null)}
          className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex justify-end"
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="w-[500px] h-full bg-[#1e293b] border-l border-white/10 flex flex-col animate-slide-in"
          >
            {/* Drawer Header */}
            <div className="p-6 border-b border-white/10">
              <div className="flex justify-between items-start mb-3">
                <div className="flex items-center gap-2">
                  <div
                    className="w-2.5 h-2.5 rounded-full"
                    style={{ backgroundColor: getSeverityColor(selectedGap.severity) }}
                  ></div>
                  <span
                    className="text-xs font-semibold uppercase tracking-wider"
                    style={{ color: getSeverityColor(selectedGap.severity) }}
                  >
                    {selectedGap.severity} Severity
                  </span>
                </div>
                <button
                  onClick={() => setSelectedGap(null)}
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  <XCircle size={20} />
                </button>
              </div>
              <div className="text-xs text-slate-500 font-mono mb-2">
                {selectedGap.framework} • {selectedGap.control_id}
              </div>
              <h3 className="text-base font-semibold">{selectedGap.control_name}</h3>
            </div>

            {/* Drawer Content */}
            <div className="flex-1 overflow-auto p-6">
              {/* Description */}
              <div className="mb-6">
                <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
                  Issue Description
                </h4>
                <p className="text-sm text-slate-400 leading-relaxed">
                  {selectedGap.description}
                </p>
              </div>

              {/* Affected Services */}
              <div className="mb-6">
                <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
                  Affected Services
                </h4>
                <div className="flex flex-wrap gap-2">
                  {selectedGap.affected_services.map((service, idx) => (
                    <span
                      key={idx}
                      className="px-3 py-1.5 bg-white/5 border border-white/10 rounded-md text-xs font-mono text-slate-300"
                    >
                      {service}
                    </span>
                  ))}
                </div>
              </div>

              {/* Remediation */}
              <div>
                <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
                  Remediation Steps
                </h4>
                <div className="p-4 bg-[#6B5AED]/10 border border-[#6B5AED]/20 rounded-md">
                  <p className="text-sm text-slate-300 leading-relaxed">
                    {selectedGap.remediation}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      <style jsx>{`
        @keyframes slide-in {
          from {
            transform: translateX(100%);
          }
          to {
            transform: translateX(0);
          }
        }
        .animate-slide-in {
          animation: slide-in 0.2s ease-out;
        }
      `}</style>
    </div>
    </AppShell>
  )
}
