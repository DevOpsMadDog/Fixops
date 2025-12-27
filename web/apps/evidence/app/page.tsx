'use client'

import { useState, useCallback, useMemo } from 'react'
import { FileText, Shield, CheckCircle, Download, Copy, ArrowLeft, Calendar, Clock, Loader2 } from 'lucide-react'
import { AppShell } from '@fixops/ui'
import { useEvidence, useSystemMode, useDemoMode } from '@fixops/api-client'
import { Switch, StatusBadge, StatCard } from '@fixops/ui'

interface EvidenceBundle {
  id: string
  timestamp: string
  issue_id: string
  issue_title: string
  severity: string
  decision: {
    verdict: string
    confidence: number
    outcome: string
  }
  signature: {
    algorithm: string
    public_key_id: string
    signature_hex: string
  }
  retention: {
    mode: string
    days: number
    retained_until: string
  }
  checksum: {
    algorithm: string
    value: string
  }
  size_bytes: number
}

const DEMO_EVIDENCE_BUNDLES: EvidenceBundle[] = [
  {
    id: 'eb-2024-001-a3f9c8',
    timestamp: '2024-11-21T10:30:00Z',
    issue_id: '1',
    issue_title: 'Apache Struts Remote Code Execution (CVE-2023-50164)',
    severity: 'critical',
    decision: {
      verdict: 'block',
      confidence: 98,
      outcome: 'immediate',
    },
    signature: {
      algorithm: 'RSA-SHA256',
      public_key_id: 'fixops-prod-2024',
      signature_hex: 'a3f9c8d2e1b4567890abcdef1234567890abcdef1234567890abcdef12345678',
    },
    retention: {
      mode: 'demo',
      days: 90,
      retained_until: '2025-02-19',
    },
    checksum: {
      algorithm: 'SHA256',
      value: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    },
    size_bytes: 4567,
  },
  {
    id: 'eb-2024-002-b7d4e9',
    timestamp: '2024-11-20T15:45:00Z',
    issue_id: '2',
    issue_title: 'SQL Injection in User Authentication',
    severity: 'high',
    decision: {
      verdict: 'review',
      confidence: 87,
      outcome: 'scheduled',
    },
    signature: {
      algorithm: 'RSA-SHA256',
      public_key_id: 'fixops-prod-2024',
      signature_hex: 'b7d4e9f3a2c5678901bcdef2345678901bcdef2345678901bcdef234567890ab',
    },
    retention: {
      mode: 'demo',
      days: 90,
      retained_until: '2025-02-18',
    },
    checksum: {
      algorithm: 'SHA256',
      value: '60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752',
    },
    size_bytes: 3892,
  },
  {
    id: 'eb-2024-003-c8e5f1',
    timestamp: '2024-11-19T09:15:00Z',
    issue_id: '3',
    issue_title: 'Exposed AWS Credentials in Configuration',
    severity: 'critical',
    decision: {
      verdict: 'block',
      confidence: 100,
      outcome: 'immediate',
    },
    signature: {
      algorithm: 'RSA-SHA256',
      public_key_id: 'fixops-prod-2024',
      signature_hex: 'c8e5f1a4b3d6789012cdef3456789012cdef3456789012cdef345678901bcdef',
    },
    retention: {
      mode: 'demo',
      days: 90,
      retained_until: '2025-02-17',
    },
    checksum: {
      algorithm: 'SHA256',
      value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    },
    size_bytes: 2134,
  },
  {
    id: 'eb-2024-004-d9f6a2',
    timestamp: '2024-11-18T14:20:00Z',
    issue_id: '4',
    issue_title: 'Outdated OpenSSL Library (CVE-2023-4807)',
    severity: 'high',
    decision: {
      verdict: 'review',
      confidence: 92,
      outcome: 'scheduled',
    },
    signature: {
      algorithm: 'RSA-SHA256',
      public_key_id: 'fixops-prod-2024',
      signature_hex: 'd9f6a2b5c4e7890123def4567890123def4567890123def456789012cdef3456',
    },
    retention: {
      mode: 'demo',
      days: 90,
      retained_until: '2025-02-16',
    },
    checksum: {
      algorithm: 'SHA256',
      value: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    },
    size_bytes: 5123,
  },
  {
    id: 'eb-2024-005-e1a7b3',
    timestamp: '2024-11-17T11:30:00Z',
    issue_id: '9',
    issue_title: 'Log4j Remote Code Execution (CVE-2021-44228)',
    severity: 'critical',
    decision: {
      verdict: 'block',
      confidence: 99,
      outcome: 'immediate',
    },
    signature: {
      algorithm: 'RSA-SHA256',
      public_key_id: 'fixops-prod-2024',
      signature_hex: 'e1a7b3c6d5f8901234ef5678901234ef5678901234ef567890123def45678901',
    },
    retention: {
      mode: 'demo',
      days: 90,
      retained_until: '2025-02-15',
    },
    checksum: {
      algorithm: 'SHA256',
      value: 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9',
    },
    size_bytes: 6789,
  },
]

export default function EvidencePage() {
  const [selectedBundle, setSelectedBundle] = useState<EvidenceBundle | null>(null)
  const [filterSeverity, setFilterSeverity] = useState<string>('all')

  const { data: evidenceData, loading: apiLoading, error: apiError } = useEvidence()
  const { mode } = useSystemMode()
  const { demoEnabled, toggleDemoMode } = useDemoMode()

  const transformApiData = useCallback((apiData: NonNullable<typeof evidenceData>): EvidenceBundle[] => {
    return apiData.items.map((bundle, index) => ({
      id: bundle.id || `eb-${index}`,
      timestamp: bundle.timestamp || new Date().toISOString(),
      issue_id: bundle.issue_id || String(index + 1),
      issue_title: bundle.issue_title || 'Unknown Issue',
      severity: bundle.severity || 'medium',
      decision: {
        verdict: bundle.decision?.verdict || 'review',
        confidence: bundle.decision?.confidence ?? 0,
        outcome: bundle.decision?.outcome || 'scheduled',
      },
      signature: {
        algorithm: bundle.signature?.algorithm || 'RSA-SHA256',
        public_key_id: bundle.signature?.public_key_id || 'fixops-prod-2024',
        signature_hex: bundle.signature?.signature_hex || '',
      },
      retention: {
        mode: bundle.retention?.mode || 'demo',
        days: bundle.retention?.days ?? 90,
        retained_until: bundle.retention?.retained_until || new Date(Date.now() + 90 * 86400000).toISOString().split('T')[0],
      },
      checksum: {
        algorithm: bundle.checksum?.algorithm || 'SHA256',
        value: bundle.checksum?.value || '',
      },
      size_bytes: bundle.size_bytes ?? 0,
    }))
  }, [])

  // Demo mode: explicitly show demo data when toggle is ON
  // Live mode: show real API data (or empty state if no data)
  const hasApiData = evidenceData?.items && evidenceData.items.length > 0
  const evidenceBundles = useMemo(() => {
    if (demoEnabled) {
      return DEMO_EVIDENCE_BUNDLES
    }
    if (hasApiData) {
      return transformApiData(evidenceData)
    }
    return [] // Empty state when no API data and demo mode is OFF
  }, [evidenceData, transformApiData, demoEnabled, hasApiData])

  const getSeverityColor = (severity: string) => {
    const colors = {
      critical: '#dc2626',
      high: '#f97316',
      medium: '#f59e0b',
      low: '#3b82f6',
    }
    return colors[severity as keyof typeof colors] || colors.low
  }

  const getVerdictColor = (verdict: string) => {
    const colors = {
      block: '#dc2626',
      review: '#f59e0b',
      allow: '#10b981',
    }
    return colors[verdict as keyof typeof colors] || colors.allow
  }

  const formatDate = (isoString: string) => {
    const date = new Date(isoString)
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
  }

  const formatTime = (isoString: string) => {
    const date = new Date(isoString)
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
  }

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  const filteredBundles = filterSeverity === 'all' 
    ? evidenceBundles 
    : evidenceBundles.filter(b => b.severity === filterSeverity)

  return (
    <AppShell activeApp="evidence">
    <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
      {/* Left Sidebar - Filters */}
      <div className="w-72 bg-white/[0.02] backdrop-blur-xl border-r border-white/[0.06] flex flex-col sticky top-0 h-screen">
        {/* Header */}
        <div className="p-5 border-b border-white/[0.06]">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-[#6B5AED] to-[#8B7CF7] flex items-center justify-center shadow-[0_0_20px_rgba(107,90,237,0.3)]">
                <FileText size={16} className="text-white" />
              </div>
              <div>
                <h2 className="text-[15px] font-semibold text-white tracking-tight">Evidence</h2>
                <p className="text-[11px] text-slate-500">Cryptographically-signed bundles</p>
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
            <StatCard label="Total Bundles" value={evidenceBundles.length} color="purple" />
            <StatCard label="Retention" value="90d" color="amber" />
            <StatCard 
              label="Critical" 
              value={evidenceBundles.filter(b => b.severity === 'critical').length} 
              color="red" 
            />
            <StatCard 
              label="High" 
              value={evidenceBundles.filter(b => b.severity === 'high').length} 
              color="amber" 
            />
          </div>
        </div>

        {/* Filters */}
        <div className="p-4 flex-1 overflow-auto">
          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">
            Filter by Severity
          </div>
          <div className="space-y-2">
            {['all', 'critical', 'high', 'medium', 'low'].map((severity) => (
              <button
                key={severity}
                onClick={() => setFilterSeverity(severity)}
                className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                  filterSeverity === severity
                    ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                    : 'text-slate-400 hover:bg-white/5'
                }`}
              >
                <span className="capitalize">{severity}</span>
                {severity !== 'all' && (
                  <span className="ml-2 text-xs">
                    ({evidenceBundles.filter(b => b.severity === severity).length})
                  </span>
                )}
                {severity === 'all' && (
                  <span className="ml-2 text-xs">({evidenceBundles.length})</span>
                )}
              </button>
            ))}
          </div>

          {/* Retention Info */}
          <div className="mt-6 p-3 bg-amber-500/10 border border-amber-500/20 rounded-md">
            <div className="text-xs font-semibold text-amber-300 mb-1">Demo Mode</div>
            <div className="text-xs text-slate-300">
              Evidence bundles retained for 90 days. Enterprise mode supports 7-year retention for compliance.
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col">
        {/* Top Bar */}
        <div className="p-5 border-b border-white/10 bg-[#0f172a]/80 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-semibold mb-1">Evidence Timeline</h1>
              <p className="text-sm text-slate-500">
                Showing {filteredBundles.length} evidence bundle{filteredBundles.length !== 1 ? 's' : ''}
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
                onClick={() => window.location.href = '/compliance'}
                className="px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all"
              >
                Compliance
              </button>
            </div>
          </div>
        </div>

        {/* Timeline */}
        <div className="flex-1 overflow-auto p-6">
          <div className="max-w-4xl mx-auto">
            <div className="relative">
              {/* Timeline Line */}
              <div className="absolute left-8 top-0 bottom-0 w-px bg-white/10"></div>

              {/* Timeline Items */}
              <div className="space-y-6">
                {filteredBundles.map((bundle, idx) => (
                  <div key={bundle.id} className="relative pl-20">
                    {/* Timeline Dot */}
                    <div
                      className="absolute left-6 top-6 w-5 h-5 rounded-full border-4 border-[#0f172a]"
                      style={{ backgroundColor: getSeverityColor(bundle.severity) }}
                    ></div>

                    {/* Bundle Card */}
                    <div
                      onClick={() => setSelectedBundle(bundle)}
                      className="p-5 bg-white/2 rounded-lg border border-white/5 cursor-pointer hover:bg-white/5 transition-all"
                    >
                      {/* Header */}
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <div
                              className="w-2 h-2 rounded-full"
                              style={{ backgroundColor: getSeverityColor(bundle.severity) }}
                            ></div>
                            <span
                              className="text-xs font-semibold uppercase tracking-wider"
                              style={{ color: getSeverityColor(bundle.severity) }}
                            >
                              {bundle.severity}
                            </span>
                            <span className="text-xs text-slate-500">•</span>
                            <span
                              className="text-xs font-semibold uppercase tracking-wider"
                              style={{ color: getVerdictColor(bundle.decision.verdict) }}
                            >
                              {bundle.decision.verdict}
                            </span>
                          </div>
                          <h3 className="text-base font-semibold text-white mb-1">
                            {bundle.issue_title}
                          </h3>
                          <div className="flex items-center gap-3 text-xs text-slate-400">
                            <span className="flex items-center gap-1">
                              <Calendar size={12} />
                              {formatDate(bundle.timestamp)}
                            </span>
                            <span className="flex items-center gap-1">
                              <Clock size={12} />
                              {formatTime(bundle.timestamp)}
                            </span>
                            <span className="font-mono">{bundle.id}</span>
                          </div>
                        </div>
                        <FileText size={20} className="text-[#6B5AED] flex-shrink-0 ml-4" />
                      </div>

                      {/* Metadata Grid */}
                      <div className="grid grid-cols-3 gap-3 text-xs">
                        <div className="p-2 bg-white/5 rounded">
                          <div className="text-slate-500 mb-1">Signature</div>
                          <div className="text-slate-300 font-mono text-[10px]">
                            {bundle.signature.algorithm}
                          </div>
                        </div>
                        <div className="p-2 bg-white/5 rounded">
                          <div className="text-slate-500 mb-1">Confidence</div>
                          <div className="text-slate-300 font-semibold">
                            {bundle.decision.confidence}%
                          </div>
                        </div>
                        <div className="p-2 bg-white/5 rounded">
                          <div className="text-slate-500 mb-1">Size</div>
                          <div className="text-slate-300 font-mono">
                            {formatBytes(bundle.size_bytes)}
                          </div>
                        </div>
                      </div>

                      {/* Retention Badge */}
                      <div className="mt-3 inline-flex items-center gap-2 px-2 py-1 bg-amber-500/10 border border-amber-500/20 rounded text-xs text-amber-300">
                        <Shield size={12} />
                        Retained until {formatDate(bundle.retention.retained_until)}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Bundle Detail Drawer */}
      {selectedBundle && (
        <div
          onClick={() => setSelectedBundle(null)}
          className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex justify-end"
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="w-[600px] h-full bg-[#1e293b] border-l border-white/10 flex flex-col animate-slide-in overflow-auto"
          >
            {/* Drawer Header */}
            <div className="p-6 border-b border-white/10 sticky top-0 bg-[#1e293b] z-10">
              <div className="flex justify-between items-start mb-3">
                <div className="flex items-center gap-2">
                  <FileText size={20} className="text-[#6B5AED]" />
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Evidence Bundle
                  </span>
                </div>
                <button
                  onClick={() => setSelectedBundle(null)}
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  ✕
                </button>
              </div>
              <div className="text-xs text-slate-500 font-mono mb-2">{selectedBundle.id}</div>
              <h3 className="text-base font-semibold">{selectedBundle.issue_title}</h3>
            </div>

            {/* Drawer Content */}
            <div className="p-6 space-y-6">
              {/* Decision */}
              <div>
                <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
                  SSVC Decision
                </h4>
                <div
                  className="p-4 rounded-md border-2"
                  style={{
                    backgroundColor: `${getVerdictColor(selectedBundle.decision.verdict)}10`,
                    borderColor: `${getVerdictColor(selectedBundle.decision.verdict)}30`,
                  }}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span
                      className="text-sm font-semibold uppercase tracking-wider"
                      style={{ color: getVerdictColor(selectedBundle.decision.verdict) }}
                    >
                      {selectedBundle.decision.verdict}
                    </span>
                    <span className="text-xs text-slate-400">
                      {selectedBundle.decision.confidence}% confidence
                    </span>
                  </div>
                  <div className="text-xs text-slate-300">
                    SSVC Outcome: <span className="font-semibold">{selectedBundle.decision.outcome}</span>
                  </div>
                </div>
              </div>

              {/* Cryptographic Signature */}
              <div>
                <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
                  Cryptographic Signature
                </h4>
                <div className="space-y-3">
                  <div className="p-3 bg-white/5 rounded-md">
                    <div className="text-xs text-slate-500 mb-1">Algorithm</div>
                    <div className="text-sm text-slate-300 font-mono">
                      {selectedBundle.signature.algorithm}
                    </div>
                  </div>
                  <div className="p-3 bg-white/5 rounded-md">
                    <div className="text-xs text-slate-500 mb-1">Public Key ID</div>
                    <div className="text-sm text-slate-300 font-mono">
                      {selectedBundle.signature.public_key_id}
                    </div>
                  </div>
                  <div className="p-3 bg-white/5 rounded-md">
                    <div className="flex items-center justify-between mb-1">
                      <div className="text-xs text-slate-500">Signature (hex)</div>
                      <button
                        onClick={() => navigator.clipboard.writeText(selectedBundle.signature.signature_hex)}
                        className="text-[#6B5AED] hover:text-[#5B4ADD] transition-colors"
                      >
                        <Copy size={12} />
                      </button>
                    </div>
                    <div className="text-[10px] text-slate-300 font-mono break-all">
                      {selectedBundle.signature.signature_hex}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 text-xs text-green-400">
                    <CheckCircle size={14} />
                    Signature verified successfully
                  </div>
                </div>
              </div>

              {/* Checksum */}
              <div>
                <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
                  Integrity Checksum
                </h4>
                <div className="space-y-3">
                  <div className="p-3 bg-white/5 rounded-md">
                    <div className="text-xs text-slate-500 mb-1">Algorithm</div>
                    <div className="text-sm text-slate-300 font-mono">
                      {selectedBundle.checksum.algorithm}
                    </div>
                  </div>
                  <div className="p-3 bg-white/5 rounded-md">
                    <div className="flex items-center justify-between mb-1">
                      <div className="text-xs text-slate-500">Checksum</div>
                      <button
                        onClick={() => navigator.clipboard.writeText(selectedBundle.checksum.value)}
                        className="text-[#6B5AED] hover:text-[#5B4ADD] transition-colors"
                      >
                        <Copy size={12} />
                      </button>
                    </div>
                    <div className="text-[10px] text-slate-300 font-mono break-all">
                      {selectedBundle.checksum.value}
                    </div>
                  </div>
                </div>
              </div>

              {/* Retention */}
              <div>
                <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
                  Retention Policy
                </h4>
                <div className="p-4 bg-amber-500/10 border border-amber-500/20 rounded-md">
                  <div className="grid grid-cols-2 gap-3 text-xs mb-3">
                    <div>
                      <div className="text-slate-400 mb-1">Mode</div>
                      <div className="text-amber-300 font-semibold uppercase">
                        {selectedBundle.retention.mode}
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-400 mb-1">Retention Period</div>
                      <div className="text-amber-300 font-semibold">
                        {selectedBundle.retention.days} days
                      </div>
                    </div>
                  </div>
                  <div className="text-xs text-slate-300">
                    Bundle will be retained until{' '}
                    <span className="font-semibold">
                      {formatDate(selectedBundle.retention.retained_until)}
                    </span>
                  </div>
                </div>
              </div>

              {/* Metadata */}
              <div>
                <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
                  Metadata
                </h4>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="p-3 bg-white/5 rounded-md">
                    <div className="text-slate-500 mb-1">Timestamp</div>
                    <div className="text-slate-300">
                      {formatDate(selectedBundle.timestamp)} at {formatTime(selectedBundle.timestamp)}
                    </div>
                  </div>
                  <div className="p-3 bg-white/5 rounded-md">
                    <div className="text-slate-500 mb-1">Bundle Size</div>
                    <div className="text-slate-300 font-mono">
                      {formatBytes(selectedBundle.size_bytes)}
                    </div>
                  </div>
                </div>
              </div>

              {/* Actions */}
              <div className="flex gap-2">
                <button className="flex-1 px-4 py-2 bg-[#6B5AED]/10 border border-[#6B5AED]/30 rounded-md text-[#6B5AED] text-sm font-medium flex items-center justify-center gap-2 hover:bg-[#6B5AED]/20 transition-all">
                  <Download size={14} />
                  Download Bundle
                </button>
                <button
                  onClick={() => {
                    const summary = `Evidence Bundle: ${selectedBundle.id}\nIssue: ${selectedBundle.issue_title}\nDecision: ${selectedBundle.decision.verdict} (${selectedBundle.decision.confidence}% confidence)\nSignature: ${selectedBundle.signature.algorithm}\nChecksum: ${selectedBundle.checksum.value}`
                    navigator.clipboard.writeText(summary)
                  }}
                  className="px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium flex items-center gap-2 hover:bg-white/10 transition-all"
                >
                  <Copy size={14} />
                  Copy Summary
                </button>
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
