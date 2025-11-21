'use client'

import { useState, useEffect } from 'react'
import { ArrowLeft, ExternalLink, Copy, CheckCircle, AlertTriangle, Shield, Clock, TrendingUp } from 'lucide-react'
import EnterpriseShell from './components/EnterpriseShell'

const FINDING_DETAIL = {
  id: '1',
  title: 'Apache Struts Remote Code Execution (CVE-2023-50164)',
  severity: 'critical',
  cve_id: 'CVE-2023-50164',
  cvss_score: 9.8,
  cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  description: 'Apache Struts versions 2.0.0 through 2.5.32 and 6.0.0 through 6.3.0 are vulnerable to path traversal that can lead to remote code execution. An attacker can manipulate file upload parameters to upload a malicious file to an arbitrary location, which can then be executed.',
  discovered: '2023-12-07',
  published: '2023-12-08',
  last_modified: '2024-01-15',
  kev: true,
  epss_score: 0.89,
  exploitability: {
    attack_vector: 'Network',
    attack_complexity: 'Low',
    privileges_required: 'None',
    user_interaction: 'None',
    scope: 'Unchanged',
  },
  impact: {
    confidentiality: 'High',
    integrity: 'High',
    availability: 'High',
  },
  affected_services: [
    { name: 'payment-api', version: '2.5.30', exposure: 'internet', criticality: 'mission_critical' },
    { name: 'user-service', version: '2.5.28', exposure: 'internal', criticality: 'high' },
  ],
  ssvc_decision: {
    verdict: 'block',
    confidence: 98,
    outcome: 'immediate',
    rationale: 'Critical vulnerability with active exploitation (KEV), high EPSS score (0.89), internet-facing deployment, and mission-critical service. Immediate action required to prevent potential breach.',
    signals: [
      { key: 'KEV', value: 'true', weight: 'high' },
      { key: 'EPSS', value: '0.89', weight: 'high' },
      { key: 'Internet-facing', value: 'true', weight: 'high' },
      { key: 'Mission-critical', value: 'true', weight: 'high' },
      { key: 'CVSS', value: '9.8', weight: 'medium' },
    ],
  },
  evidence_bundle: {
    id: 'eb-2024-001-a3f9c8',
    signature: 'RSA-SHA256',
    checksum: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    retention: '90 days (Demo)',
  },
  compliance_mappings: [
    { framework: 'SOC 2', control_id: 'CC8.1', control_name: 'Vulnerability Management' },
    { framework: 'ISO 27001', control_id: 'A.12.6.1', control_name: 'Management of Technical Vulnerabilities' },
    { framework: 'PCI-DSS', control_id: '6.2', control_name: 'Ensure all systems are protected from known vulnerabilities' },
  ],
  remediation: {
    priority: 'immediate',
    effort: 'medium',
    steps: [
      'Upgrade Apache Struts to version 2.5.33 or 6.3.1 (or later)',
      'Review and validate all file upload functionality',
      'Implement Web Application Firewall (WAF) rules to block exploitation attempts',
      'Monitor for signs of exploitation in application logs',
      'Conduct security testing after upgrade to verify fix',
    ],
    references: [
      { title: 'Apache Struts Security Bulletin S2-066', url: 'https://struts.apache.org/announce-2023#a20231207' },
      { title: 'CISA KEV Catalog Entry', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
      { title: 'NVD Entry', url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-50164' },
    ],
  },
  timeline: [
    { date: '2023-12-07', event: 'Vulnerability discovered', type: 'discovery' },
    { date: '2023-12-08', event: 'CVE published', type: 'disclosure' },
    { date: '2023-12-10', event: 'Added to CISA KEV catalog', type: 'kev' },
    { date: '2024-01-15', event: 'Detected in payment-api', type: 'detection' },
    { date: '2024-01-15', event: 'SSVC decision: BLOCK (immediate)', type: 'decision' },
  ],
}

export default function FindingDetailPage() {
  const [activeTab, setActiveTab] = useState('overview')
  const [findingId, setFindingId] = useState<string | null>(null)

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    setFindingId(params.get('id'))
  }, [])

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

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'technical', label: 'Technical Details' },
    { id: 'impact', label: 'Impact Analysis' },
    { id: 'remediation', label: 'Remediation' },
    { id: 'evidence', label: 'Evidence' },
    { id: 'timeline', label: 'Timeline' },
  ]

  return (
    <EnterpriseShell>
    <div className="min-h-screen bg-[#0f172a] font-sans text-white">
      {/* Top Bar */}
      <div className="p-5 border-b border-white/10 bg-[#0f172a]/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={() => window.location.href = '/triage'}
              className="p-2 rounded-md border border-white/10 text-slate-400 hover:bg-white/5 transition-all"
            >
              <ArrowLeft size={18} />
            </button>
            <div>
              <div className="flex items-center gap-3 mb-2">
                <div
                  className="w-3 h-3 rounded-full"
                  style={{ backgroundColor: getSeverityColor(FINDING_DETAIL.severity) }}
                ></div>
                <span
                  className="text-sm font-semibold uppercase tracking-wider"
                  style={{ color: getSeverityColor(FINDING_DETAIL.severity) }}
                >
                  {FINDING_DETAIL.severity}
                </span>
                {FINDING_DETAIL.kev && (
                  <span className="px-2 py-1 bg-amber-500/20 border border-amber-500/30 rounded text-xs font-semibold text-amber-300">
                    KEV - Known Exploited
                  </span>
                )}
                <span className="text-xs text-slate-500 font-mono">{FINDING_DETAIL.cve_id}</span>
              </div>
              <h1 className="text-xl font-semibold">{FINDING_DETAIL.title}</h1>
            </div>
          </div>
          <div className="flex gap-2">
            <button className="px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all">
              Create Ticket
            </button>
            <button className="px-4 py-2 bg-[#6B5AED] rounded-md text-white text-sm font-medium hover:bg-[#5B4ADD] transition-all">
              Accept Risk
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mt-4">
          {tabs.map(({ id, label }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${
                activeTab === id
                  ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                  : 'text-slate-400 hover:bg-white/5'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="p-6">
        <div className="max-w-6xl mx-auto">
          {/* Overview Tab */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Key Metrics */}
              <div className="grid grid-cols-4 gap-4">
                <div className="p-4 bg-white/2 rounded-lg border border-white/5">
                  <div className="text-xs text-slate-500 mb-1">CVSS Score</div>
                  <div className="text-2xl font-bold text-red-500">{FINDING_DETAIL.cvss_score}</div>
                </div>
                <div className="p-4 bg-white/2 rounded-lg border border-white/5">
                  <div className="text-xs text-slate-500 mb-1">EPSS Score</div>
                  <div className="text-2xl font-bold text-amber-500">{(FINDING_DETAIL.epss_score * 100).toFixed(0)}%</div>
                </div>
                <div className="p-4 bg-white/2 rounded-lg border border-white/5">
                  <div className="text-xs text-slate-500 mb-1">Affected Services</div>
                  <div className="text-2xl font-bold text-slate-300">{FINDING_DETAIL.affected_services.length}</div>
                </div>
                <div className="p-4 bg-white/2 rounded-lg border border-white/5">
                  <div className="text-xs text-slate-500 mb-1">Age</div>
                  <div className="text-2xl font-bold text-slate-300">
                    {Math.floor((Date.now() - new Date(FINDING_DETAIL.discovered).getTime()) / (1000 * 60 * 60 * 24))}d
                  </div>
                </div>
              </div>

              {/* Description */}
              <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                <h3 className="text-lg font-semibold mb-3">Description</h3>
                <p className="text-sm text-slate-300 leading-relaxed">{FINDING_DETAIL.description}</p>
              </div>

              {/* SSVC Decision */}
              <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                <h3 className="text-lg font-semibold mb-4">SSVC Decision</h3>
                <div
                  className="p-4 rounded-md border-2 mb-4"
                  style={{
                    backgroundColor: `${getVerdictColor(FINDING_DETAIL.ssvc_decision.verdict)}10`,
                    borderColor: `${getVerdictColor(FINDING_DETAIL.ssvc_decision.verdict)}30`,
                  }}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span
                      className="text-lg font-semibold uppercase tracking-wider"
                      style={{ color: getVerdictColor(FINDING_DETAIL.ssvc_decision.verdict) }}
                    >
                      {FINDING_DETAIL.ssvc_decision.verdict}
                    </span>
                    <span className="text-sm text-slate-400">
                      {FINDING_DETAIL.ssvc_decision.confidence}% confidence
                    </span>
                  </div>
                  <div className="text-sm text-slate-300 mb-3">
                    SSVC Outcome: <span className="font-semibold">{FINDING_DETAIL.ssvc_decision.outcome}</span>
                  </div>
                  <p className="text-sm text-slate-300 leading-relaxed">{FINDING_DETAIL.ssvc_decision.rationale}</p>
                </div>
                <div className="flex flex-wrap gap-2">
                  {FINDING_DETAIL.ssvc_decision.signals.map((signal, idx) => (
                    <span
                      key={idx}
                      className="px-3 py-1.5 bg-white/5 border border-white/10 rounded-md text-xs font-mono text-slate-300"
                    >
                      {signal.key}: {signal.value}
                    </span>
                  ))}
                </div>
              </div>

              {/* Affected Services */}
              <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                <h3 className="text-lg font-semibold mb-4">Affected Services</h3>
                <div className="space-y-3">
                  {FINDING_DETAIL.affected_services.map((service, idx) => (
                    <div key={idx} className="p-4 bg-white/5 rounded-md border border-white/10">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm font-mono text-white">{service.name}</span>
                        <div className="flex gap-2">
                          <span className="px-2 py-1 bg-slate-500/20 border border-slate-500/30 rounded text-xs font-medium text-slate-300">
                            v{service.version}
                          </span>
                          <span className={`px-2 py-1 rounded text-xs font-medium ${
                            service.exposure === 'internet'
                              ? 'bg-red-500/20 border border-red-500/30 text-red-300'
                              : 'bg-blue-500/20 border border-blue-500/30 text-blue-300'
                          }`}>
                            {service.exposure}
                          </span>
                          <span className="px-2 py-1 bg-amber-500/20 border border-amber-500/30 rounded text-xs font-medium text-amber-300">
                            {service.criticality}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Technical Details Tab */}
          {activeTab === 'technical' && (
            <div className="space-y-6">
              <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                <h3 className="text-lg font-semibold mb-4">CVSS Vector</h3>
                <div className="p-3 bg-black/20 rounded-md border border-white/10 mb-4">
                  <code className="text-sm font-mono text-slate-300">{FINDING_DETAIL.cvss_vector}</code>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <h4 className="text-sm font-semibold text-slate-300 mb-3">Exploitability Metrics</h4>
                    <div className="space-y-2">
                      {Object.entries(FINDING_DETAIL.exploitability).map(([key, value]) => (
                        <div key={key} className="flex justify-between text-sm">
                          <span className="text-slate-400">{key.replace(/_/g, ' ')}</span>
                          <span className="text-white font-medium">{value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-slate-300 mb-3">Impact Metrics</h4>
                    <div className="space-y-2">
                      {Object.entries(FINDING_DETAIL.impact).map(([key, value]) => (
                        <div key={key} className="flex justify-between text-sm">
                          <span className="text-slate-400">{key}</span>
                          <span className="text-white font-medium">{value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Remediation Tab */}
          {activeTab === 'remediation' && (
            <div className="space-y-6">
              <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                <h3 className="text-lg font-semibold mb-4">Remediation Steps</h3>
                <div className="space-y-3">
                  {FINDING_DETAIL.remediation.steps.map((step, idx) => (
                    <div key={idx} className="flex gap-3">
                      <div className="flex-shrink-0 w-6 h-6 rounded-full bg-[#6B5AED]/20 border border-[#6B5AED]/30 flex items-center justify-center text-xs font-semibold text-[#6B5AED]">
                        {idx + 1}
                      </div>
                      <p className="text-sm text-slate-300 leading-relaxed pt-0.5">{step}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                <h3 className="text-lg font-semibold mb-4">References</h3>
                <div className="space-y-2">
                  {FINDING_DETAIL.remediation.references.map((ref, idx) => (
                    <a
                      key={idx}
                      href={ref.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-2 p-3 bg-white/5 rounded-md border border-white/10 hover:bg-white/10 transition-all text-sm text-slate-300"
                    >
                      <ExternalLink size={14} className="text-[#6B5AED]" />
                      {ref.title}
                    </a>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Evidence Tab */}
          {activeTab === 'evidence' && (
            <div className="space-y-6">
              <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                <h3 className="text-lg font-semibold mb-4">Evidence Bundle</h3>
                <div className="space-y-3">
                  <div className="p-3 bg-white/5 rounded-md">
                    <div className="text-xs text-slate-500 mb-1">Bundle ID</div>
                    <div className="text-sm text-slate-300 font-mono">{FINDING_DETAIL.evidence_bundle.id}</div>
                  </div>
                  <div className="p-3 bg-white/5 rounded-md">
                    <div className="text-xs text-slate-500 mb-1">Signature</div>
                    <div className="text-sm text-slate-300 font-mono">{FINDING_DETAIL.evidence_bundle.signature}</div>
                  </div>
                  <div className="p-3 bg-white/5 rounded-md">
                    <div className="flex items-center justify-between mb-1">
                      <div className="text-xs text-slate-500">SHA256 Checksum</div>
                      <button
                        onClick={() => navigator.clipboard.writeText(FINDING_DETAIL.evidence_bundle.checksum)}
                        className="text-[#6B5AED] hover:text-[#5B4ADD] transition-colors"
                      >
                        <Copy size={12} />
                      </button>
                    </div>
                    <div className="text-xs text-slate-300 font-mono break-all">{FINDING_DETAIL.evidence_bundle.checksum}</div>
                  </div>
                  <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-md">
                    <div className="text-xs text-slate-500 mb-1">Retention</div>
                    <div className="text-sm text-amber-300 font-semibold">{FINDING_DETAIL.evidence_bundle.retention}</div>
                  </div>
                </div>
              </div>

              <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                <h3 className="text-lg font-semibold mb-4">Compliance Mappings</h3>
                <div className="space-y-2">
                  {FINDING_DETAIL.compliance_mappings.map((mapping, idx) => (
                    <div key={idx} className="p-3 bg-white/5 rounded-md border border-white/10">
                      <div className="flex items-center justify-between">
                        <div>
                          <span className="text-sm font-semibold text-white">{mapping.framework}</span>
                          <span className="text-xs text-slate-500 ml-2">• {mapping.control_id}</span>
                        </div>
                        <span className="text-xs text-slate-400">{mapping.control_name}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Timeline Tab */}
          {activeTab === 'timeline' && (
            <div className="p-6 bg-white/2 rounded-lg border border-white/5">
              <h3 className="text-lg font-semibold mb-4">Event Timeline</h3>
              <div className="relative">
                <div className="absolute left-4 top-0 bottom-0 w-px bg-white/10"></div>
                <div className="space-y-4">
                  {FINDING_DETAIL.timeline.map((event, idx) => (
                    <div key={idx} className="relative pl-12">
                      <div className="absolute left-2.5 top-2 w-3 h-3 rounded-full bg-[#6B5AED] border-4 border-[#0f172a]"></div>
                      <div className="p-3 bg-white/5 rounded-md">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-sm font-semibold text-white">{event.event}</span>
                          <span className="text-xs text-slate-500">{new Date(event.date).toLocaleDateString()}</span>
                        </div>
                        <span className="text-xs text-slate-400 uppercase tracking-wider">{event.type}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
