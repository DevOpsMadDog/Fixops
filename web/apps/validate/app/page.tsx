'use client'

import { useState, useMemo } from 'react'
import { ArrowLeft, AlertCircle, Shield, Target, Network, Server, Globe, Lock, Unlock, ChevronRight, Download, Eye, Zap, CheckCircle, XCircle } from 'lucide-react'
import { AppShell, useDemoModeContext } from '@fixops/ui'

interface AttackPathNode {
  id: string
  name: string
  type: 'internet' | 'firewall' | 'server' | 'database' | 'crown_jewel'
  vulnerabilities: string[]
  risk_score: number
  controls: string[]
}

interface AttackPath {
  id: string
  name: string
  description: string
  risk_score: number
  path_length: number
  nodes: AttackPathNode[]
  exploitability: 'high' | 'medium' | 'low'
  impact: 'critical' | 'high' | 'medium' | 'low'
  target: string
  blocked_by: string[]
}

interface SecurityControl {
  id: string
  name: string
  type: 'firewall' | 'waf' | 'edr' | 'ids' | 'mfa' | 'segmentation'
  status: 'active' | 'degraded' | 'inactive'
  coverage: number
  paths_blocked: number
}

const DEMO_ATTACK_PATHS: AttackPath[] = [
  {
    id: 'path-1',
    name: 'Internet to Customer Database',
    description: 'Attack path from internet through web application to customer PII database',
    risk_score: 95,
    path_length: 4,
    nodes: [
      { id: 'n1', name: 'Internet', type: 'internet', vulnerabilities: [], risk_score: 0, controls: [] },
      { id: 'n2', name: 'Web Application (CVE-2024-3094)', type: 'server', vulnerabilities: ['CVE-2024-3094', 'CVE-2023-50164'], risk_score: 95, controls: ['WAF'] },
      { id: 'n3', name: 'App Server', type: 'server', vulnerabilities: ['CVE-2024-21762'], risk_score: 85, controls: ['EDR'] },
      { id: 'n4', name: 'Customer Database', type: 'crown_jewel', vulnerabilities: [], risk_score: 100, controls: ['Encryption'] },
    ],
    exploitability: 'high',
    impact: 'critical',
    target: 'Customer PII Database',
    blocked_by: [],
  },
  {
    id: 'path-2',
    name: 'VPN to Domain Controller',
    description: 'Lateral movement from compromised VPN to Active Directory',
    risk_score: 92,
    path_length: 3,
    nodes: [
      { id: 'n1', name: 'VPN Gateway (CVE-2024-21762)', type: 'firewall', vulnerabilities: ['CVE-2024-21762'], risk_score: 92, controls: ['MFA'] },
      { id: 'n2', name: 'Jump Server', type: 'server', vulnerabilities: ['CVE-2023-46747'], risk_score: 78, controls: ['PAM'] },
      { id: 'n3', name: 'Domain Controller', type: 'crown_jewel', vulnerabilities: [], risk_score: 100, controls: ['Tiering'] },
    ],
    exploitability: 'high',
    impact: 'critical',
    target: 'Active Directory',
    blocked_by: ['MFA'],
  },
  {
    id: 'path-3',
    name: 'Container Escape to Host',
    description: 'Container breakout leading to host system compromise',
    risk_score: 78,
    path_length: 3,
    nodes: [
      { id: 'n1', name: 'Container (CVE-2024-21626)', type: 'server', vulnerabilities: ['CVE-2024-21626'], risk_score: 78, controls: [] },
      { id: 'n2', name: 'Kubernetes Node', type: 'server', vulnerabilities: [], risk_score: 60, controls: ['Pod Security'] },
      { id: 'n3', name: 'Cloud Control Plane', type: 'crown_jewel', vulnerabilities: [], risk_score: 100, controls: ['RBAC'] },
    ],
    exploitability: 'medium',
    impact: 'critical',
    target: 'Cloud Infrastructure',
    blocked_by: ['Pod Security Policies'],
  },
  {
    id: 'path-4',
    name: 'Phishing to Financial Systems',
    description: 'Social engineering attack leading to financial system access',
    risk_score: 85,
    path_length: 4,
    nodes: [
      { id: 'n1', name: 'Email Gateway', type: 'firewall', vulnerabilities: [], risk_score: 30, controls: ['Email Security'] },
      { id: 'n2', name: 'User Workstation', type: 'server', vulnerabilities: ['Macro Enabled'], risk_score: 70, controls: ['EDR'] },
      { id: 'n3', name: 'Finance Server', type: 'server', vulnerabilities: ['CVE-2023-44487'], risk_score: 55, controls: ['Segmentation'] },
      { id: 'n4', name: 'Payment Gateway', type: 'crown_jewel', vulnerabilities: [], risk_score: 100, controls: ['PCI Controls'] },
    ],
    exploitability: 'medium',
    impact: 'critical',
    target: 'Payment Systems',
    blocked_by: ['Email Security', 'EDR'],
  },
  {
    id: 'path-5',
    name: 'API to Internal Services',
    description: 'API exploitation leading to internal service compromise',
    risk_score: 72,
    path_length: 3,
    nodes: [
      { id: 'n1', name: 'Public API (BOLA)', type: 'server', vulnerabilities: ['BOLA', 'Rate Limiting'], risk_score: 72, controls: ['API Gateway'] },
      { id: 'n2', name: 'Microservice Mesh', type: 'server', vulnerabilities: [], risk_score: 45, controls: ['mTLS'] },
      { id: 'n3', name: 'Internal Database', type: 'database', vulnerabilities: [], risk_score: 80, controls: ['Encryption'] },
    ],
    exploitability: 'medium',
    impact: 'high',
    target: 'Internal Data',
    blocked_by: ['mTLS', 'API Gateway'],
  },
]

const DEMO_CONTROLS: SecurityControl[] = [
  { id: 'ctrl-1', name: 'Web Application Firewall', type: 'waf', status: 'active', coverage: 85, paths_blocked: 12 },
  { id: 'ctrl-2', name: 'Endpoint Detection & Response', type: 'edr', status: 'active', coverage: 92, paths_blocked: 8 },
  { id: 'ctrl-3', name: 'Multi-Factor Authentication', type: 'mfa', status: 'active', coverage: 78, paths_blocked: 15 },
  { id: 'ctrl-4', name: 'Network Segmentation', type: 'segmentation', status: 'degraded', coverage: 65, paths_blocked: 6 },
  { id: 'ctrl-5', name: 'Intrusion Detection System', type: 'ids', status: 'active', coverage: 88, paths_blocked: 4 },
  { id: 'ctrl-6', name: 'Perimeter Firewall', type: 'firewall', status: 'active', coverage: 95, paths_blocked: 20 },
]

function getNodeIcon(type: string) {
  switch (type) {
    case 'internet': return Globe
    case 'firewall': return Shield
    case 'server': return Server
    case 'database': return Server
    case 'crown_jewel': return Target
    default: return Server
  }
}

function getNodeColor(type: string) {
  switch (type) {
    case 'internet': return 'text-blue-400 bg-blue-500/10 border-blue-500/30'
    case 'firewall': return 'text-green-400 bg-green-500/10 border-green-500/30'
    case 'server': return 'text-slate-400 bg-slate-500/10 border-slate-500/30'
    case 'database': return 'text-purple-400 bg-purple-500/10 border-purple-500/30'
    case 'crown_jewel': return 'text-red-400 bg-red-500/10 border-red-500/30'
    default: return 'text-slate-400 bg-slate-500/10 border-slate-500/30'
  }
}

export default function ValidatePage() {
  const { demoEnabled } = useDemoModeContext()
  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(null)
  const [activeTab, setActiveTab] = useState<'paths' | 'controls'>('paths')
  const [showBlocked, setShowBlocked] = useState(true)

  const attackPaths = useMemo(() => demoEnabled ? DEMO_ATTACK_PATHS : [], [demoEnabled])
  const controls = useMemo(() => demoEnabled ? DEMO_CONTROLS : [], [demoEnabled])

  const filteredPaths = useMemo(() => {
    if (showBlocked) return attackPaths
    return attackPaths.filter(p => p.blocked_by.length === 0)
  }, [attackPaths, showBlocked])

  const stats = useMemo(() => ({
    totalPaths: attackPaths.length,
    criticalPaths: attackPaths.filter(p => p.risk_score >= 90).length,
    blockedPaths: attackPaths.filter(p => p.blocked_by.length > 0).length,
    avgRiskScore: attackPaths.length > 0 
      ? Math.round(attackPaths.reduce((sum, p) => sum + p.risk_score, 0) / attackPaths.length)
      : 0,
    activeControls: controls.filter(c => c.status === 'active').length,
  }), [attackPaths, controls])

  const handleExportCSV = () => {
    const headers = ['Path Name', 'Risk Score', 'Path Length', 'Target', 'Exploitability', 'Impact', 'Blocked By']
    const rows = attackPaths.map(p => [
      p.name,
      p.risk_score,
      p.path_length,
      p.target,
      p.exploitability,
      p.impact,
      p.blocked_by.join('; ') || 'None'
    ])
    const csv = [headers, ...rows].map(row => row.join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'attack-paths.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  const getRiskColor = (score: number) => {
    if (score >= 90) return 'text-red-400'
    if (score >= 70) return 'text-orange-400'
    if (score >= 50) return 'text-yellow-400'
    return 'text-green-400'
  }

  const getControlStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'text-green-400 bg-green-500/10'
      case 'degraded': return 'text-yellow-400 bg-yellow-500/10'
      case 'inactive': return 'text-red-400 bg-red-500/10'
      default: return 'text-slate-400 bg-slate-500/10'
    }
  }

  return (
    <AppShell activeApp="validate">
      <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
        <div className="w-72 bg-[#0f172a]/80 border-r border-white/10 flex flex-col sticky top-0 h-screen">
          <div className="p-6 border-b border-white/10">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-[#6B5AED]">Validate</h2>
              <button
                onClick={() => window.location.href = '/triage'}
                className="p-2 rounded-md border border-white/10 text-slate-400 hover:bg-white/5 transition-all"
                title="Back to Triage"
              >
                <ArrowLeft size={16} />
              </button>
            </div>
            <p className="text-xs text-slate-500">Attack path analysis</p>
          </div>

          <div className="p-4 border-b border-white/10">
            <div className="space-y-1">
              {[
                { id: 'paths', label: 'Attack Paths', icon: Network },
                { id: 'controls', label: 'Security Controls', icon: Shield },
              ].map(tab => {
                const Icon = tab.icon
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as typeof activeTab)}
                    className={`w-full px-3 py-2 rounded-md text-left text-sm transition-all flex items-center gap-2 ${
                      activeTab === tab.id
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <Icon size={14} />
                    {tab.label}
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
                <div className="text-2xl font-bold text-red-400">{stats.criticalPaths}</div>
                <div className="text-xs text-slate-500">Critical Paths</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md border border-white/10">
                <div className="text-2xl font-bold text-[#6B5AED]">{stats.avgRiskScore}</div>
                <div className="text-xs text-slate-500">Avg Risk Score</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md border border-white/10">
                <div className="flex items-baseline gap-1">
                  <span className="text-2xl font-bold text-green-400">{stats.blockedPaths}</span>
                  <span className="text-sm text-slate-500">/ {stats.totalPaths}</span>
                </div>
                <div className="text-xs text-slate-500">Paths Blocked</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md border border-white/10">
                <div className="text-2xl font-bold text-blue-400">{stats.activeControls}</div>
                <div className="text-xs text-slate-500">Active Controls</div>
              </div>
            </div>
          </div>
        </div>

        <div className="flex-1 flex flex-col">
          <div className="p-5 border-b border-white/10 bg-[#0f172a]/80 backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-2xl font-semibold mb-1">
                  {activeTab === 'paths' ? 'Attack Path Analysis' : 'Security Controls'}
                </h1>
                <p className="text-sm text-slate-500">
                  {activeTab === 'paths' 
                    ? `${filteredPaths.length} attack paths to critical assets`
                    : `${controls.length} security controls protecting your environment`
                  }
                </p>
              </div>
              <div className="flex gap-2">
                {activeTab === 'paths' && (
                  <>
                    <button
                      onClick={() => setShowBlocked(!showBlocked)}
                      className={`px-4 py-2 border rounded-md text-sm font-medium transition-all flex items-center gap-2 ${
                        showBlocked 
                          ? 'bg-white/5 border-white/10 text-slate-300' 
                          : 'bg-green-500/10 border-green-500/30 text-green-400'
                      }`}
                    >
                      {showBlocked ? <Eye size={14} /> : <Shield size={14} />}
                      {showBlocked ? 'Show All' : 'Unblocked Only'}
                    </button>
                    <button
                      onClick={handleExportCSV}
                      className="px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all flex items-center gap-2"
                    >
                      <Download size={14} />
                      Export CSV
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>

          <div className="flex-1 overflow-auto">
            {!demoEnabled ? (
              <div className="flex items-center justify-center h-full">
                <div className="text-center max-w-md">
                  <AlertCircle size={48} className="mx-auto mb-4 text-slate-500" />
                  <h3 className="text-lg font-semibold text-white mb-2">No Attack Path Data</h3>
                  <p className="text-sm text-slate-400 mb-4">
                    Enable demo mode to see sample attack paths, or connect your systems to see real data.
                  </p>
                </div>
              </div>
            ) : activeTab === 'paths' ? (
              <div className="flex">
                <div className={`flex-1 p-6 ${selectedPath ? 'border-r border-white/10' : ''}`}>
                  <div className="space-y-4">
                    {filteredPaths.map((path) => (
                      <div
                        key={path.id}
                        onClick={() => setSelectedPath(path)}
                        className={`p-4 rounded-lg border transition-all cursor-pointer ${
                          selectedPath?.id === path.id
                            ? 'bg-[#6B5AED]/10 border-[#6B5AED]/30'
                            : 'bg-white/5 border-white/10 hover:border-white/20'
                        }`}
                      >
                        <div className="flex items-start justify-between mb-3">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <h3 className="font-semibold text-white">{path.name}</h3>
                              {path.blocked_by.length > 0 ? (
                                <span className="px-2 py-0.5 bg-green-500/10 border border-green-500/30 rounded text-xs text-green-400 flex items-center gap-1">
                                  <Lock size={10} />
                                  Blocked
                                </span>
                              ) : (
                                <span className="px-2 py-0.5 bg-red-500/10 border border-red-500/30 rounded text-xs text-red-400 flex items-center gap-1">
                                  <Unlock size={10} />
                                  Open
                                </span>
                              )}
                            </div>
                            <p className="text-sm text-slate-400">{path.description}</p>
                          </div>
                          <div className="text-right">
                            <div className={`text-2xl font-bold ${getRiskColor(path.risk_score)}`}>
                              {path.risk_score}
                            </div>
                            <div className="text-[10px] text-slate-500">Risk Score</div>
                          </div>
                        </div>

                        <div className="flex items-center gap-6 mb-4">
                          <div className="flex items-center gap-4 text-xs text-slate-500">
                            <span>Target: <span className="text-white">{path.target}</span></span>
                            <span>Path Length: <span className="text-white">{path.path_length} hops</span></span>
                            <span>Exploitability: <span className={path.exploitability === 'high' ? 'text-red-400' : path.exploitability === 'medium' ? 'text-yellow-400' : 'text-green-400'}>{path.exploitability}</span></span>
                          </div>
                        </div>

                        <div className="flex items-center gap-2 overflow-x-auto pb-2">
                          {path.nodes.map((node, index) => {
                            const Icon = getNodeIcon(node.type)
                            return (
                              <div key={node.id} className="flex items-center">
                                <div className={`p-2 rounded-lg border ${getNodeColor(node.type)} flex items-center gap-2 whitespace-nowrap`}>
                                  <Icon size={14} />
                                  <span className="text-xs">{node.name.split(' ')[0]}</span>
                                  {node.vulnerabilities.length > 0 && (
                                    <span className="px-1.5 py-0.5 bg-red-500/20 rounded text-[10px] text-red-400">
                                      {node.vulnerabilities.length}
                                    </span>
                                  )}
                                </div>
                                {index < path.nodes.length - 1 && (
                                  <ChevronRight size={16} className="text-slate-600 mx-1" />
                                )}
                              </div>
                            )
                          })}
                        </div>

                        {path.blocked_by.length > 0 && (
                          <div className="mt-3 pt-3 border-t border-white/10">
                            <div className="flex items-center gap-2">
                              <Shield size={12} className="text-green-400" />
                              <span className="text-xs text-slate-500">Blocked by:</span>
                              {path.blocked_by.map((control, i) => (
                                <span key={i} className="px-2 py-0.5 bg-green-500/10 rounded text-xs text-green-400">
                                  {control}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {selectedPath && (
                  <div className="w-96 p-6 bg-[#0f172a]/50 sticky top-0 h-screen overflow-auto">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-lg font-semibold">Path Details</h3>
                      <button
                        onClick={() => setSelectedPath(null)}
                        className="p-1 text-slate-500 hover:text-white transition-all"
                      >
                        <ChevronRight size={16} className="rotate-180" />
                      </button>
                    </div>

                    <div className="mb-6">
                      <h4 className="text-sm font-medium text-white mb-2">{selectedPath.name}</h4>
                      <p className="text-xs text-slate-400 mb-4">{selectedPath.description}</p>
                      
                      <div className="grid grid-cols-2 gap-3">
                        <div className="p-3 bg-white/5 rounded border border-white/10">
                          <div className={`text-xl font-bold ${getRiskColor(selectedPath.risk_score)}`}>
                            {selectedPath.risk_score}
                          </div>
                          <div className="text-[10px] text-slate-500">Risk Score</div>
                        </div>
                        <div className="p-3 bg-white/5 rounded border border-white/10">
                          <div className="text-xl font-bold text-blue-400">{selectedPath.path_length}</div>
                          <div className="text-[10px] text-slate-500">Hops</div>
                        </div>
                      </div>
                    </div>

                    <div className="mb-6">
                      <div className="text-sm font-medium text-white mb-3">Attack Path Nodes</div>
                      <div className="space-y-2">
                        {selectedPath.nodes.map((node, index) => {
                          const Icon = getNodeIcon(node.type)
                          return (
                            <div key={node.id} className="relative">
                              {index > 0 && (
                                <div className="absolute left-4 -top-2 w-0.5 h-2 bg-slate-600" />
                              )}
                              <div className={`p-3 rounded-lg border ${getNodeColor(node.type)}`}>
                                <div className="flex items-center gap-2 mb-1">
                                  <Icon size={14} />
                                  <span className="text-sm font-medium">{node.name}</span>
                                </div>
                                {node.vulnerabilities.length > 0 && (
                                  <div className="mt-2">
                                    <div className="text-[10px] text-slate-500 mb-1">Vulnerabilities:</div>
                                    <div className="flex flex-wrap gap-1">
                                      {node.vulnerabilities.map((v, i) => (
                                        <span key={i} className="px-1.5 py-0.5 bg-red-500/20 rounded text-[10px] text-red-400">
                                          {v}
                                        </span>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                {node.controls.length > 0 && (
                                  <div className="mt-2">
                                    <div className="text-[10px] text-slate-500 mb-1">Controls:</div>
                                    <div className="flex flex-wrap gap-1">
                                      {node.controls.map((c, i) => (
                                        <span key={i} className="px-1.5 py-0.5 bg-green-500/20 rounded text-[10px] text-green-400">
                                          {c}
                                        </span>
                                      ))}
                                    </div>
                                  </div>
                                )}
                              </div>
                              {index < selectedPath.nodes.length - 1 && (
                                <div className="absolute left-4 -bottom-2 w-0.5 h-2 bg-slate-600" />
                              )}
                            </div>
                          )
                        })}
                      </div>
                    </div>

                    <div>
                      <div className="text-sm font-medium text-white mb-3">Recommendations</div>
                      <div className="space-y-2">
                        <div className="p-3 bg-[#6B5AED]/10 rounded border border-[#6B5AED]/20">
                          <div className="flex items-center gap-2 mb-1">
                            <Zap size={12} className="text-[#6B5AED]" />
                            <span className="text-xs font-medium text-[#6B5AED]">Patch Critical Vulnerabilities</span>
                          </div>
                          <p className="text-[10px] text-slate-400">
                            Remediate CVEs along this path to reduce risk score by ~40 points
                          </p>
                        </div>
                        <div className="p-3 bg-green-500/10 rounded border border-green-500/20">
                          <div className="flex items-center gap-2 mb-1">
                            <Shield size={12} className="text-green-400" />
                            <span className="text-xs font-medium text-green-400">Enable Additional Controls</span>
                          </div>
                          <p className="text-[10px] text-slate-400">
                            Add network segmentation to block lateral movement
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="p-6">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {controls.map((control) => (
                    <div
                      key={control.id}
                      className="p-4 bg-white/5 rounded-lg border border-white/10"
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div>
                          <h3 className="font-semibold text-white mb-1">{control.name}</h3>
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${getControlStatusColor(control.status)}`}>
                            {control.status}
                          </span>
                        </div>
                        {control.status === 'active' ? (
                          <CheckCircle size={20} className="text-green-400" />
                        ) : control.status === 'degraded' ? (
                          <AlertCircle size={20} className="text-yellow-400" />
                        ) : (
                          <XCircle size={20} className="text-red-400" />
                        )}
                      </div>

                      <div className="space-y-3">
                        <div>
                          <div className="flex items-center justify-between text-xs mb-1">
                            <span className="text-slate-500">Coverage</span>
                            <span className="text-white">{control.coverage}%</span>
                          </div>
                          <div className="h-1.5 bg-white/10 rounded-full overflow-hidden">
                            <div 
                              className={`h-full rounded-full ${
                                control.coverage >= 80 ? 'bg-green-500' :
                                control.coverage >= 60 ? 'bg-yellow-500' : 'bg-red-500'
                              }`}
                              style={{ width: `${control.coverage}%` }}
                            />
                          </div>
                        </div>

                        <div className="flex items-center justify-between">
                          <span className="text-xs text-slate-500">Paths Blocked</span>
                          <span className="text-sm font-semibold text-green-400">{control.paths_blocked}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </AppShell>
  )
}
