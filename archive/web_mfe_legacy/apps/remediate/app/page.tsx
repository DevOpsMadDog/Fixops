'use client'

import { useState, useMemo } from 'react'
import { Search, Clock, AlertTriangle, AlertCircle, ArrowLeft, Calendar, User, Ticket, Download, Plus, ChevronRight, Shield, Zap } from 'lucide-react'
import { AppShell, useDemoModeContext } from '@fixops/ui'
import { useFindings } from '@fixops/api-client'

interface RemediationPlan {
  id: string
  name: string
  description: string
  owner: string
  assignee: string
  status: 'active' | 'pending' | 'completed' | 'overdue'
  priority: 'critical' | 'high' | 'medium' | 'low'
  due_date: string
  created_date: string
  vulnerabilities: {
    total: number
    fixed: number
    in_progress: number
    pending: number
  }
  tickets: {
    jira?: string
    servicenow?: string
  }
  sla_status: 'on_track' | 'at_risk' | 'breached'
}

interface Exception {
  id: string
  vulnerability_id: string
  vulnerability_title: string
  reason: string
  approved_by: string
  expiration_date: string
  status: 'active' | 'expired' | 'pending_approval'
  risk_accepted: boolean
}

interface SpotlightVuln {
  id: string
  cve_id: string
  name: string
  description: string
  severity: 'critical' | 'high'
  affected_assets: number
  exploit_available: boolean
  trending: boolean
}

const DEMO_PLANS: RemediationPlan[] = [
  {
    id: 'plan-1',
    name: 'Log4Shell Remediation',
    description: 'Critical remediation for CVE-2021-44228 across all Java applications',
    owner: 'security-team',
    assignee: 'john.smith@company.com',
    status: 'active',
    priority: 'critical',
    due_date: '2024-12-01',
    created_date: '2024-11-15',
    vulnerabilities: { total: 47, fixed: 32, in_progress: 10, pending: 5 },
    tickets: { jira: 'SEC-1234', servicenow: 'INC0012345' },
    sla_status: 'on_track',
  },
  {
    id: 'plan-2',
    name: 'Spring4Shell Patching',
    description: 'Patch Spring Framework CVE-2022-22965 in production services',
    owner: 'platform-team',
    assignee: 'jane.doe@company.com',
    status: 'active',
    priority: 'critical',
    due_date: '2024-11-28',
    created_date: '2024-11-10',
    vulnerabilities: { total: 23, fixed: 18, in_progress: 3, pending: 2 },
    tickets: { jira: 'SEC-1189' },
    sla_status: 'at_risk',
  },
  {
    id: 'plan-3',
    name: 'OpenSSL Upgrade Campaign',
    description: 'Upgrade OpenSSL to 3.0.x across infrastructure',
    owner: 'infrastructure-team',
    assignee: 'bob.wilson@company.com',
    status: 'pending',
    priority: 'high',
    due_date: '2024-12-15',
    created_date: '2024-11-20',
    vulnerabilities: { total: 156, fixed: 0, in_progress: 0, pending: 156 },
    tickets: { servicenow: 'CHG0098765' },
    sla_status: 'on_track',
  },
  {
    id: 'plan-4',
    name: 'Container Image Updates',
    description: 'Update base images with critical CVEs in Kubernetes clusters',
    owner: 'devops-team',
    assignee: 'alice.chen@company.com',
    status: 'active',
    priority: 'high',
    due_date: '2024-12-05',
    created_date: '2024-11-18',
    vulnerabilities: { total: 89, fixed: 45, in_progress: 20, pending: 24 },
    tickets: { jira: 'DEVOPS-567' },
    sla_status: 'on_track',
  },
  {
    id: 'plan-5',
    name: 'Legacy System Hardening',
    description: 'Security hardening for legacy Windows servers',
    owner: 'it-ops-team',
    assignee: 'mike.johnson@company.com',
    status: 'overdue',
    priority: 'medium',
    due_date: '2024-11-15',
    created_date: '2024-10-01',
    vulnerabilities: { total: 234, fixed: 89, in_progress: 45, pending: 100 },
    tickets: { servicenow: 'CHG0087654' },
    sla_status: 'breached',
  },
  {
    id: 'plan-6',
    name: 'API Gateway Security',
    description: 'Remediate authentication vulnerabilities in API gateways',
    owner: 'api-team',
    assignee: 'sarah.lee@company.com',
    status: 'completed',
    priority: 'high',
    due_date: '2024-11-20',
    created_date: '2024-11-01',
    vulnerabilities: { total: 12, fixed: 12, in_progress: 0, pending: 0 },
    tickets: { jira: 'SEC-1156' },
    sla_status: 'on_track',
  },
]

const DEMO_EXCEPTIONS: Exception[] = [
  {
    id: 'exc-1',
    vulnerability_id: 'CVE-2023-12345',
    vulnerability_title: 'OpenSSH Remote Code Execution',
    reason: 'System is air-gapped and not accessible from external networks',
    approved_by: 'ciso@company.com',
    expiration_date: '2025-06-01',
    status: 'active',
    risk_accepted: true,
  },
  {
    id: 'exc-2',
    vulnerability_id: 'CVE-2023-67890',
    vulnerability_title: 'Apache Tomcat Information Disclosure',
    reason: 'Compensating controls in place via WAF rules',
    approved_by: 'security-lead@company.com',
    expiration_date: '2025-03-15',
    status: 'active',
    risk_accepted: true,
  },
  {
    id: 'exc-3',
    vulnerability_id: 'CVE-2024-11111',
    vulnerability_title: 'Node.js Prototype Pollution',
    reason: 'Application scheduled for decommission in Q1 2025',
    approved_by: 'vp-engineering@company.com',
    expiration_date: '2025-01-31',
    status: 'pending_approval',
    risk_accepted: false,
  },
]

const DEMO_SPOTLIGHT: SpotlightVuln[] = [
  {
    id: 'spot-1',
    cve_id: 'CVE-2024-3094',
    name: 'XZ Utils Backdoor',
    description: 'Malicious code in xz compression library affecting SSH authentication',
    severity: 'critical',
    affected_assets: 234,
    exploit_available: true,
    trending: true,
  },
  {
    id: 'spot-2',
    cve_id: 'CVE-2024-21762',
    name: 'Fortinet FortiOS RCE',
    description: 'Out-of-bounds write vulnerability in FortiOS SSL VPN',
    severity: 'critical',
    affected_assets: 12,
    exploit_available: true,
    trending: true,
  },
  {
    id: 'spot-3',
    cve_id: 'CVE-2024-1709',
    name: 'ConnectWise ScreenConnect Auth Bypass',
    description: 'Authentication bypass allowing unauthorized access',
    severity: 'critical',
    affected_assets: 8,
    exploit_available: true,
    trending: false,
  },
]

const SLA_CONFIG = {
  critical: { days: 7, label: '7 days' },
  high: { days: 30, label: '30 days' },
  medium: { days: 90, label: '90 days' },
  low: { days: 180, label: '180 days' },
}

function formatDate(dateString: string): string {
  return new Date(dateString).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  })
}

function getDaysRemaining(dueDate: string): number {
  const due = new Date(dueDate)
  const now = new Date()
  const diffTime = due.getTime() - now.getTime()
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24))
}

export default function RemediatePage() {
  const { demoEnabled } = useDemoModeContext()
  const { data: apiData, loading: apiLoading, error: apiError, refetch } = useFindings()
  const [activeTab, setActiveTab] = useState<'plans' | 'exceptions' | 'sla' | 'spotlight'>('plans')
  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [selectedPlan, setSelectedPlan] = useState<RemediationPlan | null>(null)

  // Transform API data to match our UI format, or use demo data
  const plansData = useMemo(() => {
    if (demoEnabled || !apiData?.items) {
      return DEMO_PLANS
    }
    // Group findings by remediation plan (using service as grouping key)
    const grouped = apiData.items.reduce((acc, finding) => {
      const key = finding.service || 'default'
      if (!acc[key]) acc[key] = []
      acc[key].push(finding)
      return acc
    }, {} as Record<string, typeof apiData.items>)
    
    return Object.entries(grouped).slice(0, 6).map(([service, findings], idx) => ({
      id: `plan-${idx}`,
      name: `${service} Remediation`,
      description: `Remediation plan for ${service} vulnerabilities`,
      owner: 'security-team',
      assignee: findings[0]?.assignee || 'unassigned',
      status: 'active' as const,
      priority: findings.some(f => f.severity === 'critical') ? 'critical' as const : 'high' as const,
      due_date: new Date(new Date().getTime() + 14 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
      created_date: new Date().toISOString().split('T')[0],
      vulnerabilities: {
        total: findings.length,
        fixed: findings.filter(f => f.status === 'resolved').length,
        in_progress: findings.filter(f => f.status === 'in_progress').length,
        pending: findings.filter(f => f.status === 'open').length,
      },
      tickets: {},
      sla_status: 'on_track' as const,
    }))
  }, [demoEnabled, apiData])

  // Use plansData directly instead of storing in state to avoid lint errors
  const plans = plansData.length > 0 ? plansData : DEMO_PLANS
  const exceptions = useMemo(() => demoEnabled ? DEMO_EXCEPTIONS : [], [demoEnabled])
  const spotlight = useMemo(() => demoEnabled ? DEMO_SPOTLIGHT : [], [demoEnabled])

  const filteredPlans = useMemo(() => {
    return plans.filter(plan => {
      const matchesSearch = plan.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                           plan.description.toLowerCase().includes(searchQuery.toLowerCase())
      const matchesStatus = statusFilter === 'all' || plan.status === statusFilter
      return matchesSearch && matchesStatus
    })
  }, [plans, searchQuery, statusFilter])

  const stats = useMemo(() => ({
    active: plans.filter(p => p.status === 'active').length,
    pending: plans.filter(p => p.status === 'pending').length,
    completed: plans.filter(p => p.status === 'completed').length,
    overdue: plans.filter(p => p.status === 'overdue').length,
    totalVulns: plans.reduce((sum, p) => sum + p.vulnerabilities.total, 0),
    fixedVulns: plans.reduce((sum, p) => sum + p.vulnerabilities.fixed, 0),
  }), [plans])

  const handleExportCSV = () => {
    const headers = ['Name', 'Owner', 'Assignee', 'Status', 'Priority', 'Due Date', 'Total Vulns', 'Fixed', 'SLA Status']
    const rows = plans.map(p => [
      p.name,
      p.owner,
      p.assignee,
      p.status,
      p.priority,
      p.due_date,
      p.vulnerabilities.total,
      p.vulnerabilities.fixed,
      p.sla_status
    ])
    const csv = [headers, ...rows].map(row => row.join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'remediation-plans.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'text-blue-400 bg-blue-500/10 border-blue-500/30'
      case 'pending': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30'
      case 'completed': return 'text-green-400 bg-green-500/10 border-green-500/30'
      case 'overdue': return 'text-red-400 bg-red-500/10 border-red-500/30'
      default: return 'text-slate-400 bg-slate-500/10 border-slate-500/30'
    }
  }

  const getSlaColor = (sla: string) => {
    switch (sla) {
      case 'on_track': return 'text-green-400'
      case 'at_risk': return 'text-yellow-400'
      case 'breached': return 'text-red-400'
      default: return 'text-slate-400'
    }
  }

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical': return 'text-red-400 bg-red-500/10'
      case 'high': return 'text-orange-400 bg-orange-500/10'
      case 'medium': return 'text-yellow-400 bg-yellow-500/10'
      case 'low': return 'text-green-400 bg-green-500/10'
      default: return 'text-slate-400 bg-slate-500/10'
    }
  }

  return (
    <AppShell activeApp="remediate">
      <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
        <div className="w-72 bg-[#0f172a]/80 border-r border-white/10 flex flex-col sticky top-0 h-screen">
          <div className="p-6 border-b border-white/10">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-[#6B5AED]">Remediation</h2>
              <button
                onClick={() => window.location.href = '/triage'}
                className="p-2 rounded-md border border-white/10 text-slate-400 hover:bg-white/5 transition-all"
                title="Back to Triage"
              >
                <ArrowLeft size={16} />
              </button>
            </div>
            <p className="text-xs text-slate-500">Manage remediation workflows</p>
          </div>

          <div className="p-4 border-b border-white/10">
            <div className="space-y-1">
              {[
                { id: 'plans', label: 'Remediation Plans', icon: Shield },
                { id: 'exceptions', label: 'Exceptions', icon: AlertTriangle },
                { id: 'sla', label: 'SLA Tracking', icon: Clock },
                { id: 'spotlight', label: 'Spotlight', icon: Zap },
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
                <div className="text-2xl font-bold text-blue-400">{stats.active}</div>
                <div className="text-xs text-slate-500">Active Plans</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md border border-white/10">
                <div className="text-2xl font-bold text-red-400">{stats.overdue}</div>
                <div className="text-xs text-slate-500">Overdue</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md border border-white/10">
                <div className="flex items-baseline gap-1">
                  <span className="text-2xl font-bold text-green-400">{stats.fixedVulns}</span>
                  <span className="text-sm text-slate-500">/ {stats.totalVulns}</span>
                </div>
                <div className="text-xs text-slate-500">Vulnerabilities Fixed</div>
                <div className="mt-2 h-1.5 bg-white/10 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-green-500 rounded-full"
                    style={{ width: `${stats.totalVulns > 0 ? (stats.fixedVulns / stats.totalVulns) * 100 : 0}%` }}
                  />
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="flex-1 flex flex-col">
          <div className="p-5 border-b border-white/10 bg-[#0f172a]/80 backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-2xl font-semibold mb-1">
                  {activeTab === 'plans' && 'Remediation Plans'}
                  {activeTab === 'exceptions' && 'Risk Exceptions'}
                  {activeTab === 'sla' && 'SLA Tracking'}
                  {activeTab === 'spotlight' && 'Celebrity Vulnerabilities'}
                </h1>
                <p className="text-sm text-slate-500">
                  {activeTab === 'plans' && `${filteredPlans.length} plans`}
                  {activeTab === 'exceptions' && `${exceptions.length} active exceptions`}
                  {activeTab === 'sla' && 'Track remediation SLAs by severity'}
                  {activeTab === 'spotlight' && 'Trending high-profile vulnerabilities'}
                </p>
              </div>
              <div className="flex gap-2">
                {activeTab === 'plans' && (
                  <>
                    <button
                      onClick={handleExportCSV}
                      className="px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all flex items-center gap-2"
                    >
                      <Download size={14} />
                      Export CSV
                    </button>
                    <button className="px-4 py-2 bg-[#6B5AED] rounded-md text-white text-sm font-medium hover:bg-[#5B4ADD] transition-all flex items-center gap-2">
                      <Plus size={14} />
                      New Plan
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>

          {activeTab === 'plans' && (
            <div className="p-4 border-b border-white/10 flex gap-4">
              <div className="relative flex-1 max-w-md">
                <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  placeholder="Search plans..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-9 pr-4 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                />
              </div>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="px-4 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white focus:outline-none focus:border-[#6B5AED]/50"
              >
                <option value="all">All Status</option>
                <option value="active">Active</option>
                <option value="pending">Pending</option>
                <option value="completed">Completed</option>
                <option value="overdue">Overdue</option>
              </select>
            </div>
          )}

          <div className="flex-1 overflow-auto p-6">
            {!demoEnabled ? (
              <div className="flex items-center justify-center h-full">
                <div className="text-center max-w-md">
                  <AlertCircle size={48} className="mx-auto mb-4 text-slate-500" />
                  <h3 className="text-lg font-semibold text-white mb-2">No Remediation Data</h3>
                  <p className="text-sm text-slate-400 mb-4">
                    Enable demo mode to see sample remediation data, or connect your systems to see real data.
                  </p>
                </div>
              </div>
            ) : activeTab === 'plans' ? (
              <div className="space-y-4">
                {filteredPlans.map(plan => {
                  const daysRemaining = getDaysRemaining(plan.due_date)
                  const progress = plan.vulnerabilities.total > 0 
                    ? (plan.vulnerabilities.fixed / plan.vulnerabilities.total) * 100 
                    : 0
                  return (
                    <div
                      key={plan.id}
                      className="p-4 bg-white/5 rounded-lg border border-white/10 hover:border-white/20 transition-all cursor-pointer"
                      onClick={() => setSelectedPlan(plan)}
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-1">
                            <h3 className="font-semibold text-white">{plan.name}</h3>
                            <span className={`px-2 py-0.5 rounded text-xs font-medium border ${getStatusColor(plan.status)}`}>
                              {plan.status}
                            </span>
                            <span className={`px-2 py-0.5 rounded text-xs font-medium ${getPriorityColor(plan.priority)}`}>
                              {plan.priority}
                            </span>
                          </div>
                          <p className="text-sm text-slate-400">{plan.description}</p>
                        </div>
                        <ChevronRight size={16} className="text-slate-500" />
                      </div>

                      <div className="grid grid-cols-4 gap-4 mb-3">
                        <div>
                          <div className="text-xs text-slate-500 mb-1">Owner</div>
                          <div className="text-sm text-white flex items-center gap-1">
                            <User size={12} />
                            {plan.owner}
                          </div>
                        </div>
                        <div>
                          <div className="text-xs text-slate-500 mb-1">Due Date</div>
                          <div className={`text-sm flex items-center gap-1 ${daysRemaining < 0 ? 'text-red-400' : daysRemaining < 7 ? 'text-yellow-400' : 'text-white'}`}>
                            <Calendar size={12} />
                            {formatDate(plan.due_date)}
                            {daysRemaining < 0 && <span className="text-xs">({Math.abs(daysRemaining)}d overdue)</span>}
                            {daysRemaining >= 0 && daysRemaining < 7 && <span className="text-xs">({daysRemaining}d left)</span>}
                          </div>
                        </div>
                        <div>
                          <div className="text-xs text-slate-500 mb-1">SLA Status</div>
                          <div className={`text-sm font-medium ${getSlaColor(plan.sla_status)}`}>
                            {plan.sla_status.replace('_', ' ')}
                          </div>
                        </div>
                        <div>
                          <div className="text-xs text-slate-500 mb-1">Tickets</div>
                          <div className="flex items-center gap-2">
                            {plan.tickets.jira && (
                              <span className="text-xs text-blue-400 flex items-center gap-1">
                                <Ticket size={10} />
                                {plan.tickets.jira}
                              </span>
                            )}
                            {plan.tickets.servicenow && (
                              <span className="text-xs text-green-400 flex items-center gap-1">
                                <Ticket size={10} />
                                {plan.tickets.servicenow}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>

                      <div>
                        <div className="flex items-center justify-between text-xs mb-1">
                          <span className="text-slate-500">Progress</span>
                          <span className="text-white">
                            {plan.vulnerabilities.fixed} / {plan.vulnerabilities.total} vulnerabilities fixed
                          </span>
                        </div>
                        <div className="h-2 bg-white/10 rounded-full overflow-hidden">
                          <div 
                            className="h-full bg-gradient-to-r from-[#6B5AED] to-green-500 rounded-full transition-all"
                            style={{ width: `${progress}%` }}
                          />
                        </div>
                        <div className="flex items-center gap-4 mt-2 text-xs">
                          <span className="text-green-400">{plan.vulnerabilities.fixed} fixed</span>
                          <span className="text-blue-400">{plan.vulnerabilities.in_progress} in progress</span>
                          <span className="text-slate-400">{plan.vulnerabilities.pending} pending</span>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            ) : activeTab === 'exceptions' ? (
              <div className="space-y-4">
                {exceptions.map(exc => (
                  <div
                    key={exc.id}
                    className="p-4 bg-white/5 rounded-lg border border-white/10"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-xs font-mono text-orange-400">{exc.vulnerability_id}</span>
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                            exc.status === 'active' ? 'text-green-400 bg-green-500/10' :
                            exc.status === 'pending_approval' ? 'text-yellow-400 bg-yellow-500/10' :
                            'text-red-400 bg-red-500/10'
                          }`}>
                            {exc.status.replace('_', ' ')}
                          </span>
                        </div>
                        <h3 className="font-semibold text-white">{exc.vulnerability_title}</h3>
                      </div>
                      {exc.risk_accepted && (
                        <span className="px-2 py-1 bg-orange-500/10 border border-orange-500/30 rounded text-xs text-orange-400">
                          Risk Accepted
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-slate-400 mb-3">{exc.reason}</p>
                    <div className="flex items-center gap-6 text-xs text-slate-500">
                      <span>Approved by: {exc.approved_by}</span>
                      <span>Expires: {formatDate(exc.expiration_date)}</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : activeTab === 'sla' ? (
              <div className="space-y-6">
                {Object.entries(SLA_CONFIG).map(([severity, config]) => {
                  const plansInSeverity = plans.filter(p => p.priority === severity)
                  const onTrack = plansInSeverity.filter(p => p.sla_status === 'on_track').length
                  const atRisk = plansInSeverity.filter(p => p.sla_status === 'at_risk').length
                  const breached = plansInSeverity.filter(p => p.sla_status === 'breached').length
                  return (
                    <div key={severity} className="p-4 bg-white/5 rounded-lg border border-white/10">
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-3">
                          <span className={`px-3 py-1 rounded text-sm font-medium ${getPriorityColor(severity)}`}>
                            {severity.charAt(0).toUpperCase() + severity.slice(1)}
                          </span>
                          <span className="text-slate-400">SLA: {config.label}</span>
                        </div>
                        <span className="text-sm text-slate-500">{plansInSeverity.length} plans</span>
                      </div>
                      <div className="grid grid-cols-3 gap-4">
                        <div className="p-3 bg-green-500/10 rounded border border-green-500/20">
                          <div className="text-2xl font-bold text-green-400">{onTrack}</div>
                          <div className="text-xs text-green-400/70">On Track</div>
                        </div>
                        <div className="p-3 bg-yellow-500/10 rounded border border-yellow-500/20">
                          <div className="text-2xl font-bold text-yellow-400">{atRisk}</div>
                          <div className="text-xs text-yellow-400/70">At Risk</div>
                        </div>
                        <div className="p-3 bg-red-500/10 rounded border border-red-500/20">
                          <div className="text-2xl font-bold text-red-400">{breached}</div>
                          <div className="text-xs text-red-400/70">Breached</div>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            ) : activeTab === 'spotlight' ? (
              <div className="space-y-4">
                <div className="p-4 bg-gradient-to-r from-red-500/10 to-orange-500/10 rounded-lg border border-red-500/20 mb-6">
                  <div className="flex items-center gap-2 mb-2">
                    <Zap size={16} className="text-orange-400" />
                    <span className="text-sm font-semibold text-orange-400">Celebrity Vulnerabilities</span>
                  </div>
                  <p className="text-xs text-slate-400">
                    High-profile vulnerabilities that are actively being exploited in the wild. Prioritize remediation immediately.
                  </p>
                </div>
                {spotlight.map(vuln => (
                  <div
                    key={vuln.id}
                    className="p-4 bg-white/5 rounded-lg border border-red-500/30 hover:border-red-500/50 transition-all"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-xs font-mono text-red-400">{vuln.cve_id}</span>
                          {vuln.trending && (
                            <span className="px-2 py-0.5 bg-orange-500/10 border border-orange-500/30 rounded text-xs text-orange-400 flex items-center gap-1">
                              <Zap size={10} />
                              Trending
                            </span>
                          )}
                          {vuln.exploit_available && (
                            <span className="px-2 py-0.5 bg-red-500/10 border border-red-500/30 rounded text-xs text-red-400">
                              Exploit Available
                            </span>
                          )}
                        </div>
                        <h3 className="font-semibold text-white">{vuln.name}</h3>
                      </div>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        vuln.severity === 'critical' ? 'text-red-400 bg-red-500/10' : 'text-orange-400 bg-orange-500/10'
                      }`}>
                        {vuln.severity}
                      </span>
                    </div>
                    <p className="text-sm text-slate-400 mb-3">{vuln.description}</p>
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-slate-500">
                        {vuln.affected_assets} affected assets in your environment
                      </span>
                      <button className="px-3 py-1.5 bg-red-500/20 border border-red-500/30 rounded text-xs text-red-300 hover:bg-red-500/30 transition-all flex items-center gap-1">
                        Create Remediation Plan
                        <ChevronRight size={12} />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </AppShell>
  )
}
