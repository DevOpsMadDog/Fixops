'use client'

import { useState } from 'react'
import { Workflow, Search, Plus, Edit2, Trash2, Play, Pause, Clock, CheckCircle, XCircle, AlertCircle, Filter, Calendar, Activity } from 'lucide-react'
import EnterpriseShell from './components/EnterpriseShell'

const DEMO_WORKFLOWS = [
  {
    id: '1',
    name: 'Auto-Triage Critical Findings',
    description: 'Automatically assign critical findings to security team and create Jira tickets',
    trigger: 'finding.created',
    conditions: [
      { field: 'severity', operator: 'equals', value: 'critical' },
      { field: 'exploitability.kev', operator: 'equals', value: 'true' },
    ],
    actions: [
      { type: 'assign', target: 'security-team' },
      { type: 'create_ticket', integration: 'jira', project: 'SEC' },
      { type: 'notify', channel: 'slack', target: '#security-alerts' },
    ],
    status: 'active',
    executions: 45,
    last_executed: '2024-11-22T08:30:00Z',
    success_rate: 98.5,
    created_at: '2024-01-15T10:00:00Z',
  },
  {
    id: '2',
    name: 'Compliance Violation Escalation',
    description: 'Escalate PCI-DSS violations to compliance team with executive notification',
    trigger: 'policy.violated',
    conditions: [
      { field: 'compliance_mappings', operator: 'contains', value: 'PCI-DSS' },
    ],
    actions: [
      { type: 'assign', target: 'compliance-team' },
      { type: 'notify', channel: 'email', target: 'compliance@fixops.io' },
      { type: 'notify', channel: 'email', target: 'ciso@fixops.io' },
    ],
    status: 'active',
    executions: 12,
    last_executed: '2024-11-21T18:30:00Z',
    success_rate: 100,
    created_at: '2024-02-01T14:30:00Z',
  },
  {
    id: '3',
    name: 'Secrets Detection Response',
    description: 'Immediately block deployments with exposed secrets and notify infra team',
    trigger: 'finding.created',
    conditions: [
      { field: 'source', operator: 'equals', value: 'IaC' },
      { field: 'title', operator: 'contains', value: 'secret' },
    ],
    actions: [
      { type: 'block_deployment', reason: 'Exposed secrets detected' },
      { type: 'assign', target: 'infra-team' },
      { type: 'create_ticket', integration: 'jira', project: 'INFRA', priority: 'highest' },
    ],
    status: 'active',
    executions: 8,
    last_executed: '2024-11-22T06:00:00Z',
    success_rate: 100,
    created_at: '2024-03-10T09:00:00Z',
  },
  {
    id: '4',
    name: 'Weekly Security Summary',
    description: 'Generate and send weekly security summary report to leadership',
    trigger: 'schedule.weekly',
    conditions: [],
    actions: [
      { type: 'generate_report', template: 'security_summary' },
      { type: 'notify', channel: 'email', target: 'leadership@fixops.io' },
    ],
    status: 'active',
    executions: 32,
    last_executed: '2024-11-18T09:00:00Z',
    success_rate: 100,
    created_at: '2024-04-05T11:20:00Z',
  },
  {
    id: '5',
    name: 'SLA Breach Warning',
    description: 'Warn teams when findings are approaching SLA breach',
    trigger: 'schedule.daily',
    conditions: [
      { field: 'sla_remaining', operator: 'less_than', value: '24h' },
    ],
    actions: [
      { type: 'notify', channel: 'slack', target: '#team-alerts' },
      { type: 'notify', channel: 'email', target: 'team-leads@fixops.io' },
    ],
    status: 'active',
    executions: 156,
    last_executed: '2024-11-22T06:00:00Z',
    success_rate: 99.2,
    created_at: '2024-05-12T13:45:00Z',
  },
  {
    id: '6',
    name: 'Auto-Close Remediated Findings',
    description: 'Automatically close findings when remediation is verified',
    trigger: 'finding.remediated',
    conditions: [
      { field: 'verification_status', operator: 'equals', value: 'verified' },
    ],
    actions: [
      { type: 'close_finding', status: 'resolved' },
      { type: 'notify', channel: 'slack', target: '#security-updates' },
    ],
    status: 'paused',
    executions: 67,
    last_executed: '2024-11-15T10:00:00Z',
    success_rate: 95.5,
    created_at: '2024-06-18T15:10:00Z',
  },
  {
    id: '7',
    name: 'Internet-Facing RCE Alert',
    description: 'Immediate escalation for RCE vulnerabilities in internet-facing services',
    trigger: 'finding.created',
    conditions: [
      { field: 'title', operator: 'contains', value: 'Remote Code Execution' },
      { field: 'internet_facing', operator: 'equals', value: 'true' },
    ],
    actions: [
      { type: 'assign', target: 'security-team' },
      { type: 'notify', channel: 'pagerduty', severity: 'critical' },
      { type: 'create_ticket', integration: 'jira', project: 'SEC', priority: 'highest' },
    ],
    status: 'active',
    executions: 4,
    last_executed: '2024-11-22T05:00:00Z',
    success_rate: 100,
    created_at: '2024-07-22T08:30:00Z',
  },
  {
    id: '8',
    name: 'Dependency Update Notification',
    description: 'Notify teams when critical dependency updates are available',
    trigger: 'scan.completed',
    conditions: [
      { field: 'has_updates', operator: 'equals', value: 'true' },
      { field: 'update_severity', operator: 'in', value: ['critical', 'high'] },
    ],
    actions: [
      { type: 'notify', channel: 'slack', target: '#dev-updates' },
      { type: 'create_ticket', integration: 'github', labels: ['dependencies', 'security'] },
    ],
    status: 'active',
    executions: 89,
    last_executed: '2024-11-22T08:00:00Z',
    success_rate: 97.8,
    created_at: '2024-08-30T10:15:00Z',
  },
]

export default function WorkflowsPage() {
  const [workflows, setWorkflows] = useState(DEMO_WORKFLOWS)
  const [filteredWorkflows, setFilteredWorkflows] = useState(DEMO_WORKFLOWS)
  const [selectedWorkflow, setSelectedWorkflow] = useState<typeof DEMO_WORKFLOWS[0] | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [triggerFilter, setTriggerFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showExecutionHistory, setShowExecutionHistory] = useState(false)

  const getTriggerColor = (trigger: string) => {
    const colors = {
      'finding.created': '#3b82f6',
      'policy.violated': '#dc2626',
      'finding.remediated': '#10b981',
      'scan.completed': '#8b5cf6',
      'schedule.weekly': '#f97316',
      'schedule.daily': '#eab308',
    }
    return colors[trigger as keyof typeof colors] || '#6b7280'
  }

  const formatDate = (isoString: string | null) => {
    if (!isoString) return 'Never'
    const date = new Date(isoString)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60))
    
    if (diffHours < 1) return 'Just now'
    if (diffHours < 24) return `${diffHours}h ago`
    const diffDays = Math.floor(diffHours / 24)
    if (diffDays < 7) return `${diffDays}d ago`
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
  }

  const applyFilters = () => {
    let filtered = [...workflows]

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(workflow =>
        workflow.name.toLowerCase().includes(query) ||
        workflow.description.toLowerCase().includes(query)
      )
    }

    if (triggerFilter !== 'all') {
      filtered = filtered.filter(workflow => workflow.trigger === triggerFilter)
    }

    if (statusFilter !== 'all') {
      filtered = filtered.filter(workflow => workflow.status === statusFilter)
    }

    setFilteredWorkflows(filtered)
  }

  useState(() => {
    applyFilters()
  })

  const summary = {
    total: workflows.length,
    active: workflows.filter(w => w.status === 'active').length,
    paused: workflows.filter(w => w.status === 'paused').length,
    total_executions: workflows.reduce((sum, w) => sum + w.executions, 0),
    avg_success_rate: Math.round(workflows.reduce((sum, w) => sum + w.success_rate, 0) / workflows.length),
  }

  const triggers = Array.from(new Set(workflows.map(w => w.trigger)))

  return (
    <EnterpriseShell>
      <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
        {/* Left Sidebar - Filters */}
        <div className="w-72 bg-[#0f172a]/80 border-r border-white/10 flex flex-col sticky top-0 min-h-screen">
          {/* Header */}
          <div className="p-6 border-b border-white/10">
            <div className="flex items-center gap-3 mb-4">
              <Workflow size={24} className="text-[#6B5AED]" />
              <h2 className="text-lg font-semibold">Workflows</h2>
            </div>
            <p className="text-xs text-slate-500">Automate security operations</p>
          </div>

          {/* Summary Stats */}
          <div className="p-4 border-b border-white/10">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Total Workflows</div>
                <div className="text-xl font-semibold text-[#6B5AED]">{summary.total}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Active</div>
                <div className="text-xl font-semibold text-green-500">{summary.active}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Executions</div>
                <div className="text-xl font-semibold text-blue-500">{summary.total_executions}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Success Rate</div>
                <div className="text-xl font-semibold text-orange-500">{summary.avg_success_rate}%</div>
              </div>
            </div>
          </div>

          {/* Filters */}
          <div className="p-4 flex-1 overflow-auto">
            <div className="mb-6">
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Filter size={12} />
                Filter by Status
              </div>
              <div className="space-y-2">
                {['all', 'active', 'paused'].map((status) => (
                  <button
                    key={status}
                    onClick={() => { setStatusFilter(status); applyFilters(); }}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      statusFilter === status
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="capitalize">{status}</span>
                    {status !== 'all' && (
                      <span className="ml-2 text-xs">
                        ({workflows.filter(w => w.status === status).length})
                      </span>
                    )}
                    {status === 'all' && (
                      <span className="ml-2 text-xs">({workflows.length})</span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Filter size={12} />
                Filter by Trigger
              </div>
              <div className="space-y-2">
                <button
                  onClick={() => { setTriggerFilter('all'); applyFilters(); }}
                  className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                    triggerFilter === 'all'
                      ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                      : 'text-slate-400 hover:bg-white/5'
                  }`}
                >
                  All Triggers
                  <span className="ml-2 text-xs">({workflows.length})</span>
                </button>
                {triggers.map((trigger) => (
                  <button
                    key={trigger}
                    onClick={() => { setTriggerFilter(trigger); applyFilters(); }}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      triggerFilter === trigger
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="truncate">{trigger.replace('.', ' ')}</span>
                    <span className="ml-2 text-xs">
                      ({workflows.filter(w => w.trigger === trigger).length})
                    </span>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1 flex flex-col">
          {/* Top Bar */}
          <div className="p-5 border-b border-white/10 bg-[#0f172a]/80 backdrop-blur-sm">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h1 className="text-2xl font-semibold mb-1">Workflows</h1>
                <p className="text-sm text-slate-500">
                  Showing {filteredWorkflows.length} workflow{filteredWorkflows.length !== 1 ? 's' : ''}
                </p>
              </div>
              <button
                onClick={() => setShowCreateModal(true)}
                className="px-4 py-2 bg-[#6B5AED] hover:bg-[#5B4ADD] rounded-md text-white text-sm font-medium transition-all flex items-center gap-2"
              >
                <Plus size={16} />
                Create Workflow
              </button>
            </div>

            {/* Search Bar */}
            <div className="relative">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search by name or description..."
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); applyFilters(); }}
                className="w-full pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-[#6B5AED]/50"
              />
            </div>
          </div>

          {/* Workflows Grid */}
          <div className="flex-1 overflow-auto p-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {filteredWorkflows.map((workflow) => (
                <div
                  key={workflow.id}
                  onClick={() => setSelectedWorkflow(workflow)}
                  className="bg-white/2 border border-white/5 rounded-lg p-5 hover:bg-white/5 hover:border-[#6B5AED]/30 cursor-pointer transition-all"
                >
                  {/* Header */}
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-[#6B5AED]/20 flex items-center justify-center">
                        <Workflow size={20} className="text-[#6B5AED]" />
                      </div>
                      <div>
                        <h3 className="text-sm font-semibold text-white">{workflow.name}</h3>
                        <p className="text-xs text-slate-400">{workflow.executions} executions</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${workflow.status === 'active' ? 'bg-green-500' : 'bg-gray-500'}`} />
                      <span className="text-xs text-slate-400 capitalize">{workflow.status}</span>
                    </div>
                  </div>

                  {/* Description */}
                  <p className="text-sm text-slate-300 mb-4">{workflow.description}</p>

                  {/* Trigger Badge */}
                  <div className="mb-4">
                    <span
                      className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium"
                      style={{ 
                        backgroundColor: `${getTriggerColor(workflow.trigger)}20`,
                        color: getTriggerColor(workflow.trigger)
                      }}
                    >
                      <Activity size={12} />
                      {workflow.trigger.replace('.', ' ')}
                    </span>
                  </div>

                  {/* Stats */}
                  <div className="grid grid-cols-3 gap-3 mb-4">
                    <div className="p-3 bg-white/5 rounded-lg text-center">
                      <div className="text-xs text-slate-400 mb-1">Success Rate</div>
                      <div className="text-lg font-semibold text-green-500">{workflow.success_rate}%</div>
                    </div>
                    <div className="p-3 bg-white/5 rounded-lg text-center">
                      <div className="text-xs text-slate-400 mb-1">Conditions</div>
                      <div className="text-lg font-semibold text-blue-500">{workflow.conditions.length}</div>
                    </div>
                    <div className="p-3 bg-white/5 rounded-lg text-center">
                      <div className="text-xs text-slate-400 mb-1">Actions</div>
                      <div className="text-lg font-semibold text-orange-500">{workflow.actions.length}</div>
                    </div>
                  </div>

                  {/* Footer */}
                  <div className="flex items-center justify-between pt-3 border-t border-white/5">
                    <div className="flex items-center gap-2 text-xs text-slate-400">
                      <Clock size={12} />
                      Last: {formatDate(workflow.last_executed)}
                    </div>
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        alert(`Executing workflow: ${workflow.name}`)
                      }}
                      className="text-xs text-[#6B5AED] hover:underline flex items-center gap-1"
                    >
                      <Play size={12} />
                      Execute Now
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Workflow Detail Drawer */}
        {selectedWorkflow && !showExecutionHistory && (
          <div
            onClick={() => setSelectedWorkflow(null)}
            className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex justify-end"
          >
            <div
              onClick={(e) => e.stopPropagation()}
              className="w-[600px] h-full bg-[#1e293b] border-l border-white/10 flex flex-col animate-slide-in overflow-auto"
            >
              {/* Drawer Header */}
              <div className="p-6 border-b border-white/10 sticky top-0 bg-[#1e293b] z-10">
                <div className="flex justify-between items-start mb-4">
                  <div>
                    <h3 className="text-lg font-semibold mb-1">{selectedWorkflow.name}</h3>
                    <p className="text-sm text-slate-400">{selectedWorkflow.description}</p>
                  </div>
                  <button
                    onClick={() => setSelectedWorkflow(null)}
                    className="text-slate-400 hover:text-white transition-colors"
                  >
                    ✕
                  </button>
                </div>

                <div className="flex gap-2">
                  <span
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium"
                    style={{ 
                      backgroundColor: `${getTriggerColor(selectedWorkflow.trigger)}20`,
                      color: getTriggerColor(selectedWorkflow.trigger)
                    }}
                  >
                    <Activity size={14} />
                    {selectedWorkflow.trigger.replace('.', ' ')}
                  </span>
                  <span className={`inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium ${
                    selectedWorkflow.status === 'active' ? 'bg-green-500/10 text-green-500' : 'bg-gray-500/10 text-gray-500'
                  }`}>
                    {selectedWorkflow.status === 'active' ? <CheckCircle size={14} /> : <Pause size={14} />}
                    {selectedWorkflow.status}
                  </span>
                </div>
              </div>

              {/* Drawer Content */}
              <div className="flex-1 p-6 space-y-6">
                {/* Workflow Stats */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Statistics</h4>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="p-4 bg-white/5 rounded-lg">
                      <div className="text-xs text-slate-400 mb-1">Total Executions</div>
                      <div className="text-2xl font-semibold text-[#6B5AED]">{selectedWorkflow.executions}</div>
                    </div>
                    <div className="p-4 bg-white/5 rounded-lg">
                      <div className="text-xs text-slate-400 mb-1">Success Rate</div>
                      <div className="text-2xl font-semibold text-green-500">{selectedWorkflow.success_rate}%</div>
                    </div>
                  </div>
                  <div className="mt-3 space-y-2 bg-white/5 rounded-lg p-4">
                    <div className="flex justify-between text-sm">
                      <span className="text-slate-400">Last Executed</span>
                      <span className="text-white">{formatDate(selectedWorkflow.last_executed)}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-slate-400">Created</span>
                      <span className="text-white">{formatDate(selectedWorkflow.created_at)}</span>
                    </div>
                  </div>
                </div>

                {/* Conditions */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Conditions</h4>
                  {selectedWorkflow.conditions.length > 0 ? (
                    <div className="space-y-2">
                      {selectedWorkflow.conditions.map((condition, idx) => (
                        <div key={idx} className="p-3 bg-white/5 rounded-lg">
                          <div className="flex items-center gap-2 text-sm">
                            <span className="text-slate-400">{condition.field}</span>
                            <span className="text-[#6B5AED] font-mono">{condition.operator}</span>
                            <span className="text-white font-medium">{condition.value}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-4 bg-white/5 rounded-lg text-center text-sm text-slate-400">
                      No conditions (always executes)
                    </div>
                  )}
                </div>

                {/* Actions */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Actions</h4>
                  <div className="space-y-2">
                    {selectedWorkflow.actions.map((action, idx) => (
                      <div key={idx} className="p-3 bg-white/5 rounded-lg">
                        <div className="text-sm text-white font-medium mb-1 capitalize">{action.type.replace('_', ' ')}</div>
                        <div className="text-xs text-slate-400">
                          {Object.entries(action).filter(([key]) => key !== 'type').map(([key, value]) => (
                            <span key={key} className="mr-3">
                              {key}: <span className="text-white">{value}</span>
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Workflow Actions */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Workflow Actions</h4>
                  <div className="space-y-2">
                    <button
                      onClick={() => alert(`Executing workflow: ${selectedWorkflow.name}`)}
                      className="w-full p-3 bg-[#6B5AED]/10 hover:bg-[#6B5AED]/20 rounded-lg text-sm text-left text-[#6B5AED] transition-colors flex items-center gap-2"
                    >
                      <Play size={16} />
                      Execute Now
                    </button>
                    <button
                      onClick={() => setShowExecutionHistory(true)}
                      className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2"
                    >
                      <Calendar size={16} />
                      View Execution History
                    </button>
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <Edit2 size={16} />
                      Edit Workflow
                    </button>
                    {selectedWorkflow.status === 'active' ? (
                      <button className="w-full p-3 bg-yellow-500/10 hover:bg-yellow-500/20 rounded-lg text-sm text-left text-yellow-400 transition-colors flex items-center gap-2">
                        <Pause size={16} />
                        Pause Workflow
                      </button>
                    ) : (
                      <button className="w-full p-3 bg-green-500/10 hover:bg-green-500/20 rounded-lg text-sm text-left text-green-400 transition-colors flex items-center gap-2">
                        <Play size={16} />
                        Resume Workflow
                      </button>
                    )}
                    <button className="w-full p-3 bg-red-500/10 hover:bg-red-500/20 rounded-lg text-sm text-left text-red-400 transition-colors flex items-center gap-2">
                      <Trash2 size={16} />
                      Delete Workflow
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </EnterpriseShell>
  )
}
