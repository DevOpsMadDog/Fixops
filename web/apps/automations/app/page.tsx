'use client'

import { useState } from 'react'
import { Play, Pause, Plus, Trash2, Edit2, ArrowLeft, Zap, Shield, AlertTriangle } from 'lucide-react'
import EnterpriseShell from './components/EnterpriseShell'

const AUTOMATION_RULES = [
  {
    id: 'rule1',
    name: 'Auto-Block KEV Vulnerabilities',
    description: 'Automatically block any vulnerability in CISA KEV catalog',
    enabled: true,
    trigger: 'New finding detected',
    conditions: [
      { field: 'KEV', operator: 'equals', value: 'true' },
    ],
    actions: [
      { type: 'set_verdict', value: 'block' },
      { type: 'set_priority', value: 'immediate' },
      { type: 'notify', value: 'security-team' },
    ],
    executions: 12,
    last_executed: '2024-11-21T10:30:00Z',
    created: '2024-09-15',
  },
  {
    id: 'rule2',
    name: 'Escalate Critical Internet-Facing',
    description: 'Create Jira ticket for critical issues in internet-facing services',
    enabled: true,
    trigger: 'New finding detected',
    conditions: [
      { field: 'Severity', operator: 'equals', value: 'critical' },
      { field: 'Internet-Facing', operator: 'equals', value: 'true' },
    ],
    actions: [
      { type: 'create_ticket', value: 'jira' },
      { type: 'assign', value: 'team-security' },
      { type: 'notify', value: 'slack-security' },
    ],
    executions: 45,
    last_executed: '2024-11-21T09:15:00Z',
    created: '2024-08-20',
  },
  {
    id: 'rule3',
    name: 'Auto-Accept Low Severity Internal',
    description: 'Automatically accept risk for low severity issues in internal services',
    enabled: true,
    trigger: 'New finding detected',
    conditions: [
      { field: 'Severity', operator: 'equals', value: 'low' },
      { field: 'Internet-Facing', operator: 'equals', value: 'false' },
      { field: 'EPSS', operator: 'less_than', value: '0.1' },
    ],
    actions: [
      { type: 'set_verdict', value: 'allow' },
      { type: 'add_comment', value: 'Auto-accepted: Low risk internal issue' },
    ],
    executions: 234,
    last_executed: '2024-11-21T08:45:00Z',
    created: '2024-07-10',
  },
  {
    id: 'rule4',
    name: 'Flag Compliance-Critical Issues',
    description: 'Tag issues affecting SOC2 or PCI-DSS controls',
    enabled: false,
    trigger: 'New finding detected',
    conditions: [
      { field: 'Compliance Framework', operator: 'in', value: 'SOC2, PCI-DSS' },
      { field: 'Severity', operator: 'in', value: 'high, critical' },
    ],
    actions: [
      { type: 'add_tag', value: 'compliance-critical' },
      { type: 'notify', value: 'compliance-team' },
    ],
    executions: 67,
    last_executed: '2024-11-20T14:20:00Z',
    created: '2024-06-05',
  },
]

const POLICY_GATES = [
  {
    id: 'gate1',
    name: 'Production Deployment Gate',
    description: 'Block deployments with critical or KEV vulnerabilities',
    enabled: true,
    gate_type: 'deployment',
    conditions: [
      { field: 'Critical Issues', operator: 'greater_than', value: '0' },
      { field: 'KEV Issues', operator: 'greater_than', value: '0' },
    ],
    action: 'block',
    blocks: 8,
    last_triggered: '2024-11-20T16:30:00Z',
  },
  {
    id: 'gate2',
    name: 'PR Merge Gate',
    description: 'Require review for PRs introducing high/critical findings',
    enabled: true,
    gate_type: 'pr_merge',
    conditions: [
      { field: 'New High Issues', operator: 'greater_than', value: '0' },
      { field: 'New Critical Issues', operator: 'greater_than', value: '0' },
    ],
    action: 'require_review',
    blocks: 23,
    last_triggered: '2024-11-21T11:00:00Z',
  },
]

export default function AutomationsPage() {
  const [selectedRule, setSelectedRule] = useState<typeof AUTOMATION_RULES[0] | null>(null)
  const [activeTab, setActiveTab] = useState<'rules' | 'gates'>('rules')
  const [isCreating, setIsCreating] = useState(false)

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
    <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
      {/* Left Sidebar - Rules/Gates List */}
      <div className="w-80 bg-[#0f172a]/80 border-r border-white/10 flex flex-col sticky top-0 h-screen">
        {/* Header */}
        <div className="p-6 border-b border-white/10">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-[#6B5AED]">Automations</h2>
            <button
              onClick={() => window.location.href = '/triage'}
              className="p-2 rounded-md border border-white/10 text-slate-400 hover:bg-white/5 transition-all"
              title="Back to Triage"
            >
              <ArrowLeft size={16} />
            </button>
          </div>
          <p className="text-xs text-slate-500">Rules and policy gates</p>
        </div>

        {/* Tabs */}
        <div className="p-4 border-b border-white/10">
          <div className="flex gap-2">
            <button
              onClick={() => setActiveTab('rules')}
              className={`flex-1 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                activeTab === 'rules'
                  ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                  : 'text-slate-400 hover:bg-white/5'
              }`}
            >
              Rules ({AUTOMATION_RULES.length})
            </button>
            <button
              onClick={() => setActiveTab('gates')}
              className={`flex-1 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                activeTab === 'gates'
                  ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                  : 'text-slate-400 hover:bg-white/5'
              }`}
            >
              Gates ({POLICY_GATES.length})
            </button>
          </div>
        </div>

        {/* Create New Button */}
        <div className="p-4 border-b border-white/10">
          <button
            onClick={() => setIsCreating(true)}
            className="w-full px-4 py-2.5 bg-[#6B5AED] rounded-md text-white text-sm font-medium flex items-center justify-center gap-2 hover:bg-[#5B4ADD] transition-all"
          >
            <Plus size={16} />
            Create New {activeTab === 'rules' ? 'Rule' : 'Gate'}
          </button>
        </div>

        {/* List */}
        <div className="p-4 flex-1 overflow-auto">
          {activeTab === 'rules' ? (
            <div className="space-y-2">
              {AUTOMATION_RULES.map((rule) => (
                <button
                  key={rule.id}
                  onClick={() => setSelectedRule(rule)}
                  className={`w-full p-3 rounded-md text-left transition-all ${
                    selectedRule?.id === rule.id
                      ? 'bg-[#6B5AED]/10 border border-[#6B5AED]/30'
                      : 'bg-white/5 border border-white/10 hover:bg-white/10'
                  }`}
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      {rule.enabled ? (
                        <Zap size={14} className="text-green-500" />
                      ) : (
                        <Pause size={14} className="text-slate-500" />
                      )}
                      <span className="text-sm font-semibold text-white">{rule.name}</span>
                    </div>
                  </div>
                  <p className="text-xs text-slate-400 mb-2">{rule.description}</p>
                  <div className="flex items-center gap-2 text-[10px] text-slate-500">
                    <span>{rule.executions} executions</span>
                  </div>
                </button>
              ))}
            </div>
          ) : (
            <div className="space-y-2">
              {POLICY_GATES.map((gate) => (
                <button
                  key={gate.id}
                  className="w-full p-3 rounded-md text-left bg-white/5 border border-white/10 hover:bg-white/10 transition-all"
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      {gate.enabled ? (
                        <Shield size={14} className="text-green-500" />
                      ) : (
                        <Pause size={14} className="text-slate-500" />
                      )}
                      <span className="text-sm font-semibold text-white">{gate.name}</span>
                    </div>
                  </div>
                  <p className="text-xs text-slate-400 mb-2">{gate.description}</p>
                  <div className="flex items-center gap-2 text-[10px] text-slate-500">
                    <span>{gate.blocks} blocks</span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col">
        {/* Top Bar */}
        <div className="p-5 border-b border-white/10 bg-[#0f172a]/80 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-semibold mb-1">
                {selectedRule ? selectedRule.name : activeTab === 'rules' ? 'Automation Rules' : 'Policy Gates'}
              </h1>
              <p className="text-sm text-slate-500">
                {selectedRule ? selectedRule.description : activeTab === 'rules' ? 'Auto-triage and workflow automation' : 'Deployment and PR merge controls'}
              </p>
            </div>
            {selectedRule && (
              <div className="flex gap-2">
                <button
                  className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${
                    selectedRule.enabled
                      ? 'bg-green-500/20 border border-green-500/30 text-green-300 hover:bg-green-500/30'
                      : 'bg-slate-500/20 border border-slate-500/30 text-slate-300 hover:bg-slate-500/30'
                  }`}
                >
                  {selectedRule.enabled ? <Pause size={14} /> : <Play size={14} />}
                </button>
                <button className="px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all">
                  <Edit2 size={14} />
                </button>
                <button className="px-4 py-2 bg-white/5 border border-white/10 rounded-md text-red-400 text-sm font-medium hover:bg-red-500/10 transition-all">
                  <Trash2 size={14} />
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-auto p-6">
          {!selectedRule && !isCreating ? (
            /* Empty State */
            <div className="flex items-center justify-center h-full">
              <div className="text-center max-w-md">
                <Zap size={48} className="text-slate-600 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-white mb-2">No {activeTab === 'rules' ? 'Rule' : 'Gate'} Selected</h3>
                <p className="text-sm text-slate-400 mb-6">
                  Select a {activeTab === 'rules' ? 'rule' : 'gate'} from the sidebar or create a new one to get started.
                </p>
                <button
                  onClick={() => setIsCreating(true)}
                  className="px-4 py-2 bg-[#6B5AED] rounded-md text-white text-sm font-medium hover:bg-[#5B4ADD] transition-all"
                >
                  Create New {activeTab === 'rules' ? 'Rule' : 'Gate'}
                </button>
              </div>
            </div>
          ) : isCreating ? (
            /* Create Rule Form */
            <div className="max-w-3xl mx-auto">
              <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                <h3 className="text-lg font-semibold mb-6">Create New {activeTab === 'rules' ? 'Rule' : 'Gate'}</h3>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      Name
                    </label>
                    <input
                      type="text"
                      placeholder="e.g., Auto-Block KEV Vulnerabilities"
                      className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      Description
                    </label>
                    <textarea
                      placeholder="Describe what this rule does..."
                      rows={3}
                      className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                    />
                  </div>

                  {activeTab === 'rules' && (
                    <div>
                      <label className="block text-sm font-medium text-slate-300 mb-2">
                        Trigger
                      </label>
                      <select className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white focus:outline-none focus:border-[#6B5AED]/50">
                        <option>New finding detected</option>
                        <option>Finding updated</option>
                        <option>SSVC decision changed</option>
                      </select>
                    </div>
                  )}

                  <div className="border-t border-white/10 pt-4">
                    <h4 className="text-sm font-semibold text-slate-300 mb-4">Conditions</h4>
                    <div className="space-y-3">
                      <div className="grid grid-cols-3 gap-3">
                        <select className="px-3 py-2 bg-white/5 border border-white/10 rounded-md text-white text-sm focus:outline-none focus:border-[#6B5AED]/50">
                          <option>Severity</option>
                          <option>KEV</option>
                          <option>EPSS</option>
                          <option>Internet-Facing</option>
                          <option>Compliance Framework</option>
                        </select>
                        <select className="px-3 py-2 bg-white/5 border border-white/10 rounded-md text-white text-sm focus:outline-none focus:border-[#6B5AED]/50">
                          <option>equals</option>
                          <option>not equals</option>
                          <option>greater than</option>
                          <option>less than</option>
                          <option>in</option>
                        </select>
                        <input
                          type="text"
                          placeholder="Value"
                          className="px-3 py-2 bg-white/5 border border-white/10 rounded-md text-white text-sm placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                        />
                      </div>
                      <button className="text-sm text-[#6B5AED] hover:text-[#5B4ADD] transition-colors">
                        + Add Condition
                      </button>
                    </div>
                  </div>

                  <div className="border-t border-white/10 pt-4">
                    <h4 className="text-sm font-semibold text-slate-300 mb-4">Actions</h4>
                    <div className="space-y-3">
                      <div className="grid grid-cols-2 gap-3">
                        <select className="px-3 py-2 bg-white/5 border border-white/10 rounded-md text-white text-sm focus:outline-none focus:border-[#6B5AED]/50">
                          <option>Set Verdict</option>
                          <option>Set Priority</option>
                          <option>Create Ticket</option>
                          <option>Assign</option>
                          <option>Notify</option>
                          <option>Add Tag</option>
                          <option>Add Comment</option>
                        </select>
                        <input
                          type="text"
                          placeholder="Value"
                          className="px-3 py-2 bg-white/5 border border-white/10 rounded-md text-white text-sm placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                        />
                      </div>
                      <button className="text-sm text-[#6B5AED] hover:text-[#5B4ADD] transition-colors">
                        + Add Action
                      </button>
                    </div>
                  </div>

                  <div className="flex gap-3 pt-4">
                    <button
                      onClick={() => setIsCreating(false)}
                      className="flex-1 px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all"
                    >
                      Cancel
                    </button>
                    <button className="flex-1 px-4 py-2 bg-[#6B5AED] rounded-md text-white text-sm font-medium hover:bg-[#5B4ADD] transition-all">
                      Create {activeTab === 'rules' ? 'Rule' : 'Gate'}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ) : selectedRule ? (
            /* Rule Details */
            <div className="max-w-4xl mx-auto space-y-6">
              {/* Rule Info */}
              <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      {selectedRule.enabled ? (
                        <Zap size={18} className="text-green-500" />
                      ) : (
                        <Pause size={18} className="text-slate-500" />
                      )}
                      <h3 className="text-xl font-semibold">{selectedRule.name}</h3>
                    </div>
                    <p className="text-sm text-slate-400">{selectedRule.description}</p>
                  </div>
                  <div className="text-right">
                    <div className="text-3xl font-bold text-[#6B5AED] mb-1">{selectedRule.executions}</div>
                    <div className="text-xs text-slate-500">executions</div>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-4 mt-4 pt-4 border-t border-white/10">
                  <div>
                    <div className="text-xs text-slate-500 mb-1">Status</div>
                    <div className={`text-sm font-semibold ${selectedRule.enabled ? 'text-green-500' : 'text-slate-500'}`}>
                      {selectedRule.enabled ? 'Enabled' : 'Disabled'}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 mb-1">Last Executed</div>
                    <div className="text-sm text-slate-300">
                      {new Date(selectedRule.last_executed).toLocaleString()}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 mb-1">Created</div>
                    <div className="text-sm text-slate-300">
                      {new Date(selectedRule.created).toLocaleDateString()}
                    </div>
                  </div>
                </div>
              </div>

              {/* Trigger */}
              <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                <h4 className="text-sm font-semibold text-slate-300 mb-3">Trigger</h4>
                <div className="p-3 bg-white/5 rounded-md border border-white/10">
                  <span className="text-sm text-slate-300">{selectedRule.trigger}</span>
                </div>
              </div>

              {/* Conditions */}
              <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                <h4 className="text-sm font-semibold text-slate-300 mb-3">Conditions</h4>
                <div className="space-y-2">
                  {selectedRule.conditions.map((condition, idx) => (
                    <div key={idx} className="p-3 bg-white/5 rounded-md border border-white/10 flex items-center gap-3">
                      <span className="text-sm font-semibold text-white">{condition.field}</span>
                      <span className="text-xs text-slate-500">{condition.operator}</span>
                      <span className="text-sm text-[#6B5AED] font-mono">{condition.value}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Actions */}
              <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                <h4 className="text-sm font-semibold text-slate-300 mb-3">Actions</h4>
                <div className="space-y-2">
                  {selectedRule.actions.map((action, idx) => (
                    <div key={idx} className="p-3 bg-white/5 rounded-md border border-white/10 flex items-center gap-3">
                      <span className="text-sm font-semibold text-white">{action.type.replace(/_/g, ' ')}</span>
                      <span className="text-sm text-[#6B5AED] font-mono">{action.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  )
}
