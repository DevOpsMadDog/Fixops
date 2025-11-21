'use client'

import { useState } from 'react'
import { Plus, Check, X, ArrowLeft, ExternalLink, RefreshCw, Settings } from 'lucide-react'

const INTEGRATIONS = [
  {
    id: 'jira',
    name: 'Jira',
    description: 'Create and sync security issues as Jira tickets',
    category: 'Issue Tracking',
    status: 'connected',
    icon: '🎫',
    config: {
      url: 'https://company.atlassian.net',
      project: 'SEC',
      issue_type: 'Security Finding',
    },
    stats: {
      tickets_created: 156,
      last_sync: '2024-11-21T11:30:00Z',
    },
  },
  {
    id: 'github',
    name: 'GitHub',
    description: 'Scan repositories and create security advisories',
    category: 'Source Control',
    status: 'connected',
    icon: '🐙',
    config: {
      org: 'company-org',
      repos: 'payment-api, user-service, auth-service',
    },
    stats: {
      repos_scanned: 23,
      last_sync: '2024-11-21T10:15:00Z',
    },
  },
  {
    id: 'slack',
    name: 'Slack',
    description: 'Send notifications to Slack channels',
    category: 'Communication',
    status: 'connected',
    icon: '💬',
    config: {
      workspace: 'company-workspace',
      channels: '#security, #engineering',
    },
    stats: {
      notifications_sent: 487,
      last_notification: '2024-11-21T11:45:00Z',
    },
  },
  {
    id: 'pagerduty',
    name: 'PagerDuty',
    description: 'Create incidents for critical vulnerabilities',
    category: 'Incident Management',
    status: 'available',
    icon: '🚨',
    config: null,
    stats: null,
  },
  {
    id: 'servicenow',
    name: 'ServiceNow',
    description: 'Sync security findings to ServiceNow CMDB',
    category: 'ITSM',
    status: 'available',
    icon: '📋',
    config: null,
    stats: null,
  },
  {
    id: 'splunk',
    name: 'Splunk',
    description: 'Send security events to Splunk for SIEM',
    category: 'Security',
    status: 'available',
    icon: '🔍',
    config: null,
    stats: null,
  },
]

const WEBHOOKS = [
  {
    id: 'webhook1',
    name: 'Security Dashboard',
    url: 'https://dashboard.company.com/api/webhooks/fixops',
    events: ['finding.created', 'finding.updated', 'ssvc.decision'],
    enabled: true,
    last_triggered: '2024-11-21T11:30:00Z',
    success_rate: 99.8,
  },
  {
    id: 'webhook2',
    name: 'Compliance Portal',
    url: 'https://compliance.company.com/webhooks/security',
    events: ['compliance.gap', 'evidence.created'],
    enabled: true,
    last_triggered: '2024-11-21T09:15:00Z',
    success_rate: 100,
  },
]

export default function IntegrationsPage() {
  const [selectedIntegration, setSelectedIntegration] = useState<typeof INTEGRATIONS[0] | null>(null)
  const [activeTab, setActiveTab] = useState<'integrations' | 'webhooks'>('integrations')
  const [isConfiguring, setIsConfiguring] = useState(false)

  return (
    <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
      {/* Left Sidebar - Integrations List */}
      <div className="w-80 bg-[#0f172a]/80 border-r border-white/10 flex flex-col sticky top-0 h-screen">
        {/* Header */}
        <div className="p-6 border-b border-white/10">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-[#6B5AED]">Integrations</h2>
            <button
              onClick={() => window.location.href = '/triage'}
              className="p-2 rounded-md border border-white/10 text-slate-400 hover:bg-white/5 transition-all"
              title="Back to Triage"
            >
              <ArrowLeft size={16} />
            </button>
          </div>
          <p className="text-xs text-slate-500">Connect external tools</p>
        </div>

        {/* Tabs */}
        <div className="p-4 border-b border-white/10">
          <div className="flex gap-2">
            <button
              onClick={() => setActiveTab('integrations')}
              className={`flex-1 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                activeTab === 'integrations'
                  ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                  : 'text-slate-400 hover:bg-white/5'
              }`}
            >
              Apps
            </button>
            <button
              onClick={() => setActiveTab('webhooks')}
              className={`flex-1 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                activeTab === 'webhooks'
                  ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                  : 'text-slate-400 hover:bg-white/5'
              }`}
            >
              Webhooks
            </button>
          </div>
        </div>

        {/* List */}
        <div className="p-4 flex-1 overflow-auto">
          {activeTab === 'integrations' ? (
            <div className="space-y-4">
              {/* Connected */}
              <div>
                <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">
                  Connected ({INTEGRATIONS.filter(i => i.status === 'connected').length})
                </div>
                <div className="space-y-2">
                  {INTEGRATIONS.filter(i => i.status === 'connected').map((integration) => (
                    <button
                      key={integration.id}
                      onClick={() => setSelectedIntegration(integration)}
                      className={`w-full p-3 rounded-md text-left transition-all ${
                        selectedIntegration?.id === integration.id
                          ? 'bg-[#6B5AED]/10 border border-[#6B5AED]/30'
                          : 'bg-white/5 border border-white/10 hover:bg-white/10'
                      }`}
                    >
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <span className="text-xl">{integration.icon}</span>
                          <span className="text-sm font-semibold text-white">{integration.name}</span>
                        </div>
                        <Check size={14} className="text-green-500" />
                      </div>
                      <p className="text-xs text-slate-400">{integration.description}</p>
                    </button>
                  ))}
                </div>
              </div>

              {/* Available */}
              <div>
                <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">
                  Available ({INTEGRATIONS.filter(i => i.status === 'available').length})
                </div>
                <div className="space-y-2">
                  {INTEGRATIONS.filter(i => i.status === 'available').map((integration) => (
                    <button
                      key={integration.id}
                      onClick={() => setSelectedIntegration(integration)}
                      className="w-full p-3 rounded-md text-left bg-white/5 border border-white/10 hover:bg-white/10 transition-all"
                    >
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <span className="text-xl">{integration.icon}</span>
                          <span className="text-sm font-semibold text-white">{integration.name}</span>
                        </div>
                        <Plus size={14} className="text-slate-500" />
                      </div>
                      <p className="text-xs text-slate-400">{integration.description}</p>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="space-y-2">
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">
                Active Webhooks ({WEBHOOKS.length})
              </div>
              {WEBHOOKS.map((webhook) => (
                <div
                  key={webhook.id}
                  className="p-3 rounded-md bg-white/5 border border-white/10"
                >
                  <div className="flex items-start justify-between mb-2">
                    <span className="text-sm font-semibold text-white">{webhook.name}</span>
                    <Check size={14} className="text-green-500" />
                  </div>
                  <p className="text-xs text-slate-400 mb-2 font-mono truncate">{webhook.url}</p>
                  <div className="flex items-center gap-2 text-[10px] text-slate-500">
                    <span>{webhook.success_rate}% success</span>
                  </div>
                </div>
              ))}
              <button
                onClick={() => setIsConfiguring(true)}
                className="w-full px-4 py-2.5 bg-[#6B5AED] rounded-md text-white text-sm font-medium flex items-center justify-center gap-2 hover:bg-[#5B4ADD] transition-all mt-3"
              >
                <Plus size={16} />
                Add Webhook
              </button>
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
                {selectedIntegration ? selectedIntegration.name : activeTab === 'integrations' ? 'Integrations' : 'Webhooks'}
              </h1>
              <p className="text-sm text-slate-500">
                {selectedIntegration ? selectedIntegration.description : activeTab === 'integrations' ? 'Connect external tools and services' : 'Custom HTTP webhooks for events'}
              </p>
            </div>
            {selectedIntegration && (
              <div className="flex gap-2">
                {selectedIntegration.status === 'connected' ? (
                  <>
                    <button className="px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all flex items-center gap-2">
                      <RefreshCw size={14} />
                      Test Connection
                    </button>
                    <button
                      onClick={() => setIsConfiguring(true)}
                      className="px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all flex items-center gap-2"
                    >
                      <Settings size={14} />
                      Configure
                    </button>
                    <button className="px-4 py-2 bg-red-500/20 border border-red-500/30 rounded-md text-red-300 text-sm font-medium hover:bg-red-500/30 transition-all">
                      Disconnect
                    </button>
                  </>
                ) : (
                  <button
                    onClick={() => setIsConfiguring(true)}
                    className="px-4 py-2 bg-[#6B5AED] rounded-md text-white text-sm font-medium hover:bg-[#5B4ADD] transition-all"
                  >
                    Connect
                  </button>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-auto p-6">
          {!selectedIntegration && !isConfiguring ? (
            /* Empty State */
            <div className="flex items-center justify-center h-full">
              <div className="text-center max-w-md">
                <div className="text-6xl mb-4">🔌</div>
                <h3 className="text-lg font-semibold text-white mb-2">No Integration Selected</h3>
                <p className="text-sm text-slate-400 mb-6">
                  Select an integration from the sidebar to view details or configure a new connection.
                </p>
              </div>
            </div>
          ) : isConfiguring ? (
            /* Configuration Form */
            <div className="max-w-3xl mx-auto">
              <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                <h3 className="text-lg font-semibold mb-6">
                  {activeTab === 'integrations' ? `Configure ${selectedIntegration?.name || 'Integration'}` : 'Add Webhook'}
                </h3>
                <div className="space-y-4">
                  {activeTab === 'integrations' ? (
                    <>
                      {selectedIntegration?.id === 'jira' && (
                        <>
                          <div>
                            <label className="block text-sm font-medium text-slate-300 mb-2">
                              Jira URL
                            </label>
                            <input
                              type="text"
                              placeholder="https://company.atlassian.net"
                              defaultValue={selectedIntegration.config?.url}
                              className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-slate-300 mb-2">
                              API Token
                            </label>
                            <input
                              type="password"
                              placeholder="••••••••••••••••"
                              className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-slate-300 mb-2">
                              Project Key
                            </label>
                            <input
                              type="text"
                              placeholder="SEC"
                              defaultValue={selectedIntegration.config?.project}
                              className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-slate-300 mb-2">
                              Issue Type
                            </label>
                            <select
                              defaultValue={selectedIntegration.config?.issue_type}
                              className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white focus:outline-none focus:border-[#6B5AED]/50"
                            >
                              <option>Security Finding</option>
                              <option>Bug</option>
                              <option>Task</option>
                            </select>
                          </div>
                        </>
                      )}
                      {selectedIntegration?.id === 'github' && (
                        <>
                          <div>
                            <label className="block text-sm font-medium text-slate-300 mb-2">
                              GitHub Organization
                            </label>
                            <input
                              type="text"
                              placeholder="company-org"
                              defaultValue={selectedIntegration.config?.org}
                              className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-slate-300 mb-2">
                              Personal Access Token
                            </label>
                            <input
                              type="password"
                              placeholder="ghp_••••••••••••••••"
                              className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-slate-300 mb-2">
                              Repositories (comma-separated)
                            </label>
                            <input
                              type="text"
                              placeholder="payment-api, user-service"
                              defaultValue={selectedIntegration.config?.repos}
                              className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                            />
                          </div>
                        </>
                      )}
                      {selectedIntegration?.id === 'slack' && (
                        <>
                          <div>
                            <label className="block text-sm font-medium text-slate-300 mb-2">
                              Workspace
                            </label>
                            <input
                              type="text"
                              placeholder="company-workspace"
                              defaultValue={selectedIntegration.config?.workspace}
                              className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-slate-300 mb-2">
                              Webhook URL
                            </label>
                            <input
                              type="text"
                              placeholder="https://hooks.slack.com/services/..."
                              className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-slate-300 mb-2">
                              Channels (comma-separated)
                            </label>
                            <input
                              type="text"
                              placeholder="#security, #engineering"
                              defaultValue={selectedIntegration.config?.channels}
                              className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                            />
                          </div>
                        </>
                      )}
                    </>
                  ) : (
                    <>
                      <div>
                        <label className="block text-sm font-medium text-slate-300 mb-2">
                          Webhook Name
                        </label>
                        <input
                          type="text"
                          placeholder="e.g., Security Dashboard"
                          className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-slate-300 mb-2">
                          Webhook URL
                        </label>
                        <input
                          type="text"
                          placeholder="https://example.com/webhooks/fixops"
                          className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-slate-300 mb-2">
                          Events
                        </label>
                        <div className="space-y-2">
                          {['finding.created', 'finding.updated', 'ssvc.decision', 'compliance.gap', 'evidence.created'].map((event) => (
                            <label
                              key={event}
                              className="flex items-center gap-2 p-3 bg-white/5 border border-white/10 rounded-md cursor-pointer hover:bg-white/10 transition-all"
                            >
                              <input type="checkbox" className="cursor-pointer" />
                              <span className="text-sm text-slate-300 font-mono">{event}</span>
                            </label>
                          ))}
                        </div>
                      </div>
                    </>
                  )}

                  <div className="flex gap-3 pt-4">
                    <button
                      onClick={() => setIsConfiguring(false)}
                      className="flex-1 px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-300 text-sm font-medium hover:bg-white/10 transition-all"
                    >
                      Cancel
                    </button>
                    <button className="flex-1 px-4 py-2 bg-[#6B5AED] rounded-md text-white text-sm font-medium hover:bg-[#5B4ADD] transition-all">
                      {selectedIntegration?.status === 'connected' ? 'Save Changes' : 'Connect'}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ) : selectedIntegration ? (
            /* Integration Details */
            <div className="max-w-4xl mx-auto space-y-6">
              {/* Integration Info */}
              <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <span className="text-4xl">{selectedIntegration.icon}</span>
                    <div>
                      <h3 className="text-xl font-semibold mb-1">{selectedIntegration.name}</h3>
                      <p className="text-sm text-slate-400">{selectedIntegration.description}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {selectedIntegration.status === 'connected' ? (
                      <span className="px-3 py-1.5 bg-green-500/20 border border-green-500/30 rounded-md text-xs font-semibold text-green-300 flex items-center gap-2">
                        <Check size={12} />
                        Connected
                      </span>
                    ) : (
                      <span className="px-3 py-1.5 bg-slate-500/20 border border-slate-500/30 rounded-md text-xs font-semibold text-slate-300">
                        Not Connected
                      </span>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4 mt-4 pt-4 border-t border-white/10">
                  <div>
                    <div className="text-xs text-slate-500 mb-1">Category</div>
                    <div className="text-sm text-slate-300">{selectedIntegration.category}</div>
                  </div>
                  {selectedIntegration.stats?.last_sync && (
                    <div>
                      <div className="text-xs text-slate-500 mb-1">Last Sync</div>
                      <div className="text-sm text-slate-300">
                        {new Date(selectedIntegration.stats.last_sync).toLocaleString()}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Configuration */}
              {selectedIntegration.config && (
                <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                  <h4 className="text-sm font-semibold text-slate-300 mb-4">Configuration</h4>
                  <div className="space-y-3">
                    {Object.entries(selectedIntegration.config).map(([key, value]) => (
                      <div key={key} className="p-3 bg-white/5 rounded-md border border-white/10">
                        <div className="text-xs text-slate-500 mb-1">{key.replace(/_/g, ' ').toUpperCase()}</div>
                        <div className="text-sm text-slate-300 font-mono">{value}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Statistics */}
              {selectedIntegration.stats && (
                <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                  <h4 className="text-sm font-semibold text-slate-300 mb-4">Statistics</h4>
                  <div className="grid grid-cols-2 gap-4">
                    {Object.entries(selectedIntegration.stats)
                      .filter(([key]) => !key.includes('last'))
                      .map(([key, value]) => (
                        <div key={key} className="p-4 bg-white/5 rounded-md">
                          <div className="text-xs text-slate-500 mb-1">{key.replace(/_/g, ' ').toUpperCase()}</div>
                          <div className="text-2xl font-bold text-[#6B5AED]">{value}</div>
                        </div>
                      ))}
                  </div>
                </div>
              )}

              {/* Documentation */}
              <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                <h4 className="text-sm font-semibold text-slate-300 mb-4">Documentation</h4>
                <a
                  href="#"
                  className="flex items-center gap-2 p-3 bg-white/5 rounded-md border border-white/10 hover:bg-white/10 transition-all text-sm text-slate-300"
                >
                  <ExternalLink size={14} className="text-[#6B5AED]" />
                  View {selectedIntegration.name} Integration Guide
                </a>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  )
}
