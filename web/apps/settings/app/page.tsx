'use client'

import { useState } from 'react'
import { Settings as SettingsIcon, Key, Users, Bell, Shield, ArrowLeft, Copy, Eye, EyeOff, Plus, Trash2 } from 'lucide-react'
import EnterpriseShell from './components/EnterpriseShell'

const API_KEYS = [
  {
    id: 'key1',
    name: 'Production API Key',
    key: 'fixops_prod_a3f9c8d2e1b4567890abcdef',
    created: '2024-09-15',
    last_used: '2024-11-21',
    permissions: ['read', 'write'],
  },
  {
    id: 'key2',
    name: 'CI/CD Pipeline Key',
    key: 'fixops_cicd_b7d4e9f3a2c5678901bcdef2',
    created: '2024-10-01',
    last_used: '2024-11-20',
    permissions: ['read'],
  },
]

const TEAM_MEMBERS = [
  {
    id: 'user1',
    name: 'Alice Johnson',
    email: 'alice@company.com',
    role: 'Admin',
    joined: '2024-01-15',
  },
  {
    id: 'user2',
    name: 'Bob Smith',
    email: 'bob@company.com',
    role: 'Developer',
    joined: '2024-03-20',
  },
  {
    id: 'user3',
    name: 'Carol Williams',
    email: 'carol@company.com',
    role: 'Security Engineer',
    joined: '2024-05-10',
  },
]

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState('general')
  const [showApiKey, setShowApiKey] = useState<Record<string, boolean>>({})
  const [orgName, setOrgName] = useState('Aldeci Inc.')
  const [retentionMode, setRetentionMode] = useState('demo')
  const [notificationsEnabled, setNotificationsEnabled] = useState(true)

  const tabs = [
    { id: 'general', label: 'General', icon: SettingsIcon },
    { id: 'api-keys', label: 'API Keys', icon: Key },
    { id: 'team', label: 'Team', icon: Users },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'security', label: 'Security', icon: Shield },
  ]

  const toggleApiKeyVisibility = (keyId: string) => {
    setShowApiKey(prev => ({ ...prev, [keyId]: !prev[keyId] }))
  }

  const maskApiKey = (key: string) => {
    return key.slice(0, 12) + '•'.repeat(20)
  }

  return (
    <EnterpriseShell>
    <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
      {/* Left Sidebar - Tabs */}
      <div className="w-64 bg-[#0f172a]/80 border-r border-white/10 flex flex-col sticky top-0 h-screen">
        {/* Header */}
        <div className="p-6 border-b border-white/10">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-[#6B5AED]">Settings</h2>
            <button
              onClick={() => window.location.href = '/triage'}
              className="p-2 rounded-md border border-white/10 text-slate-400 hover:bg-white/5 transition-all"
              title="Back to Triage"
            >
              <ArrowLeft size={16} />
            </button>
          </div>
          <p className="text-xs text-slate-500">Organization configuration</p>
        </div>

        {/* Tabs */}
        <div className="p-3 flex-1">
          <div className="space-y-1">
            {tabs.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setActiveTab(id)}
                className={`w-full p-3 rounded-md text-sm font-medium cursor-pointer flex items-center gap-3 transition-all ${
                  activeTab === id
                    ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                    : 'text-slate-400 hover:bg-white/5'
                }`}
              >
                <Icon size={18} />
                {label}
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
              <h1 className="text-2xl font-semibold mb-1">
                {tabs.find(t => t.id === activeTab)?.label}
              </h1>
              <p className="text-sm text-slate-500">
                Manage your organization settings and preferences
              </p>
            </div>
          </div>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-auto p-6">
          <div className="max-w-4xl">
            {/* General Tab */}
            {activeTab === 'general' && (
              <div className="space-y-6">
                <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                  <h3 className="text-lg font-semibold mb-4">Organization Details</h3>
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-slate-300 mb-2">
                        Organization Name
                      </label>
                      <input
                        type="text"
                        value={orgName}
                        onChange={(e) => setOrgName(e.target.value)}
                        className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-300 mb-2">
                        Evidence Retention Mode
                      </label>
                      <select
                        value={retentionMode}
                        onChange={(e) => setRetentionMode(e.target.value)}
                        className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white focus:outline-none focus:border-[#6B5AED]/50"
                      >
                        <option value="demo">Demo (90 days)</option>
                        <option value="enterprise">Enterprise (2555 days / 7 years)</option>
                      </select>
                      <p className="text-xs text-slate-500 mt-2">
                        {retentionMode === 'demo' 
                          ? 'Evidence bundles retained for 90 days for testing and evaluation'
                          : 'Evidence bundles retained for 7 years for compliance (SOC2, ISO27001, PCI-DSS)'}
                      </p>
                    </div>
                  </div>
                </div>

                <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                  <h3 className="text-lg font-semibold mb-4">Branding</h3>
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-slate-300 mb-2">
                        Product Name
                      </label>
                      <input
                        type="text"
                        value="Aldeci"
                        disabled
                        className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-slate-400"
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-slate-300 mb-2">
                          Primary Color
                        </label>
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-md bg-[#6B5AED] border border-white/10"></div>
                          <span className="text-sm font-mono text-slate-400">#6B5AED</span>
                        </div>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-slate-300 mb-2">
                          Secondary Color
                        </label>
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-md bg-[#0F172A] border border-white/10"></div>
                          <span className="text-sm font-mono text-slate-400">#0F172A</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* API Keys Tab */}
            {activeTab === 'api-keys' && (
              <div className="space-y-6">
                <div className="flex items-center justify-between mb-4">
                  <p className="text-sm text-slate-400">
                    API keys allow external systems to authenticate with FixOps
                  </p>
                  <button className="px-4 py-2 bg-[#6B5AED] rounded-md text-white text-sm font-medium flex items-center gap-2 hover:bg-[#5B4ADD] transition-all">
                    <Plus size={16} />
                    Create API Key
                  </button>
                </div>

                <div className="space-y-3">
                  {API_KEYS.map((apiKey) => (
                    <div
                      key={apiKey.id}
                      className="p-5 bg-white/2 rounded-lg border border-white/5"
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div>
                          <h4 className="text-base font-semibold text-white mb-1">
                            {apiKey.name}
                          </h4>
                          <div className="flex items-center gap-2 text-xs text-slate-400">
                            <span>Created {new Date(apiKey.created).toLocaleDateString()}</span>
                            <span>•</span>
                            <span>Last used {new Date(apiKey.last_used).toLocaleDateString()}</span>
                          </div>
                        </div>
                        <button className="text-red-400 hover:text-red-300 transition-colors">
                          <Trash2 size={16} />
                        </button>
                      </div>

                      <div className="p-3 bg-black/20 rounded-md border border-white/10 mb-3">
                        <div className="flex items-center justify-between">
                          <code className="text-sm font-mono text-slate-300">
                            {showApiKey[apiKey.id] ? apiKey.key : maskApiKey(apiKey.key)}
                          </code>
                          <div className="flex gap-2">
                            <button
                              onClick={() => toggleApiKeyVisibility(apiKey.id)}
                              className="text-slate-400 hover:text-white transition-colors"
                            >
                              {showApiKey[apiKey.id] ? <EyeOff size={16} /> : <Eye size={16} />}
                            </button>
                            <button
                              onClick={() => navigator.clipboard.writeText(apiKey.key)}
                              className="text-slate-400 hover:text-white transition-colors"
                            >
                              <Copy size={16} />
                            </button>
                          </div>
                        </div>
                      </div>

                      <div className="flex gap-2">
                        {apiKey.permissions.map((perm) => (
                          <span
                            key={perm}
                            className="px-2 py-1 bg-[#6B5AED]/10 border border-[#6B5AED]/30 rounded text-xs font-medium text-[#6B5AED]"
                          >
                            {perm}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Team Tab */}
            {activeTab === 'team' && (
              <div className="space-y-6">
                <div className="flex items-center justify-between mb-4">
                  <p className="text-sm text-slate-400">
                    Manage team members and their access levels
                  </p>
                  <button className="px-4 py-2 bg-[#6B5AED] rounded-md text-white text-sm font-medium flex items-center gap-2 hover:bg-[#5B4ADD] transition-all">
                    <Plus size={16} />
                    Invite Member
                  </button>
                </div>

                <div className="bg-white/2 rounded-lg border border-white/5 overflow-hidden">
                  {/* Table Header */}
                  <div className="grid grid-cols-[1fr_200px_150px_100px] gap-4 p-4 bg-black/20 border-b border-white/5 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    <div>Member</div>
                    <div>Email</div>
                    <div>Role</div>
                    <div>Actions</div>
                  </div>

                  {/* Table Body */}
                  {TEAM_MEMBERS.map((member) => (
                    <div
                      key={member.id}
                      className="grid grid-cols-[1fr_200px_150px_100px] gap-4 p-4 border-b border-white/5 last:border-0"
                    >
                      <div>
                        <div className="text-sm font-medium text-white">{member.name}</div>
                        <div className="text-xs text-slate-500">
                          Joined {new Date(member.joined).toLocaleDateString()}
                        </div>
                      </div>
                      <div className="text-sm text-slate-400 font-mono">{member.email}</div>
                      <div>
                        <span
                          className={`px-2 py-1 rounded text-xs font-medium ${
                            member.role === 'Admin'
                              ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                              : 'bg-white/5 text-slate-300 border border-white/10'
                          }`}
                        >
                          {member.role}
                        </span>
                      </div>
                      <div>
                        <button className="text-slate-400 hover:text-white transition-colors">
                          <SettingsIcon size={16} />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Notifications Tab */}
            {activeTab === 'notifications' && (
              <div className="space-y-6">
                <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                  <h3 className="text-lg font-semibold mb-4">Email Notifications</h3>
                  <div className="space-y-4">
                    <label className="flex items-center justify-between p-3 bg-white/5 rounded-md cursor-pointer hover:bg-white/10 transition-all">
                      <div>
                        <div className="text-sm font-medium text-white">Enable Notifications</div>
                        <div className="text-xs text-slate-400">
                          Receive email alerts for critical security findings
                        </div>
                      </div>
                      <input
                        type="checkbox"
                        checked={notificationsEnabled}
                        onChange={(e) => setNotificationsEnabled(e.target.checked)}
                        className="cursor-pointer"
                      />
                    </label>

                    {notificationsEnabled && (
                      <>
                        <label className="flex items-center justify-between p-3 bg-white/5 rounded-md cursor-pointer hover:bg-white/10 transition-all">
                          <div>
                            <div className="text-sm font-medium text-white">Critical Vulnerabilities</div>
                            <div className="text-xs text-slate-400">
                              Notify when critical CVEs are detected
                            </div>
                          </div>
                          <input type="checkbox" defaultChecked className="cursor-pointer" />
                        </label>

                        <label className="flex items-center justify-between p-3 bg-white/5 rounded-md cursor-pointer hover:bg-white/10 transition-all">
                          <div>
                            <div className="text-sm font-medium text-white">KEV Alerts</div>
                            <div className="text-xs text-slate-400">
                              Notify when Known Exploited Vulnerabilities are found
                            </div>
                          </div>
                          <input type="checkbox" defaultChecked className="cursor-pointer" />
                        </label>

                        <label className="flex items-center justify-between p-3 bg-white/5 rounded-md cursor-pointer hover:bg-white/10 transition-all">
                          <div>
                            <div className="text-sm font-medium text-white">Compliance Gaps</div>
                            <div className="text-xs text-slate-400">
                              Notify when new compliance control gaps are identified
                            </div>
                          </div>
                          <input type="checkbox" defaultChecked className="cursor-pointer" />
                        </label>

                        <label className="flex items-center justify-between p-3 bg-white/5 rounded-md cursor-pointer hover:bg-white/10 transition-all">
                          <div>
                            <div className="text-sm font-medium text-white">Weekly Summary</div>
                            <div className="text-xs text-slate-400">
                              Receive a weekly digest of security findings
                            </div>
                          </div>
                          <input type="checkbox" className="cursor-pointer" />
                        </label>
                      </>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Security Tab */}
            {activeTab === 'security' && (
              <div className="space-y-6">
                <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                  <h3 className="text-lg font-semibold mb-4">Authentication</h3>
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-slate-300 mb-2">
                        Authentication Provider
                      </label>
                      <select
                        className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-md text-white focus:outline-none focus:border-[#6B5AED]/50"
                        defaultValue="credentials"
                      >
                        <option value="credentials">Credentials (Username/Password)</option>
                        <option value="oauth">OAuth 2.0</option>
                        <option value="saml">SAML SSO</option>
                      </select>
                    </div>

                    <label className="flex items-center justify-between p-3 bg-white/5 rounded-md cursor-pointer hover:bg-white/10 transition-all">
                      <div>
                        <div className="text-sm font-medium text-white">Require 2FA</div>
                        <div className="text-xs text-slate-400">
                          Enforce two-factor authentication for all users
                        </div>
                      </div>
                      <input type="checkbox" className="cursor-pointer" />
                    </label>
                  </div>
                </div>

                <div className="p-6 bg-white/2 rounded-lg border border-white/5">
                  <h3 className="text-lg font-semibold mb-4">Evidence Signing</h3>
                  <div className="space-y-4">
                    <div className="p-4 bg-[#6B5AED]/10 border border-[#6B5AED]/20 rounded-md">
                      <div className="flex items-center gap-2 mb-2">
                        <Shield size={16} className="text-[#6B5AED]" />
                        <span className="text-sm font-semibold text-[#6B5AED]">
                          RSA-SHA256 Signing Enabled
                        </span>
                      </div>
                      <p className="text-xs text-slate-300">
                        All evidence bundles are cryptographically signed with RSA-SHA256 for tamper detection and audit compliance.
                      </p>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-slate-300 mb-2">
                        Public Key ID
                      </label>
                      <div className="p-3 bg-black/20 rounded-md border border-white/10">
                        <code className="text-sm font-mono text-slate-300">fixops-prod-2024</code>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
    </EnterpriseShell>
  )
}
