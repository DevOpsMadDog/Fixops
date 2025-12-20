'use client'

import { useState, useEffect, useCallback } from 'react'
import { 
  Search, 
  Filter, 
  Star, 
  Download, 
  ShoppingCart, 
  Package, 
  Shield, 
  FileText, 
  Zap, 
  Target,
  ChevronRight,
  X,
  CheckCircle,
  AlertTriangle,
  Clock,
  Users,
  TrendingUp,
  Award,
  RefreshCw,
  ToggleLeft,
  ToggleRight
} from 'lucide-react'
import EnterpriseShell from './components/EnterpriseShell'
import { useMarketplaceBrowse, useMarketplaceStats, useSystemMode } from '@fixops/api-client'

type ContentType = 'policy_template' | 'compliance_testset' | 'mitigation_playbook' | 'attack_scenario' | 'pipeline_gate'
type PricingModel = 'free' | 'one_time' | 'subscription'
type QAStatus = 'passed' | 'warning' | 'failed'

interface MarketplaceItem {
  id: string
  name: string
  description: string
  content_type: ContentType
  compliance_frameworks: string[]
  ssdlc_stages: string[]
  pricing_model: PricingModel
  price: number
  tags: string[]
  rating: number
  rating_count: number
  downloads: number
  version: string
  qa_status: QAStatus
  author: string
  organization: string
  created_at: string
}

interface Contributor {
  author: string
  organization: string
  submissions: number
  reputation_score: number
  average_rating: number
}

const DEMO_ITEMS: MarketplaceItem[] = [
  {
    id: '1',
    name: 'PCI DSS Payment Gateway Policy Pack',
    description: 'Prebuilt OPA/Rego policies for gating PCI workloads. Includes validation rules for payment data handling, encryption requirements, and access control policies.',
    content_type: 'policy_template',
    compliance_frameworks: ['pci_dss'],
    ssdlc_stages: ['build', 'deploy'],
    pricing_model: 'free',
    price: 0,
    tags: ['pci', 'payments', 'rego', 'opa'],
    rating: 4.8,
    rating_count: 87,
    downloads: 312,
    version: '1.0.0',
    qa_status: 'passed',
    author: 'FixOps Team',
    organization: 'FixOps',
    created_at: '2024-06-15',
  },
  {
    id: '2',
    name: 'NIST SSDF Test Set (SAST Baseline)',
    description: 'Curated test set to validate SAST configuration against NIST SSDF controls. Covers secure coding practices and vulnerability detection.',
    content_type: 'compliance_testset',
    compliance_frameworks: ['nist_ssdf', 'soc2'],
    ssdlc_stages: ['code', 'build'],
    pricing_model: 'free',
    price: 0,
    tags: ['sast', 'baseline', 'nist'],
    rating: 4.5,
    rating_count: 54,
    downloads: 198,
    version: '2.1.0',
    qa_status: 'passed',
    author: 'Security Team',
    organization: 'FixOps',
    created_at: '2024-07-20',
  },
  {
    id: '3',
    name: 'ATT&CK Ransomware Attack Scenario',
    description: 'Scenario files and checks mapping to common ransomware TTPs. Use for red team exercises and security validation.',
    content_type: 'attack_scenario',
    compliance_frameworks: ['mitre_attack'],
    ssdlc_stages: ['test', 'operate'],
    pricing_model: 'one_time',
    price: 99,
    tags: ['ransomware', 'ttp', 'mitre', 'red-team'],
    rating: 4.4,
    rating_count: 23,
    downloads: 77,
    version: '1.2.0',
    qa_status: 'warning',
    author: 'Threat Intel',
    organization: 'FixOps',
    created_at: '2024-08-10',
  },
  {
    id: '4',
    name: 'SOC 2 Compliance Playbook',
    description: 'Complete mitigation playbook for SOC 2 Type II compliance. Includes remediation steps, evidence collection templates, and audit preparation guides.',
    content_type: 'mitigation_playbook',
    compliance_frameworks: ['soc2'],
    ssdlc_stages: ['operate', 'deploy'],
    pricing_model: 'free',
    price: 0,
    tags: ['soc2', 'compliance', 'audit'],
    rating: 4.9,
    rating_count: 112,
    downloads: 456,
    version: '3.0.0',
    qa_status: 'passed',
    author: 'Compliance Team',
    organization: 'FixOps',
    created_at: '2024-05-01',
  },
  {
    id: '5',
    name: 'ISO 27001 Pipeline Gate',
    description: 'Automated pipeline gate for ISO 27001 compliance verification. Blocks deployments that don\'t meet security requirements.',
    content_type: 'pipeline_gate',
    compliance_frameworks: ['iso27001'],
    ssdlc_stages: ['build', 'deploy'],
    pricing_model: 'subscription',
    price: 49,
    tags: ['iso27001', 'cicd', 'gate'],
    rating: 4.7,
    rating_count: 45,
    downloads: 189,
    version: '2.0.0',
    qa_status: 'passed',
    author: 'DevSecOps',
    organization: 'FixOps',
    created_at: '2024-09-05',
  },
  {
    id: '6',
    name: 'GDPR Data Protection Test Suite',
    description: 'Comprehensive test suite for GDPR compliance validation. Covers data handling, consent management, and privacy controls.',
    content_type: 'compliance_testset',
    compliance_frameworks: ['gdpr'],
    ssdlc_stages: ['test', 'operate'],
    pricing_model: 'free',
    price: 0,
    tags: ['gdpr', 'privacy', 'data-protection'],
    rating: 4.6,
    rating_count: 67,
    downloads: 234,
    version: '1.5.0',
    qa_status: 'passed',
    author: 'Privacy Team',
    organization: 'FixOps',
    created_at: '2024-04-12',
  },
]

const DEMO_CONTRIBUTORS: Contributor[] = [
  { author: 'FixOps Team', organization: 'FixOps', submissions: 12, reputation_score: 450, average_rating: 4.8 },
  { author: 'Security Team', organization: 'FixOps', submissions: 8, reputation_score: 320, average_rating: 4.6 },
  { author: 'Compliance Team', organization: 'FixOps', submissions: 6, reputation_score: 280, average_rating: 4.9 },
  { author: 'DevSecOps', organization: 'FixOps', submissions: 5, reputation_score: 210, average_rating: 4.7 },
  { author: 'Threat Intel', organization: 'FixOps', submissions: 4, reputation_score: 180, average_rating: 4.4 },
]

const CONTENT_TYPE_LABELS: Record<ContentType, string> = {
  policy_template: 'Policy Template',
  compliance_testset: 'Compliance Test Set',
  mitigation_playbook: 'Mitigation Playbook',
  attack_scenario: 'Attack Scenario',
  pipeline_gate: 'Pipeline Gate',
}

const CONTENT_TYPE_ICONS: Record<ContentType, typeof Shield> = {
  policy_template: Shield,
  compliance_testset: FileText,
  mitigation_playbook: Zap,
  attack_scenario: Target,
  pipeline_gate: Package,
}

export default function MarketplacePage() {
  // API hooks
  const { data: apiItems, loading: apiLoading, error: apiError, refetch } = useMarketplaceBrowse()
  const { data: apiStats, loading: statsLoading } = useMarketplaceStats()
  const { mode, toggleMode, loading: modeLoading } = useSystemMode()

  const [searchQuery, setSearchQuery] = useState('')
  const [selectedContentType, setSelectedContentType] = useState<ContentType | ''>('')
  const [selectedFramework, setSelectedFramework] = useState('')
  const [selectedPricing, setSelectedPricing] = useState<PricingModel | ''>('')
  const [selectedItem, setSelectedItem] = useState<MarketplaceItem | null>(null)
  const [activeTab, setActiveTab] = useState<'browse' | 'contributors' | 'stats'>('browse')

  // Transform API data to match UI format
  const transformItem = useCallback((item: Record<string, unknown>): MarketplaceItem => ({
    id: String(item.id || ''),
    name: String(item.name || ''),
    description: String(item.description || ''),
    content_type: (item.content_type as ContentType) || 'policy_template',
    compliance_frameworks: Array.isArray(item.compliance_frameworks) ? item.compliance_frameworks.map(String) : [],
    ssdlc_stages: Array.isArray(item.ssdlc_stages) ? item.ssdlc_stages.map(String) : [],
    pricing_model: (item.pricing_model as PricingModel) || 'free',
    price: typeof item.price === 'number' ? item.price : 0,
    tags: Array.isArray(item.tags) ? item.tags.map(String) : [],
    rating: typeof item.rating === 'number' ? item.rating : 0,
    rating_count: typeof item.rating_count === 'number' ? item.rating_count : 0,
    downloads: typeof item.downloads === 'number' ? item.downloads : 0,
    version: String(item.version || '1.0.0'),
    qa_status: (item.qa_status as QAStatus) || 'passed',
    author: String(item.author || 'Unknown'),
    organization: String(item.organization || 'Unknown'),
    created_at: String(item.created_at || new Date().toISOString()),
  }), [])

  // Use API data if available, otherwise use fallback
  const items = apiItems?.items?.map(transformItem) || DEMO_ITEMS

  const filteredItems = items.filter((item: MarketplaceItem) => {
    if (searchQuery && !item.name.toLowerCase().includes(searchQuery.toLowerCase()) && 
        !item.description.toLowerCase().includes(searchQuery.toLowerCase()) &&
        !item.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()))) {
      return false
    }
    if (selectedContentType && item.content_type !== selectedContentType) return false
    if (selectedFramework && !item.compliance_frameworks.includes(selectedFramework)) return false
    if (selectedPricing && item.pricing_model !== selectedPricing) return false
    return true
  })

  const getQAStatusColor = (status: QAStatus) => {
    const colors = {
      passed: '#10b981',
      warning: '#f59e0b',
      failed: '#dc2626',
    }
    return colors[status]
  }

  const getQAStatusIcon = (status: QAStatus) => {
    if (status === 'passed') return CheckCircle
    if (status === 'warning') return AlertTriangle
    return X
  }

  const getPricingLabel = (item: MarketplaceItem) => {
    if (item.pricing_model === 'free') return 'Free'
    if (item.pricing_model === 'one_time') return `$${item.price}`
    return `$${item.price}/mo`
  }

  // Handle download - generates a demo pack file for the item
  const handleDownload = useCallback((item: MarketplaceItem) => {
    // Generate demo pack content based on item type
    const packContent = {
      metadata: {
        name: item.name,
        version: item.version,
        description: item.description,
        author: item.author,
        organization: item.organization,
        content_type: item.content_type,
        compliance_frameworks: item.compliance_frameworks,
        ssdlc_stages: item.ssdlc_stages,
        tags: item.tags,
        created_at: item.created_at,
        downloaded_at: new Date().toISOString(),
      },
      content: {
        // Demo content based on type
        ...(item.content_type === 'policy_template' && {
          policies: [
            { id: 'policy-001', name: 'Data Encryption Policy', rego: 'package example\ndefault allow = false\nallow { input.encrypted == true }' },
            { id: 'policy-002', name: 'Access Control Policy', rego: 'package example\ndefault allow = false\nallow { input.role == "admin" }' },
          ]
        }),
        ...(item.content_type === 'compliance_testset' && {
          tests: [
            { id: 'test-001', name: 'Encryption Validation', description: 'Validates data encryption requirements', expected: 'pass' },
            { id: 'test-002', name: 'Access Control Check', description: 'Validates access control policies', expected: 'pass' },
          ]
        }),
        ...(item.content_type === 'mitigation_playbook' && {
          steps: [
            { id: 'step-001', name: 'Identify Gap', description: 'Identify compliance gap from findings' },
            { id: 'step-002', name: 'Remediate', description: 'Apply remediation steps' },
            { id: 'step-003', name: 'Validate', description: 'Validate remediation was successful' },
          ]
        }),
        ...(item.content_type === 'attack_scenario' && {
          scenarios: [
            { id: 'scenario-001', name: 'Initial Access', mitre_id: 'T1190', description: 'Exploit public-facing application' },
            { id: 'scenario-002', name: 'Privilege Escalation', mitre_id: 'T1068', description: 'Exploit vulnerability for privilege escalation' },
          ]
        }),
        ...(item.content_type === 'pipeline_gate' && {
          gates: [
            { id: 'gate-001', name: 'Security Scan Gate', condition: 'no_critical_vulnerabilities', action: 'block' },
            { id: 'gate-002', name: 'Compliance Gate', condition: 'compliance_score >= 80', action: 'warn' },
          ]
        }),
      }
    }

    // Create and download the file
    const blob = new Blob([JSON.stringify(packContent, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${item.name.toLowerCase().replace(/\s+/g, '-')}-v${item.version}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }, [])

  const stats = {
    total_items: items.length,
    total_downloads: items.reduce((sum, item) => sum + item.downloads, 0),
    average_rating: items.length > 0 ? (items.reduce((sum, item) => sum + item.rating, 0) / items.length).toFixed(1) : '0.0',
    content_types: Object.entries(
      items.reduce((acc, item) => {
        acc[item.content_type] = (acc[item.content_type] || 0) + 1
        return acc
      }, {} as Record<string, number>)
    ),
    frameworks: Object.entries(
      items.reduce((acc, item) => {
        item.compliance_frameworks.forEach(f => {
          acc[f] = (acc[f] || 0) + 1
        })
        return acc
      }, {} as Record<string, number>)
    ),
  }

  return (
    <EnterpriseShell>
      <div className="min-h-screen bg-[#0f172a] font-sans text-white">
        <div className="p-6">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h1 className="text-2xl font-semibold mb-1">Marketplace</h1>
              <p className="text-sm text-slate-400">
                Browse, contribute, and purchase compliance packs, policy templates, and security content
              </p>
            </div>
            <div className="flex items-center gap-4">
              {/* Mode Toggle */}
              <div className="flex items-center gap-2 px-3 py-2 bg-white/5 rounded-md">
                <span className="text-xs text-slate-400">Mode:</span>
                <button
                  onClick={toggleMode}
                  disabled={modeLoading}
                  className="flex items-center gap-2 text-xs font-medium"
                >
                  {mode === 'demo' ? (
                    <>
                      <ToggleLeft size={18} className="text-orange-400" />
                      <span className="text-orange-400">Demo</span>
                    </>
                  ) : (
                    <>
                      <ToggleRight size={18} className="text-green-400" />
                      <span className="text-green-400">Enterprise</span>
                    </>
                  )}
                </button>
              </div>
              <button
                onClick={() => refetch()}
                disabled={apiLoading}
                className="p-2 hover:bg-white/10 rounded-md transition-colors"
                title="Refresh data"
              >
                <RefreshCw size={16} className={apiLoading ? 'animate-spin' : ''} />
              </button>
              <button className="px-4 py-2 bg-[#6B5AED] text-white rounded-md text-sm font-medium hover:bg-[#5B4ADD] transition-all flex items-center gap-2">
                <Package size={16} />
                Contribute Content
              </button>
            </div>
          </div>
          {apiError && (
            <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 rounded-md text-sm text-red-400">
              API unavailable - showing demo data
            </div>
          )}

          <div className="flex gap-2 mb-6 border-b border-white/10">
            <button
              onClick={() => setActiveTab('browse')}
              className={`px-4 py-3 text-sm font-medium transition-all border-b-2 ${
                activeTab === 'browse'
                  ? 'text-[#6B5AED] border-[#6B5AED]'
                  : 'text-slate-400 border-transparent hover:text-white'
              }`}
            >
              Browse
            </button>
            <button
              onClick={() => setActiveTab('contributors')}
              className={`px-4 py-3 text-sm font-medium transition-all border-b-2 ${
                activeTab === 'contributors'
                  ? 'text-[#6B5AED] border-[#6B5AED]'
                  : 'text-slate-400 border-transparent hover:text-white'
              }`}
            >
              Contributors
            </button>
            <button
              onClick={() => setActiveTab('stats')}
              className={`px-4 py-3 text-sm font-medium transition-all border-b-2 ${
                activeTab === 'stats'
                  ? 'text-[#6B5AED] border-[#6B5AED]'
                  : 'text-slate-400 border-transparent hover:text-white'
              }`}
            >
              Statistics
            </button>
          </div>

          {activeTab === 'browse' && (
            <>
              <div className="flex gap-4 mb-6">
                <div className="flex-1 relative">
                  <Search size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                  <input
                    type="text"
                    placeholder="Search marketplace..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full pl-10 pr-4 py-2.5 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-400 focus:outline-none focus:border-[#6B5AED]/50"
                  />
                </div>
                <select
                  value={selectedContentType}
                  onChange={(e) => setSelectedContentType(e.target.value as ContentType | '')}
                  className="px-4 py-2.5 bg-white/5 border border-white/10 rounded-md text-sm text-white focus:outline-none focus:border-[#6B5AED]/50"
                >
                  <option value="">All Types</option>
                  <option value="policy_template">Policy Template</option>
                  <option value="compliance_testset">Compliance Test Set</option>
                  <option value="mitigation_playbook">Mitigation Playbook</option>
                  <option value="attack_scenario">Attack Scenario</option>
                  <option value="pipeline_gate">Pipeline Gate</option>
                </select>
                <select
                  value={selectedFramework}
                  onChange={(e) => setSelectedFramework(e.target.value)}
                  className="px-4 py-2.5 bg-white/5 border border-white/10 rounded-md text-sm text-white focus:outline-none focus:border-[#6B5AED]/50"
                >
                  <option value="">All Frameworks</option>
                  <option value="soc2">SOC 2</option>
                  <option value="iso27001">ISO 27001</option>
                  <option value="pci_dss">PCI DSS</option>
                  <option value="gdpr">GDPR</option>
                  <option value="nist_ssdf">NIST SSDF</option>
                  <option value="mitre_attack">MITRE ATT&CK</option>
                </select>
                <select
                  value={selectedPricing}
                  onChange={(e) => setSelectedPricing(e.target.value as PricingModel | '')}
                  className="px-4 py-2.5 bg-white/5 border border-white/10 rounded-md text-sm text-white focus:outline-none focus:border-[#6B5AED]/50"
                >
                  <option value="">All Pricing</option>
                  <option value="free">Free</option>
                  <option value="one_time">One-time</option>
                  <option value="subscription">Subscription</option>
                </select>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredItems.map((item) => {
                  const ContentIcon = CONTENT_TYPE_ICONS[item.content_type]
                  const QAIcon = getQAStatusIcon(item.qa_status)
                  return (
                    <div
                      key={item.id}
                      onClick={() => setSelectedItem(item)}
                      className="p-5 bg-white/2 rounded-lg border border-white/5 cursor-pointer hover:bg-white/5 hover:border-white/10 transition-all"
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-md bg-[#6B5AED]/20 flex items-center justify-center">
                            <ContentIcon size={20} className="text-[#6B5AED]" />
                          </div>
                          <div>
                            <h3 className="text-sm font-semibold text-white line-clamp-1">{item.name}</h3>
                            <p className="text-xs text-slate-400">{CONTENT_TYPE_LABELS[item.content_type]}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-1">
                          <QAIcon size={14} style={{ color: getQAStatusColor(item.qa_status) }} />
                        </div>
                      </div>

                      <p className="text-xs text-slate-400 mb-3 line-clamp-2">{item.description}</p>

                      <div className="flex flex-wrap gap-1.5 mb-3">
                        {item.compliance_frameworks.slice(0, 2).map((framework) => (
                          <span
                            key={framework}
                            className="px-2 py-0.5 bg-[#6B5AED]/10 text-[#6B5AED] rounded text-[10px] font-medium uppercase"
                          >
                            {framework.replaceAll('_', ' ')}
                          </span>
                        ))}
                        {item.compliance_frameworks.length > 2 && (
                          <span className="px-2 py-0.5 bg-white/5 text-slate-400 rounded text-[10px]">
                            +{item.compliance_frameworks.length - 2}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center justify-between pt-3 border-t border-white/5">
                        <div className="flex items-center gap-3 text-xs text-slate-400">
                          <div className="flex items-center gap-1">
                            <Star size={12} className="text-yellow-500 fill-yellow-500" />
                            <span>{item.rating}</span>
                            <span className="text-slate-500">({item.rating_count})</span>
                          </div>
                          <div className="flex items-center gap-1">
                            <Download size={12} />
                            <span>{item.downloads}</span>
                          </div>
                        </div>
                        <span
                          className={`text-xs font-semibold ${
                            item.pricing_model === 'free' ? 'text-green-500' : 'text-[#6B5AED]'
                          }`}
                        >
                          {getPricingLabel(item)}
                        </span>
                      </div>
                    </div>
                  )
                })}
              </div>

              {filteredItems.length === 0 && (
                <div className="text-center py-12">
                  <Package size={48} className="mx-auto text-slate-500 mb-4" />
                  <h3 className="text-lg font-semibold text-slate-300 mb-2">No items found</h3>
                  <p className="text-sm text-slate-400">Try adjusting your filters or search query</p>
                </div>
              )}
            </>
          )}

          {activeTab === 'contributors' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {DEMO_CONTRIBUTORS.map((contributor, index) => (
                  <div
                    key={contributor.author}
                    className="p-5 bg-white/2 rounded-lg border border-white/5"
                  >
                    <div className="flex items-start gap-4">
                      <div className="relative">
                        <div className="w-12 h-12 rounded-full bg-[#6B5AED]/20 flex items-center justify-center">
                          <Users size={24} className="text-[#6B5AED]" />
                        </div>
                        {index < 3 && (
                          <div className="absolute -top-1 -right-1 w-5 h-5 rounded-full bg-yellow-500 flex items-center justify-center">
                            <Award size={12} className="text-black" />
                          </div>
                        )}
                      </div>
                      <div className="flex-1">
                        <h3 className="text-sm font-semibold text-white">{contributor.author}</h3>
                        <p className="text-xs text-slate-400">{contributor.organization}</p>
                      </div>
                    </div>

                    <div className="grid grid-cols-3 gap-3 mt-4 pt-4 border-t border-white/5">
                      <div className="text-center">
                        <div className="text-lg font-semibold text-[#6B5AED]">{contributor.submissions}</div>
                        <div className="text-[10px] text-slate-500 uppercase">Submissions</div>
                      </div>
                      <div className="text-center">
                        <div className="text-lg font-semibold text-green-500">{contributor.reputation_score}</div>
                        <div className="text-[10px] text-slate-500 uppercase">Reputation</div>
                      </div>
                      <div className="text-center">
                        <div className="flex items-center justify-center gap-1">
                          <Star size={12} className="text-yellow-500 fill-yellow-500" />
                          <span className="text-lg font-semibold text-white">{contributor.average_rating}</span>
                        </div>
                        <div className="text-[10px] text-slate-500 uppercase">Avg Rating</div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'stats' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="p-5 bg-white/2 rounded-lg border border-white/5">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="w-10 h-10 rounded-md bg-[#6B5AED]/20 flex items-center justify-center">
                      <Package size={20} className="text-[#6B5AED]" />
                    </div>
                    <div>
                      <div className="text-2xl font-semibold text-white">{stats.total_items}</div>
                      <div className="text-xs text-slate-400">Total Items</div>
                    </div>
                  </div>
                </div>
                <div className="p-5 bg-white/2 rounded-lg border border-white/5">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="w-10 h-10 rounded-md bg-green-500/20 flex items-center justify-center">
                      <Download size={20} className="text-green-500" />
                    </div>
                    <div>
                      <div className="text-2xl font-semibold text-white">{stats.total_downloads}</div>
                      <div className="text-xs text-slate-400">Total Downloads</div>
                    </div>
                  </div>
                </div>
                <div className="p-5 bg-white/2 rounded-lg border border-white/5">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="w-10 h-10 rounded-md bg-yellow-500/20 flex items-center justify-center">
                      <Star size={20} className="text-yellow-500" />
                    </div>
                    <div>
                      <div className="text-2xl font-semibold text-white">{stats.average_rating}</div>
                      <div className="text-xs text-slate-400">Average Rating</div>
                    </div>
                  </div>
                </div>
                <div className="p-5 bg-white/2 rounded-lg border border-white/5">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="w-10 h-10 rounded-md bg-blue-500/20 flex items-center justify-center">
                      <Users size={20} className="text-blue-500" />
                    </div>
                    <div>
                      <div className="text-2xl font-semibold text-white">{DEMO_CONTRIBUTORS.length}</div>
                      <div className="text-xs text-slate-400">Contributors</div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="p-5 bg-white/2 rounded-lg border border-white/5">
                  <h3 className="text-sm font-semibold text-white mb-4">Content by Type</h3>
                  <div className="space-y-3">
                    {stats.content_types.map(([type, count]) => (
                      <div key={type} className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <div className="w-2 h-2 rounded-full bg-[#6B5AED]"></div>
                          <span className="text-sm text-slate-300">{CONTENT_TYPE_LABELS[type as ContentType]}</span>
                        </div>
                        <span className="text-sm font-semibold text-white">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="p-5 bg-white/2 rounded-lg border border-white/5">
                  <h3 className="text-sm font-semibold text-white mb-4">Content by Framework</h3>
                  <div className="space-y-3">
                    {stats.frameworks.map(([framework, count]) => (
                      <div key={framework} className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <div className="w-2 h-2 rounded-full bg-green-500"></div>
                          <span className="text-sm text-slate-300">{framework.replace('_', ' ').toUpperCase()}</span>
                        </div>
                        <span className="text-sm font-semibold text-white">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {selectedItem && (
          <div
            onClick={() => setSelectedItem(null)}
            className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex justify-end"
          >
            <div
              onClick={(e) => e.stopPropagation()}
              className="w-[600px] h-full bg-[#1e293b] border-l border-white/10 flex flex-col overflow-auto"
            >
              <div className="p-6 border-b border-white/10">
                <div className="flex justify-between items-start mb-4">
                  <div className="flex items-center gap-3">
                    <div className="w-12 h-12 rounded-md bg-[#6B5AED]/20 flex items-center justify-center">
                      {(() => {
                        const ContentIcon = CONTENT_TYPE_ICONS[selectedItem.content_type]
                        return <ContentIcon size={24} className="text-[#6B5AED]" />
                      })()}
                    </div>
                    <div>
                      <h2 className="text-lg font-semibold text-white">{selectedItem.name}</h2>
                      <p className="text-sm text-slate-400">{CONTENT_TYPE_LABELS[selectedItem.content_type]}</p>
                    </div>
                  </div>
                  <button
                    onClick={() => setSelectedItem(null)}
                    className="p-2 hover:bg-white/5 rounded-md transition-colors"
                  >
                    <X size={20} className="text-slate-400" />
                  </button>
                </div>

                <div className="flex items-center gap-4 text-sm">
                  <div className="flex items-center gap-1">
                    <Star size={14} className="text-yellow-500 fill-yellow-500" />
                    <span className="text-white font-medium">{selectedItem.rating}</span>
                    <span className="text-slate-400">({selectedItem.rating_count} reviews)</span>
                  </div>
                  <div className="flex items-center gap-1 text-slate-400">
                    <Download size={14} />
                    <span>{selectedItem.downloads} downloads</span>
                  </div>
                  <div className="flex items-center gap-1">
                    {(() => {
                      const QAIcon = getQAStatusIcon(selectedItem.qa_status)
                      return (
                        <>
                          <QAIcon size={14} style={{ color: getQAStatusColor(selectedItem.qa_status) }} />
                          <span style={{ color: getQAStatusColor(selectedItem.qa_status) }} className="capitalize">
                            {selectedItem.qa_status}
                          </span>
                        </>
                      )
                    })()}
                  </div>
                </div>
              </div>

              <div className="p-6 flex-1">
                <div className="mb-6">
                  <h3 className="text-sm font-semibold text-white mb-2">Description</h3>
                  <p className="text-sm text-slate-400">{selectedItem.description}</p>
                </div>

                <div className="mb-6">
                  <h3 className="text-sm font-semibold text-white mb-2">Compliance Frameworks</h3>
                  <div className="flex flex-wrap gap-2">
                    {selectedItem.compliance_frameworks.map((framework) => (
                      <span
                        key={framework}
                        className="px-3 py-1 bg-[#6B5AED]/10 text-[#6B5AED] rounded text-xs font-medium uppercase"
                      >
                        {framework.replaceAll('_', ' ')}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="mb-6">
                  <h3 className="text-sm font-semibold text-white mb-2">SSDLC Stages</h3>
                  <div className="flex flex-wrap gap-2">
                    {selectedItem.ssdlc_stages.map((stage) => (
                      <span
                        key={stage}
                        className="px-3 py-1 bg-white/5 text-slate-300 rounded text-xs font-medium capitalize"
                      >
                        {stage}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="mb-6">
                  <h3 className="text-sm font-semibold text-white mb-2">Tags</h3>
                  <div className="flex flex-wrap gap-2">
                    {selectedItem.tags.map((tag) => (
                      <span
                        key={tag}
                        className="px-3 py-1 bg-white/5 text-slate-400 rounded text-xs"
                      >
                        #{tag}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4 mb-6">
                  <div className="p-4 bg-white/5 rounded-md">
                    <div className="text-xs text-slate-500 mb-1">Version</div>
                    <div className="text-sm font-semibold text-white">{selectedItem.version}</div>
                  </div>
                  <div className="p-4 bg-white/5 rounded-md">
                    <div className="text-xs text-slate-500 mb-1">Author</div>
                    <div className="text-sm font-semibold text-white">{selectedItem.author}</div>
                  </div>
                  <div className="p-4 bg-white/5 rounded-md">
                    <div className="text-xs text-slate-500 mb-1">Organization</div>
                    <div className="text-sm font-semibold text-white">{selectedItem.organization}</div>
                  </div>
                  <div className="p-4 bg-white/5 rounded-md">
                    <div className="text-xs text-slate-500 mb-1">Published</div>
                    <div className="text-sm font-semibold text-white">
                      {new Date(selectedItem.created_at).toLocaleDateString()}
                    </div>
                  </div>
                </div>
              </div>

              <div className="p-6 border-t border-white/10">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <div className="text-2xl font-bold text-white">
                      {selectedItem.pricing_model === 'free' ? 'Free' : `$${selectedItem.price}`}
                    </div>
                    {selectedItem.pricing_model === 'subscription' && (
                      <div className="text-xs text-slate-400">per month</div>
                    )}
                  </div>
                  <button 
                    onClick={() => selectedItem.pricing_model === 'free' ? handleDownload(selectedItem) : alert('Purchase functionality coming soon!')}
                    className="px-6 py-3 bg-[#6B5AED] text-white rounded-md text-sm font-medium hover:bg-[#5B4ADD] transition-all flex items-center gap-2"
                  >
                    {selectedItem.pricing_model === 'free' ? (
                      <>
                        <Download size={16} />
                        Download
                      </>
                    ) : (
                      <>
                        <ShoppingCart size={16} />
                        Purchase
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </EnterpriseShell>
  )
}
