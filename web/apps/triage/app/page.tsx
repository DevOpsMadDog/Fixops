'use client'

import { useState, useEffect } from 'react'
import { AlertCircle, Shield, Code, Cloud, CheckCircle, XCircle, Copy, Ticket, Search, Users, Archive, Eye, EyeOff, BarChart3, Keyboard, Settings, Pin, PinOff, Edit2, Tag, Calendar } from 'lucide-react'
import EnterpriseShell from './components/EnterpriseShell'

const DEMO_ISSUES = [
  {
    id: '1',
    title: 'Apache Struts Remote Code Execution (CVE-2023-50164)',
    assignee: 'security-team',
    tags: ['critical', 'rce'],
    sla_date: '2024-12-01',
    severity: 'critical',
    source: 'CVE',
    repo: 'payment-api',
    location: 'pom.xml:45',
    exploitability: { kev: true, epss: 0.89 },
    internet_facing: true,
    age_days: 3,
    business_criticality: 'mission_critical',
    description: 'Critical RCE vulnerability in Apache Struts allowing remote attackers to execute arbitrary code.',
    remediation: 'Upgrade Apache Struts to version 2.5.33 or later. Apply security patches immediately.'
  },
  {
    id: '2',
    title: 'SQL Injection in User Authentication',
    assignee: 'dev-team',
    tags: ['sql-injection', 'auth'],
    sla_date: '2024-12-05',
    severity: 'high',
    source: 'SAST',
    repo: 'user-service',
    location: 'src/auth/login.ts:127',
    exploitability: { kev: false, epss: 0.45 },
    business_criticality: 'high',
    internet_facing: true,
    age_days: 12,
    description: 'SQL injection vulnerability in user authentication endpoint allowing unauthorized access.',
    remediation: 'Use parameterized queries or prepared statements. Implement input validation and sanitization.'
  },
  {
    id: '3',
    title: 'Exposed AWS Credentials in Configuration',
    assignee: 'infra-team',
    tags: ['secrets', 'aws'],
    sla_date: '2024-11-30',
    severity: 'critical',
    source: 'IaC',
    repo: 'infrastructure',
    location: 'terraform/main.tf:89',
    exploitability: { kev: false, epss: 0.12 },
    business_criticality: 'mission_critical',
    internet_facing: false,
    age_days: 1,
    description: 'AWS access keys hardcoded in Terraform configuration files.',
    remediation: 'Remove hardcoded credentials. Use AWS Secrets Manager or environment variables.'
  },
  {
    id: '4',
    title: 'Outdated OpenSSL Library (CVE-2023-4807)',
    assignee: 'security-team',
    tags: ['openssl', 'cve'],
    sla_date: '2024-12-10',
    severity: 'high',
    source: 'CVE',
    repo: 'api-gateway',
    location: 'Dockerfile:12',
    exploitability: { kev: true, epss: 0.72 },
    business_criticality: 'high',
    internet_facing: true,
    age_days: 8,
    description: 'Vulnerable OpenSSL version with known exploits in the wild.',
    remediation: 'Update OpenSSL to version 3.0.11 or later. Rebuild and redeploy containers.'
  },
  {
    id: '5',
    title: 'Cross-Site Scripting (XSS) in Dashboard',
    assignee: 'dev-team',
    tags: ['xss', 'frontend'],
    sla_date: '2024-12-15',
    severity: 'medium',
    source: 'SAST',
    repo: 'web-dashboard',
    location: 'src/components/UserProfile.tsx:45',
    exploitability: { kev: false, epss: 0.23 },
    business_criticality: 'medium',
    internet_facing: true,
    age_days: 15,
    description: 'Reflected XSS vulnerability in user profile component.',
    remediation: 'Implement proper output encoding. Use Content Security Policy headers.'
  },
  {
    assignee: 'infra-team',
    tags: ['docker', 'config'],
    sla_date: '2024-12-20',
    id: '6',
    title: 'Insecure S3 Bucket Configuration',
    severity: 'high',
    source: 'IaC',
    repo: 'infrastructure',
    location: 'terraform/s3.tf:23',
    exploitability: { kev: false, epss: 0.08 },
    business_criticality: 'high',
    internet_facing: true,
    age_days: 5,
    description: 'S3 bucket configured with public read access exposing sensitive data.',
    remediation: 'Remove public access. Implement bucket policies with least privilege.'
  },
  {
    id: '7',
    assignee: 'security-team',
    tags: ['jwt', 'auth'],
    sla_date: '2024-12-03',
    title: 'Weak Cryptographic Algorithm (MD5)',
    severity: 'medium',
    source: 'SAST',
    repo: 'auth-service',
    location: 'src/crypto/hash.ts:34',
    exploitability: { kev: false, epss: 0.15 },
    business_criticality: 'medium',
    internet_facing: false,
    age_days: 22,
    description: 'MD5 hash algorithm used for password hashing, vulnerable to collision attacks.',
    remediation: 'Replace MD5 with bcrypt, Argon2, or PBKDF2 for password hashing.'
  },
  {
    id: '8',
    title: 'Kubernetes RBAC Misconfiguration',
    assignee: 'dev-team',
    tags: ['api', 'rate-limit'],
    sla_date: '2024-12-25',
    severity: 'high',
    source: 'IaC',
    repo: 'k8s-manifests',
    location: 'rbac/service-account.yaml:15',
    exploitability: { kev: false, epss: 0.19 },
    business_criticality: 'high',
    internet_facing: false,
    age_days: 4,
    description: 'Service account with cluster-admin privileges violating least privilege principle.',
    remediation: 'Restrict RBAC permissions to minimum required. Use namespace-scoped roles.'
  },
  {
    id: '9',
    title: 'Log4j Remote Code Execution (CVE-2021-44228)',
    severity: 'critical',
    assignee: 'infra-team',
    tags: ['s3', 'permissions'],
    sla_date: '2024-11-28',
    source: 'CVE',
    repo: 'logging-service',
    location: 'pom.xml:67',
    exploitability: { kev: true, epss: 0.95 },
    business_criticality: 'mission_critical',
    internet_facing: true,
    age_days: 2,
    description: 'Critical Log4Shell vulnerability allowing remote code execution.',
    remediation: 'Upgrade Log4j to version 2.17.1 or later immediately. Apply emergency patches.'
  },
  {
    id: '10',
    title: 'Missing Rate Limiting on API Endpoints',
    severity: 'medium',
    source: 'SAST',
    assignee: 'security-team',
    tags: ['csrf', 'web'],
    sla_date: '2024-12-08',
    repo: 'api-gateway',
    location: 'src/middleware/auth.ts:89',
    exploitability: { kev: false, epss: 0.31 },
    business_criticality: 'medium',
    internet_facing: true,
    age_days: 18,
    description: 'API endpoints lack rate limiting, vulnerable to brute force and DoS attacks.',
    remediation: 'Implement rate limiting middleware. Use Redis or similar for distributed rate limiting.'
  },
  {
    id: '11',
    title: 'Insecure Direct Object Reference (IDOR)',
    severity: 'high',
    source: 'SAST',
    repo: 'user-service',
    assignee: 'dev-team',
    tags: ['logging', 'pii'],
    sla_date: '2024-12-12',
    location: 'src/api/users.ts:156',
    exploitability: { kev: false, epss: 0.42 },
    business_criticality: 'high',
    internet_facing: true,
    age_days: 9,
    description: 'User ID parameter not validated, allowing unauthorized access to other users data.',
    remediation: 'Implement proper authorization checks. Validate user ownership before data access.'
  },
  {
    id: '12',
    title: 'Unencrypted Database Connection',
    severity: 'medium',
    source: 'IaC',
    repo: 'infrastructure',
    location: 'terraform/rds.tf:45',
    assignee: 'infra-team',
    tags: ['tls', 'encryption'],
    sla_date: '2024-12-18',
    exploitability: { kev: false, epss: 0.11 },
    business_criticality: 'medium',
    internet_facing: false,
    age_days: 14,
    description: 'RDS database connection not enforcing SSL/TLS encryption.',
    remediation: 'Enable SSL/TLS for database connections. Update connection strings to require encryption.'
  }
]

export default function TriagePage() {
  const [issues, setIssues] = useState(DEMO_ISSUES)
  const [filteredIssues, setFilteredIssues] = useState(DEMO_ISSUES)
  const [selectedIssue, setSelectedIssue] = useState<typeof DEMO_ISSUES[0] | null>(null)
  const [selectedIssues, setSelectedIssues] = useState<Set<string>>(new Set())
  const [focusedIndex, setFocusedIndex] = useState(0)
  const [feedView, setFeedView] = useState('all')
  const [filters, setFilters] = useState({
    new_7d: false,
    high_critical: false,
    exploitable: false,
    internet_facing: false,
  })
  const [searchQuery, setSearchQuery] = useState('')
  const [viewMode, setViewMode] = useState('all')
  const [showKeyboardHelp, setShowKeyboardHelp] = useState(false)
  const [showColumnChooser, setShowColumnChooser] = useState(false)
  const [visibleColumns, setVisibleColumns] = useState({
    severity: true,
    title: true,
    source: true,
    repo: true,
    location: true,
    exploitability: true,
    age: true,
  })
  const [pinnedColumns, setPinnedColumns] = useState<Set<string>>(new Set(['severity', 'title']))
  const [editingCell, setEditingCell] = useState<{ issueId: string; field: string } | null>(null)
  const [editValue, setEditValue] = useState('')
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; issue: typeof DEMO_ISSUES[0] } | null>(null)

  const summary = {
    total: issues.length,
    new_7d: issues.filter(i => i.age_days <= 7).length,
    high_critical: issues.filter(i => i.severity === 'high' || i.severity === 'critical').length,
    exploitable: issues.filter(i => i.exploitability.kev || i.exploitability.epss >= 0.7).length,
    internet_facing: issues.filter(i => i.internet_facing).length,
    snoozed: 0,
    ignored: 0,
    solved: 0,
  }

  useEffect(() => {
    applyFilters()
  }, [filters, issues, feedView, searchQuery, viewMode])

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
        return
      }

      switch (e.key) {
        case 'j': // Move down
        case 'ArrowDown':
          e.preventDefault()
          setFocusedIndex(prev => Math.min(prev + 1, filteredIssues.length - 1))
          break
        
        case 'k': // Move up
        case 'ArrowUp':
          e.preventDefault()
          setFocusedIndex(prev => Math.max(prev - 1, 0))
          break
        
        case ' ': // Toggle selection
          e.preventDefault()
          if (filteredIssues[focusedIndex]) {
            toggleIssueSelection(filteredIssues[focusedIndex].id)
          }
          break
        
        case 'Enter': // Open drawer
          e.preventDefault()
          if (filteredIssues[focusedIndex]) {
            setSelectedIssue(filteredIssues[focusedIndex])
          }
          break
        
        case 'Escape':
          e.preventDefault()
          if (showKeyboardHelp) {
            setShowKeyboardHelp(false)
          } else {
            setSelectedIssue(null)
          }
          break
        
        case '?':
          e.preventDefault()
          setShowKeyboardHelp(true)
          break
        
        case 'a':
          if (e.ctrlKey || e.metaKey) {
            e.preventDefault()
            toggleSelectAll()
          }
          break
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [focusedIndex, filteredIssues, selectedIssue, showKeyboardHelp])

  useEffect(() => {
    setFocusedIndex(0)
  }, [filteredIssues])

  const applyFilters = () => {
    let filtered = [...issues]

    if (viewMode === 'refined') {
      filtered = filtered.filter(issue => {
        if (issue.severity === 'low' && !issue.exploitability.kev && issue.exploitability.epss < 0.3) {
          return false
        }
        return true
      })
    }

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(issue =>
        issue.title?.toLowerCase().includes(query) ||
        issue.repo?.toLowerCase().includes(query) ||
        issue.location?.toLowerCase().includes(query)
      )
    }

    if (filters.new_7d) {
      filtered = filtered.filter(issue => issue.age_days <= 7)
    }

    if (filters.high_critical) {
      filtered = filtered.filter(issue => 
        issue.severity === 'high' || issue.severity === 'critical'
      )
    }

    if (filters.exploitable) {
      filtered = filtered.filter(issue => 
        issue.exploitability.kev || issue.exploitability.epss >= 0.7
      )
    }

    if (filters.internet_facing) {
      filtered = filtered.filter(issue => issue.internet_facing)
    }

    setFilteredIssues(filtered)
  }

  const toggleFilter = (filterKey: keyof typeof filters) => {
    setFilters(prev => ({
      ...prev,
      [filterKey]: !prev[filterKey],
    }))
  }

  const toggleIssueSelection = (issueId: string) => {
    setSelectedIssues(prev => {
      const newSet = new Set(prev)
      if (newSet.has(issueId)) {
        newSet.delete(issueId)
      } else {
        newSet.add(issueId)
      }
      return newSet
    })
  }

  const toggleSelectAll = () => {
    if (selectedIssues.size === filteredIssues.length) {
      setSelectedIssues(new Set())
    } else {
      setSelectedIssues(new Set(filteredIssues.map(i => i.id)))
    }
  }

  const toggleColumnVisibility = (column: string) => {
    setVisibleColumns(prev => ({
      ...prev,
      [column]: !prev[column as keyof typeof prev]
    }))
  }

  const toggleColumnPin = (column: string) => {
    setPinnedColumns(prev => {
      const newPinned = new Set(prev)
      if (newPinned.has(column)) {
        newPinned.delete(column)
      } else {
        newPinned.add(column)
      }
      return newPinned
    })
  }

  const columnDefinitions = [
    { id: 'severity', label: 'Severity', width: '80px' },
    { id: 'title', label: 'Issue', width: '1fr' },
    { id: 'source', label: 'Source', width: '100px' },
    { id: 'repo', label: 'Repository', width: '180px' },
    { id: 'location', label: 'Location', width: '180px' },
    { id: 'exploitability', label: 'Exploitability', width: '120px' },
    { id: 'age', label: 'Age', width: '80px' },
  ]

  const visibleColumnDefs = columnDefinitions.filter(col => visibleColumns[col.id as keyof typeof visibleColumns])
  const gridTemplateColumns = `40px ${visibleColumnDefs.map(col => col.width).join(' ')}`

  const startEditing = (issueId: string, field: string, currentValue: string) => {
    setEditingCell({ issueId, field })
    setEditValue(currentValue)
  }

  const saveEdit = (issueId: string, field: string) => {
    setIssues(prev => prev.map(issue => {
      if (issue.id === issueId) {
        if (field === 'tags') {
          return { ...issue, tags: editValue.split(',').map(t => t.trim()).filter(t => t) }
        }
        return { ...issue, [field]: editValue }
      }
      return issue
    }))
    setEditingCell(null)
    setEditValue('')
  }

  const cancelEdit = () => {
    setEditingCell(null)
    setEditValue('')
  }

  const handleContextMenu = (e: React.MouseEvent, issue: typeof DEMO_ISSUES[0]) => {
    e.preventDefault()
    setContextMenu({ x: e.clientX, y: e.clientY, issue })
  }

  const closeContextMenu = () => {
    setContextMenu(null)
  }

  const handleContextAction = (action: string, issue: typeof DEMO_ISSUES[0]) => {
    switch (action) {
      case 'assign':
        startEditing(issue.id, 'assignee', issue.assignee)
        break
      case 'create-ticket':
        alert(`Creating ticket for: ${issue.title}`)
        break
      case 'accept-risk':
        alert(`Accepting risk for: ${issue.title}`)
        break
      case 'snooze':
        alert(`Snoozing: ${issue.title}`)
        break
      case 'ignore':
        alert(`Ignoring: ${issue.title}`)
        break
      case 'copy-link':
        navigator.clipboard.writeText(`${window.location.origin}/findings/${issue.id}`)
        alert('Link copied to clipboard!')
        break
    }
    closeContextMenu()
  }

  useEffect(() => {
    const handleClick = () => closeContextMenu()
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeContextMenu()
    }
    document.addEventListener('click', handleClick)
    document.addEventListener('keydown', handleEscape)
    return () => {
      document.removeEventListener('click', handleClick)
      document.removeEventListener('keydown', handleEscape)
    }
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

  const getSourceIcon = (source: string) => {
    const icons = {
      CVE: Shield,
      SAST: Code,
      IaC: Cloud,
    }
    const Icon = icons[source as keyof typeof icons] || AlertCircle
    return <Icon size={14} />
  }

  const calculateRiskScore = (issue: typeof DEMO_ISSUES[0]) => {
    let score = 0
    const breakdown = {
      severity: 0,
      kev: 0,
      epss: 0,
      exposure: 0,
      criticality: 0,
    }

    const severityPoints = {
      critical: 40,
      high: 30,
      medium: 20,
      low: 10,
    }
    breakdown.severity = severityPoints[issue.severity as keyof typeof severityPoints] || 0
    score += breakdown.severity

    if (issue.exploitability.kev) {
      breakdown.kev = 30
      score += 30
    }

    breakdown.epss = Math.round(issue.exploitability.epss * 20)
    score += breakdown.epss

    if (issue.internet_facing) {
      breakdown.exposure = 10
      score += 10
    }

    const criticalityPoints = {
      mission_critical: 10,
      high: 5,
      medium: 0,
      low: 0,
    }
    breakdown.criticality = criticalityPoints[issue.business_criticality as keyof typeof criticalityPoints] || 0
    score += breakdown.criticality

    return { score: Math.min(score, 100), breakdown }
  }

  return (
    <EnterpriseShell>
    <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
      {/* Left Sidebar - Feed Navigation */}
      <div className="w-60 bg-[#0f172a]/80 border-r border-white/10 flex flex-col sticky top-0 h-screen">
        {/* Logo/Title */}
        <div className="p-6 border-b border-white/10">
          <h2 className="text-lg font-semibold text-[#6B5AED]">FixOps</h2>
          <p className="text-xs text-slate-500 mt-1">Security Triage</p>
        </div>

        {/* Feed Navigation */}
        <div className="p-3 flex-1">
          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 px-2">
            Feed
          </div>
          
          {[
            { id: 'all', label: 'All Issues', icon: AlertCircle, count: summary.total },
            { id: 'snoozed', label: 'Snoozed', icon: EyeOff, count: summary.snoozed },
            { id: 'ignored', label: 'Ignored', icon: Archive, count: summary.ignored },
            { id: 'solved', label: 'Solved', icon: CheckCircle, count: summary.solved },
          ].map(({ id, label, icon: Icon, count }) => (
            <button
              key={id}
              onClick={() => setFeedView(id)}
              className={`w-full p-2.5 rounded-md mb-1 text-sm font-medium cursor-pointer flex items-center justify-between transition-all ${
                feedView === id
                  ? 'bg-[#6B5AED]/10 text-[#6B5AED]'
                  : 'text-slate-400 hover:bg-white/5'
              }`}
            >
              <span className="flex items-center gap-2">
                <Icon size={16} />
                {label}
              </span>
              <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
                feedView === id
                  ? 'bg-[#6B5AED]/20'
                  : 'bg-slate-800'
              }`}>
                {count}
              </span>
            </button>
          ))}
        </div>

        {/* Bottom Actions */}
        <div className="p-3 border-t border-white/10 space-y-2">
          <button
            onClick={() => window.location.href = '/risk'}
            className="w-full p-2.5 rounded-md border border-white/10 text-slate-400 text-sm font-medium cursor-pointer flex items-center gap-2 justify-center hover:bg-white/5 transition-all"
          >
            <BarChart3 size={16} />
            Risk Graph
          </button>
          <button
            onClick={() => setShowColumnChooser(!showColumnChooser)}
            className="w-full p-2.5 rounded-md border border-white/10 text-slate-400 text-sm font-medium cursor-pointer flex items-center gap-2 justify-center hover:bg-white/5 transition-all"
          >
            <Settings size={16} />
            Columns
          </button>
          <button
            onClick={() => setShowKeyboardHelp(!showKeyboardHelp)}
            className="w-full p-2.5 rounded-md border border-white/10 text-slate-400 text-sm font-medium cursor-pointer flex items-center gap-2 justify-center hover:bg-white/5 transition-all"
          >
            <Keyboard size={16} />
            Shortcuts
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col">
        {/* Top Bar */}
        <div className="border-b border-white/10 bg-[#0f172a]/80 backdrop-blur-sm sticky top-0 z-10">
          <div className="p-5">
            {/* Summary Bar */}
            <div className="flex items-center justify-between mb-5">
              <div className="flex items-center gap-4">
                <div>
                  <span className="text-3xl font-semibold">{filteredIssues.length}</span>
                  <span className="text-sm text-slate-500 ml-2">Open Issues</span>
                </div>
                <div className="h-8 w-px bg-white/10"></div>
                <div className="flex gap-4 text-sm">
                  <div>
                    <span className="text-red-500 font-semibold">{summary.high_critical}</span>
                    <span className="text-slate-500 ml-1">High/Critical</span>
                  </div>
                  <div>
                    <span className="text-amber-500 font-semibold">{summary.exploitable}</span>
                    <span className="text-slate-500 ml-1">Exploitable</span>
                  </div>
                  <div>
                    <span className="text-[#6B5AED] font-semibold">{summary.new_7d}</span>
                    <span className="text-slate-500 ml-1">New (7d)</span>
                  </div>
                </div>
              </div>

              {/* View Mode Selector */}
              <div className="flex gap-2 bg-white/5 p-1 rounded-md">
                <button
                  onClick={() => setViewMode('all')}
                  className={`px-3 py-1.5 rounded text-sm font-medium transition-all ${
                    viewMode === 'all' ? 'bg-[#6B5AED] text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  All Findings
                </button>
                <button
                  onClick={() => setViewMode('refined')}
                  className={`px-3 py-1.5 rounded text-sm font-medium transition-all ${
                    viewMode === 'refined' ? 'bg-[#6B5AED] text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  FixOps Refined
                </button>
              </div>
            </div>

            {/* Search and Filters */}
            <div className="flex gap-3 items-center flex-wrap">
              {/* Search */}
              <div className="relative flex-[0_0_300px]">
                <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  placeholder="Search issues..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full py-2 pl-10 pr-3 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
                />
              </div>

              {/* Filter Chips */}
              {[
                { key: 'new_7d', label: 'New (7d)', count: summary.new_7d, color: '#6B5AED' },
                { key: 'high_critical', label: 'High/Critical', count: summary.high_critical, color: '#f97316' },
                { key: 'exploitable', label: 'Exploitable', count: summary.exploitable, color: '#dc2626' },
                { key: 'internet_facing', label: 'Internet-facing', count: summary.internet_facing, color: '#6B5AED' },
              ].map(({ key, label, count, color }) => (
                <button
                  key={key}
                  onClick={() => toggleFilter(key as keyof typeof filters)}
                  className={`py-2 px-3 rounded-md text-sm font-medium transition-all flex items-center gap-2 ${
                    filters[key as keyof typeof filters]
                      ? `text-white`
                      : 'bg-white/5 border border-white/10 text-white hover:bg-white/10'
                  }`}
                  style={filters[key as keyof typeof filters] ? { backgroundColor: color } : {}}
                >
                  {label}
                  <span className={`px-1.5 py-0.5 rounded text-xs font-semibold ${
                    filters[key as keyof typeof filters]
                      ? 'bg-white/20'
                      : 'bg-[#6B5AED]/20 text-[#6B5AED]'
                  }`}>
                    {count}
                  </span>
                </button>
              ))}

              {Object.values(filters).some(v => v) && (
                <button
                  onClick={() => setFilters({ new_7d: false, high_critical: false, exploitable: false, internet_facing: false })}
                  className="py-2 px-3 rounded-md border border-white/10 text-slate-400 text-sm font-medium hover:bg-white/5 transition-all"
                >
                  Clear filters
                </button>
              )}
            </div>

            {/* Bulk Actions Bar */}
            {selectedIssues.size > 0 && (
              <div className="mt-4 p-3 bg-[#6B5AED]/10 border border-[#6B5AED]/30 rounded-md flex items-center justify-between">
                <div className="text-sm text-slate-300">
                  <span className="font-semibold text-[#6B5AED]">{selectedIssues.size}</span> issue{selectedIssues.size > 1 ? 's' : ''} selected
                </div>
                <div className="flex gap-2">
                  <button className="px-3 py-1.5 bg-[#6B5AED]/20 border border-[#6B5AED]/30 rounded text-sm font-medium flex items-center gap-2 hover:bg-[#6B5AED]/30 transition-all">
                    <Users size={14} />
                    Assign
                  </button>
                  <button className="px-3 py-1.5 bg-[#6B5AED]/20 border border-[#6B5AED]/30 rounded text-sm font-medium flex items-center gap-2 hover:bg-[#6B5AED]/30 transition-all">
                    <Ticket size={14} />
                    Create Ticket
                  </button>
                  <button className="px-3 py-1.5 bg-[#6B5AED]/20 border border-[#6B5AED]/30 rounded text-sm font-medium flex items-center gap-2 hover:bg-[#6B5AED]/30 transition-all">
                    <CheckCircle size={14} />
                    Accept Risk
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Issues Table */}
        <div className="flex-1 overflow-auto p-6">
          {filteredIssues.length === 0 ? (
            <div className="text-center py-16 bg-white/2 rounded-lg border border-white/5">
              <CheckCircle size={48} className="mx-auto mb-4 text-green-500" />
              <h3 className="text-lg font-semibold mb-2">No issues found</h3>
              <p className="text-sm text-slate-400">
                {Object.values(filters).some(v => v) || searchQuery
                  ? 'Try adjusting your filters or search to see more results'
                  : 'All security issues have been resolved'}
              </p>
            </div>
          ) : (
            <div className="bg-white/2 rounded-lg border border-white/5 overflow-hidden">
              {/* Table Header */}
              <div className="grid grid-cols-[40px_80px_1fr_100px_180px_180px_120px_80px] gap-3 p-3 bg-black/20 border-b border-white/5 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                <div>
                  <input
                    type="checkbox"
                    checked={selectedIssues.size === filteredIssues.length && filteredIssues.length > 0}
                    onChange={toggleSelectAll}
                    className="cursor-pointer"
                  />
                </div>
                <div>Severity</div>
                <div>Issue</div>
                <div>Source</div>
                <div>Repository</div>
                <div>Location</div>
                <div>Exploitability</div>
                <div>Age</div>
              </div>

              {/* Table Body */}
              {filteredIssues.map((issue, index) => {
                const isSelected = selectedIssues.has(issue.id)
                const isFocused = index === focusedIndex
                return (
                  <div
                    key={issue.id}
                    className={`grid grid-cols-[40px_80px_1fr_100px_180px_180px_120px_80px] gap-3 p-4 border-b border-white/5 cursor-pointer transition-colors ${
                      isFocused ? 'bg-[#6B5AED]/10 ring-2 ring-[#6B5AED]/30' : 
                      isSelected ? 'bg-[#6B5AED]/5' : 'hover:bg-white/2'
                    }`}
                    onClick={() => setSelectedIssue(issue)}
                    onContextMenu={(e) => handleContextMenu(e, issue)}
                  >
                    {/* Checkbox */}
                    <div className="flex items-center">
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={(e) => {
                          e.stopPropagation()
                          toggleIssueSelection(issue.id)
                        }}
                        onClick={(e) => e.stopPropagation()}
                        className="cursor-pointer"
                      />
                    </div>

                    {/* Severity */}
                    <div className="flex items-center">
                      <div
                        className="w-2 h-2 rounded-full mr-2"
                        style={{ backgroundColor: getSeverityColor(issue.severity) }}
                      ></div>
                      <span
                        className="text-xs font-medium capitalize"
                        style={{ color: getSeverityColor(issue.severity) }}
                      >
                        {issue.severity}
                      </span>
                    </div>

                    {/* Issue */}
                    <div className="text-sm font-medium text-white">
                      {issue.title}
                    </div>

                    {/* Source */}
                    <div className="flex items-center gap-1.5 text-xs text-slate-400">
                      {getSourceIcon(issue.source)}
                      {issue.source}
                    </div>

                    {/* Repository */}
                    <div className="text-xs text-slate-400 font-mono">
                      {issue.repo}
                    </div>

                    {/* Location */}
                    <div className="text-[11px] text-slate-500 font-mono overflow-hidden text-ellipsis whitespace-nowrap">
                      {issue.location}
                    </div>

                    {/* Exploitability */}
                    <div className="flex flex-col gap-1">
                      {issue.exploitability.kev && (
                        <span className="px-1.5 py-0.5 bg-red-500/20 border border-red-500/30 rounded text-[10px] font-semibold text-red-300 text-center">
                          KEV
                        </span>
                      )}
                      {issue.exploitability.epss > 0 && (
                        <span className={`text-[11px] ${issue.exploitability.epss >= 0.7 ? 'text-red-300' : 'text-slate-400'}`}>
                          EPSS: {(issue.exploitability.epss * 100).toFixed(0)}%
                        </span>
                      )}
                    </div>

                    {/* Age */}
                    <div className={`text-xs ${issue.age_days <= 7 ? 'text-[#6B5AED]' : 'text-slate-400'}`}>
                      {issue.age_days}d
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>

      {/* Issue Drawer */}
      {selectedIssue && (
        <div
          onClick={() => setSelectedIssue(null)}
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
                    style={{ backgroundColor: getSeverityColor(selectedIssue.severity) }}
                  ></div>
                  <span
                    className="text-xs font-semibold uppercase tracking-wider"
                    style={{ color: getSeverityColor(selectedIssue.severity) }}
                  >
                    {selectedIssue.severity}
                  </span>
                </div>
                <button
                  onClick={() => setSelectedIssue(null)}
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  <XCircle size={20} />
                </button>
              </div>
              <h3 className="text-base font-semibold mb-2">{selectedIssue.title}</h3>
              <div className="text-xs text-slate-500 font-mono">{selectedIssue.location}</div>
            </div>

            {/* Drawer Content */}
            <div className="flex-1 overflow-auto p-6">
              {/* Overview Section */}
              <div className="mb-6">
                <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
                  Overview
                </h4>
                <p className="text-sm text-slate-400 leading-relaxed mb-4">
                  {selectedIssue.description}
                </p>

                {/* Exploitability */}
                {(selectedIssue.exploitability.kev || selectedIssue.exploitability.epss > 0) && (
                  <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-md mb-4">
                    <div className="text-xs font-semibold text-red-300 mb-2">
                      Exploitability
                    </div>
                    {selectedIssue.exploitability.kev && (
                      <div className="text-xs text-slate-300 mb-1">
                        • Known Exploited Vulnerability (KEV)
                      </div>
                    )}
                    {selectedIssue.exploitability.epss > 0 && (
                      <div className="text-xs text-slate-300">
                        • EPSS Score: {(selectedIssue.exploitability.epss * 100).toFixed(1)}% probability of exploitation
                      </div>
                    )}
                  </div>
                )}

                {/* Metadata */}
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <div className="text-slate-500 mb-1">Source</div>
                    <div className="text-slate-300 font-medium">{selectedIssue.source}</div>
                  </div>
                  <div>
                    <div className="text-slate-500 mb-1">Repository</div>
                    <div className="text-slate-300 font-medium font-mono">{selectedIssue.repo}</div>
                  </div>
                  <div>
                    <div className="text-slate-500 mb-1">Age</div>
                    <div className="text-slate-300 font-medium">{selectedIssue.age_days} days</div>
                  </div>
                  <div>
                    <div className="text-slate-500 mb-1">Exposure</div>
                    <div className="text-slate-300 font-medium">
                      {selectedIssue.internet_facing ? 'Internet-facing' : 'Internal'}
                    </div>
                  </div>
                </div>
              </div>

              {/* Remediation Section */}
              <div>
                <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
                  Remediation
                </h4>
                <p className="text-sm text-slate-400 leading-relaxed mb-4">
                  {selectedIssue.remediation}
                </p>

                {/* Action Buttons */}
                <div className="flex gap-2 flex-wrap">
                  <button
                    onClick={() => {
                      const guidance = `Issue: ${selectedIssue.title}\nLocation: ${selectedIssue.location}\nRemediation: ${selectedIssue.remediation}`
                      navigator.clipboard.writeText(guidance)
                    }}
                    className="px-3 py-2 bg-[#6B5AED]/10 border border-[#6B5AED]/30 rounded-md text-[#6B5AED] text-xs font-medium flex items-center gap-2 hover:bg-[#6B5AED]/20 transition-all"
                  >
                    <Copy size={14} />
                    Copy Fix Guidance
                  </button>
                  <button className="px-3 py-2 bg-[#6B5AED]/10 border border-[#6B5AED]/30 rounded-md text-[#6B5AED] text-xs font-medium flex items-center gap-2 hover:bg-[#6B5AED]/20 transition-all">
                    <Ticket size={14} />
                    Create Ticket
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {showColumnChooser && (
        <div
          onClick={() => setShowColumnChooser(false)}
          className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center"
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="w-[450px] bg-[#1e293b] border border-white/10 rounded-lg flex flex-col"
          >
            <div className="p-6 border-b border-white/10">
              <div className="flex justify-between items-start">
                <div>
                  <h3 className="text-lg font-semibold mb-1">Column Settings</h3>
                  <p className="text-sm text-slate-400">Show, hide, and pin columns</p>
                </div>
                <button
                  onClick={() => setShowColumnChooser(false)}
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  <XCircle size={20} />
                </button>
              </div>
            </div>

            <div className="p-6 space-y-3">
              {columnDefinitions.map(({ id, label }) => {
                const isVisible = visibleColumns[id as keyof typeof visibleColumns]
                const isPinned = pinnedColumns.has(id)
                return (
                  <div key={id} className="flex items-center justify-between p-3 bg-white/2 rounded-lg border border-white/5">
                    <div className="flex items-center gap-3">
                      <input
                        type="checkbox"
                        checked={isVisible}
                        onChange={() => toggleColumnVisibility(id)}
                        className="cursor-pointer"
                      />
                      <span className="text-sm font-medium">{label}</span>
                    </div>
                    <button
                      onClick={() => toggleColumnPin(id)}
                      disabled={!isVisible}
                      className={`p-1.5 rounded transition-colors ${
                        isPinned
                          ? 'bg-[#6B5AED]/20 text-[#6B5AED]'
                          : isVisible
                          ? 'text-slate-400 hover:bg-white/5'
                          : 'text-slate-600 cursor-not-allowed'
                      }`}
                      title={isPinned ? 'Unpin column' : 'Pin column'}
                    >
                      {isPinned ? <Pin size={16} /> : <PinOff size={16} />}
                    </button>
                  </div>
                )
              })}
            </div>

            <div className="p-6 border-t border-white/10 bg-white/2">
              <p className="text-xs text-slate-400 text-center">
                Pinned columns stay visible when scrolling horizontally
              </p>
            </div>
          </div>
        </div>
      )}

      {showKeyboardHelp && (
        <div
          onClick={() => setShowKeyboardHelp(false)}
          className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center"
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="w-[500px] bg-[#1e293b] border border-white/10 rounded-lg flex flex-col"
          >
            <div className="p-6 border-b border-white/10">
              <div className="flex justify-between items-start">
                <div>
                  <h3 className="text-lg font-semibold mb-1">Keyboard Shortcuts</h3>
                  <p className="text-sm text-slate-400">Navigate and manage issues faster</p>
                </div>
                <button
                  onClick={() => setShowKeyboardHelp(false)}
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  <XCircle size={20} />
                </button>
              </div>
            </div>

            <div className="p-6 space-y-4">
              {[
                { keys: ['j', '↓'], description: 'Move down to next issue' },
                { keys: ['k', '↑'], description: 'Move up to previous issue' },
                { keys: ['Space'], description: 'Toggle selection of focused issue' },
                { keys: ['Enter'], description: 'Open issue detail drawer' },
                { keys: ['Escape'], description: 'Close drawer or modal' },
                { keys: ['Ctrl+A', 'Cmd+A'], description: 'Select all issues' },
              ].map(({ keys, description }, index) => (
                <div key={index} className="flex items-center justify-between">
                  <span className="text-sm text-slate-300">{description}</span>
                  <div className="flex gap-2">
                    {keys.map((key, i) => (
                      <span key={i}>
                        <kbd className="px-2 py-1 bg-white/5 border border-white/10 rounded text-xs font-mono text-slate-300">
                          {key}
                        </kbd>
                        {i < keys.length - 1 && <span className="text-slate-500 mx-1">or</span>}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            <div className="p-6 border-t border-white/10 bg-white/2">
              <p className="text-xs text-slate-400 text-center">
                Press <kbd className="px-1.5 py-0.5 bg-white/5 border border-white/10 rounded text-xs font-mono">?</kbd> anytime to show this help
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Context Menu */}
      {contextMenu && (
        <div
          className="fixed bg-[#1e293b] border border-white/10 rounded-md shadow-2xl py-1 z-[100] min-w-[200px]"
          style={{ left: contextMenu.x, top: contextMenu.y }}
          onClick={(e) => e.stopPropagation()}
        >
          <button
            onClick={() => handleContextAction('assign', contextMenu.issue)}
            className="w-full px-4 py-2 text-left text-sm text-slate-300 hover:bg-white/5 flex items-center gap-2"
          >
            <Users size={14} />
            Assign to Team
          </button>
          <button
            onClick={() => handleContextAction('create-ticket', contextMenu.issue)}
            className="w-full px-4 py-2 text-left text-sm text-slate-300 hover:bg-white/5 flex items-center gap-2"
          >
            <Ticket size={14} />
            Create Ticket
          </button>
          <button
            onClick={() => handleContextAction('accept-risk', contextMenu.issue)}
            className="w-full px-4 py-2 text-left text-sm text-slate-300 hover:bg-white/5 flex items-center gap-2"
          >
            <CheckCircle size={14} />
            Accept Risk
          </button>
          <div className="border-t border-white/10 my-1"></div>
          <button
            onClick={() => handleContextAction('snooze', contextMenu.issue)}
            className="w-full px-4 py-2 text-left text-sm text-slate-300 hover:bg-white/5 flex items-center gap-2"
          >
            <Archive size={14} />
            Snooze
          </button>
          <button
            onClick={() => handleContextAction('ignore', contextMenu.issue)}
            className="w-full px-4 py-2 text-left text-sm text-slate-300 hover:bg-white/5 flex items-center gap-2"
          >
            <Eye size={14} />
            Ignore
          </button>
          <div className="border-t border-white/10 my-1"></div>
          <button
            onClick={() => handleContextAction('copy-link', contextMenu.issue)}
            className="w-full px-4 py-2 text-left text-sm text-slate-300 hover:bg-white/5 flex items-center gap-2"
          >
            <Copy size={14} />
            Copy Link
          </button>
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
    </EnterpriseShell>
  )
}
