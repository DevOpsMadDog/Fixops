import { useState, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { useQuery } from '@tanstack/react-query';
import {
  LayoutDashboard,
  Brain,
  Swords,
  Wrench,
  Settings,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  Shield,
  Bot,
  Bell,
  Search,
  User,
  Loader2,
  Code,
  Key,
  Building2,
  FileText,
  Cloud,
  Box,
  Network,
  Target,
  Radio,
  ClipboardList,
  Zap,
  Users,
  Ticket,
  TrendingUp,
  Cpu,
  BarChart3,
  Scale,
  Package,
  Lock,
  FileSignature,
  ScrollText,
  Workflow,
  FolderKanban,
  ShieldCheck,
  Upload,
  FlaskConical,
  Crosshair,
  AlertTriangle,
  Activity,
  Radar,
  Database,
  Link2,
  Clock,
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Badge } from '../components/ui/badge';
import { useUIStore } from '../stores';
import { searchApi } from '../lib/api';
import AICopilot from '../components/AICopilot';
import GlobalStatusBar from '../components/GlobalStatusBar';

interface MainLayoutProps {
  children: React.ReactNode;
}

// ═══════════════════════════════════════════════════════════════════════════
// 5 WORKFLOW SPACES — Organized by WHAT PEOPLE DO, not what the product can do
// Per CEO Vision Section V + VISION_TO_ACCOMPLISH.MD Part IV (Section 4.2)
// Resolves KP-003: 8 Technical Suites → 5 Workflow Spaces
// ═══════════════════════════════════════════════════════════════════════════

interface NavItem {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  path: string;
  badge?: string;
  pillar?: string; // V3, V5, V7, V10 tags for dev reference
}

interface NavSection {
  id: string;
  title: string;
  emoji: string;
  subtitle: string;
  items: NavItem[];
}

const workflowSpaces: NavSection[] = [
  // ═══ SPACE 1: MISSION CONTROL ═══
  // "What needs my attention right now?"
  // Personas: Sarah (CISO), Raj (DevSecOps), Janet (SOC), Tom (CFO)
  {
    id: 'mission-control',
    title: 'Mission Control',
    emoji: '🎯',
    subtitle: 'What needs attention now?',
    items: [
      { id: 'command-dashboard', label: 'Command Dashboard', icon: LayoutDashboard, path: '/', pillar: 'V3' },
      { id: 'executive', label: 'Executive View', icon: BarChart3, path: '/executive', badge: 'CEO' },
      { id: 'nerve-center', label: 'Nerve Center', icon: Brain, path: '/nerve-center', badge: 'BRAIN', pillar: 'V3' },
      { id: 'brain-pipeline', label: 'Brain Pipeline', icon: Workflow, path: '/core/brain-pipeline', badge: 'V3', pillar: 'V3' },
      { id: 'exposure-cases', label: 'Exposure Cases', icon: FolderKanban, path: '/core/exposure-cases', pillar: 'V3' },
      { id: 'live-feed', label: 'Live Feed', icon: Radio, path: '/feeds/live', badge: 'LIVE' },
      { id: 'sla-dashboard', label: 'SLA Dashboard', icon: Clock, path: '/mission-control/sla', pillar: 'V3' },
      { id: 'predictions', label: 'Risk Predictions', icon: TrendingUp, path: '/ai-engine/predictions', pillar: 'V3' },
      { id: 'multi-llm', label: 'AI Consensus', icon: Cpu, path: '/ai-engine/multi-llm', badge: 'AI', pillar: 'V3' },
      { id: 'policy-engine', label: 'Policy Engine', icon: Scale, path: '/ai-engine/policy-engine', pillar: 'V3' },
    ],
  },
  // ═══ SPACE 2: DISCOVER ═══
  // "What risks exist across my applications?"
  // Personas: Alex (Security Eng), Marcus (AppSec), Brian (Cloud Sec)
  {
    id: 'discover',
    title: 'Discover',
    emoji: '🔍',
    subtitle: 'Find every risk',
    items: [
      { id: 'scanner-dashboard', label: 'Scanner Dashboard', icon: Shield, path: '/discover/scanners', badge: 'CTEM+', pillar: 'V7' },
      { id: 'scanner-ingest', label: 'Scanner Ingest', icon: Upload, path: '/discover/scanner-ingest', badge: 'V7', pillar: 'V7' },
      { id: 'code-scanning', label: 'Code Scanning', icon: Code, path: '/code/code-scanning' },
      { id: 'secrets-detection', label: 'Secrets Detection', icon: Key, path: '/code/secrets-detection' },
      { id: 'iac-scanning', label: 'Infrastructure as Code', icon: Building2, path: '/code/iac-scanning' },
      { id: 'cloud-posture', label: 'Cloud Posture', icon: Cloud, path: '/cloud/cloud-posture' },
      { id: 'container-security', label: 'Container Security', icon: Box, path: '/cloud/container-security' },
      { id: 'knowledge-graph', label: 'Knowledge Graph', icon: Network, path: '/core/knowledge-graph', badge: 'V3', pillar: 'V3' },
      { id: 'attack-paths', label: 'Attack Paths', icon: Network, path: '/attack/attack-paths' },
      { id: 'correlation', label: 'Finding Correlation', icon: Link2, path: '/intelligence' },
      { id: 'threat-feeds', label: 'Threat Feeds', icon: Radar, path: '/cloud/threat-feeds' },
      { id: 'data-fabric', label: 'Data Fabric', icon: Database, path: '/ingest' },
      { id: 'sbom-inventory', label: 'SBOM & Inventory', icon: Package, path: '/code/sbom-generation' },
    ],
  },
  // ═══ SPACE 3: VALIDATE ═══
  // "Is this vulnerability actually exploitable?"
  // Personas: Jason (Red Team), Marcus (AppSec), Dr. Wei (ML Eng)
  {
    id: 'validate',
    title: 'Validate',
    emoji: '⚡',
    subtitle: 'Prove what\'s exploitable',
    items: [
      { id: 'mpte-console', label: 'MPTE Console', icon: Swords, path: '/attack/mpte', badge: 'V5', pillar: 'V5' },
      { id: 'micro-pentest', label: 'Micro Pentest', icon: Target, path: '/attack/micro-pentest', pillar: 'V5' },
      { id: 'sandbox', label: 'Sandbox Verification', icon: FlaskConical, path: '/attack/sandbox', badge: 'V5', pillar: 'V5' },
      { id: 'attack-simulation', label: 'Attack Simulation', icon: Crosshair, path: '/attack/attack-simulation', pillar: 'V5' },
      { id: 'fail-engine', label: 'FAIL Engine', icon: AlertTriangle, path: '/validate/fail-engine', badge: 'NEW', pillar: 'V5' },
      { id: 'reachability', label: 'Reachability', icon: Activity, path: '/attack/reachability' },
      { id: 'playbooks', label: 'Playbooks', icon: ClipboardList, path: '/protect/playbooks' },
      { id: 'playbook-editor', label: 'Playbook Editor', icon: FileText, path: '/protect/playbook-editor' },
    ],
  },
  // ═══ SPACE 4: REMEDIATE ═══
  // "How do I fix these vulnerabilities efficiently?"
  // Personas: Alex (Security Eng), Mike (Developer), Kevin (Dev Lead)
  {
    id: 'remediate',
    title: 'Remediate',
    emoji: '🔧',
    subtitle: 'Fix it, track it, close it',
    items: [
      { id: 'remediation', label: 'Remediation Center', icon: Wrench, path: '/protect/remediation' },
      { id: 'autofix', label: 'AutoFix Dashboard', icon: Zap, path: '/protect/autofix', badge: 'AI', pillar: 'V3' },
      { id: 'bulk-ops', label: 'Bulk Operations', icon: Zap, path: '/protect/bulk-operations' },
      { id: 'workflows', label: 'Workflows', icon: Workflow, path: '/protect/workflows' },
      { id: 'collaboration', label: 'Collaboration', icon: Users, path: '/protect/collaboration' },
      { id: 'integrations', label: 'Ticket Integrations', icon: Ticket, path: '/protect/integrations' },
    ],
  },
  // ═══ SPACE 5: COMPLY ═══
  // "Can I prove we're secure to auditors and the board?"
  // Personas: Maria (Compliance), Laura (Auditor), Sarah (CISO), Tom (CFO)
  {
    id: 'comply',
    title: 'Comply',
    emoji: '🛡️',
    subtitle: 'Prove we\'re secure',
    items: [
      { id: 'compliance', label: 'Compliance Dashboard', icon: ShieldCheck, path: '/evidence/compliance', pillar: 'V10' },
      { id: 'evidence-bundles', label: 'Evidence Bundles', icon: Package, path: '/evidence/bundles', pillar: 'V10' },
      { id: 'soc2', label: 'SOC2 Evidence', icon: Shield, path: '/evidence/soc2', badge: 'SOC2', pillar: 'V10' },
      { id: 'slsa', label: 'SLSA Provenance', icon: Lock, path: '/evidence/slsa-provenance' },
      { id: 'audit-trail', label: 'Audit Trail', icon: ScrollText, path: '/evidence/audit-trail', pillar: 'V10' },
      { id: 'reports', label: 'Reports', icon: FileSignature, path: '/evidence/reports' },
      { id: 'analytics', label: 'Evidence Analytics', icon: BarChart3, path: '/evidence/analytics' },
    ],
  },
];

// Space accent colors for active indicators
const spaceColors: Record<string, string> = {
  'mission-control': 'text-indigo-400 border-indigo-400 bg-indigo-500/10',
  'discover': 'text-cyan-400 border-cyan-400 bg-cyan-500/10',
  'validate': 'text-orange-400 border-orange-400 bg-orange-500/10',
  'remediate': 'text-emerald-400 border-emerald-400 bg-emerald-500/10',
  'comply': 'text-violet-400 border-violet-400 bg-violet-500/10',
};

const spaceHeaderColors: Record<string, string> = {
  'mission-control': 'text-indigo-300/90 hover:text-indigo-200',
  'discover': 'text-cyan-300/90 hover:text-cyan-200',
  'validate': 'text-orange-300/90 hover:text-orange-200',
  'remediate': 'text-emerald-300/90 hover:text-emerald-200',
  'comply': 'text-violet-300/90 hover:text-violet-200',
};

export default function MainLayout({ children }: MainLayoutProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const { sidebarCollapsed, toggleSidebar, copilotOpen, toggleCopilot } = useUIStore();
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  const [showSearchResults, setShowSearchResults] = useState(false);
  const [expandedSections, setExpandedSections] = useState<Set<string>>(
    new Set(['mission-control', 'discover', 'validate', 'remediate', 'comply'])
  );

  // Determine which space contains the current path
  const getActiveSpace = (): string | null => {
    for (const space of workflowSpaces) {
      for (const item of space.items) {
        if (item.path === '/' && location.pathname === '/') return space.id;
        if (item.path !== '/' && location.pathname.startsWith(item.path)) return space.id;
      }
    }
    return null;
  };

  const activeSpace = getActiveSpace();

  // Check if a path is active
  const isActivePath = (path: string) => {
    if (path === '/') return location.pathname === '/';
    return location.pathname === path || location.pathname.startsWith(path + '/');
  };

  // Toggle section expansion
  const toggleSection = (sectionId: string) => {
    setExpandedSections((prev) => {
      const next = new Set(prev);
      if (next.has(sectionId)) {
        next.delete(sectionId);
      } else {
        next.add(sectionId);
      }
      return next;
    });
  };

  // Debounced search
  const handleSearchChange = useCallback((value: string) => {
    setSearchQuery(value);
    if (value.length >= 2) {
      const timeout = setTimeout(() => {
        setDebouncedQuery(value);
        setShowSearchResults(true);
      }, 300);
      return () => clearTimeout(timeout);
    } else {
      setShowSearchResults(false);
    }
  }, []);

  // Real search API call
  const { data: searchResults, isLoading: searchLoading } = useQuery({
    queryKey: ['search', debouncedQuery],
    queryFn: () => searchApi.searchFindings(debouncedQuery),
    enabled: debouncedQuery.length >= 2,
  });

  return (
    <div className="flex h-screen bg-background overflow-hidden">
      {/* ═══ SIDEBAR — 5 WORKFLOW SPACES ═══ */}
      <motion.aside
        initial={false}
        animate={{ width: sidebarCollapsed ? 72 : 280 }}
        transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
        className="flex flex-col border-r border-border bg-card/50 backdrop-blur-xl"
      >
        {/* Logo */}
        <div className="flex items-center gap-3 p-4 border-b border-border">
          <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500/20 to-violet-500/20 border border-indigo-500/20">
            <Shield className="w-6 h-6 text-indigo-400" />
          </div>
          {!sidebarCollapsed && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            >
              <h1 className="font-bold text-lg tracking-tight">ALdeci</h1>
              <p className="text-[10px] text-muted-foreground font-medium tracking-wide uppercase">CTEM+ Platform</p>
            </motion.div>
          )}
        </div>

        {/* Navigation — 5 Workflow Spaces */}
        <nav aria-label="Main navigation" role="navigation" className="flex-1 px-2 py-3 space-y-1 overflow-y-auto scrollbar-thin scrollbar-track-transparent scrollbar-thumb-gray-700/30">
          {workflowSpaces.map((space) => {
            const isSpaceActive = space.id === activeSpace;
            const colorClass = spaceColors[space.id] || 'text-primary border-primary bg-primary/10';
            const headerColor = spaceHeaderColors[space.id] || 'text-muted-foreground hover:text-foreground';

            return (
              <div key={space.id} className="mb-1">
                {/* Space Header */}
                {!sidebarCollapsed ? (
                  <button
                    onClick={() => toggleSection(space.id)}
                    aria-expanded={expandedSections.has(space.id)}
                    aria-label={`${space.title} workspace — ${space.subtitle}`}
                    className={`flex items-center justify-between w-full px-3 py-2 text-xs font-semibold uppercase tracking-wider transition-colors rounded-md ${
                      isSpaceActive ? headerColor : 'text-muted-foreground/70 hover:text-muted-foreground'
                    }`}
                  >
                    <span className="flex items-center gap-2">
                      <span className="text-sm">{space.emoji}</span>
                      <span>{space.title}</span>
                    </span>
                    <ChevronDown
                      className={`w-3 h-3 transition-transform duration-200 ${
                        expandedSections.has(space.id) ? 'rotate-0' : '-rotate-90'
                      }`}
                    />
                  </button>
                ) : (
                  /* Collapsed: show emoji as divider */
                  <div className="flex items-center justify-center py-2">
                    <span className="text-sm opacity-60" title={space.title}>{space.emoji}</span>
                  </div>
                )}

                {/* Space Items */}
                <AnimatePresence>
                  {(expandedSections.has(space.id) || sidebarCollapsed) && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.15, ease: [0.16, 1, 0.3, 1] }}
                      className="space-y-0.5 overflow-hidden"
                    >
                      {space.items.map((item) => {
                        const Icon = item.icon;
                        const isActive = isActivePath(item.path);

                        return (
                          <Button
                            key={item.id}
                            variant={isActive ? 'secondary' : 'ghost'}
                            size="sm"
                            className={`w-full justify-start gap-3 h-8 px-3 transition-all duration-150 ${
                              isActive
                                ? `${colorClass} border-l-2 rounded-l-none font-medium`
                                : 'text-muted-foreground hover:text-foreground'
                            }`}
                            onClick={() => navigate(item.path)}
                            title={sidebarCollapsed ? item.label : undefined}
                            aria-label={item.label}
                          >
                            <Icon className={`w-4 h-4 flex-shrink-0 ${isActive ? '' : ''}`} />
                            {!sidebarCollapsed && (
                              <>
                                <span className="flex-1 text-left text-[13px] truncate">
                                  {item.label}
                                </span>
                                {item.badge && (
                                  <Badge
                                    variant="outline"
                                    className={`text-[9px] px-1.5 py-0 h-4 font-medium ${
                                      item.badge === 'NEW'
                                        ? 'border-emerald-500/40 text-emerald-400 bg-emerald-500/10'
                                        : item.badge === 'AI'
                                        ? 'border-purple-500/40 text-purple-400 bg-purple-500/10'
                                        : item.badge === 'LIVE'
                                        ? 'border-red-500/40 text-red-400 bg-red-500/10 animate-pulse'
                                        : item.badge === 'CTEM+'
                                        ? 'border-amber-500/40 text-amber-400 bg-amber-500/10'
                                        : ''
                                    }`}
                                  >
                                    {item.badge}
                                  </Badge>
                                )}
                              </>
                            )}
                          </Button>
                        );
                      })}
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            );
          })}
        </nav>

        {/* Bottom Actions — Settings, Logs, MCP Registry, Collapse */}
        <div className="p-2 border-t border-border space-y-0.5">
          <Button
            variant={location.pathname.startsWith('/settings/mcp') ? 'secondary' : 'ghost'}
            size="sm"
            className={`w-full justify-start gap-3 h-8 ${sidebarCollapsed ? 'px-3' : ''} ${
              location.pathname.startsWith('/settings/mcp') ? 'bg-primary/10 text-primary' : 'text-muted-foreground'
            }`}
            onClick={() => navigate('/settings/mcp-registry')}
            title={sidebarCollapsed ? 'MCP Registry' : undefined}
            aria-label="MCP Tool Registry"
          >
            <Database className="w-4 h-4" />
            {!sidebarCollapsed && <span className="text-[13px]">MCP Registry</span>}
            {!sidebarCollapsed && <Badge variant="outline" className="text-[9px] px-1.5 py-0 h-4 border-blue-500/40 text-blue-400 bg-blue-500/10">V7</Badge>}
          </Button>
          <Button
            variant={location.pathname === '/settings/logs' ? 'secondary' : 'ghost'}
            size="sm"
            className={`w-full justify-start gap-3 h-8 ${sidebarCollapsed ? 'px-3' : ''} ${
              location.pathname === '/settings/logs' ? 'bg-primary/10 text-primary' : 'text-muted-foreground'
            }`}
            onClick={() => navigate('/settings/logs')}
            title={sidebarCollapsed ? 'API Logs' : undefined}
            aria-label="API Logs"
          >
            <ScrollText className="w-4 h-4" />
            {!sidebarCollapsed && <span className="text-[13px]">API Logs</span>}
          </Button>
          <Button
            variant={location.pathname === '/settings' || (location.pathname.startsWith('/settings') && !location.pathname.includes('/logs') && !location.pathname.includes('/mcp')) ? 'secondary' : 'ghost'}
            size="sm"
            className={`w-full justify-start gap-3 h-8 ${sidebarCollapsed ? 'px-3' : ''}`}
            onClick={() => navigate('/settings')}
            aria-label="Settings"
          >
            <Settings className="w-4 h-4" />
            {!sidebarCollapsed && <span className="text-[13px]">Settings</span>}
          </Button>

          <Button
            variant="ghost"
            size="sm"
            className="w-full justify-center h-7 text-muted-foreground hover:text-foreground"
            onClick={toggleSidebar}
            aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {sidebarCollapsed ? (
              <ChevronRight className="w-4 h-4" />
            ) : (
              <ChevronLeft className="w-4 h-4" />
            )}
          </Button>
        </div>
      </motion.aside>

      {/* ═══ MAIN CONTENT ═══ */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Global API Status Bar */}
        <GlobalStatusBar />

        {/* Top Bar */}
        <header className="flex items-center justify-between px-6 py-2.5 border-b border-border bg-card/30 backdrop-blur-xl">
          <div className="flex items-center gap-4 flex-1 max-w-xl">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" aria-hidden="true" />
              <Input
                placeholder="Search vulnerabilities, assets, findings..."
                value={searchQuery}
                onChange={(e) => handleSearchChange(e.target.value)}
                onFocus={() => searchQuery.length >= 2 && setShowSearchResults(true)}
                onBlur={() => setTimeout(() => setShowSearchResults(false), 200)}
                className="pl-10 pr-20 bg-background/50 h-9"
                aria-label="Search vulnerabilities, assets, and findings"
                role="searchbox"
              />
              <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-1 pointer-events-none">
                <kbd className="px-1.5 py-0.5 bg-gray-800/80 border border-gray-600/50 rounded text-[10px] text-gray-400 font-mono">
                  {navigator.platform?.includes('Mac') ? '⌘' : 'Ctrl'}
                </kbd>
                <kbd className="px-1.5 py-0.5 bg-gray-800/80 border border-gray-600/50 rounded text-[10px] text-gray-400 font-mono">K</kbd>
              </div>

              {/* Search Results Dropdown */}
              <AnimatePresence>
                {showSearchResults && (
                  <motion.div
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    className="absolute top-full mt-2 left-0 right-0 bg-popover border border-border rounded-lg shadow-lg z-50 max-h-80 overflow-y-auto"
                  >
                    {searchLoading ? (
                      <div className="p-4 flex items-center justify-center">
                        <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
                      </div>
                    ) : searchResults?.findings?.length > 0 ? (
                      <div className="p-2">
                        <p className="px-2 py-1 text-xs text-muted-foreground">
                          Found {searchResults.findings.length} results
                        </p>
                        {searchResults.findings.slice(0, 10).map((finding: { id: string; severity: string; title?: string; cve_id?: string }) => (
                          <button
                            key={finding.id}
                            className="w-full px-3 py-2 text-left hover:bg-accent rounded-md flex items-center gap-3"
                            onClick={() => {
                              navigate('/intelligence');
                              setShowSearchResults(false);
                            }}
                          >
                            <Badge variant={finding.severity === 'critical' ? 'destructive' : 'secondary'}>
                              {finding.severity}
                            </Badge>
                            <span className="text-sm truncate">{finding.title || finding.cve_id}</span>
                          </button>
                        ))}
                      </div>
                    ) : (
                      <div className="p-4 text-center text-muted-foreground text-sm">
                        No results found for &ldquo;{debouncedQuery}&rdquo;
                      </div>
                    )}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* AI Copilot Toggle */}
            <Button
              variant={copilotOpen ? 'secondary' : 'ghost'}
              size="icon"
              onClick={toggleCopilot}
              className="relative h-9 w-9"
              aria-label="Toggle AI Copilot"
            >
              <Bot className="w-5 h-5" />
              <span className="absolute -top-1 -right-1 w-2 h-2 bg-green-500 rounded-full animate-pulse" />
            </Button>

            {/* Notifications */}
            <Button variant="ghost" size="icon" className="relative h-9 w-9" aria-label="Notifications">
              <Bell className="w-5 h-5" />
              <span className="absolute -top-1 -right-1 bg-red-500 text-white text-[10px] rounded-full w-4 h-4 flex items-center justify-center">
                3
              </span>
            </Button>

            {/* User Menu */}
            <Button variant="ghost" size="icon" className="h-9 w-9" aria-label="User menu">
              <User className="w-5 h-5" />
            </Button>
          </div>
        </header>

        {/* Page Content */}
        <main role="main" aria-label="Page content" className="flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>

      {/* ═══ AI COPILOT SIDEBAR — Persistent, any space ═══ */}
      <AnimatePresence>
        {copilotOpen && (
          <motion.div
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: 400, opacity: 1 }}
            exit={{ width: 0, opacity: 0 }}
            transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
            className="border-l border-border bg-card/50 backdrop-blur-xl overflow-hidden"
          >
            <AICopilot />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
