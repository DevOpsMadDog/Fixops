import { useState, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { useQuery } from '@tanstack/react-query';
import { 
  LayoutDashboard, 
  Database, 
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
  Link2,
  Network,
  Target,
  Radio,
  ClipboardList,
  Zap,
  Users,
  RefreshCw,
  Ticket,
  TrendingUp,
  Cpu,
  BarChart3,
  Scale,
  Package,
  Lock,
  FileSignature,
  ScrollText,
  MessageSquare,
  Workflow,
  FolderKanban,
  ShieldCheck
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
// 5-SUITE NAVIGATION STRUCTURE (per ALDECI_COMPLETE_UI_ARCHITECTURE.md)
// ═══════════════════════════════════════════════════════════════════════════

interface NavItem {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  path: string;
  badge?: string;
}

interface NavSection {
  id: string;
  title: string;
  items: NavItem[];
}

const navigationSections: NavSection[] = [
  // Core Pages
  {
    id: 'core',
    title: '',
    items: [
      { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, path: '/' },
      { id: 'nerve-center', label: 'Nerve Center', icon: Brain, path: '/nerve-center', badge: 'BRAIN' },
      { id: 'knowledge-graph', label: 'Knowledge Graph', icon: Network, path: '/core/knowledge-graph', badge: 'BRAIN' },
      { id: 'brain-pipeline', label: 'Brain Pipeline', icon: Workflow, path: '/core/brain-pipeline', badge: 'E2E' },
      { id: 'exposure-cases', label: 'Exposure Cases', icon: FolderKanban, path: '/core/exposure-cases', badge: 'NEW' },
      { id: 'copilot', label: 'AI Copilot', icon: MessageSquare, path: '/attack/mpte-chat', badge: 'AI' },
    ],
  },
  // CODE SUITE (FR-ING: Ingest)
  {
    id: 'code-suite',
    title: '🔍 CODE SUITE',
    items: [
      { id: 'code-scanning', label: 'Code Scanning', icon: Code, path: '/code/code-scanning' },
      { id: 'secrets-detection', label: 'Secrets Detection', icon: Key, path: '/code/secrets-detection' },
      { id: 'iac-scanning', label: 'Infrastructure as Code', icon: Building2, path: '/code/iac-scanning' },
      { id: 'license-sbom', label: 'License & SBOM', icon: FileText, path: '/code/sbom-generation' },
    ],
  },
  // CLOUD SUITE (FR-COR: Correlate)
  {
    id: 'cloud-suite',
    title: '☁️ CLOUD SUITE',
    items: [
      { id: 'cloud-posture', label: 'Cloud Posture (CSPM)', icon: Cloud, path: '/cloud/cloud-posture' },
      { id: 'container-scanning', label: 'Container & VM Scanning', icon: Box, path: '/cloud/container-security' },
      { id: 'data-fabric', label: 'Data Fabric', icon: Database, path: '/ingest' },
      { id: 'intelligence-hub', label: 'Finding Correlation', icon: Link2, path: '/intelligence' },
      { id: 'attack-paths', label: 'Attack Paths (GNN)', icon: Network, path: '/attack/attack-paths' },
    ],
  },
  // ATTACK SUITE (FR-VER: Verify)
  {
    id: 'attack-suite',
    title: '⚔️ ATTACK SUITE',
    items: [
      { id: 'attack-lab', label: 'AI Pentesting (MPTE)', icon: Swords, path: '/attack/mpte-chat' },
      { id: 'attack-simulation', label: 'Attack Simulation', icon: Target, path: '/attack/attack-simulation' },
      { id: 'playbooks', label: 'Playbooks & Campaigns', icon: ClipboardList, path: '/protect/playbooks' },
      { id: 'playbook-editor', label: 'Playbook Editor', icon: FileText, path: '/protect/playbook-editor' },
      { id: 'surface-monitoring', label: 'Surface Monitoring', icon: Radio, path: '/attack/reachability' },
    ],
  },
  // PROTECT SUITE (FR-REM: Remediate)
  {
    id: 'protect-suite',
    title: '🛡️ PROTECT SUITE',
    items: [
      { id: 'remediation-center', label: 'Remediation Center', icon: Wrench, path: '/protect/remediation' },
      { id: 'bulk-operations', label: 'Bulk Operations', icon: Zap, path: '/protect/bulk-operations' },
      { id: 'collaboration', label: 'Collaboration', icon: Users, path: '/protect/collaboration' },
      { id: 'autofix', label: 'AutoFix Dashboard', icon: Zap, path: '/protect/autofix', badge: 'AI' },
      { id: 'automation-studio', label: 'Workflows & Automation', icon: RefreshCw, path: '/ai-engine/automation' },
      { id: 'ticket-integrations', label: 'Ticket Integrations', icon: Ticket, path: '/protect/integrations' },
    ],
  },
  // AI ENGINE (FR-DEC: Decide)
  {
    id: 'ai-engine',
    title: '🧠 AI ENGINE',
    items: [
      { id: 'decision-engine', label: 'Algorithmic Lab', icon: Brain, path: '/decisions' },
      { id: 'multi-llm', label: 'Multi-LLM Consensus', icon: Cpu, path: '/ai-engine/multi-llm', badge: 'AI' },
      { id: 'ml-dashboard', label: 'ML Intelligence', icon: Cpu, path: '/ai-engine/ml-dashboard', badge: 'ML' },
      { id: 'predictions', label: 'Predictions', icon: TrendingUp, path: '/ai-engine/predictions' },
      { id: 'policy-engine', label: 'Policy Engine', icon: Scale, path: '/ai-engine/policy-engine' },
    ],
  },
  // EVIDENCE (FR-EVD: Evidence)
  {
    id: 'evidence',
    title: '📦 EVIDENCE',
    items: [
      { id: 'evidence-vault', label: 'Evidence Bundles', icon: Package, path: '/evidence/bundles' },
      { id: 'slsa-provenance', label: 'SLSA Provenance', icon: Lock, path: '/evidence/slsa-provenance' },
      { id: 'compliance-reports', label: 'Compliance Reports', icon: FileSignature, path: '/evidence/compliance' },
      { id: 'audit-trail', label: 'Audit Trail', icon: ScrollText, path: '/evidence/audit-trail' },
      { id: 'analytics', label: 'Analytics Dashboard', icon: BarChart3, path: '/evidence/analytics' },
      { id: 'soc2-evidence', label: 'SOC2 Evidence', icon: ShieldCheck, path: '/evidence/soc2', badge: 'SOC2' },
    ],
  },
  // FEEDS SUITE (Real-time Intelligence)
  {
    id: 'feeds-suite',
    title: '📡 FEEDS SUITE',
    items: [
      { id: 'live-feeds', label: 'Live Feed Dashboard', icon: Radio, path: '/feeds/live', badge: 'LIVE' },
      { id: 'threat-feeds', label: 'Threat Feeds', icon: Shield, path: '/cloud/threat-feeds' },
    ],
  },
];

export default function MainLayout({ children }: MainLayoutProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const { sidebarCollapsed, toggleSidebar, copilotOpen, toggleCopilot } = useUIStore();
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  const [showSearchResults, setShowSearchResults] = useState(false);
  const [expandedSections, setExpandedSections] = useState<Set<string>>(
    new Set(['core', 'cloud-suite', 'attack-suite', 'ai-engine', 'feeds-suite'])
  );

  // Check if a path is active
  const isActivePath = (path: string) => {
    if (path === '/') {
      return location.pathname === '/';
    }
    return location.pathname.startsWith(path);
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
      {/* Sidebar */}
      <motion.aside
        initial={false}
        animate={{ width: sidebarCollapsed ? 72 : 280 }}
        transition={{ duration: 0.2 }}
        className="flex flex-col border-r border-border bg-card/50 backdrop-blur-xl"
      >
        {/* Logo */}
        <div className="flex items-center gap-3 p-4 border-b border-border">
          <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-primary/10">
            <Shield className="w-6 h-6 text-primary" />
          </div>
          {!sidebarCollapsed && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            >
              <h1 className="font-bold text-lg">ALdeci</h1>
              <p className="text-xs text-muted-foreground">Intelligence Hub</p>
            </motion.div>
          )}
        </div>

        {/* Navigation - Scrollable */}
        <nav className="flex-1 p-2 space-y-1 overflow-y-auto scrollbar-thin">
          {navigationSections.map((section) => (
            <div key={section.id} className="mb-2">
              {/* Section Header */}
              {section.title && !sidebarCollapsed && (
                <button
                  onClick={() => toggleSection(section.id)}
                  className="flex items-center justify-between w-full px-3 py-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider hover:text-foreground transition-colors"
                >
                  <span>{section.title}</span>
                  <ChevronDown
                    className={`w-3 h-3 transition-transform ${
                      expandedSections.has(section.id) ? 'rotate-0' : '-rotate-90'
                    }`}
                  />
                </button>
              )}
              
              {/* Section Items */}
              <AnimatePresence>
                {(expandedSections.has(section.id) || sidebarCollapsed || !section.title) && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.15 }}
                    className="space-y-0.5"
                  >
                    {section.items.map((item) => {
                      const Icon = item.icon;
                      const isActive = isActivePath(item.path);
                      
                      return (
                        <Button
                          key={item.id}
                          variant={isActive ? 'secondary' : 'ghost'}
                          size="sm"
                          className={`w-full justify-start gap-3 h-9 ${
                            sidebarCollapsed ? 'px-3' : 'px-3'
                          } ${isActive ? 'bg-primary/10 text-primary border-l-2 border-primary rounded-l-none' : ''}`}
                          onClick={() => navigate(item.path)}
                          title={sidebarCollapsed ? item.label : undefined}
                        >
                          <Icon className={`w-4 h-4 flex-shrink-0 ${isActive ? 'text-primary' : ''}`} />
                          {!sidebarCollapsed && (
                            <>
                              <span className={`flex-1 text-left text-sm ${isActive ? 'text-primary font-medium' : ''}`}>
                                {item.label}
                              </span>
                              {item.badge && (
                                <Badge variant="outline" className="text-[10px] px-1.5 py-0 h-4">
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
          ))}
        </nav>

        {/* Bottom Actions */}
        <div className="p-2 border-t border-border space-y-1">
          <Button
            variant={location.pathname === '/settings' ? 'secondary' : 'ghost'}
            size="sm"
            className={`w-full justify-start gap-3 h-9 ${sidebarCollapsed ? 'px-3' : ''}`}
            onClick={() => navigate('/settings')}
          >
            <Settings className="w-4 h-4" />
            {!sidebarCollapsed && <span>Settings</span>}
          </Button>
          
          <Button
            variant="ghost"
            size="sm"
            className="w-full justify-center h-8"
            onClick={toggleSidebar}
          >
            {sidebarCollapsed ? (
              <ChevronRight className="w-4 h-4" />
            ) : (
              <ChevronLeft className="w-4 h-4" />
            )}
          </Button>
        </div>
      </motion.aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Global API Status Bar — always visible after logo */}
        <GlobalStatusBar />

        {/* Top Bar */}
        <header className="flex items-center justify-between px-6 py-3 border-b border-border bg-card/30 backdrop-blur-xl">
          <div className="flex items-center gap-4 flex-1 max-w-xl">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search vulnerabilities, assets, findings..."
                value={searchQuery}
                onChange={(e) => handleSearchChange(e.target.value)}
                onFocus={() => searchQuery.length >= 2 && setShowSearchResults(true)}
                onBlur={() => setTimeout(() => setShowSearchResults(false), 200)}
                className="pl-10 bg-background/50"
              />
              
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
                        No results found for "{debouncedQuery}"
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
              className="relative"
            >
              <Bot className="w-5 h-5" />
              <span className="absolute -top-1 -right-1 w-2 h-2 bg-green-500 rounded-full animate-pulse" />
            </Button>
            
            {/* Notifications */}
            <Button variant="ghost" size="icon" className="relative">
              <Bell className="w-5 h-5" />
              <span className="absolute -top-1 -right-1 bg-red-500 text-white text-[10px] rounded-full w-4 h-4 flex items-center justify-center">
                3
              </span>
            </Button>
            
            {/* User Menu */}
            <Button variant="ghost" size="icon">
              <User className="w-5 h-5" />
            </Button>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>

      {/* AI Copilot Sidebar */}
      <AnimatePresence>
        {copilotOpen && (
          <motion.div
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: 400, opacity: 1 }}
            exit={{ width: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="border-l border-border bg-card/50 backdrop-blur-xl overflow-hidden"
          >
            <AICopilot />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
