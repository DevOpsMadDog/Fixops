import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search,
  LayoutDashboard,
  Code,
  Shield,
  Swords,
  Wrench,
  FileText,
  Settings,
  Brain,
  Network,
  Target,
  Upload,
  FlaskConical,
  Cloud,
  Radio,
  BarChart3,
  Scale,
  Users,
  ScrollText,
  Zap,
  ClipboardList,
  Bot,
  Cpu,
  TrendingUp,
  Command,
  ArrowRight,
} from 'lucide-react';

interface CommandItem {
  id: string;
  label: string;
  description: string;
  path: string;
  icon: React.ReactNode;
  category: 'Mission Control' | 'Discover' | 'Validate' | 'Remediate' | 'Comply' | 'Settings' | 'AI Engine';
  keywords: string[];
}

const COMMAND_ITEMS: CommandItem[] = [
  // Mission Control
  { id: 'dashboard', label: 'Command Dashboard', description: 'Security posture overview with risk metrics', path: '/dashboard', icon: <LayoutDashboard className="w-4 h-4" />, category: 'Mission Control', keywords: ['home', 'overview', 'risk', 'posture'] },
  { id: 'executive', label: 'Executive Dashboard', description: 'CEO/CISO-level security summary', path: '/executive', icon: <TrendingUp className="w-4 h-4" />, category: 'Mission Control', keywords: ['ceo', 'ciso', 'executive', 'summary'] },
  { id: 'nerve-center', label: 'Nerve Center', description: 'Real-time security operations hub', path: '/nerve-center', icon: <Brain className="w-4 h-4" />, category: 'Mission Control', keywords: ['soc', 'operations', 'live', 'real-time'] },
  { id: 'brain-pipeline', label: 'Brain Pipeline', description: '12-step CTEM decision intelligence pipeline', path: '/core/brain-pipeline', icon: <Cpu className="w-4 h-4" />, category: 'Mission Control', keywords: ['brain', 'pipeline', 'ctem', 'decision', 'triage'] },
  { id: 'exposure-cases', label: 'Exposure Cases', description: 'Track and manage security exposure cases', path: '/core/exposure-cases', icon: <Target className="w-4 h-4" />, category: 'Mission Control', keywords: ['exposure', 'cases', 'findings', 'triage'] },
  { id: 'knowledge-graph', label: 'Knowledge Graph', description: 'Interactive vulnerability relationship graph', path: '/core/knowledge-graph', icon: <Network className="w-4 h-4" />, category: 'Mission Control', keywords: ['graph', 'knowledge', 'relationships', 'cve'] },

  // Discover
  { id: 'scanner-dashboard', label: 'Scanner Dashboard', description: '8 native CTEM+ scanners status', path: '/discover/scanners', icon: <Shield className="w-4 h-4" />, category: 'Discover', keywords: ['scanner', 'sast', 'dast', 'secrets', 'scan'] },
  { id: 'scanner-ingest', label: 'Scanner Ingest', description: 'Upload and parse third-party scanner reports', path: '/discover/scanner-ingest', icon: <Upload className="w-4 h-4" />, category: 'Discover', keywords: ['upload', 'ingest', 'import', 'zap', 'burp', 'nessus'] },
  { id: 'code-scanning', label: 'Code Scanning', description: 'SAST, DAST, Secrets, Container scanning', path: '/code/code-scanning', icon: <Code className="w-4 h-4" />, category: 'Discover', keywords: ['code', 'sast', 'static', 'analysis'] },
  { id: 'secrets-detection', label: 'Secrets Detection', description: 'Find exposed credentials and API keys', path: '/code/secrets-detection', icon: <Shield className="w-4 h-4" />, category: 'Discover', keywords: ['secrets', 'credentials', 'api', 'keys', 'tokens'] },
  { id: 'cloud-posture', label: 'Cloud Posture (CSPM)', description: 'Cloud Security Posture Management', path: '/cloud/cloud-posture', icon: <Cloud className="w-4 h-4" />, category: 'Discover', keywords: ['cloud', 'cspm', 'aws', 'azure', 'gcp'] },
  { id: 'inventory', label: 'Asset Inventory', description: 'Application and infrastructure inventory', path: '/code/inventory', icon: <BarChart3 className="w-4 h-4" />, category: 'Discover', keywords: ['inventory', 'assets', 'applications'] },
  { id: 'threat-feeds', label: 'Threat Intelligence Feeds', description: 'NVD, KEV, EPSS, OSV intelligence feeds', path: '/cloud/threat-feeds', icon: <Radio className="w-4 h-4" />, category: 'Discover', keywords: ['feeds', 'nvd', 'kev', 'epss', 'threat', 'intel'] },
  { id: 'live-feeds', label: 'Live Feed Dashboard', description: 'Real-time threat intelligence stream', path: '/feeds/live', icon: <Radio className="w-4 h-4" />, category: 'Discover', keywords: ['live', 'feed', 'stream', 'real-time'] },

  // Validate
  { id: 'mpte', label: 'MPTE Console', description: 'Micro Pen-Test Engine for exploit verification', path: '/attack/mpte', icon: <Swords className="w-4 h-4" />, category: 'Validate', keywords: ['mpte', 'pentest', 'exploit', 'verification'] },
  { id: 'attack-simulation', label: 'Attack Simulation', description: 'Simulate real-world attack scenarios', path: '/attack/attack-simulation', icon: <FlaskConical className="w-4 h-4" />, category: 'Validate', keywords: ['attack', 'simulation', 'scenario'] },
  { id: 'attack-paths', label: 'Attack Paths (GNN)', description: 'Graph neural network attack path analysis', path: '/attack/attack-paths', icon: <Network className="w-4 h-4" />, category: 'Validate', keywords: ['attack', 'path', 'gnn', 'graph'] },
  { id: 'reachability', label: 'Reachability Analysis', description: 'Determine if vulnerabilities are reachable', path: '/attack/reachability', icon: <Target className="w-4 h-4" />, category: 'Validate', keywords: ['reachability', 'exploitable', 'reachable'] },
  { id: 'sandbox', label: 'Sandbox Verification', description: 'PoC exploit verification in isolated sandbox', path: '/attack/sandbox', icon: <FlaskConical className="w-4 h-4" />, category: 'Validate', keywords: ['sandbox', 'poc', 'verify', 'docker'] },

  // Remediate
  { id: 'autofix', label: 'AutoFix Center', description: 'AI-generated code fixes with confidence levels', path: '/protect/autofix', icon: <Zap className="w-4 h-4" />, category: 'Remediate', keywords: ['autofix', 'fix', 'patch', 'remediate', 'ai'] },
  { id: 'remediation', label: 'Remediation Tasks', description: 'Track and manage remediation efforts', path: '/protect/remediation', icon: <Wrench className="w-4 h-4" />, category: 'Remediate', keywords: ['remediation', 'tasks', 'fix', 'resolve'] },
  { id: 'playbooks', label: 'Playbooks & Campaigns', description: 'Automated security response playbooks', path: '/protect/playbooks', icon: <ClipboardList className="w-4 h-4" />, category: 'Remediate', keywords: ['playbook', 'automation', 'workflow', 'campaign'] },
  { id: 'workflows', label: 'Workflows', description: 'Manage remediation workflows', path: '/protect/workflows', icon: <Zap className="w-4 h-4" />, category: 'Remediate', keywords: ['workflow', 'automation', 'process'] },
  { id: 'integrations', label: 'Integrations', description: 'Connect Jira, Slack, GitHub, and more', path: '/protect/integrations', icon: <Wrench className="w-4 h-4" />, category: 'Remediate', keywords: ['jira', 'slack', 'github', 'integration', 'connect'] },
  { id: 'collaboration', label: 'Collaboration', description: 'Team collaboration on security issues', path: '/protect/collaboration', icon: <Users className="w-4 h-4" />, category: 'Remediate', keywords: ['collaboration', 'team', 'discuss'] },

  // Comply
  { id: 'evidence-bundles', label: 'Evidence Bundles', description: 'Cryptographically signed evidence packages', path: '/evidence/bundles', icon: <FileText className="w-4 h-4" />, category: 'Comply', keywords: ['evidence', 'bundle', 'crypto', 'signed'] },
  { id: 'compliance', label: 'Compliance Reports', description: 'SOC2, PCI-DSS, HIPAA compliance', path: '/evidence/compliance', icon: <Scale className="w-4 h-4" />, category: 'Comply', keywords: ['compliance', 'soc2', 'pci', 'hipaa', 'report'] },
  { id: 'soc2', label: 'SOC2 Evidence', description: 'SOC2 Type II evidence collection', path: '/evidence/soc2', icon: <Shield className="w-4 h-4" />, category: 'Comply', keywords: ['soc2', 'evidence', 'audit'] },
  { id: 'audit-logs', label: 'Audit Trail', description: 'Immutable audit log with crypto verification', path: '/evidence/audit-trail', icon: <ScrollText className="w-4 h-4" />, category: 'Comply', keywords: ['audit', 'log', 'trail', 'immutable'] },
  { id: 'reports', label: 'Reports', description: 'Generate and export security reports', path: '/evidence/reports', icon: <FileText className="w-4 h-4" />, category: 'Comply', keywords: ['report', 'export', 'pdf', 'csv'] },

  // AI Engine
  { id: 'predictions', label: 'Predictions', description: 'Risk trajectory and attack chain prediction', path: '/ai-engine/predictions', icon: <TrendingUp className="w-4 h-4" />, category: 'AI Engine', keywords: ['predictions', 'forecast', 'trajectory', 'risk'] },
  { id: 'policies', label: 'Policy Engine', description: 'Security policies and governance rules', path: '/ai-engine/policies', icon: <Scale className="w-4 h-4" />, category: 'AI Engine', keywords: ['policy', 'governance', 'rules', 'engine'] },
  { id: 'ml-dashboard', label: 'ML Dashboard', description: 'Machine learning models and anomaly detection', path: '/ai-engine/ml-dashboard', icon: <Cpu className="w-4 h-4" />, category: 'AI Engine', keywords: ['ml', 'machine', 'learning', 'anomaly', 'model'] },
  { id: 'copilot', label: 'AI Copilot', description: 'Natural language security assistant', path: '/copilot', icon: <Bot className="w-4 h-4" />, category: 'AI Engine', keywords: ['copilot', 'ai', 'assistant', 'chat', 'query'] },

  // Settings
  { id: 'settings', label: 'Settings', description: 'Application configuration', path: '/settings', icon: <Settings className="w-4 h-4" />, category: 'Settings', keywords: ['settings', 'config', 'preferences'] },
  { id: 'users', label: 'User Management', description: 'Manage users and roles', path: '/settings/users', icon: <Users className="w-4 h-4" />, category: 'Settings', keywords: ['users', 'roles', 'permissions'] },
  { id: 'system-health', label: 'System Health', description: 'Monitor system components and health', path: '/settings/system-health', icon: <BarChart3 className="w-4 h-4" />, category: 'Settings', keywords: ['health', 'system', 'status', 'monitor'] },
];

const CATEGORY_COLORS: Record<string, string> = {
  'Mission Control': 'text-blue-400',
  'Discover': 'text-emerald-400',
  'Validate': 'text-orange-400',
  'Remediate': 'text-purple-400',
  'Comply': 'text-cyan-400',
  'AI Engine': 'text-pink-400',
  'Settings': 'text-gray-400',
};

export default function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // Filter items based on query
  const filteredItems = useMemo(() => {
    if (!query.trim()) return COMMAND_ITEMS;
    const q = query.toLowerCase();
    return COMMAND_ITEMS.filter(item =>
      item.label.toLowerCase().includes(q) ||
      item.description.toLowerCase().includes(q) ||
      item.category.toLowerCase().includes(q) ||
      item.keywords.some(k => k.includes(q))
    );
  }, [query]);

  // Group by category
  const groupedItems = useMemo(() => {
    const groups: Record<string, CommandItem[]> = {};
    filteredItems.forEach(item => {
      if (!groups[item.category]) groups[item.category] = [];
      groups[item.category].push(item);
    });
    return groups;
  }, [filteredItems]);

  // Flatten for keyboard navigation
  const flatItems = useMemo(() => {
    const flat: CommandItem[] = [];
    Object.values(groupedItems).forEach(items => flat.push(...items));
    return flat;
  }, [groupedItems]);

  // Global keyboard shortcut
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setOpen(prev => !prev);
        setQuery('');
        setSelectedIndex(0);
      }
      if (e.key === 'Escape' && open) {
        setOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open]);

  // Focus input when opened
  useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  // Scroll selected item into view
  useEffect(() => {
    if (listRef.current && flatItems.length > 0) {
      const selectedEl = listRef.current.querySelector(`[data-index="${selectedIndex}"]`);
      selectedEl?.scrollIntoView({ block: 'nearest' });
    }
  }, [selectedIndex, flatItems.length]);

  const handleSelect = useCallback((item: CommandItem) => {
    navigate(item.path);
    setOpen(false);
    setQuery('');
  }, [navigate]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex(prev => (prev + 1) % flatItems.length);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex(prev => (prev - 1 + flatItems.length) % flatItems.length);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (flatItems[selectedIndex]) {
        handleSelect(flatItems[selectedIndex]);
      }
    }
  }, [flatItems, selectedIndex, handleSelect]);

  // Reset selection when query changes
  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  if (!open) return null;

  let flatIndex = -1;

  return (
    <AnimatePresence>
      {open && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50"
            onClick={() => setOpen(false)}
          />

          {/* Palette */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: -20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: -20 }}
            transition={{ type: 'spring', stiffness: 400, damping: 30 }}
            className="fixed top-[15%] left-1/2 -translate-x-1/2 w-full max-w-2xl z-50"
          >
            <div className="bg-gray-900/95 border border-gray-700/50 rounded-2xl shadow-2xl overflow-hidden backdrop-blur-xl">
              {/* Search Input */}
              <div className="flex items-center gap-3 px-5 py-4 border-b border-gray-700/50">
                <Search className="w-5 h-5 text-gray-400 flex-shrink-0" />
                <input
                  ref={inputRef}
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Search pages, features, actions..."
                  className="flex-1 bg-transparent text-gray-100 text-lg placeholder:text-gray-500 outline-none"
                  autoComplete="off"
                  spellCheck={false}
                />
                <div className="flex items-center gap-1">
                  <kbd className="px-1.5 py-0.5 bg-gray-800 border border-gray-600 rounded text-[10px] text-gray-400 font-mono">ESC</kbd>
                </div>
              </div>

              {/* Results */}
              <div ref={listRef} className="max-h-[400px] overflow-y-auto py-2">
                {flatItems.length === 0 ? (
                  <div className="px-5 py-12 text-center">
                    <Search className="w-10 h-10 text-gray-600 mx-auto mb-3" />
                    <p className="text-gray-400 font-medium">No results found</p>
                    <p className="text-gray-500 text-sm mt-1">Try searching for &ldquo;scanner&rdquo;, &ldquo;autofix&rdquo;, or &ldquo;compliance&rdquo;</p>
                  </div>
                ) : (
                  Object.entries(groupedItems).map(([category, items]) => (
                    <div key={category}>
                      <div className={`px-5 py-1.5 text-xs font-semibold uppercase tracking-wider ${CATEGORY_COLORS[category] || 'text-gray-500'}`}>
                        {category}
                      </div>
                      {items.map((item) => {
                        flatIndex++;
                        const currentIndex = flatIndex;
                        const isSelected = currentIndex === selectedIndex;
                        return (
                          <div
                            key={item.id}
                            data-index={currentIndex}
                            onClick={() => handleSelect(item)}
                            onMouseEnter={() => setSelectedIndex(currentIndex)}
                            className={`flex items-center gap-3 px-5 py-2.5 cursor-pointer transition-colors ${
                              isSelected ? 'bg-indigo-500/15 text-white' : 'text-gray-300 hover:bg-gray-800/50'
                            }`}
                          >
                            <div className={`flex-shrink-0 ${isSelected ? 'text-indigo-400' : 'text-gray-500'}`}>
                              {item.icon}
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="font-medium text-sm truncate">{item.label}</div>
                              <div className="text-xs text-gray-500 truncate">{item.description}</div>
                            </div>
                            {isSelected && (
                              <ArrowRight className="w-4 h-4 text-indigo-400 flex-shrink-0" />
                            )}
                          </div>
                        );
                      })}
                    </div>
                  ))
                )}
              </div>

              {/* Footer */}
              <div className="flex items-center justify-between px-5 py-2.5 border-t border-gray-700/50 bg-gray-900/50">
                <div className="flex items-center gap-4 text-xs text-gray-500">
                  <span className="flex items-center gap-1">
                    <kbd className="px-1 py-0.5 bg-gray-800 border border-gray-700 rounded text-[10px] font-mono">↑↓</kbd>
                    Navigate
                  </span>
                  <span className="flex items-center gap-1">
                    <kbd className="px-1 py-0.5 bg-gray-800 border border-gray-700 rounded text-[10px] font-mono">↵</kbd>
                    Open
                  </span>
                  <span className="flex items-center gap-1">
                    <kbd className="px-1 py-0.5 bg-gray-800 border border-gray-700 rounded text-[10px] font-mono">esc</kbd>
                    Close
                  </span>
                </div>
                <div className="flex items-center gap-1.5 text-xs text-gray-500">
                  <Command className="w-3 h-3" />
                  <span>{flatItems.length} results</span>
                </div>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
