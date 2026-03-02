import { useState, useRef, useEffect, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Bot, Send, User, Loader2, Sparkles, Trash2,
  Brain, Shield, Code, FileText, TrendingUp,
  AlertTriangle, Zap,
  MessageSquare, Copy, ChevronDown,
} from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Skeleton } from '@/components/ui/skeleton';
import {
  feedsApi, algorithmsApi, systemApi, mpteApi, complianceApi,
  reachabilityApi, api,
} from '../lib/api';
import { toast } from 'sonner';

// ── Animation ───────────────────────────────────────────────────────────────

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.05 } },
};
const itemVariants = {
  hidden: { opacity: 0, y: 12 },
  visible: { opacity: 1, y: 0, transition: { type: 'spring' as const, stiffness: 200, damping: 22 } },
};
const easeOutExpo = [0.16, 1, 0.3, 1];

// ── Interfaces ──────────────────────────────────────────────────────────────

interface Message {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: Date;
  sources?: string[];
  isStreaming?: boolean;
}

interface QuickAction {
  icon: React.ElementType;
  label: string;
  description: string;
  query: string;
  category: 'intelligence' | 'scan' | 'compliance' | 'remediation';
}

// ── Quick Actions ───────────────────────────────────────────────────────────

const quickActions: QuickAction[] = [
  {
    icon: Shield,
    label: 'System Health',
    description: 'Check API and service status',
    query: 'What is the current system health status?',
    category: 'intelligence',
  },
  {
    icon: TrendingUp,
    label: 'EPSS Scores',
    description: 'Exploit prediction data',
    query: 'Show me the latest EPSS exploitation scores',
    category: 'intelligence',
  },
  {
    icon: AlertTriangle,
    label: 'KEV Database',
    description: 'Known exploited vulnerabilities',
    query: 'What are the latest known exploited vulnerabilities?',
    category: 'intelligence',
  },
  {
    icon: Brain,
    label: 'Algorithm Lab',
    description: 'Available prioritization engines',
    query: 'What prioritization algorithms are available?',
    category: 'intelligence',
  },
  {
    icon: Zap,
    label: 'Attack Simulation',
    description: 'MPTE & pentest status',
    query: 'Show me the attack simulation and MPTE capabilities',
    category: 'scan',
  },
  {
    icon: FileText,
    label: 'Compliance Status',
    description: 'Framework compliance check',
    query: 'What is our current compliance status across all frameworks?',
    category: 'compliance',
  },
  {
    icon: Code,
    label: 'Remediation Help',
    description: 'Get fix recommendations',
    query: 'How can I remediate my top critical vulnerabilities?',
    category: 'remediation',
  },
  {
    icon: MessageSquare,
    label: 'Reachability',
    description: 'Attack surface exposure',
    query: 'Analyze my attack surface and reachability metrics',
    category: 'scan',
  },
];

// ── Category colors ─────────────────────────────────────────────────────────

const categoryColors: Record<string, string> = {
  intelligence: 'from-blue-500/20 to-blue-500/5 border-blue-500/20',
  scan: 'from-purple-500/20 to-purple-500/5 border-purple-500/20',
  compliance: 'from-emerald-500/20 to-emerald-500/5 border-emerald-500/20',
  remediation: 'from-amber-500/20 to-amber-500/5 border-amber-500/20',
};

// ── Simple markdown-like renderer ───────────────────────────────────────────

function RenderMarkdown({ content }: { content: string }) {
  const lines = content.split('\n');
  const elements: React.ReactNode[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Bold headers **text**
    if (line.startsWith('**') && line.endsWith('**')) {
      elements.push(
        <h4 key={i} className="font-semibold text-foreground mt-3 first:mt-0 mb-1">
          {line.replace(/\*\*/g, '')}
        </h4>
      );
    }
    // Bullet points
    else if (line.startsWith('- ') || line.startsWith('• ')) {
      elements.push(
        <div key={i} className="flex items-start gap-2 text-sm text-muted-foreground ml-2">
          <span className="text-primary mt-1">•</span>
          <span>{line.replace(/^[-•]\s*/, '').replace(/\*\*(.*?)\*\*/g, '$1')}</span>
        </div>
      );
    }
    // Empty line
    else if (line.trim() === '') {
      elements.push(<div key={i} className="h-2" />);
    }
    // Regular text
    else {
      elements.push(
        <p key={i} className="text-sm text-muted-foreground">
          {line.replace(/\*\*(.*?)\*\*/g, '$1')}
        </p>
      );
    }
  }

  return <div className="space-y-0.5">{elements}</div>;
}

// ── Typing indicator ────────────────────────────────────────────────────────

function TypingIndicator() {
  return (
    <div className="flex items-center gap-1.5 px-3 py-2">
      {[0, 1, 2].map((i) => (
        <motion.div
          key={i}
          className="w-1.5 h-1.5 rounded-full bg-primary/60"
          animate={{ y: [0, -4, 0] }}
          transition={{ duration: 0.6, repeat: Infinity, delay: i * 0.15 }}
        />
      ))}
    </div>
  );
}

// ── Skeleton ────────────────────────────────────────────────────────────────

function CopilotSkeleton() {
  return (
    <div className="space-y-6 p-6">
      {/* Header skeleton */}
      <div className="flex items-center justify-between">
        <div className="space-y-2">
          <Skeleton className="h-9 w-64" />
          <Skeleton className="h-5 w-96" />
        </div>
        <Skeleton className="h-10 w-28" />
      </div>
      {/* Quick actions skeleton */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[1, 2, 3, 4].map((i) => (
          <Skeleton key={i} className="h-24 rounded-xl" />
        ))}
      </div>
      {/* Chat area skeleton */}
      <Skeleton className="h-[500px] rounded-xl" />
    </div>
  );
}

// ── Main Component ──────────────────────────────────────────────────────────

export default function Copilot() {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'welcome',
      role: 'system',
      content: `Welcome to **ALdeci AI Copilot**

I'm your security intelligence assistant. I can help you with:

- **Vulnerability Analysis** — Search and analyze CVEs with EPSS & KEV data
- **Risk Prioritization** — Use multi-algorithm scoring (CVSS, EPSS, SSVC)
- **Attack Simulation** — Check MPTE capabilities and exploit validation
- **Compliance Mapping** — Generate evidence for SOC2, PCI-DSS, HIPAA
- **Remediation Guidance** — Get AI-powered fix recommendations

Ask me anything or use the quick actions below to get started.`,
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [showQuickActions, setShowQuickActions] = useState(true);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Fetch copilot health to show status
  const { data: copilotHealth } = useQuery({
    queryKey: ['copilot-health'],
    queryFn: () => api.get('/api/v1/copilot/health').then((r) => r.data),
    retry: 1,
    refetchInterval: 60000,
  });

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Auto-focus input
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  // ── AI Query Router ─────────────────────────────────────────────────────

  const routeQuery = useCallback(async (query: string): Promise<string> => {
    const q = query.toLowerCase();

    if (q.includes('status') || q.includes('health')) {
      const health = await systemApi.getHealth();
      const status = await systemApi.getStatus();
      return `**System Health: ${(health.status || 'healthy').toUpperCase()}**

- Service: ${health.service || 'ALdeci API Gateway'}
- Version: ${status.version || health.version || 'N/A'}
- Uptime: ${status.uptime || 'Active'}
- Mode: ${status.mode || 'Enterprise'}
- Timestamp: ${new Date().toLocaleString()}

All core services are operational. Navigate to Settings → System Health for detailed service monitoring.`;
    }

    if (q.includes('epss') || q.includes('exploit prediction') || q.includes('exploitation')) {
      const epss = await feedsApi.getEPSS();
      const count = epss?.scores?.length || epss?.count || 0;
      const topScores = (epss?.scores || []).slice(0, 5);
      const topList = topScores
        .map((s: Record<string, unknown>) => `- ${s.cve || s.cve_id}: EPSS ${((Number(s.epss ?? s.score ?? 0)) * 100).toFixed(2)}%`)
        .join('\n');
      return `**EPSS Exploitation Scoring**

- Total scores loaded: **${count}**
- Last updated: ${epss?.last_updated || 'Recently'}

${topList ? `**Top High-Risk CVEs:**\n${topList}` : ''}

EPSS predicts the likelihood of a vulnerability being exploited in the next 30 days. Higher scores = higher priority for remediation.

Navigate to Intelligence Hub for full EPSS analysis.`;
    }

    if (q.includes('kev') || q.includes('known exploited')) {
      const kev = await feedsApi.getKEV();
      const count = kev?.total_kev_entries || kev?.vulnerabilities?.length || 0;
      const recentKevs = (kev?.vulnerabilities || []).slice(0, 3);
      const kevList = recentKevs
        .map((v: Record<string, string>) => `- **${v.cve_id || v.cve}**: ${v.vulnerability_name || v.name || 'N/A'}`)
        .join('\n');
      return `**CISA Known Exploited Vulnerabilities (KEV)**

- Total KEV entries: **${count}**
- Source: CISA KEV Catalog

${kevList ? `**Recent Additions:**\n${kevList}` : ''}

KEV vulnerabilities have **confirmed active exploitation** in the wild. CISA mandates remediation within specific timelines for federal agencies. These should be your #1 priority.

Navigate to Intelligence Hub → Known Exploited tab for full catalog.`;
    }

    if (q.includes('algorithm') || q.includes('capabilities') || q.includes('prioritiz')) {
      const caps = await algorithmsApi.getCapabilities();
      const algos = caps?.algorithms?.map((a: Record<string, string>) => `- **${a.name || a}**: ${a.description || 'Available'}`).join('\n') || '- CVSS, EPSS, SSVC, KEV, Monte Carlo';
      return `**Prioritization Algorithms**

${algos}

**Key Differentiators:**
- Multi-factor analysis combining CVSS + EPSS + KEV + business context
- Monte Carlo risk quantification for financial impact
- Causal analysis to identify root-cause vulnerabilities
- SSVC decision trees for stakeholder-specific prioritization

Navigate to AI Engine → Algorithmic Lab to configure your strategy.`;
    }

    if (q.includes('pentest') || q.includes('attack') || q.includes('mpte') || q.includes('simulat')) {
      try {
        const configs = await mpteApi.getConfigs();
        return `**MPTE & Attack Simulation**

- Configurations: ${Array.isArray(configs) ? configs.length : 'Available'}
- Mode: Safe sandbox testing (no production impact)

**Capabilities:**
- Automated CVE exploit validation (19-phase pipeline)
- Micro-penetration testing with proof-of-concept
- Attack path analysis via GNN graph algorithms
- Sandbox verification for safe exploit testing

Navigate to Attack Suite → MPTE Console for live attack validation.`;
      } catch {
        return `**Attack Simulation Capabilities**

ALdeci provides comprehensive offensive security testing:
- **MPTE Console**: 19-phase micro-pentest pipeline
- **Sandbox Verification**: Docker-isolated PoC execution
- **Attack Path Analysis**: GNN-powered path visualization
- **Reachability Analysis**: Attack surface mapping

Navigate to Attack Suite to begin testing.`;
      }
    }

    if (q.includes('compliance') || q.includes('pci') || q.includes('soc') || q.includes('hipaa')) {
      try {
        const status = await complianceApi.getStatus();
        const frameworks = status?.frameworks?.map(
          (f: Record<string, unknown>) => `- **${f.name}**: ${f.compliance_percentage || 0}% compliant`
        ).join('\n') || '- PCI DSS 4.0\n- SOC 2 Type II\n- HIPAA\n- NIST CSF';
        return `**Compliance Framework Status**

${frameworks}

**Evidence Collection:**
- Cryptographically signed evidence bundles (RSA-SHA256)
- SLSA provenance chain
- Audit trail with tamper-proof hashes
- One-click evidence export for auditors

Navigate to Evidence Suite → Compliance Reports for detailed controls.`;
      } catch {
        return `**Compliance Mapping Available**

Supported frameworks:
- **PCI DSS 4.0** — Payment card industry security
- **SOC 2 Type II** — Service organization controls
- **HIPAA** — Healthcare data protection
- **NIST CSF** — Cybersecurity framework
- **ISO 27001** — Information security management
- **SLSA** — Supply chain integrity

Navigate to Evidence Suite for reports and evidence packages.`;
      }
    }

    if (q.includes('reachability') || q.includes('exposure') || q.includes('surface')) {
      try {
        const metrics = await reachabilityApi.getMetrics();
        return `**Reachability & Attack Surface Analysis**

- Analyzed assets: ${metrics?.total_assets || 'Available'}
- Exposed services: ${metrics?.exposed_services || 'N/A'}
- Protected: ${metrics?.protected_assets || 'N/A'}
- Coverage: ${metrics?.coverage_percent ? `${metrics.coverage_percent}%` : 'N/A'}

Reachability analysis determines which vulnerabilities are **actually exploitable** by tracing network paths from external attack surfaces to vulnerable components.

Navigate to Cloud Suite → Attack Paths for visualization.`;
      } catch {
        return `**Attack Surface Analysis**

Determines which vulnerabilities can actually be exploited:
- Network path analysis from external to internal
- Service exposure mapping
- Defense layer evaluation
- Blast radius calculation

Navigate to Attack Suite → Surface Monitoring for insights.`;
      }
    }

    if (q.includes('remediat') || q.includes('fix') || q.includes('patch') || q.includes('autofix')) {
      return `**Remediation & AutoFix Center**

ALdeci provides AI-powered remediation:

**AutoFix Engine (10 Fix Types):**
- Dependency upgrade patches
- Secure coding pattern fixes
- Configuration hardening
- Input validation injection
- Authentication flow fixes
- Authorization policy updates
- Encryption upgrades
- API security patches
- Container security fixes
- Infrastructure as Code remediations

**Confidence Levels:**
- 🟢 HIGH — Safe to auto-apply
- 🟡 MEDIUM — Review recommended
- 🔴 LOW — Manual review required

Navigate to Protect Suite → AutoFix Dashboard for fix generation.`;
    }

    // Fallback
    return `I can help you with security intelligence across the ALdeci platform:

**Quick Commands:**
- "Check system health" — Service status overview
- "Show EPSS scores" — Exploitation probability data
- "Check KEV database" — Known exploited vulnerabilities
- "Compliance status" — Framework compliance check
- "Attack capabilities" — MPTE and pentest tools
- "Remediation help" — AutoFix and fix generation

**Pro Tip:** You can also ask specific questions like "Is CVE-2024-3400 in the KEV database?" or "What's our PCI compliance score?"

What would you like to explore?`;
  }, []);

  // ── Send Message ────────────────────────────────────────────────────────

  const handleSend = async (overrideInput?: string) => {
    const text = (overrideInput || input).trim();
    if (!text || isLoading) return;

    const userMsg: Message = {
      id: crypto.randomUUID(),
      role: 'user',
      content: text,
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setIsLoading(true);
    setShowQuickActions(false);

    try {
      const response = await routeQuery(text);

      const assistantMsg: Message = {
        id: crypto.randomUUID(),
        role: 'assistant',
        content: response,
        timestamp: new Date(),
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (error: unknown) {
      const errObj = error as { response?: { status?: number } };
      const fallback = await routeQuery('help');
      const assistantMsg: Message = {
        id: crypto.randomUUID(),
        role: 'assistant',
        content: fallback,
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, assistantMsg]);

      if (errObj.response?.status !== 404) {
        toast.error('API service unavailable, using local intelligence');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleClear = () => {
    setMessages([
      {
        id: 'welcome',
        role: 'system',
        content: 'Session cleared. How can I help you?',
        timestamp: new Date(),
      },
    ]);
    setShowQuickActions(true);
    toast.success('Chat history cleared');
  };

  const copyMessage = (content: string) => {
    navigator.clipboard.writeText(content);
    toast.success('Copied to clipboard');
  };

  // ── Loading state ─────────────────────────────────────────────────────

  const isInitializing = false; // No session init needed for local routing
  if (isInitializing) return <CopilotSkeleton />;

  return (
    <motion.div
      initial={{ opacity: 0, y: 12, scale: 0.995 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.5, ease: easeOutExpo }}
      className="h-full flex flex-col relative"
    >
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-gray-700/30">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border border-indigo-500/30 flex items-center justify-center">
            <Sparkles className="w-5 h-5 text-indigo-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2">
              AI Copilot
              <Badge
                variant="outline"
                className={`text-[10px] px-1.5 py-0 h-4 ${
                  copilotHealth?.status === 'healthy'
                    ? 'border-green-500/30 text-green-400'
                    : 'border-yellow-500/30 text-yellow-400'
                }`}
              >
                {copilotHealth?.status === 'healthy' ? 'ONLINE' : 'LOCAL'}
              </Badge>
            </h1>
            <p className="text-xs text-muted-foreground">
              Security intelligence assistant — ask anything about your posture
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={handleClear}
            className="gap-1.5 text-xs text-muted-foreground hover:text-foreground"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Clear
          </Button>
        </div>
      </div>

      {/* Quick Actions (shown when no conversation) */}
      <AnimatePresence>
        {showQuickActions && messages.length <= 1 && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="px-6 pt-4 overflow-hidden"
          >
            <p className="text-xs text-muted-foreground uppercase tracking-wider mb-3">
              Quick Actions
            </p>
            <motion.div
              variants={containerVariants}
              initial="hidden"
              animate="visible"
              className="grid grid-cols-2 lg:grid-cols-4 gap-2"
            >
              {quickActions.map((action) => {
                const Icon = action.icon;
                return (
                  <motion.button
                    key={action.label}
                    variants={itemVariants}
                    whileHover={{ scale: 1.02, y: -2 }}
                    whileTap={{ scale: 0.98 }}
                    onClick={() => handleSend(action.query)}
                    className={`p-3 rounded-xl bg-gradient-to-br ${categoryColors[action.category]} border text-left transition-all hover:shadow-lg hover:shadow-primary/5`}
                  >
                    <Icon className="w-4 h-4 text-primary mb-1.5" />
                    <p className="text-sm font-medium">{action.label}</p>
                    <p className="text-[11px] text-muted-foreground line-clamp-1">
                      {action.description}
                    </p>
                  </motion.button>
                );
              })}
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Messages */}
      <ScrollArea className="flex-1 px-6 py-4">
        <div className="space-y-4 max-w-3xl mx-auto">
          {messages.map((msg) => (
            <motion.div
              key={msg.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ type: 'spring', stiffness: 200, damping: 22 }}
              className={`flex gap-3 group ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}
            >
              {/* Avatar */}
              <div
                className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${
                  msg.role === 'user'
                    ? 'bg-indigo-500/20 border border-indigo-500/30'
                    : msg.role === 'system'
                    ? 'bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border border-indigo-500/30'
                    : 'bg-gray-800/60 border border-gray-700/30'
                }`}
              >
                {msg.role === 'user' ? (
                  <User className="w-4 h-4 text-indigo-400" />
                ) : (
                  <Bot className="w-4 h-4 text-indigo-400" />
                )}
              </div>

              {/* Bubble */}
              <div
                className={`flex-1 max-w-[85%] rounded-xl p-4 relative ${
                  msg.role === 'user'
                    ? 'bg-indigo-500/15 border border-indigo-500/20'
                    : 'bg-gray-800/40 border border-gray-700/20'
                }`}
              >
                <RenderMarkdown content={msg.content} />
                <div className="flex items-center justify-between mt-2 pt-2 border-t border-gray-700/10">
                  <span className="text-[10px] text-muted-foreground/60">
                    {msg.timestamp.toLocaleTimeString()}
                  </span>
                  {msg.role === 'assistant' && (
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-5 w-5 opacity-0 group-hover:opacity-100 transition-opacity"
                      onClick={() => copyMessage(msg.content)}
                    >
                      <Copy className="w-3 h-3" />
                    </Button>
                  )}
                </div>
              </div>
            </motion.div>
          ))}

          {/* Typing indicator */}
          {isLoading && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="flex gap-3"
            >
              <div className="w-8 h-8 rounded-lg bg-gray-800/60 border border-gray-700/30 flex items-center justify-center">
                <Bot className="w-4 h-4 text-indigo-400" />
              </div>
              <div className="bg-gray-800/40 border border-gray-700/20 rounded-xl px-4 py-3">
                <TypingIndicator />
              </div>
            </motion.div>
          )}

          <div ref={messagesEndRef} />
        </div>
      </ScrollArea>

      {/* Conversation starters (after messages) */}
      {!showQuickActions && messages.length > 1 && !isLoading && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="px-6 pb-2"
        >
          <button
            onClick={() => setShowQuickActions(true)}
            className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            <ChevronDown className="w-3 h-3" />
            Show quick actions
          </button>
        </motion.div>
      )}

      {/* Input Area */}
      <div className="px-6 pb-6 pt-2">
        <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
          <CardContent className="p-3">
            <div className="flex items-end gap-2">
              <textarea
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask about vulnerabilities, compliance, risk scores..."
                disabled={isLoading}
                rows={1}
                className="flex-1 resize-none bg-transparent border-none outline-none text-sm text-foreground placeholder:text-muted-foreground/50 min-h-[36px] max-h-[120px] py-2 px-1"
                style={{ fieldSizing: 'content' } as React.CSSProperties}
              />
              <Button
                onClick={() => handleSend()}
                disabled={!input.trim() || isLoading}
                size="icon"
                className="h-9 w-9 rounded-lg bg-indigo-500 hover:bg-indigo-600 flex-shrink-0"
              >
                {isLoading ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Send className="w-4 h-4" />
                )}
              </Button>
            </div>
            <div className="flex items-center justify-between mt-2 px-1">
              <span className="text-[10px] text-muted-foreground/50">
                Press Enter to send, Shift+Enter for new line
              </span>
              <span className="text-[10px] text-muted-foreground/50">
                Powered by ALdeci Brain Engine
              </span>
            </div>
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
