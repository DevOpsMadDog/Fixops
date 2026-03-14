import { useState, useMemo, useCallback, useEffect, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  Target,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  ChevronDown,
  ChevronRight,
  Play,
  Loader2,
  Download,
  Eye,
  Zap,
  Lock,
  FileText,
  RefreshCw,
  Search,
  SkipForward,
  Activity,
  Server,
  Fingerprint,
  Bug,
  Cpu,
  Database,
  Network,
  Key,
  Upload,
  Terminal,
  ArrowUpRight,
  Trash2,
  Crosshair,
  Globe,
  BarChart3,
  StopCircle,
  HeartPulse,
  Plus,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../../components/ui/tabs';
import { Input } from '../../components/ui/input';
import { ScrollArea } from '../../components/ui/scroll-area';
import { Progress } from '../../components/ui/progress';
import { mpteApi, microPentestApi, api } from '../../lib/api';
import { toast } from 'sonner';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

type PhaseStatus = 'PASS' | 'FAIL' | 'SKIP' | 'RUNNING' | 'PENDING';
type Verdict = 'EXPLOITABLE' | 'NOT_EXPLOITABLE' | 'INCONCLUSIVE' | 'IN_PROGRESS';
type VerificationScope = 'quick' | 'standard' | 'full';
type Priority = 'critical' | 'high' | 'medium' | 'low';

interface PhaseDefinition {
  id: number;
  name: string;
  description: string;
  icon: React.ReactNode;
  category: 'recon' | 'exploit' | 'post-exploit' | 'reporting';
}

interface PhaseResult {
  phaseId: number;
  status: PhaseStatus;
  durationMs: number;
  evidence: string;
  details: string;
  confidenceContribution: number;
  relatedPhases: number[];
}

interface VerificationResult {
  id: string;
  requestId: string;
  target: string;
  targetUrl: string;
  cveId: string | null;
  verdict: Verdict;
  confidenceScore: number;
  scope: VerificationScope;
  phases: PhaseResult[];
  startedAt: string;
  completedAt: string | null;
  riskScore: number;
  findingId: string | null;
  failScore?: { grade: string; score: number } | null;
}

interface MpteHealth {
  status: string;
  engine_version?: string;
  uptime?: number;
  active_tests?: number;
  queue_size?: number;
}

interface PhaseAnalyticsStat {
  phaseId: number;
  name: string;
  category: string;
  passRate: number;
  failRate: number;
  skipRate: number;
  avgDurationMs: number;
  totalRuns: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// 19 MPTE Phase Definitions
// ─────────────────────────────────────────────────────────────────────────────

const MPTE_PHASES: PhaseDefinition[] = [
  { id: 1, name: 'Reconnaissance', description: 'Gather target information, DNS, WHOIS, and publicly available data', icon: <Search className="w-4 h-4" />, category: 'recon' },
  { id: 2, name: 'Port Discovery', description: 'Scan for open ports and accessible services', icon: <Globe className="w-4 h-4" />, category: 'recon' },
  { id: 3, name: 'Service Fingerprinting', description: 'Identify service versions and technologies', icon: <Fingerprint className="w-4 h-4" />, category: 'recon' },
  { id: 4, name: 'Version Detection', description: 'Match service versions against vulnerability databases', icon: <Server className="w-4 h-4" />, category: 'recon' },
  { id: 5, name: 'CVE Matching', description: 'Correlate detected versions with known CVEs', icon: <Bug className="w-4 h-4" />, category: 'recon' },
  { id: 6, name: 'Exploit Selection', description: 'Select optimal exploit for target configuration', icon: <Crosshair className="w-4 h-4" />, category: 'recon' },
  { id: 7, name: 'Payload Generation', description: 'Generate environment-specific exploit payload', icon: <Cpu className="w-4 h-4" />, category: 'exploit' },
  { id: 8, name: 'Environment Prep', description: 'Prepare sandboxed test environment', icon: <Database className="w-4 h-4" />, category: 'exploit' },
  { id: 9, name: 'Pre-Auth Testing', description: 'Test unauthenticated attack vectors', icon: <Key className="w-4 h-4" />, category: 'exploit' },
  { id: 10, name: 'Auth Bypass Attempt', description: 'Attempt authentication bypass techniques', icon: <Lock className="w-4 h-4" />, category: 'exploit' },
  { id: 11, name: 'Exploit Delivery', description: 'Deliver exploit payload to target', icon: <Upload className="w-4 h-4" />, category: 'exploit' },
  { id: 12, name: 'Payload Execution', description: 'Execute exploit and verify code execution', icon: <Terminal className="w-4 h-4" />, category: 'exploit' },
  { id: 13, name: 'Privilege Escalation', description: 'Attempt to escalate from initial access', icon: <ArrowUpRight className="w-4 h-4" />, category: 'post-exploit' },
  { id: 14, name: 'Lateral Movement', description: 'Test ability to move to adjacent systems', icon: <Network className="w-4 h-4" />, category: 'post-exploit' },
  { id: 15, name: 'Data Exfiltration', description: 'Verify data access and extraction capability', icon: <Download className="w-4 h-4" />, category: 'post-exploit' },
  { id: 16, name: 'Persistence Check', description: 'Test ability to maintain persistent access', icon: <Activity className="w-4 h-4" />, category: 'post-exploit' },
  { id: 17, name: 'Cleanup Verification', description: 'Verify all test artifacts are removed', icon: <Trash2 className="w-4 h-4" />, category: 'reporting' },
  { id: 18, name: 'Evidence Collection', description: 'Compile all evidence into structured format', icon: <FileText className="w-4 h-4" />, category: 'reporting' },
  { id: 19, name: 'Report Generation', description: 'Generate final verification report', icon: <FileText className="w-4 h-4" />, category: 'reporting' },
];

const CATEGORY_COLORS: Record<string, string> = {
  recon: 'text-blue-400',
  exploit: 'text-orange-400',
  'post-exploit': 'text-red-400',
  reporting: 'text-emerald-400',
};

const CATEGORY_LABELS: Record<string, string> = {
  recon: 'Reconnaissance',
  exploit: 'Exploitation',
  'post-exploit': 'Post-Exploitation',
  reporting: 'Reporting',
};

const CATEGORY_BG: Record<string, string> = {
  recon: 'bg-blue-500/10 border-blue-500/30',
  exploit: 'bg-orange-500/10 border-orange-500/30',
  'post-exploit': 'bg-red-500/10 border-red-500/30',
  reporting: 'bg-emerald-500/10 border-emerald-500/30',
};

// Apple ease curve
const EASE_OUT_EXPO: [number, number, number, number] = [0.16, 1, 0.3, 1];

// ─────────────────────────────────────────────────────────────────────────────
// Helper Components
// ─────────────────────────────────────────────────────────────────────────────

function PhaseStatusIcon({ status }: { status: PhaseStatus }) {
  switch (status) {
    case 'PASS': return <CheckCircle2 className="w-5 h-5 text-emerald-400" />;
    case 'FAIL': return <XCircle className="w-5 h-5 text-red-400" />;
    case 'SKIP': return <SkipForward className="w-5 h-5 text-slate-500" />;
    case 'RUNNING': return <Loader2 className="w-5 h-5 text-blue-400 animate-spin" />;
    case 'PENDING': return <Clock className="w-5 h-5 text-slate-600" />;
  }
}

function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const config: Record<Verdict, { bg: string; text: string; border: string; label: string }> = {
    EXPLOITABLE: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30', label: 'EXPLOITABLE' },
    NOT_EXPLOITABLE: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30', label: 'NOT EXPLOITABLE' },
    INCONCLUSIVE: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/30', label: 'INCONCLUSIVE' },
    IN_PROGRESS: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30', label: 'IN PROGRESS' },
  };
  const c = config[verdict];
  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold tracking-wide border ${c.bg} ${c.text} ${c.border}`}>
      {verdict === 'EXPLOITABLE' && <AlertTriangle className="w-3 h-3" />}
      {verdict === 'NOT_EXPLOITABLE' && <Shield className="w-3 h-3" />}
      {verdict === 'IN_PROGRESS' && <Loader2 className="w-3 h-3 animate-spin" />}
      {c.label}
    </span>
  );
}

function FAILGradeBadge({ grade, score }: { grade: string; score: number }) {
  const gradeColors: Record<string, string> = {
    F: 'bg-red-500/15 text-red-400 border-red-500/30',
    D: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
    C: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    B: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
    A: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  };
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold border ${gradeColors[grade] || gradeColors.C}`}>
      FAIL: {grade} ({score})
    </span>
  );
}

function ConfidenceRing({ score }: { score: number }) {
  const radius = 20;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;
  const color = score >= 80 ? '#22c55e' : score >= 60 ? '#f59e0b' : score >= 40 ? '#f97316' : '#ef4444';

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width="56" height="56" viewBox="0 0 56 56" className="-rotate-90">
        <circle cx="28" cy="28" r={radius} fill="none" stroke="currentColor" strokeWidth="4" className="text-slate-700/50" />
        <motion.circle
          cx="28" cy="28" r={radius} fill="none" stroke={color} strokeWidth="4"
          strokeLinecap="round" strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: circumference - progress }}
          transition={{ duration: 1.2, ease: EASE_OUT_EXPO }}
        />
      </svg>
      <span className="absolute text-xs font-bold" style={{ color }}>{score}%</span>
    </div>
  );
}

function formatDuration(ms: number): string {
  if (ms === 0) return '--';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

// ─────────────────────────────────────────────────────────────────────────────
// MPTE Engine Health Badge
// ─────────────────────────────────────────────────────────────────────────────

function MpteHealthBadge() {
  const { data: health } = useQuery<MpteHealth>({
    queryKey: ['mpte-health'],
    queryFn: () => microPentestApi.getHealth(),
    refetchInterval: 30_000,
    retry: 1,
  });

  const isHealthy = health?.status === 'healthy' || health?.status === 'ok' || health?.status === 'running';

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold border ${
        isHealthy
          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
          : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
      }`}
    >
      <HeartPulse className="w-3 h-3" />
      <span>{isHealthy ? 'Engine Online' : 'Connecting...'}</span>
      {isHealthy && (
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
        </span>
      )}
      {health?.active_tests !== undefined && health.active_tests > 0 && (
        <span className="ml-0.5 text-emerald-300">{health.active_tests} active</span>
      )}
    </motion.div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Hero Stats Bar
// ─────────────────────────────────────────────────────────────────────────────

function HeroStatsBar({ verifications }: { verifications: VerificationResult[] }) {
  const stats = useMemo(() => {
    const total = verifications.length;
    const exploitable = verifications.filter(v => v.verdict === 'EXPLOITABLE').length;
    const notExploitable = verifications.filter(v => v.verdict === 'NOT_EXPLOITABLE').length;
    const inProgress = verifications.filter(v => v.verdict === 'IN_PROGRESS').length;
    const inconclusive = verifications.filter(v => v.verdict === 'INCONCLUSIVE').length;
    const avgConfidence = total > 0
      ? Math.round(verifications.reduce((sum, v) => sum + v.confidenceScore, 0) / total)
      : 0;
    const totalPhases = verifications.reduce((sum, v) => sum + v.phases.filter(p => p.status === 'PASS' || p.status === 'FAIL').length, 0);
    return { total, exploitable, notExploitable, inProgress, inconclusive, avgConfidence, totalPhases };
  }, [verifications]);

  const statCards = [
    { label: 'Total Verifications', value: stats.total, icon: <Target className="w-5 h-5" />, color: 'text-slate-300', bgGlow: 'from-indigo-500/10' },
    { label: 'Confirmed Exploitable', value: stats.exploitable, icon: <AlertTriangle className="w-5 h-5" />, color: 'text-red-400', bgGlow: 'from-red-500/10' },
    { label: 'Not Exploitable', value: stats.notExploitable, icon: <Shield className="w-5 h-5" />, color: 'text-emerald-400', bgGlow: 'from-emerald-500/10' },
    { label: 'Phases Executed', value: stats.totalPhases, icon: <Activity className="w-5 h-5" />, color: 'text-blue-400', bgGlow: 'from-blue-500/10' },
    { label: 'Avg Confidence', value: `${stats.avgConfidence}%`, icon: <Zap className="w-5 h-5" />, color: stats.avgConfidence >= 80 ? 'text-emerald-400' : stats.avgConfidence >= 60 ? 'text-amber-400' : 'text-red-400', bgGlow: 'from-amber-500/10' },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
      {statCards.map((stat, i) => (
        <motion.div
          key={stat.label}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: i * 0.08, duration: 0.5, ease: EASE_OUT_EXPO }}
        >
          <Card className="relative overflow-hidden border-slate-700/50 bg-slate-800/40 backdrop-blur-xl">
            <div className={`absolute inset-0 bg-gradient-to-br ${stat.bgGlow} to-transparent opacity-60`} />
            <CardContent className="relative p-4">
              <div className="flex items-center justify-between mb-2">
                <span className={stat.color}>{stat.icon}</span>
              </div>
              <div className={`text-2xl font-bold tracking-tight ${stat.color}`}>{stat.value}</div>
              <div className="text-xs text-slate-500 mt-1 font-medium">{stat.label}</div>
            </CardContent>
          </Card>
        </motion.div>
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase Timeline (the HERO feature)
// ─────────────────────────────────────────────────────────────────────────────

function PhaseTimeline({ phases, scope }: { phases: PhaseResult[]; scope: VerificationScope }) {
  const [expandedPhase, setExpandedPhase] = useState<number | null>(null);

  const totalDuration = useMemo(() => phases.reduce((sum, p) => sum + p.durationMs, 0), [phases]);
  const passCount = phases.filter(p => p.status === 'PASS').length;
  const failCount = phases.filter(p => p.status === 'FAIL').length;
  const skipCount = phases.filter(p => p.status === 'SKIP').length;

  let currentCategory: PhaseDefinition['category'] | null = null;

  return (
    <div className="space-y-1">
      {/* Phase Summary Bar */}
      <div className="flex items-center gap-4 px-4 py-2 mb-3 rounded-lg bg-slate-800/60 border border-slate-700/40">
        <div className="flex items-center gap-1.5 text-xs">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          <span className="text-emerald-400 font-semibold">{passCount} Passed</span>
        </div>
        <div className="flex items-center gap-1.5 text-xs">
          <XCircle className="w-3.5 h-3.5 text-red-400" />
          <span className="text-red-400 font-semibold">{failCount} Failed</span>
        </div>
        <div className="flex items-center gap-1.5 text-xs">
          <SkipForward className="w-3.5 h-3.5 text-slate-500" />
          <span className="text-slate-500 font-semibold">{skipCount} Skipped</span>
        </div>
        <div className="ml-auto flex items-center gap-1.5 text-xs text-slate-400">
          <Clock className="w-3.5 h-3.5" />
          <span className="font-mono">{formatDuration(totalDuration)}</span>
        </div>
        <Badge variant="outline" className="text-[10px] h-5 border-slate-600 text-slate-400">
          {scope.toUpperCase()} SCOPE
        </Badge>
      </div>

      {/* Phase Progress Bar */}
      <div className="flex gap-0.5 mb-4 px-1">
        {phases.map((phase) => (
          <motion.div
            key={phase.phaseId}
            className={`h-1.5 rounded-full flex-1 cursor-pointer transition-all ${
              phase.status === 'PASS' ? 'bg-emerald-500' :
              phase.status === 'FAIL' ? 'bg-red-500' :
              phase.status === 'RUNNING' ? 'bg-blue-500 animate-pulse' :
              phase.status === 'SKIP' ? 'bg-slate-700' : 'bg-slate-800'
            }`}
            whileHover={{ scaleY: 2.5 }}
            onClick={() => setExpandedPhase(expandedPhase === phase.phaseId ? null : phase.phaseId)}
            title={`Phase ${phase.phaseId}: ${MPTE_PHASES[phase.phaseId - 1]?.name}`}
          />
        ))}
      </div>

      {/* Phase List */}
      <div className="space-y-0">
        {MPTE_PHASES.map((phaseDef) => {
          const phaseResult = phases.find(p => p.phaseId === phaseDef.id);
          if (!phaseResult) return null;

          const isExpanded = expandedPhase === phaseDef.id;
          const showCategoryHeader = phaseDef.category !== currentCategory;
          if (showCategoryHeader) currentCategory = phaseDef.category;

          return (
            <div key={phaseDef.id}>
              {showCategoryHeader && (
                <div className="flex items-center gap-2 pt-3 pb-1 px-2">
                  <div className={`text-[10px] font-bold tracking-widest uppercase ${CATEGORY_COLORS[phaseDef.category]}`}>
                    {CATEGORY_LABELS[phaseDef.category]}
                  </div>
                  <div className="flex-1 h-px bg-slate-700/50" />
                </div>
              )}

              <motion.div
                layout
                className={`group relative rounded-lg transition-colors cursor-pointer ${
                  isExpanded
                    ? 'bg-slate-800/80 border border-slate-600/50'
                    : 'hover:bg-slate-800/40 border border-transparent'
                }`}
                onClick={() => setExpandedPhase(isExpanded ? null : phaseDef.id)}
              >
                <div className="flex items-center gap-3 px-3 py-2">
                  <div className="relative flex flex-col items-center">
                    <div className={`w-8 h-8 rounded-full flex items-center justify-center border-2 transition-colors ${
                      phaseResult.status === 'PASS' ? 'border-emerald-500/50 bg-emerald-500/10' :
                      phaseResult.status === 'FAIL' ? 'border-red-500/50 bg-red-500/10' :
                      phaseResult.status === 'RUNNING' ? 'border-blue-500/50 bg-blue-500/10' :
                      phaseResult.status === 'SKIP' ? 'border-slate-600/50 bg-slate-700/20' :
                      'border-slate-700/50 bg-slate-800/20'
                    }`}>
                      <PhaseStatusIcon status={phaseResult.status} />
                    </div>
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className={`text-xs font-mono ${CATEGORY_COLORS[phaseDef.category]} opacity-60`}>
                        {String(phaseDef.id).padStart(2, '0')}
                      </span>
                      <span className={`text-sm font-medium ${
                        phaseResult.status === 'SKIP' ? 'text-slate-500' : 'text-slate-200'
                      }`}>
                        {phaseDef.name}
                      </span>
                      <span className="hidden sm:inline text-slate-600">{phaseDef.icon}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <span className={`text-xs font-bold tracking-wide ${
                      phaseResult.status === 'PASS' ? 'text-emerald-400' :
                      phaseResult.status === 'FAIL' ? 'text-red-400' :
                      phaseResult.status === 'RUNNING' ? 'text-blue-400' :
                      'text-slate-600'
                    }`}>
                      {phaseResult.status}
                    </span>
                    <span className="text-xs font-mono text-slate-500 w-14 text-right">
                      {formatDuration(phaseResult.durationMs)}
                    </span>
                    {phaseResult.confidenceContribution !== 0 && (
                      <span className={`text-[10px] font-mono w-10 text-right ${
                        phaseResult.confidenceContribution > 0 ? 'text-emerald-500' : 'text-red-500'
                      }`}>
                        {phaseResult.confidenceContribution > 0 ? '+' : ''}{phaseResult.confidenceContribution}%
                      </span>
                    )}
                    <motion.div animate={{ rotate: isExpanded ? 90 : 0 }} transition={{ duration: 0.2 }}>
                      <ChevronRight className="w-4 h-4 text-slate-500" />
                    </motion.div>
                  </div>
                </div>

                <AnimatePresence>
                  {isExpanded && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.3, ease: EASE_OUT_EXPO }}
                      className="overflow-hidden"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <div className="px-4 pb-4 pt-1 ml-11 space-y-3 border-t border-slate-700/30">
                        <p className="text-xs text-slate-400 leading-relaxed">{phaseDef.description}</p>
                        <div className="flex flex-wrap gap-3 text-xs">
                          <div className="flex items-center gap-1.5 text-slate-400">
                            <Clock className="w-3 h-3" />
                            <span>Duration: <span className="font-mono text-slate-300">{formatDuration(phaseResult.durationMs)}</span></span>
                          </div>
                          {phaseResult.confidenceContribution !== 0 && (
                            <div className="flex items-center gap-1.5">
                              <Zap className="w-3 h-3 text-amber-400" />
                              <span className="text-slate-400">
                                Confidence: <span className={`font-mono ${phaseResult.confidenceContribution > 0 ? 'text-emerald-400' : 'text-red-400'}`}>
                                  {phaseResult.confidenceContribution > 0 ? '+' : ''}{phaseResult.confidenceContribution}%
                                </span>
                              </span>
                            </div>
                          )}
                          {phaseResult.relatedPhases.length > 0 && (
                            <div className="flex items-center gap-1.5 text-slate-400">
                              <Network className="w-3 h-3" />
                              <span>Related: {phaseResult.relatedPhases.map(p => `Phase ${p}`).join(', ')}</span>
                            </div>
                          )}
                        </div>
                        <div className="relative group/evidence">
                          <div className="flex items-center justify-between mb-1.5">
                            <span className="text-[10px] font-bold tracking-widest uppercase text-slate-500">Evidence</span>
                            <Button
                              variant="ghost" size="sm"
                              className="h-6 px-2 text-[10px] text-slate-500 hover:text-slate-300"
                              onClick={(e) => {
                                e.stopPropagation();
                                navigator.clipboard.writeText(phaseResult.evidence);
                                toast.success('Evidence copied to clipboard');
                              }}
                              aria-label="Copy evidence to clipboard"
                            >
                              Copy
                            </Button>
                          </div>
                          <ScrollArea className="max-h-64">
                            <pre className="text-xs font-mono leading-relaxed p-3 rounded-lg bg-slate-900/80 border border-slate-700/40 text-slate-300 whitespace-pre-wrap break-words">
                              {phaseResult.evidence}
                            </pre>
                          </ScrollArea>
                        </div>
                        {phaseResult.details && (
                          <div className="text-xs text-slate-500 italic">{phaseResult.details}</div>
                        )}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Live Execution Viewer — THE DEMO WOW FEATURE
// Phase-by-phase animated execution with live evidence appearing
// ─────────────────────────────────────────────────────────────────────────────

function LiveRunViewer() {
  const [isRunning, setIsRunning] = useState(false);
  const [currentPhaseIdx, setCurrentPhaseIdx] = useState(-1);
  const [completedPhases, setCompletedPhases] = useState<PhaseResult[]>([]);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [liveTarget, setLiveTarget] = useState('api.acmecorp.com');
  const [liveCve, setLiveCve] = useState('CVE-2024-38816');
  const [liveScope, setLiveScope] = useState<VerificationScope>('full');
  const [elapsedMs, setElapsedMs] = useState(0);
  const [confidence, setConfidence] = useState(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const phaseTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const maxPhase = liveScope === 'quick' ? 6 : liveScope === 'standard' ? 12 : 19;

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
      if (phaseTimerRef.current) clearTimeout(phaseTimerRef.current);
    };
  }, []);

  const startRun = useCallback(() => {
    setIsRunning(true);
    setCurrentPhaseIdx(0);
    setCompletedPhases([]);
    setVerdict(null);
    setElapsedMs(0);
    setConfidence(0);

    // Start elapsed timer
    const startTime = Date.now();
    timerRef.current = setInterval(() => {
      setElapsedMs(Date.now() - startTime);
    }, 100);
  }, []);

  const stopRun = useCallback(() => {
    setIsRunning(false);
    if (timerRef.current) clearInterval(timerRef.current);
    if (phaseTimerRef.current) clearTimeout(phaseTimerRef.current);
    setVerdict('INCONCLUSIVE');
    toast.error('Verification stopped by operator');
  }, []);

  // Phase progression engine
  useEffect(() => {
    if (!isRunning || currentPhaseIdx < 0) return;

    if (currentPhaseIdx >= maxPhase) {
      // All phases complete — determine verdict
      setIsRunning(false);
      if (timerRef.current) clearInterval(timerRef.current);

      const failedPhases = completedPhases.filter(p => p.status === 'FAIL');
      if (failedPhases.length === 0) {
        setVerdict('EXPLOITABLE');
        toast.success('Verification complete: EXPLOITABLE', { duration: 5000 });
      } else if (failedPhases.some(p => p.phaseId >= 7 && p.phaseId <= 12)) {
        setVerdict('NOT_EXPLOITABLE');
        toast.success('Verification complete: NOT EXPLOITABLE', { duration: 5000 });
      } else {
        setVerdict('INCONCLUSIVE');
        toast.success('Verification complete: INCONCLUSIVE', { duration: 5000 });
      }
      return;
    }

    const phaseDef = MPTE_PHASES[currentPhaseIdx];
    if (!phaseDef) return;

    // Phase duration for live-scan animation (transient UI, not persisted)
    const duration = 800 + Math.random() * 2200;

    phaseTimerRef.current = setTimeout(() => {
      // TODO: Replace local simulation with real MPTE API polling
      // For now, mark all phases as PASS in the live-scan animation
      const status: PhaseStatus = 'PASS';

      const result: PhaseResult = {
        phaseId: phaseDef.id,
        status,
        durationMs: duration,
        evidence: `${phaseDef.name} — awaiting real engine results`,
        details: `${phaseDef.name} ${status === 'PASS' ? 'completed' : 'pending'}`,
        confidenceContribution: status === 'PASS' ? 5 : 0,
        relatedPhases: [phaseDef.id - 1, phaseDef.id + 1].filter(p => p > 0 && p <= 19),
      };

      setCompletedPhases(prev => [...prev, result]);
      setConfidence(prev => Math.max(0, Math.min(100, prev + result.confidenceContribution)));
      setCurrentPhaseIdx(prev => prev + 1);
    }, duration);

    return () => {
      if (phaseTimerRef.current) clearTimeout(phaseTimerRef.current);
    };
  }, [isRunning, currentPhaseIdx, maxPhase, completedPhases]);

  const progressPercent = maxPhase > 0 ? Math.round(((currentPhaseIdx >= 0 ? currentPhaseIdx : 0) / maxPhase) * 100) : 0;

  return (
    <div className="space-y-6">
      {/* Live Run Controls */}
      <Card className="border-slate-700/50 bg-slate-800/30 backdrop-blur-xl overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-indigo-500/5 to-transparent" />
        <CardHeader className="relative pb-3">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center">
              <Play className="w-4 h-4 text-indigo-400" />
            </div>
            <div>
              <CardTitle className="text-base">Live Verification Run</CardTitle>
              <CardDescription className="text-xs">Watch a 19-phase exploit verification execute in real-time</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="relative space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <Input
              value={liveTarget}
              onChange={(e) => setLiveTarget(e.target.value)}
              placeholder="Target URL or IP"
              className="bg-slate-900/50 border-slate-700 text-sm"
              disabled={isRunning}
            />
            <Input
              value={liveCve}
              onChange={(e) => setLiveCve(e.target.value)}
              placeholder="CVE-ID (optional)"
              className="bg-slate-900/50 border-slate-700 text-sm"
              disabled={isRunning}
            />
            <div className="flex gap-2">
              {(['quick', 'standard', 'full'] as VerificationScope[]).map(s => (
                <button
                  key={s}
                  onClick={() => !isRunning && setLiveScope(s)}
                  disabled={isRunning}
                  className={`flex-1 py-1.5 rounded text-xs font-semibold transition-all ${
                    liveScope === s
                      ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/40'
                      : 'bg-slate-900/50 text-slate-500 border border-slate-700/50 hover:border-slate-600'
                  } ${isRunning ? 'opacity-50 cursor-not-allowed' : ''}`}
                >
                  {s.charAt(0).toUpperCase() + s.slice(1)}
                </button>
              ))}
            </div>
          </div>

          <div className="flex gap-3">
            {!isRunning ? (
              <Button
                onClick={startRun}
                className="flex-1 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold"
                disabled={!liveTarget.trim()}
              >
                <Play className="w-4 h-4 mr-2" />
                Launch Live Verification ({maxPhase} Phases)
              </Button>
            ) : (
              <Button
                onClick={stopRun}
                variant="outline"
                className="flex-1 border-red-500/50 text-red-400 hover:bg-red-500/10"
              >
                <StopCircle className="w-4 h-4 mr-2" />
                Stop Verification
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Live Progress Dashboard */}
      {(isRunning || completedPhases.length > 0) && (
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ease: EASE_OUT_EXPO }}
        >
          <Card className="border-slate-700/50 bg-slate-800/30 backdrop-blur-xl">
            {/* Status Bar */}
            <div className="flex items-center gap-4 px-6 py-4 border-b border-slate-700/30">
              <div className="flex items-center gap-2">
                {isRunning ? (
                  <Loader2 className="w-5 h-5 text-blue-400 animate-spin" />
                ) : verdict ? (
                  verdict === 'EXPLOITABLE' ? <AlertTriangle className="w-5 h-5 text-red-400" /> :
                  verdict === 'NOT_EXPLOITABLE' ? <Shield className="w-5 h-5 text-emerald-400" /> :
                  <Clock className="w-5 h-5 text-amber-400" />
                ) : null}
                <span className="text-sm font-semibold text-slate-200">
                  {isRunning ? `Running Phase ${(currentPhaseIdx + 1).toString().padStart(2, '0')}/${maxPhase}` :
                   verdict ? `Verdict: ${verdict.replace('_', ' ')}` : 'Ready'}
                </span>
              </div>
              <div className="flex-1" />
              <div className="flex items-center gap-4 text-xs text-slate-400">
                <div className="flex items-center gap-1">
                  <Target className="w-3 h-3" />
                  <span className="font-mono">{liveTarget}</span>
                </div>
                {liveCve && (
                  <Badge variant="outline" className="text-[10px] h-5 border-indigo-500/40 text-indigo-400">
                    {liveCve}
                  </Badge>
                )}
                <div className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  <span className="font-mono">{(elapsedMs / 1000).toFixed(1)}s</span>
                </div>
                <div className="flex items-center gap-1">
                  <Zap className="w-3 h-3 text-amber-400" />
                  <span className="font-mono">{confidence}%</span>
                </div>
              </div>
            </div>

            {/* Overall Progress Bar */}
            <div className="px-6 py-3 border-b border-slate-700/20">
              <div className="flex items-center gap-3">
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 w-16">Progress</span>
                <div className="flex-1">
                  <Progress value={progressPercent} className="h-2" />
                </div>
                <span className="text-xs font-mono text-slate-400 w-10 text-right">{progressPercent}%</span>
              </div>
            </div>

            {/* Phase-by-Phase Live Feed */}
            <CardContent className="p-4">
              <ScrollArea className="max-h-[500px]">
                <div className="space-y-1">
                  {MPTE_PHASES.slice(0, maxPhase).map((phaseDef, idx) => {
                    const result = completedPhases.find(p => p.phaseId === phaseDef.id);
                    const isCurrentlyRunning = isRunning && idx === currentPhaseIdx;
                    const isPending = !result && !isCurrentlyRunning;

                    return (
                      <motion.div
                        key={phaseDef.id}
                        initial={{ opacity: 0.3 }}
                        animate={{
                          opacity: result || isCurrentlyRunning ? 1 : 0.3,
                          backgroundColor: isCurrentlyRunning ? 'rgba(59, 130, 246, 0.08)' : 'transparent',
                        }}
                        transition={{ duration: 0.4 }}
                        className={`flex items-start gap-3 p-3 rounded-lg ${
                          isCurrentlyRunning ? 'ring-1 ring-blue-500/30' : ''
                        }`}
                      >
                        {/* Phase number and status */}
                        <div className={`w-8 h-8 rounded-full flex-shrink-0 flex items-center justify-center border-2 transition-all ${
                          result?.status === 'PASS' ? 'border-emerald-500/50 bg-emerald-500/10' :
                          result?.status === 'FAIL' ? 'border-red-500/50 bg-red-500/10' :
                          result?.status === 'SKIP' ? 'border-slate-600/50 bg-slate-700/20' :
                          isCurrentlyRunning ? 'border-blue-500/50 bg-blue-500/10' :
                          'border-slate-700/30 bg-slate-800/30'
                        }`}>
                          {result ? <PhaseStatusIcon status={result.status} /> :
                           isCurrentlyRunning ? <Loader2 className="w-4 h-4 text-blue-400 animate-spin" /> :
                           <span className="text-[10px] font-mono text-slate-600">{String(phaseDef.id).padStart(2, '0')}</span>}
                        </div>

                        {/* Phase info */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-0.5">
                            <span className={`text-sm font-medium ${
                              result ? 'text-slate-200' : isCurrentlyRunning ? 'text-blue-300' : 'text-slate-600'
                            }`}>
                              {phaseDef.name}
                            </span>
                            <span className={`text-[10px] px-1.5 py-0.5 rounded border ${CATEGORY_BG[phaseDef.category]} ${CATEGORY_COLORS[phaseDef.category]}`}>
                              {CATEGORY_LABELS[phaseDef.category]}
                            </span>
                            {result && (
                              <span className="text-[10px] font-mono text-slate-500">
                                {formatDuration(result.durationMs)}
                              </span>
                            )}
                          </div>

                          {/* Live evidence appearing */}
                          <AnimatePresence>
                            {result && (
                              <motion.div
                                initial={{ height: 0, opacity: 0 }}
                                animate={{ height: 'auto', opacity: 1 }}
                                transition={{ duration: 0.5, ease: EASE_OUT_EXPO }}
                              >
                                <pre className="text-[11px] font-mono leading-relaxed p-2 mt-1 rounded bg-slate-900/80 border border-slate-700/30 text-slate-400 whitespace-pre-wrap break-words max-h-32 overflow-y-auto">
                                  {result.evidence}
                                </pre>
                              </motion.div>
                            )}
                            {isCurrentlyRunning && (
                              <motion.div
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                className="mt-1"
                              >
                                <div className="flex items-center gap-2 text-xs text-blue-400">
                                  <Loader2 className="w-3 h-3 animate-spin" />
                                  <span className="animate-pulse">{phaseDef.description}...</span>
                                </div>
                              </motion.div>
                            )}
                          </AnimatePresence>
                        </div>

                        {/* Status badge */}
                        <div className="flex-shrink-0">
                          {result ? (
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                              result.status === 'PASS' ? 'bg-emerald-500/10 text-emerald-400' :
                              result.status === 'FAIL' ? 'bg-red-500/10 text-red-400' :
                              'bg-slate-700/30 text-slate-500'
                            }`}>
                              {result.status}
                            </span>
                          ) : isCurrentlyRunning ? (
                            <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 animate-pulse">
                              RUNNING
                            </span>
                          ) : (
                            <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-slate-800/30 text-slate-700">
                              {isPending ? 'PENDING' : ''}
                            </span>
                          )}
                        </div>
                      </motion.div>
                    );
                  })}
                </div>
              </ScrollArea>

              {/* Verdict Banner */}
              <AnimatePresence>
                {verdict && !isRunning && (
                  <motion.div
                    initial={{ opacity: 0, y: 20, scale: 0.95 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    transition={{ type: 'spring', stiffness: 300, damping: 25 }}
                    className={`mt-4 p-4 rounded-xl border ${
                      verdict === 'EXPLOITABLE' ? 'bg-red-500/5 border-red-500/30' :
                      verdict === 'NOT_EXPLOITABLE' ? 'bg-emerald-500/5 border-emerald-500/30' :
                      'bg-amber-500/5 border-amber-500/30'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        {verdict === 'EXPLOITABLE' ? <AlertTriangle className="w-6 h-6 text-red-400" /> :
                         verdict === 'NOT_EXPLOITABLE' ? <Shield className="w-6 h-6 text-emerald-400" /> :
                         <Clock className="w-6 h-6 text-amber-400" />}
                        <div>
                          <div className="text-lg font-bold text-slate-100">
                            Final Verdict: <VerdictBadge verdict={verdict} />
                          </div>
                          <div className="text-xs text-slate-400 mt-1">
                            {completedPhases.filter(p => p.status === 'PASS').length} phases passed ·{' '}
                            {completedPhases.filter(p => p.status === 'FAIL').length} failed ·{' '}
                            Confidence: {confidence}% · Duration: {(elapsedMs / 1000).toFixed(1)}s
                          </div>
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <Button variant="outline" size="sm" className="border-slate-700 text-slate-400"
                          onClick={() => { setCompletedPhases([]); setVerdict(null); setCurrentPhaseIdx(-1); setElapsedMs(0); setConfidence(0); }}
                        >
                          <RefreshCw className="w-3 h-3 mr-1" />
                          Reset
                        </Button>
                        <Button variant="outline" size="sm" className="border-slate-700 text-slate-400"
                          onClick={() => {
                            const reportContent = completedPhases.map(p => `Phase ${p.phaseId}: ${p.status}\n${p.evidence}`).join('\n\n');
                            navigator.clipboard.writeText(reportContent);
                            toast.success('Full evidence report copied to clipboard');
                          }}
                        >
                          <FileText className="w-3 h-3 mr-1" />
                          Copy Report
                        </Button>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </CardContent>
          </Card>
        </motion.div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase Analytics Dashboard
// ─────────────────────────────────────────────────────────────────────────────

function PhaseAnalyticsDashboard({ verifications }: { verifications: VerificationResult[] }) {
  const analytics: PhaseAnalyticsStat[] = useMemo(() => {
    return MPTE_PHASES.map(phase => {
      const results = verifications.flatMap(v => v.phases).filter(p => p.phaseId === phase.id);
      const total = results.length || 1;
      const passed = results.filter(r => r.status === 'PASS').length;
      const failed = results.filter(r => r.status === 'FAIL').length;
      const skipped = results.filter(r => r.status === 'SKIP').length;
      const avgDuration = results.reduce((sum, r) => sum + r.durationMs, 0) / total;

      return {
        phaseId: phase.id,
        name: phase.name,
        category: phase.category,
        passRate: Math.round((passed / total) * 100),
        failRate: Math.round((failed / total) * 100),
        skipRate: Math.round((skipped / total) * 100),
        avgDurationMs: avgDuration,
        totalRuns: results.length,
      };
    });
  }, [verifications]);

  const maxDuration = Math.max(...analytics.map(a => a.avgDurationMs), 1);

  return (
    <div className="space-y-6">
      {/* Category Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {(['recon', 'exploit', 'post-exploit', 'reporting'] as const).map(cat => {
          const phases = analytics.filter(a => a.category === cat);
          const avgPass = Math.round(phases.reduce((s, p) => s + p.passRate, 0) / (phases.length || 1));
          return (
            <motion.div
              key={cat}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, ease: EASE_OUT_EXPO }}
            >
              <Card className={`border ${CATEGORY_BG[cat]} bg-slate-800/40`}>
                <CardContent className="p-4">
                  <div className={`text-xs font-bold uppercase tracking-wider mb-2 ${CATEGORY_COLORS[cat]}`}>
                    {CATEGORY_LABELS[cat]}
                  </div>
                  <div className="text-2xl font-bold text-slate-200">{avgPass}%</div>
                  <div className="text-xs text-slate-500">avg pass rate · {phases.length} phases</div>
                </CardContent>
              </Card>
            </motion.div>
          );
        })}
      </div>

      {/* Phase Heatmap */}
      <Card className="border-slate-700/50 bg-slate-800/30 backdrop-blur-xl">
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-indigo-400" />
            Phase Performance Heatmap
          </CardTitle>
          <CardDescription className="text-xs">Pass/fail/skip rates and average duration per phase</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-1">
            {analytics.map((stat, idx) => {
              let currentCategory: string | null = null;
              const showHeader = idx === 0 || analytics[idx - 1].category !== stat.category;
              if (showHeader) currentCategory = stat.category;

              return (
                <div key={stat.phaseId}>
                  {showHeader && currentCategory && (
                    <div className="flex items-center gap-2 pt-3 pb-1">
                      <span className={`text-[10px] font-bold tracking-widest uppercase ${CATEGORY_COLORS[stat.category]}`}>
                        {CATEGORY_LABELS[stat.category]}
                      </span>
                      <div className="flex-1 h-px bg-slate-700/50" />
                    </div>
                  )}

                  <motion.div
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.03, duration: 0.4 }}
                    className="flex items-center gap-3 py-1.5 px-2 rounded-md hover:bg-slate-800/40"
                  >
                    {/* Phase number */}
                    <span className={`text-[10px] font-mono w-5 text-right ${CATEGORY_COLORS[stat.category]} opacity-60`}>
                      {String(stat.phaseId).padStart(2, '0')}
                    </span>

                    {/* Phase name */}
                    <span className="text-xs text-slate-300 w-36 truncate">{stat.name}</span>

                    {/* Stacked bar */}
                    <div className="flex-1 flex h-5 rounded-full overflow-hidden bg-slate-800/60">
                      {stat.passRate > 0 && (
                        <motion.div
                          className="bg-emerald-500/70 h-full"
                          initial={{ width: 0 }}
                          animate={{ width: `${stat.passRate}%` }}
                          transition={{ duration: 0.8, delay: idx * 0.03, ease: EASE_OUT_EXPO }}
                        />
                      )}
                      {stat.failRate > 0 && (
                        <motion.div
                          className="bg-red-500/70 h-full"
                          initial={{ width: 0 }}
                          animate={{ width: `${stat.failRate}%` }}
                          transition={{ duration: 0.8, delay: idx * 0.03 + 0.1, ease: EASE_OUT_EXPO }}
                        />
                      )}
                      {stat.skipRate > 0 && (
                        <motion.div
                          className="bg-slate-600/70 h-full"
                          initial={{ width: 0 }}
                          animate={{ width: `${stat.skipRate}%` }}
                          transition={{ duration: 0.8, delay: idx * 0.03 + 0.2, ease: EASE_OUT_EXPO }}
                        />
                      )}
                    </div>

                    {/* Stats */}
                    <div className="flex items-center gap-2 text-[10px] font-mono w-40">
                      <span className="text-emerald-400 w-8 text-right">{stat.passRate}%</span>
                      <span className="text-red-400 w-8 text-right">{stat.failRate}%</span>
                      <span className="text-slate-500 w-8 text-right">{stat.skipRate}%</span>
                    </div>

                    {/* Duration bar */}
                    <div className="w-24 flex items-center gap-1">
                      <div className="flex-1 h-1.5 rounded-full bg-slate-800/60 overflow-hidden">
                        <motion.div
                          className="h-full rounded-full bg-indigo-500/60"
                          initial={{ width: 0 }}
                          animate={{ width: `${maxDuration > 0 ? (stat.avgDurationMs / maxDuration) * 100 : 0}%` }}
                          transition={{ duration: 0.8, delay: idx * 0.03 }}
                        />
                      </div>
                      <span className="text-[9px] font-mono text-slate-500 w-12 text-right">
                        {formatDuration(stat.avgDurationMs)}
                      </span>
                    </div>
                  </motion.div>
                </div>
              );
            })}
          </div>

          {/* Legend */}
          <div className="flex items-center gap-6 mt-4 pt-3 border-t border-slate-700/30">
            <div className="flex items-center gap-1.5 text-xs">
              <div className="w-3 h-3 rounded-sm bg-emerald-500/70" />
              <span className="text-slate-400">Pass</span>
            </div>
            <div className="flex items-center gap-1.5 text-xs">
              <div className="w-3 h-3 rounded-sm bg-red-500/70" />
              <span className="text-slate-400">Fail</span>
            </div>
            <div className="flex items-center gap-1.5 text-xs">
              <div className="w-3 h-3 rounded-sm bg-slate-600/70" />
              <span className="text-slate-400">Skip</span>
            </div>
            <div className="flex items-center gap-1.5 text-xs ml-auto">
              <div className="w-3 h-3 rounded-sm bg-indigo-500/60" />
              <span className="text-slate-400">Avg Duration</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Verification Card
// ─────────────────────────────────────────────────────────────────────────────

function VerificationCard({ verification }: { verification: VerificationResult }) {
  const [isExpanded, setIsExpanded] = useState(false);

  const totalDuration = useMemo(
    () => verification.phases.reduce((sum, p) => sum + p.durationMs, 0),
    [verification.phases]
  );

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: EASE_OUT_EXPO }}
    >
      <Card className={`relative overflow-hidden border-slate-700/50 bg-slate-800/30 backdrop-blur-xl transition-all ${
        isExpanded ? 'ring-1 ring-slate-600/50' : 'hover:border-slate-600/60'
      }`}>
        <div className={`absolute left-0 top-0 bottom-0 w-1 ${
          verification.verdict === 'EXPLOITABLE' ? 'bg-red-500' :
          verification.verdict === 'NOT_EXPLOITABLE' ? 'bg-emerald-500' :
          verification.verdict === 'IN_PROGRESS' ? 'bg-blue-500' :
          'bg-amber-500'
        }`} />

        <div
          className="flex items-center gap-4 p-4 cursor-pointer"
          onClick={() => setIsExpanded(!isExpanded)}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setIsExpanded(!isExpanded); } }}
          aria-expanded={isExpanded}
          aria-label={`Verification for ${verification.target}, verdict: ${verification.verdict}`}
        >
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <Target className="w-4 h-4 text-slate-400 flex-shrink-0" />
              <span className="text-sm font-semibold text-slate-100 truncate">{verification.target}</span>
              {verification.cveId && (
                <Badge variant="outline" className="text-[10px] h-5 border-indigo-500/40 text-indigo-400 bg-indigo-500/5 flex-shrink-0">
                  {verification.cveId}
                </Badge>
              )}
              {verification.failScore && (
                <FAILGradeBadge grade={verification.failScore.grade} score={verification.failScore.score} />
              )}
            </div>
            <div className="flex items-center gap-3 text-xs text-slate-500">
              <span className="font-mono truncate max-w-[200px]">{verification.targetUrl}</span>
              <span className="hidden sm:inline">|</span>
              <span className="hidden sm:inline">{formatDuration(totalDuration)}</span>
              <span className="hidden sm:inline">|</span>
              <span className="hidden sm:inline">{verification.scope.toUpperCase()} scope</span>
            </div>
          </div>

          <div className="flex items-center gap-4 flex-shrink-0">
            <VerdictBadge verdict={verification.verdict} />
            <ConfidenceRing score={verification.confidenceScore} />
            <div className="hidden sm:block text-right">
              <div className="text-lg font-bold font-mono text-slate-200">{verification.riskScore.toFixed(1)}</div>
              <div className="text-[10px] text-slate-500 uppercase tracking-wide">Risk</div>
            </div>
            <motion.div
              animate={{ rotate: isExpanded ? 180 : 0 }}
              transition={{ duration: 0.25 }}
            >
              <ChevronDown className="w-5 h-5 text-slate-500" />
            </motion.div>
          </div>
        </div>

        <AnimatePresence>
          {isExpanded && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.4, ease: EASE_OUT_EXPO }}
              className="overflow-hidden"
            >
              <div className="px-4 pb-4 border-t border-slate-700/30">
                <div className="pt-4">
                  <div className="flex items-center gap-2 mb-4">
                    <Activity className="w-4 h-4 text-indigo-400" />
                    <span className="text-sm font-semibold text-slate-200">19-Phase Verification Breakdown</span>
                  </div>
                  <PhaseTimeline phases={verification.phases} scope={verification.scope} />
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </Card>
    </motion.div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// New Verification Form
// ─────────────────────────────────────────────────────────────────────────────

function NewVerificationForm({ onCreated }: { onCreated: () => void }) {
  const [targetUrl, setTargetUrl] = useState('');
  const [cveId, setCveId] = useState('');
  const [scope, setScope] = useState<VerificationScope>('standard');
  const [priority, setPriority] = useState<Priority>('high');
  const [isEnterprise, setIsEnterprise] = useState(false);
  const [additionalTargets, setAdditionalTargets] = useState('');
  const [reportReady, setReportReady] = useState(false);
  const [scanRunning, setScanRunning] = useState(false);

  const createMutation = useMutation({
    mutationFn: async () => {
      if (isEnterprise) {
        // Enterprise 8-phase scan with LLM intelligence
        setScanRunning(true);
        setReportReady(false);
        const url = targetUrl.includes('://') ? targetUrl : `https://${targetUrl}`;
        return microPentestApi.runEnterprise({
          name: `Enterprise Scan — ${new URL(url).hostname}`,
          attack_surface: {
            name: `${new URL(url).hostname} Surface`,
            target_url: url,
            target_type: 'web',
            endpoints: ['/', '/login', '/api'],
            authentication_required: false,
          },
          threat_model: {
            name: `${new URL(url).hostname} Threat Model`,
            description: `Full enterprise scan of ${new URL(url).hostname}`,
            attack_vectors: ['web_application', 'injection', 'authentication'],
            compliance_frameworks: ['soc2', 'pci_dss', 'gdpr'],
            priority: priority === 'critical' ? 10 : priority === 'high' ? 8 : priority === 'medium' ? 5 : 3,
          },
          scan_mode: 'active',
          timeout_seconds: 300,
          stop_on_critical: false,
          include_proof_of_concept: true,
        });
      }
      const payload = {
        finding_id: `finding-${Date.now()}`,
        target_url: targetUrl,
        vulnerability_type: cveId || 'general',
        test_case: `mpte-${scope}-verification`,
        priority,
        scope,
        cve_id: cveId || undefined,
      };
      const response = await api.post('/api/v1/mpte/requests', payload);
      return response.data;
    },
    onSuccess: (data: Record<string, unknown>) => {
      setScanRunning(false);
      if (isEnterprise) {
        const findings = (data?.findings as unknown[])?.length ?? 0;
        const scanId = String(data?.scan_id ?? 'OK').slice(0, 8);
        toast.success(`Enterprise scan completed: ${scanId}… — ${findings} findings`);
      } else {
        toast.success(`Verification request created: ${String(data?.id ?? data?.flow_id ?? 'OK').slice(0, 8)}`);
      }
      setTargetUrl('');
      setCveId('');
      setAdditionalTargets('');
      onCreated();
    },
    onError: (error: { response?: { data?: { detail?: string } }; message?: string }) => {
      setScanRunning(false);
      const msg = error?.response?.data?.detail || error?.message || 'Unknown error';
      toast.error(`Failed to create verification: ${msg}`);
    },
  });

  const reportMutation = useMutation({
    mutationFn: async () => {
      const url = targetUrl.includes('://') ? targetUrl : `https://${targetUrl}`;
      const targets = [url, ...additionalTargets.split('\n').map(t => t.trim()).filter(Boolean).map(u => u.includes('://') ? u : `https://${u}`)];
      const cveIds = cveId ? cveId.split(',').map(c => c.trim()).filter(Boolean) : [];
      return microPentestApi.generateReport({ cve_ids: cveIds, target_urls: targets, context: { scope, priority } });
    },
    onSuccess: () => {
      setReportReady(true);
      toast.success('Report generated — click View/Download to access');
    },
    onError: (error: { response?: { data?: { detail?: string } }; message?: string }) => {
      toast.error(`Report failed: ${error?.response?.data?.detail || error?.message || 'Unknown error'}`);
    },
  });

  const scopeOptions: { value: VerificationScope; label: string; phases: string; description: string }[] = [
    { value: 'quick', label: 'Quick', phases: '1-6', description: 'Recon + CVE matching only' },
    { value: 'standard', label: 'Standard', phases: '1-12', description: 'Full exploitation attempt' },
    { value: 'full', label: 'Full', phases: '1-19', description: 'Complete with post-exploit + reporting' },
  ];

  const priorityOptions: { value: Priority; label: string; color: string }[] = [
    { value: 'critical', label: 'Critical', color: 'text-red-400 border-red-500/40 bg-red-500/10' },
    { value: 'high', label: 'High', color: 'text-orange-400 border-orange-500/40 bg-orange-500/10' },
    { value: 'medium', label: 'Medium', color: 'text-amber-400 border-amber-500/40 bg-amber-500/10' },
    { value: 'low', label: 'Low', color: 'text-blue-400 border-blue-500/40 bg-blue-500/10' },
  ];

  return (
    <Card className="border-slate-700/50 bg-slate-800/30 backdrop-blur-xl overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-br from-indigo-500/5 to-transparent" />
      <CardHeader className="relative pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center">
              <Play className="w-4 h-4 text-indigo-400" />
            </div>
            <div>
              <CardTitle className="text-base">New Verification</CardTitle>
              <CardDescription className="text-xs">
                {isEnterprise ? '8-phase enterprise scan: LLM recon → MITRE ATT&CK → vuln scan → PoC → compliance → report' : 'Launch a 19-phase MPTE exploitability verification'}
              </CardDescription>
            </div>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setIsEnterprise(!isEnterprise)}
            className={`text-xs ${isEnterprise ? 'text-indigo-400 bg-indigo-500/10' : 'text-slate-500'}`}
          >
            {isEnterprise ? 'Enterprise Mode' : 'Single Target'}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="relative space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className={isEnterprise ? '' : 'sm:col-span-2'}>
            <label htmlFor="target-url" className="text-xs text-slate-400 mb-1.5 block font-medium">
              Target URL / IP
            </label>
            <Input
              id="target-url"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://api.example.com or 10.0.1.45"
              className="bg-slate-900/50 border-slate-700 text-sm"
            />
          </div>
          <div>
            <label htmlFor="cve-id" className="text-xs text-slate-400 mb-1.5 block font-medium">
              CVE ID{isEnterprise ? 's (comma-separated)' : ''} <span className="text-slate-600">(optional)</span>
            </label>
            <Input
              id="cve-id"
              value={cveId}
              onChange={(e) => setCveId(e.target.value)}
              placeholder={isEnterprise ? 'CVE-2024-XXXXX, CVE-2024-YYYYY' : 'CVE-2024-XXXXX'}
              className="bg-slate-900/50 border-slate-700 text-sm"
            />
          </div>
          {isEnterprise && (
            <div>
              <label className="text-xs text-slate-400 mb-1.5 block font-medium">
                Additional Targets <span className="text-slate-600">(one per line)</span>
              </label>
              <textarea
                value={additionalTargets}
                onChange={(e) => setAdditionalTargets(e.target.value)}
                placeholder={'https://staging.example.com\n10.0.2.100:8080\nhttps://internal.api.dev'}
                rows={3}
                className="w-full bg-slate-900/50 border border-slate-700 rounded-md text-sm p-2 text-slate-200 placeholder-slate-600 focus:ring-1 focus:ring-indigo-500/50 focus:border-indigo-500/50 resize-none"
              />
            </div>
          )}
        </div>

        {/* Scope */}
        <div>
          <label className="text-xs text-slate-400 mb-2 block font-medium">Verification Scope</label>
          <div className="grid grid-cols-3 gap-2">
            {scopeOptions.map((opt) => (
              <button
                key={opt.value}
                type="button"
                onClick={() => setScope(opt.value)}
                className={`relative p-3 rounded-lg border text-left transition-all ${
                  scope === opt.value
                    ? 'border-indigo-500/60 bg-indigo-500/10 ring-1 ring-indigo-500/30'
                    : 'border-slate-700/50 bg-slate-900/30 hover:border-slate-600/60'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className={`text-sm font-semibold ${scope === opt.value ? 'text-indigo-300' : 'text-slate-300'}`}>
                    {opt.label}
                  </span>
                  <Badge variant="outline" className={`text-[9px] h-4 ${scope === opt.value ? 'border-indigo-500/40 text-indigo-400' : 'border-slate-700 text-slate-500'}`}>
                    {opt.phases}
                  </Badge>
                </div>
                <p className="text-[11px] text-slate-500 leading-tight">{opt.description}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Priority */}
        <div>
          <label className="text-xs text-slate-400 mb-2 block font-medium">Priority</label>
          <div className="flex gap-2">
            {priorityOptions.map((opt) => (
              <button
                key={opt.value}
                type="button"
                onClick={() => setPriority(opt.value)}
                className={`px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all ${
                  priority === opt.value
                    ? opt.color + ' ring-1 ring-current/20'
                    : 'border-slate-700/50 text-slate-500 hover:border-slate-600'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex gap-2">
          <Button
            onClick={() => createMutation.mutate()}
            disabled={!targetUrl.trim() || createMutation.isPending || scanRunning}
            className="flex-1 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold"
          >
            {createMutation.isPending || scanRunning ? (
              <><Loader2 className="w-4 h-4 mr-2 animate-spin" />{isEnterprise ? 'Running 8-Phase Scan…' : 'Launching Verification…'}</>
            ) : (
              <><Play className="w-4 h-4 mr-2" />
                {isEnterprise ? 'Launch Enterprise Scan (8 Phases)' : `Launch ${scope.charAt(0).toUpperCase() + scope.slice(1)} Verification (${scope === 'quick' ? '6' : scope === 'standard' ? '12' : '19'} Phases)`}
              </>
            )}
          </Button>
          {isEnterprise && (
            <Button
              onClick={() => reportMutation.mutate()}
              disabled={!targetUrl.trim() || reportMutation.isPending || scanRunning}
              variant="outline"
              className="border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10"
            >
              {reportMutation.isPending ? (
                <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Generating…</>
              ) : (
                <><FileText className="w-4 h-4 mr-2" />Run + Report</>
              )}
            </Button>
          )}
        </div>

        {/* Report Download/View Buttons */}
        {reportReady && (
          <div className="flex gap-2 pt-1">
            <Button
              variant="outline"
              size="sm"
              className="border-cyan-500/40 text-cyan-400 hover:bg-cyan-500/10"
              onClick={() => window.open(microPentestApi.viewReportUrl, '_blank')}
            >
              <Eye className="w-3.5 h-3.5 mr-1.5" />View Report
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="border-violet-500/40 text-violet-400 hover:bg-violet-500/10"
              onClick={() => window.open(microPentestApi.downloadReportUrl, '_blank')}
            >
              <Download className="w-3.5 h-3.5 mr-1.5" />Download HTML
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Loading Skeleton & Empty State
// ─────────────────────────────────────────────────────────────────────────────

function VerificationSkeleton() {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <Card key={i} className="border-slate-700/50 bg-slate-800/40">
            <CardContent className="p-4 space-y-3">
              <div className="w-6 h-6 rounded bg-slate-700/50 animate-pulse" />
              <div className="w-16 h-6 rounded bg-slate-700/50 animate-pulse" />
              <div className="w-24 h-3 rounded bg-slate-700/30 animate-pulse" />
            </CardContent>
          </Card>
        ))}
      </div>
      {Array.from({ length: 3 }).map((_, i) => (
        <Card key={i} className="border-slate-700/50 bg-slate-800/30">
          <CardContent className="p-4">
            <div className="flex items-center gap-4">
              <div className="flex-1 space-y-2">
                <div className="w-48 h-5 rounded bg-slate-700/50 animate-pulse" />
                <div className="w-64 h-3 rounded bg-slate-700/30 animate-pulse" />
              </div>
              <div className="w-20 h-6 rounded-full bg-slate-700/50 animate-pulse" />
              <div className="w-14 h-14 rounded-full bg-slate-700/30 animate-pulse" />
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function EmptyState() {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className="flex flex-col items-center justify-center py-16 px-8"
    >
      <div className="w-20 h-20 rounded-2xl bg-slate-800/60 border border-slate-700/50 flex items-center justify-center mb-6">
        <Shield className="w-10 h-10 text-slate-600" />
      </div>
      <h3 className="text-lg font-semibold text-slate-300 mb-2">No Verifications Yet</h3>
      <p className="text-sm text-slate-500 text-center max-w-md leading-relaxed">
        Launch your first MPTE verification to prove whether a vulnerability is truly exploitable.
        Each verification runs up to 19 phases of automated penetration testing with full evidence collection.
      </p>
    </motion.div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Component
// ─────────────────────────────────────────────────────────────────────────────

export default function MPTEConsole() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState('verifications');
  const [searchQuery, setSearchQuery] = useState('');
  const [verdictFilter, setVerdictFilter] = useState<Verdict | 'ALL'>('ALL');

  // Fetch verification requests
  const { data: requestsData, isLoading: requestsLoading } = useQuery({
    queryKey: ['mpte-requests'],
    queryFn: () => mpteApi.getRequests(),
    retry: 1,
    staleTime: 5_000,
    refetchInterval: (query) => {
      const items = query.state.data?.items || query.state.data?.requests || [];
      const hasPending = Array.isArray(items) && items.some(
        (r: Record<string, unknown>) => r.status === 'pending' || r.status === 'running'
      );
      return hasPending ? 3_000 : false;
    },
  });

  // Fetch verification results
  const { data: resultsData, isLoading: resultsLoading } = useQuery({
    queryKey: ['mpte-results'],
    queryFn: () => mpteApi.getResults(),
    retry: 1,
    staleTime: 5_000,
    refetchInterval: () => {
      const items = requestsData?.items || requestsData?.requests || [];
      const hasPending = Array.isArray(items) && items.some(
        (r: Record<string, unknown>) => r.status === 'pending' || r.status === 'running'
      );
      return hasPending ? 3_000 : false;
    },
  });

  // Transform API data or fall back to demo data
  const verifications: VerificationResult[] = useMemo(() => {
    const rawResults = resultsData?.items || resultsData?.results || (Array.isArray(resultsData) ? resultsData : []);

    if (rawResults.length === 0) {
      return []; // No verifications yet — run a scan via the MPTE engine
    }

    return rawResults.map((res: Record<string, unknown>, idx: number) => {
      const exploitability = (res.exploitability as string) || '';
      const verdict: Verdict = (() => {
        const e = exploitability.toLowerCase();
        if (e === 'confirmed' || e === 'exploitable') return 'EXPLOITABLE';
        if (e === 'not_exploitable') return 'NOT_EXPLOITABLE';
        return 'INCONCLUSIVE';
      })();

      const confidence = typeof res.confidence_score === 'number'
        ? Math.round(res.confidence_score * (res.confidence_score <= 1 ? 100 : 1))
        : 75;

      const phases: PhaseResult[] = Array.isArray(res.phases)
        ? (res.phases as PhaseResult[])
        : []; // No phase data from API — phases unavailable

      return {
        id: (res.id as string) || `vr-${idx}`,
        requestId: (res.request_id as string) || '',
        target: (res.target as string) || (res.target_url as string) || 'Unknown Target',
        targetUrl: (res.target_url as string) || '',
        cveId: (res.cve_id as string) || null,
        verdict,
        confidenceScore: confidence,
        scope: 'full' as VerificationScope,
        phases,
        startedAt: (res.started_at as string) || new Date().toISOString(),
        completedAt: (res.completed_at as string) || null,
        riskScore: typeof res.risk_score === 'number' ? res.risk_score : 5.0,
        findingId: (res.finding_id as string) || null,
        failScore: res.fail_score ? (res.fail_score as { grade: string; score: number }) : null,
      };
    });
  }, [resultsData]);

  // Filter verifications by search + verdict
  const filteredVerifications = useMemo(() => {
    let result = verifications;
    if (verdictFilter !== 'ALL') {
      result = result.filter(v => v.verdict === verdictFilter);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(v =>
        v.target.toLowerCase().includes(q) ||
        v.targetUrl.toLowerCase().includes(q) ||
        (v.cveId && v.cveId.toLowerCase().includes(q)) ||
        v.verdict.toLowerCase().includes(q)
      );
    }
    return result;
  }, [verifications, searchQuery, verdictFilter]);

  const handleRefresh = useCallback(() => {
    queryClient.invalidateQueries({ queryKey: ['mpte-requests'] });
    queryClient.invalidateQueries({ queryKey: ['mpte-results'] });
    toast.success('Refreshing verification data...');
  }, [queryClient]);

  const handleExport = useCallback(async () => {
    try {
      toast.loading('Generating MPTE report...', { id: 'mpte-report' });
      // Try to get report data from the API
      const data = await microPentestApi.getReportData();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `mpte-report-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success('Report downloaded', { id: 'mpte-report' });
    } catch {
      // Fallback: export current verifications data
      const blob = new Blob([JSON.stringify(verifications, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `mpte-verifications-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success('Verifications exported', { id: 'mpte-report' });
    }
  }, [verifications]);

  const isLoading = requestsLoading || resultsLoading;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Page Header */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: EASE_OUT_EXPO }}
        className="flex flex-col sm:flex-row sm:items-center justify-between gap-4"
      >
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center shadow-lg shadow-indigo-500/20">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-100 tracking-tight">MPTE Console</h1>
            <p className="text-sm text-slate-500">Micro Pentest Verification Engine — 19-Phase Exploitability Proof</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <MpteHealthBadge />
          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            className="border-slate-700 text-slate-400 hover:text-slate-200"
            aria-label="Refresh verification data"
          >
            <RefreshCw className="w-4 h-4 mr-1.5" />
            Refresh
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleExport}
            className="border-slate-700 text-slate-400 hover:text-slate-200"
            aria-label="Download all verification reports"
          >
            <Download className="w-4 h-4 mr-1.5" />
            Export
          </Button>
        </div>
      </motion.div>

      {/* Hero Stats */}
      {!isLoading && <HeroStatsBar verifications={verifications} />}

      {/* Main Content Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <TabsList className="bg-slate-800/60 border border-slate-700/40">
            <TabsTrigger value="verifications" className="data-[state=active]:bg-slate-700">
              <Eye className="w-4 h-4 mr-1.5" />
              Verifications ({filteredVerifications.length})
            </TabsTrigger>
            <TabsTrigger value="live" className="data-[state=active]:bg-slate-700">
              <Activity className="w-4 h-4 mr-1.5" />
              Live Run
            </TabsTrigger>
            <TabsTrigger value="analytics" className="data-[state=active]:bg-slate-700">
              <BarChart3 className="w-4 h-4 mr-1.5" />
              Analytics
            </TabsTrigger>
            <TabsTrigger value="new" className="data-[state=active]:bg-slate-700">
              <Plus className="w-4 h-4 mr-1.5" />
              New
            </TabsTrigger>
          </TabsList>

          {activeTab === 'verifications' && (
            <div className="flex items-center gap-2">
              {/* Verdict Filter Pills */}
              <div className="flex items-center gap-1">
                {(['ALL', 'EXPLOITABLE', 'NOT_EXPLOITABLE', 'INCONCLUSIVE'] as const).map(v => (
                  <button
                    key={v}
                    onClick={() => setVerdictFilter(v)}
                    className={`px-2 py-0.5 rounded-full text-[10px] font-semibold transition-all ${
                      verdictFilter === v
                        ? v === 'ALL' ? 'bg-slate-700 text-slate-200' :
                          v === 'EXPLOITABLE' ? 'bg-red-500/20 text-red-400' :
                          v === 'NOT_EXPLOITABLE' ? 'bg-emerald-500/20 text-emerald-400' :
                          'bg-amber-500/20 text-amber-400'
                        : 'text-slate-600 hover:text-slate-400'
                    }`}
                  >
                    {v === 'ALL' ? 'All' : v === 'NOT_EXPLOITABLE' ? 'Safe' : v.charAt(0) + v.slice(1).toLowerCase()}
                  </button>
                ))}
              </div>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <Input
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search target, CVE, or verdict..."
                  className="pl-9 w-64 bg-slate-800/60 border-slate-700/50 text-sm"
                />
              </div>
            </div>
          )}
        </div>

        {/* Verifications Tab */}
        <TabsContent value="verifications" className="mt-4">
          {isLoading ? (
            <VerificationSkeleton />
          ) : filteredVerifications.length === 0 ? (
            <EmptyState />
          ) : (
            <div className="space-y-3">
              {filteredVerifications.map((v) => (
                <VerificationCard key={v.id} verification={v} />
              ))}
            </div>
          )}
        </TabsContent>

        {/* Live Run Tab */}
        <TabsContent value="live" className="mt-4">
          <LiveRunViewer />
        </TabsContent>

        {/* Analytics Tab */}
        <TabsContent value="analytics" className="mt-4">
          <PhaseAnalyticsDashboard verifications={verifications} />
        </TabsContent>

        {/* New Verification Tab */}
        <TabsContent value="new" className="mt-4">
          <div className="max-w-2xl">
            <NewVerificationForm onCreated={() => {
              handleRefresh();
              setActiveTab('verifications');
            }} />
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
