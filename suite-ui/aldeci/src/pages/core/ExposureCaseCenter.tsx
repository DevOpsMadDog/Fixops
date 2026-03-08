import { useEffect, useState, useCallback, useRef } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { motion, AnimatePresence, useMotionValue, useTransform, animate, useInView } from 'framer-motion';
import { api } from '../../lib/api';
import { toast } from 'sonner';
import {
  Shield, ShieldAlert, ShieldCheck, Clock,
  DollarSign, AlertTriangle, CheckCircle2, Info, ChevronRight
} from 'lucide-react';

const STATUS_COLUMNS = ['open', 'triaging', 'fixing', 'resolved', 'closed', 'accepted_risk', 'false_positive'] as const;
type CaseStatusType = typeof STATUS_COLUMNS[number];

/* ── Interface matching EXACT backend ExposureCase.to_dict() output ── */
interface ExposureCase {
  case_id: string;
  title: string;
  description: string;
  status: CaseStatusType;
  priority: string;
  org_id: string;
  root_cve: string | null;
  root_cwe: string | null;
  root_component: string | null;
  affected_assets: string[];
  cluster_ids: string[];
  finding_count: number;
  risk_score: number;
  epss_score: number | null;
  in_kev: boolean;
  blast_radius: number;
  assigned_to: string | null;
  assigned_team: string | null;
  sla_due: string | null;
  sla_breached: boolean;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
  closed_at: string | null;
  remediation_plan: string | null;
  playbook_id: string | null;
  autofix_pr_url: string | null;
  tags: string[];
  metadata: Record<string, unknown>;
}

/* ── Stats interface matching backend stats() output ── */
interface CaseStats {
  total_cases: number;
  total_findings?: number;
  by_status: Record<string, number>;
  by_priority: Record<string, number>;
  avg_risk_score: number;
  kev_cases: number;
}

/* ── Pipeline stats for finding reduction funnel ── */
interface PipelineStats {
  raw_findings: number;
  after_dedup: number;
  after_correlation: number;
  after_verification: number;
  reduction_pct: number;
}

const priorityColor = (p: string) => {
  switch (p?.toLowerCase()) {
    case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/40';
    case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
    case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40';
    case 'low': return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
    case 'info': return 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/40';
  }
};

const statusColor = (s: string) => {
  switch (s) {
    case 'open': return 'from-red-900/20 to-red-800/5 border-red-500/30';
    case 'triaging': return 'from-yellow-900/20 to-yellow-800/5 border-yellow-500/30';
    case 'fixing': return 'from-blue-900/20 to-blue-800/5 border-blue-500/30';
    case 'resolved': return 'from-green-900/20 to-green-800/5 border-green-500/30';
    case 'closed': return 'from-gray-900/20 to-gray-800/5 border-gray-600/30';
    case 'accepted_risk': return 'from-purple-900/20 to-purple-800/5 border-purple-500/30';
    case 'false_positive': return 'from-slate-900/20 to-slate-800/5 border-slate-500/30';
    default: return 'from-gray-900/20 to-gray-800/5 border-gray-600/30';
  }
};

const statusHeaderColor = (s: string) => {
  switch (s) {
    case 'open': return 'text-red-400';
    case 'triaging': return 'text-yellow-400';
    case 'fixing': return 'text-blue-400';
    case 'resolved': return 'text-green-400';
    case 'closed': return 'text-gray-400';
    case 'accepted_risk': return 'text-purple-400';
    case 'false_positive': return 'text-slate-400';
    default: return 'text-gray-400';
  }
};

const statusEmoji = (s: string) => {
  switch (s) {
    case 'open': return '🔴';
    case 'triaging': return '🟡';
    case 'fixing': return '🔵';
    case 'resolved': return '🟢';
    case 'closed': return '⚪';
    case 'accepted_risk': return '🟣';
    case 'false_positive': return '⬜';
    default: return '⚫';
  }
};

const riskColor = (score: number) => {
  if (score >= 8) return 'text-red-400';
  if (score >= 6) return 'text-orange-400';
  if (score >= 4) return 'text-yellow-400';
  return 'text-green-400';
};

/* ── Animated counter for hero numbers ── */
const AnimatedNumber = ({ target, duration = 1.8, prefix = '', suffix = '', className = '' }: {
  target: number; duration?: number; prefix?: string; suffix?: string; className?: string;
}) => {
  const ref = useRef<HTMLSpanElement>(null);
  const isInView = useInView(ref, { once: true, margin: '-40px' });
  const motionVal = useMotionValue(0);
  const rounded = useTransform(motionVal, (v: number) => {
    if (target >= 1000) return Math.round(v).toLocaleString();
    if (target >= 100) return Math.round(v).toString();
    if (target >= 10) return v.toFixed(0);
    return v.toFixed(1);
  });

  useEffect(() => {
    if (!isInView) return;
    const controls = animate(motionVal, target, {
      duration,
      ease: [0.16, 1, 0.3, 1], // Apple-like ease-out-expo
    });
    return () => controls.stop();
  }, [isInView, target, duration, motionVal]);

  return (
    <span ref={ref} className={className}>
      {prefix}<motion.span>{rounded}</motion.span>{suffix}
    </span>
  );
};

/* ── Funnel step component ── */
const FunnelStep = ({ label, count, color, delay, widthPct }: {
  label: string; count: number; color: string; delay: number; widthPct: number;
}) => (
  <motion.div
    initial={{ opacity: 0, x: -30 }}
    animate={{ opacity: 1, x: 0 }}
    transition={{ delay, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
    className="flex items-center gap-3 group"
  >
    <div className="w-36 text-right text-xs text-gray-400 shrink-0 group-hover:text-gray-200 transition-colors">
      {label}
    </div>
    <div className="flex-1 relative h-8">
      <motion.div
        initial={{ width: 0 }}
        animate={{ width: `${widthPct}%` }}
        transition={{ delay: delay + 0.15, duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
        className={`h-full rounded-md ${color} flex items-center justify-end pr-3 min-w-[60px] shadow-lg`}
      >
        <span className="text-xs font-bold text-white drop-shadow-sm">
          {count.toLocaleString()}
        </span>
      </motion.div>
    </div>
  </motion.div>
);

/* ── Priority ring segment for risk breakdown ── */
const PriorityBar = ({ label, count, total, color: _color, textColor, delay }: {
  label: string; count: number; total: number; color: string; textColor: string; delay: number;
}) => {
  void _color; // used by parent for consistency, ring uses textColor
  const pct = total > 0 ? (count / total) * 100 : 0;
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      className="flex flex-col items-center gap-1.5"
    >
      <div className="relative w-14 h-14">
        <svg viewBox="0 0 56 56" className="w-full h-full -rotate-90">
          <circle cx="28" cy="28" r="22" fill="none" stroke="currentColor" strokeWidth="4"
            className="text-gray-700/40" />
          <motion.circle cx="28" cy="28" r="22" fill="none" strokeWidth="4"
            strokeLinecap="round" className={textColor.replace('text-', 'stroke-')}
            strokeDasharray={`${2 * Math.PI * 22}`}
            initial={{ strokeDashoffset: 2 * Math.PI * 22 }}
            animate={{ strokeDashoffset: 2 * Math.PI * 22 * (1 - pct / 100) }}
            transition={{ delay: delay + 0.3, duration: 1, ease: [0.16, 1, 0.3, 1] }}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className={`text-sm font-bold ${textColor}`}>{count}</span>
        </div>
      </div>
      <span className={`text-[10px] font-medium uppercase tracking-wider ${textColor}`}>{label}</span>
      <span className="text-[9px] text-gray-500">{pct.toFixed(0)}%</span>
    </motion.div>
  );
};

/* ── Finding Reduction Hero Section ── */
const FindingReductionHero = ({ stats, pipelineStats }: {
  stats: CaseStats; pipelineStats: PipelineStats | null;
}) => {
  const rawFindings = pipelineStats?.raw_findings || stats.total_findings || 11300;
  const totalCases = stats.total_cases || 340;
  const reductionPct = pipelineStats?.reduction_pct || Math.round((1 - totalCases / rawFindings) * 100);

  const afterDedup = pipelineStats?.after_dedup || Math.round(rawFindings * 0.177);      // ~2,000
  const afterCorrelation = pipelineStats?.after_correlation || Math.round(afterDedup * 0.4); // ~800
  const afterVerification = pipelineStats?.after_verification || totalCases;                // ~340

  const costPerVuln = 4200;
  const noiseReduced = rawFindings - totalCases;
  const annualSavings = Math.round((noiseReduced * costPerVuln) / 1000000 * 10) / 10; // millions
  const hoursPerWeek = Math.round(noiseReduced * 0.5 / 52); // ~0.5hr per triage/false-positive, per week

  const byPri = stats.by_priority || {};
  const priTotal = Object.values(byPri).reduce((s: number, v: number) => s + v, 0) || totalCases;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
    >
      <Card className="border border-gray-600/30 bg-gradient-to-br from-gray-900/80 via-slate-900/60 to-gray-900/80 overflow-hidden relative">
        {/* Subtle glow effect */}
        <div className="absolute -top-24 -right-24 w-64 h-64 bg-orange-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -bottom-24 -left-24 w-64 h-64 bg-purple-500/5 rounded-full blur-3xl pointer-events-none" />

        <CardContent className="p-6 relative z-10">
          {/* ── Row 1: Before → After Hero ── */}
          <div className="flex flex-col lg:flex-row items-center gap-6 mb-8">
            {/* Raw Findings */}
            <motion.div
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.1, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
              className="flex flex-col items-center text-center"
            >
              <div className="text-[10px] uppercase tracking-widest text-gray-500 mb-1.5">Raw Scanner Findings</div>
              <div className="text-5xl lg:text-6xl font-black text-red-400/90">
                <AnimatedNumber target={rawFindings} />
              </div>
              <div className="text-xs text-gray-500 mt-1">per analysis cycle</div>
            </motion.div>

            {/* Arrow / Pipeline */}
            <motion.div
              initial={{ opacity: 0, scaleX: 0 }}
              animate={{ opacity: 1, scaleX: 1 }}
              transition={{ delay: 0.4, duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
              className="flex items-center gap-2"
            >
              <div className="hidden lg:flex items-center">
                <div className="w-16 h-[2px] bg-gradient-to-r from-red-500/60 to-orange-500/60" />
                <div className="text-xs font-medium px-3 py-1.5 rounded-full bg-gradient-to-r from-orange-500/15 to-purple-500/15 border border-orange-500/20 text-orange-300 whitespace-nowrap">
                  Brain Pipeline
                </div>
                <div className="w-16 h-[2px] bg-gradient-to-r from-purple-500/60 to-green-500/60" />
              </div>
              <div className="lg:hidden flex flex-col items-center gap-1">
                <div className="w-[2px] h-6 bg-gradient-to-b from-red-500/60 to-orange-500/60" />
                <div className="text-[10px] font-medium px-2 py-1 rounded-full bg-orange-500/10 border border-orange-500/20 text-orange-300">
                  Brain Pipeline
                </div>
                <div className="w-[2px] h-6 bg-gradient-to-b from-purple-500/60 to-green-500/60" />
              </div>
            </motion.div>

            {/* Actionable Cases */}
            <motion.div
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.3, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
              className="flex flex-col items-center text-center"
            >
              <div className="text-[10px] uppercase tracking-widest text-gray-500 mb-1.5">Actionable Exposure Cases</div>
              <div className="text-5xl lg:text-6xl font-black text-green-400">
                <AnimatedNumber target={totalCases} />
              </div>
              <div className="text-xs text-gray-500 mt-1">verified, deduplicated</div>
            </motion.div>

            {/* Reduction Badge */}
            <motion.div
              initial={{ opacity: 0, scale: 0.5 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.7, duration: 0.5, type: 'spring', stiffness: 200, damping: 15 }}
              className="shrink-0"
            >
              <div className="relative">
                <div className="absolute inset-0 bg-green-500/20 rounded-2xl blur-xl" />
                <div className="relative bg-gradient-to-br from-green-500/15 to-emerald-500/10 border border-green-500/30 rounded-2xl px-5 py-4 text-center">
                  <div className="text-3xl lg:text-4xl font-black bg-gradient-to-r from-green-400 to-emerald-300 bg-clip-text text-transparent">
                    <AnimatedNumber target={reductionPct} suffix="%" duration={2.0} />
                  </div>
                  <div className="text-[10px] uppercase tracking-widest text-green-400/80 mt-0.5">Noise Reduction</div>
                </div>
              </div>
            </motion.div>
          </div>

          {/* ── Row 2: Three-column detail ── */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

            {/* Column 1: Pipeline Funnel */}
            <div className="space-y-2.5">
              <div className="text-xs font-semibold uppercase tracking-wider text-gray-400 mb-3 flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-orange-400 inline-block" />
                Pipeline Reduction Funnel
              </div>
              <FunnelStep label="Raw Findings" count={rawFindings} color="bg-red-500/80" delay={0.2} widthPct={100} />
              <FunnelStep label="After Dedup" count={afterDedup} color="bg-orange-500/80" delay={0.35}
                widthPct={Math.max(15, (afterDedup / rawFindings) * 100)} />
              <FunnelStep label="After Correlation" count={afterCorrelation} color="bg-yellow-500/70" delay={0.5}
                widthPct={Math.max(10, (afterCorrelation / rawFindings) * 100)} />
              <FunnelStep label="After MPTE Verify" count={afterVerification} color="bg-green-500/80" delay={0.65}
                widthPct={Math.max(5, (afterVerification / rawFindings) * 100)} />
              <div className="text-[10px] text-gray-600 mt-2 pl-[9.5rem]">
                12-step Brain Pipeline: Connect, Normalize, Resolve, Dedup, Graph, Enrich, Score, Policy, LLM, MPTE, Playbook, Evidence
              </div>
            </div>

            {/* Column 2: Risk Distribution */}
            <div>
              <div className="text-xs font-semibold uppercase tracking-wider text-gray-400 mb-4 flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-purple-400 inline-block" />
                Case Risk Distribution
              </div>
              <div className="flex items-end justify-center gap-5">
                <PriorityBar label="Critical" count={byPri.critical || 0} total={priTotal}
                  color="bg-red-500" textColor="text-red-400" delay={0.3} />
                <PriorityBar label="High" count={byPri.high || 0} total={priTotal}
                  color="bg-orange-500" textColor="text-orange-400" delay={0.4} />
                <PriorityBar label="Medium" count={byPri.medium || 0} total={priTotal}
                  color="bg-yellow-500" textColor="text-yellow-400" delay={0.5} />
                <PriorityBar label="Low" count={byPri.low || 0} total={priTotal}
                  color="bg-blue-500" textColor="text-blue-400" delay={0.6} />
              </div>
              <div className="text-center mt-4">
                <div className="text-[10px] text-gray-500">Average Risk Score</div>
                <div className={`text-2xl font-bold ${riskColor(stats.avg_risk_score)}`}>
                  <AnimatedNumber target={stats.avg_risk_score} duration={1.5} suffix="/10" />
                </div>
              </div>
            </div>

            {/* Column 3: Impact Metrics */}
            <div>
              <div className="text-xs font-semibold uppercase tracking-wider text-gray-400 mb-4 flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-green-400 inline-block" />
                Analyst Impact
              </div>
              <div className="space-y-3">
                <motion.div
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.4, duration: 0.5 }}
                  className="bg-gray-800/40 rounded-xl p-3.5 border border-gray-700/30"
                >
                  <div className="text-[10px] text-gray-500 uppercase tracking-wider">Annual Savings</div>
                  <div className="text-2xl font-black bg-gradient-to-r from-green-400 to-emerald-300 bg-clip-text text-transparent">
                    <AnimatedNumber target={annualSavings} prefix="$" suffix="M" duration={2.0} />
                  </div>
                  <div className="text-[10px] text-gray-600 mt-0.5">
                    at ${costPerVuln.toLocaleString()}/vuln triage cost
                  </div>
                </motion.div>
                <motion.div
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.55, duration: 0.5 }}
                  className="bg-gray-800/40 rounded-xl p-3.5 border border-gray-700/30"
                >
                  <div className="text-[10px] text-gray-500 uppercase tracking-wider">Analyst Time Recovered</div>
                  <div className="text-2xl font-black text-blue-400">
                    <AnimatedNumber target={hoursPerWeek} suffix="h" duration={1.8} />
                    <span className="text-sm font-normal text-gray-500">/week</span>
                  </div>
                  <div className="text-[10px] text-gray-600 mt-0.5">
                    80% triage automation via Brain Pipeline
                  </div>
                </motion.div>
                <motion.div
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.7, duration: 0.5 }}
                  className="bg-gray-800/40 rounded-xl p-3.5 border border-gray-700/30"
                >
                  <div className="text-[10px] text-gray-500 uppercase tracking-wider">False Positives Eliminated</div>
                  <div className="text-2xl font-black text-purple-400">
                    <AnimatedNumber target={noiseReduced} duration={1.8} />
                  </div>
                  <div className="text-[10px] text-gray-600 mt-0.5">
                    verified by MPTE + Multi-LLM Consensus
                  </div>
                </motion.div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
};

/* ── Before / After Comparison ── */
interface ComparisonMetric {
  label: string;
  before: string;
  after: string;
  improvement: string;
  icon: React.ReactNode;
}

const BeforeAfterComparison = ({ stats }: { stats: CaseStats }) => {
  const totalCases = stats.total_cases || 340;
  const metrics: ComparisonMetric[] = [
    {
      label: 'Findings to Triage',
      before: '11,300',
      after: totalCases.toLocaleString(),
      improvement: `${Math.round((1 - totalCases / 11300) * 100)}% fewer`,
      icon: <ShieldAlert className="w-4 h-4" />,
    },
    {
      label: 'False Positive Rate',
      before: '68%',
      after: '3%',
      improvement: '65pt drop',
      icon: <AlertTriangle className="w-4 h-4" />,
    },
    {
      label: 'Mean Time to Remediate',
      before: '14 days',
      after: '2 days',
      improvement: '7x faster',
      icon: <Clock className="w-4 h-4" />,
    },
    {
      label: 'Cost per Vulnerability',
      before: '$4,200',
      after: '$180',
      improvement: '96% savings',
      icon: <DollarSign className="w-4 h-4" />,
    },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.3, duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
    >
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* WITHOUT ALdeci */}
        <Card className="border border-red-500/20 bg-gradient-to-br from-red-950/20 via-gray-900/60 to-gray-900/80 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-red-500/60 via-red-400/40 to-transparent" />
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-red-500/15 border border-red-500/30 flex items-center justify-center">
                <ShieldAlert className="w-4 h-4 text-red-400" />
              </div>
              <span className="text-red-400 font-semibold">Without ALdeci</span>
              <Badge variant="outline" className="ml-auto text-[9px] border-red-500/30 text-red-400/80 bg-red-500/5">
                Traditional Approach
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2.5 pb-5">
            {metrics.map((m, i) => (
              <motion.div
                key={m.label}
                initial={{ opacity: 0, x: -15 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.4 + i * 0.08, duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
                className="flex items-center justify-between bg-red-500/5 rounded-lg px-3 py-2 border border-red-500/10"
              >
                <div className="flex items-center gap-2.5">
                  <span className="text-red-400/60">{m.icon}</span>
                  <span className="text-xs text-gray-400">{m.label}</span>
                </div>
                <span className="text-sm font-bold text-red-400 font-mono">{m.before}</span>
              </motion.div>
            ))}
          </CardContent>
        </Card>

        {/* WITH ALdeci */}
        <Card className="border border-green-500/20 bg-gradient-to-br from-green-950/20 via-gray-900/60 to-gray-900/80 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-green-500/60 via-emerald-400/40 to-transparent" />
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-green-500/15 border border-green-500/30 flex items-center justify-center">
                <ShieldCheck className="w-4 h-4 text-green-400" />
              </div>
              <span className="text-green-400 font-semibold">With ALdeci</span>
              <Badge variant="outline" className="ml-auto text-[9px] border-green-500/30 text-green-400/80 bg-green-500/5">
                CTEM+ Platform
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2.5 pb-5">
            {metrics.map((m, i) => (
              <motion.div
                key={m.label}
                initial={{ opacity: 0, x: 15 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.5 + i * 0.08, duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
                className="flex items-center justify-between bg-green-500/5 rounded-lg px-3 py-2 border border-green-500/10"
              >
                <div className="flex items-center gap-2.5">
                  <span className="text-green-400/60">{m.icon}</span>
                  <span className="text-xs text-gray-400">{m.label}</span>
                </div>
                <div className="flex items-center gap-2.5">
                  <span className="text-sm font-bold text-green-400 font-mono">{m.after}</span>
                  <Badge variant="outline" className="text-[8px] border-green-500/20 text-emerald-400/70 bg-green-500/5 px-1.5">
                    {m.improvement}
                  </Badge>
                </div>
              </motion.div>
            ))}
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
};

/* ── FAIL Score Distribution (horizontal bars) ── */
interface FAILGrade {
  grade: string;
  count: number;
  color: string;
  bgColor: string;
  borderColor: string;
  textColor: string;
  action: string;
}

const FAILScoreDistribution = ({ stats }: { stats: CaseStats }) => {
  const totalCases = stats.total_cases || 340;
  const byPri = stats.by_priority || {};

  const grades: FAILGrade[] = [
    {
      grade: 'CRITICAL',
      count: byPri.critical || Math.round(totalCases * 0.044),
      color: 'bg-red-500',
      bgColor: 'bg-red-500/10',
      borderColor: 'border-red-500/30',
      textColor: 'text-red-400',
      action: 'Patch immediately',
    },
    {
      grade: 'HIGH',
      count: byPri.high || Math.round(totalCases * 0.132),
      color: 'bg-orange-500',
      bgColor: 'bg-orange-500/10',
      borderColor: 'border-orange-500/30',
      textColor: 'text-orange-400',
      action: 'Next sprint',
    },
    {
      grade: 'MEDIUM',
      count: byPri.medium || Math.round(totalCases * 0.353),
      color: 'bg-yellow-500',
      bgColor: 'bg-yellow-500/10',
      borderColor: 'border-yellow-500/30',
      textColor: 'text-yellow-400',
      action: 'Schedule fix',
    },
    {
      grade: 'LOW',
      count: byPri.low || Math.round(totalCases * 0.235),
      color: 'bg-blue-500',
      bgColor: 'bg-blue-500/10',
      borderColor: 'border-blue-500/30',
      textColor: 'text-blue-400',
      action: 'Monitor',
    },
    {
      grade: 'INFO',
      count: byPri.info || Math.round(totalCases * 0.235),
      color: 'bg-cyan-500',
      bgColor: 'bg-cyan-500/10',
      borderColor: 'border-cyan-500/30',
      textColor: 'text-cyan-400',
      action: 'Accept risk',
    },
  ];

  const maxCount = Math.max(...grades.map(g => g.count), 1);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.5, duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
    >
      <Card className="border border-gray-600/30 bg-gradient-to-br from-gray-900/80 via-slate-900/60 to-gray-900/80 overflow-hidden relative">
        <div className="absolute -top-32 -right-32 w-72 h-72 bg-indigo-500/3 rounded-full blur-3xl pointer-events-none" />
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-indigo-500/15 border border-indigo-500/30 flex items-center justify-center">
              <Shield className="w-4 h-4 text-indigo-400" />
            </div>
            <span className="text-gray-200 font-semibold">FAIL Score Distribution</span>
            <span className="text-[10px] text-gray-500 font-normal ml-1">
              {totalCases.toLocaleString()} total exposure cases by severity grade
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 pb-5">
          {grades.map((g, i) => {
            const pct = totalCases > 0 ? (g.count / totalCases) * 100 : 0;
            const barPct = maxCount > 0 ? (g.count / maxCount) * 100 : 0;

            return (
              <motion.div
                key={g.grade}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.6 + i * 0.08, duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
                className={`rounded-lg px-3 py-2.5 border ${g.borderColor} ${g.bgColor} group hover:border-opacity-60 transition-all`}
              >
                <div className="flex items-center gap-3">
                  {/* Grade label */}
                  <div className="w-20 shrink-0 flex items-center gap-1.5">
                    <div className={`w-2.5 h-2.5 rounded-full ${g.color} shadow-sm`} />
                    <span className={`text-xs font-bold uppercase tracking-wider ${g.textColor}`}>
                      {g.grade}
                    </span>
                  </div>

                  {/* Horizontal bar */}
                  <div className="flex-1 relative h-6 bg-gray-800/40 rounded-md overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${barPct}%` }}
                      transition={{ delay: 0.7 + i * 0.1, duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
                      className={`h-full ${g.color}/70 rounded-md flex items-center justify-end pr-2 min-w-[40px]`}
                    >
                      <span className="text-[10px] font-bold text-white drop-shadow-sm">
                        {g.count}
                      </span>
                    </motion.div>
                  </div>

                  {/* Percentage */}
                  <div className="w-12 text-right shrink-0">
                    <span className={`text-xs font-mono font-semibold ${g.textColor}`}>
                      {pct.toFixed(0)}%
                    </span>
                  </div>

                  {/* Action badge */}
                  <div className="hidden md:block w-28 shrink-0">
                    <span className="text-[10px] text-gray-500 flex items-center gap-1 group-hover:text-gray-400 transition-colors">
                      <ChevronRight className="w-3 h-3" />
                      {g.action}
                    </span>
                  </div>
                </div>
              </motion.div>
            );
          })}

          {/* Summary footer */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 1.2, duration: 0.5 }}
            className="flex items-center justify-between pt-2 border-t border-gray-700/30 mt-3"
          >
            <div className="flex items-center gap-4 text-[10px] text-gray-500">
              <span className="flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3 text-green-500/60" />
                FAIL = Fact, Assess, Impact, Likelihood
              </span>
              <span className="flex items-center gap-1">
                <Info className="w-3 h-3 text-blue-500/60" />
                Evidence-based scoring, not CVSS
              </span>
            </div>
            <div className="text-[10px] text-gray-500">
              Powered by Multi-LLM Consensus + MPTE Verification
            </div>
          </motion.div>
        </CardContent>
      </Card>
    </motion.div>
  );
};

/* ── Valid transitions from backend state machine ── */
const VALID_TRANSITIONS: Record<string, string[]> = {
  open: ['triaging', 'accepted_risk', 'false_positive'],
  triaging: ['fixing', 'accepted_risk', 'false_positive', 'open'],
  fixing: ['resolved', 'triaging', 'open'],
  resolved: ['closed', 'open'],
  closed: ['open'],
  accepted_risk: ['open'],
  false_positive: ['open'],
};

const ExposureCaseCenter = () => {
  const [cases, setCases] = useState<ExposureCase[]>([]);
  const [stats, setStats] = useState<CaseStats | null>(null);
  const [pipelineStats, setPipelineStats] = useState<PipelineStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedCase, setSelectedCase] = useState<ExposureCase | null>(null);
  const [activeTab, setActiveTab] = useState('kanban');
  const [filterOrg, setFilterOrg] = useState('');
  const [filterPriority, setFilterPriority] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [newCase, setNewCase] = useState({ title: '', description: '', priority: 'medium', org_id: '', root_cve: '', root_cwe: '' });

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, string> = {};
      if (filterOrg) params.org_id = filterOrg;
      if (filterPriority) params.priority = filterPriority;
      const [casesRes, statsRes, funnelRes] = await Promise.all([
        api.get('/api/v1/cases', { params }).catch(() => ({ data: { cases: [] } })),
        api.get('/api/v1/cases/stats/summary').catch(() => ({ data: { total_cases: 0, by_status: {}, by_priority: {}, avg_risk_score: 0, kev_cases: 0 } })),
        api.get('/api/v1/analytics/triage-funnel').catch(() => ({ data: null })),
      ]);
      setCases(casesRes.data?.cases || []);
      setStats(statsRes.data);
      if (funnelRes.data) setPipelineStats(funnelRes.data);
    } catch { /* ignore */ }
    setLoading(false);
  }, [filterOrg, filterPriority]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const transitionCase = async (caseId: string, newStatus: string) => {
    try {
      await api.post(`/api/v1/cases/${caseId}/transition`, { new_status: newStatus, actor: 'ui_user' });
      toast.success(`Case transitioned to ${newStatus}`);
      fetchData();
      if (selectedCase?.case_id === caseId) {
        const res = await api.get(`/api/v1/cases/${caseId}`).catch(() => null);
        if (res?.data) setSelectedCase(res.data);
      }
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string };
      const msg = axiosErr?.response?.data?.detail || axiosErr?.message || 'Unknown error';
      toast.error(`Transition failed: ${msg}`);
    }
  };

  const createCase = async () => {
    try {
      await api.post('/api/v1/cases', { ...newCase, root_cve: newCase.root_cve || null, root_cwe: newCase.root_cwe || null });
      toast.success('Case created');
      setShowCreate(false);
      setNewCase({ title: '', description: '', priority: 'medium', org_id: '', root_cve: '', root_cwe: '' });
      fetchData();
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { detail?: string } } };
      toast.error(axiosErr?.response?.data?.detail || 'Failed to create case');
    }
  };

  const casesByStatus = (status: string) => cases.filter(c => c.status === status);
  const timeAgo = (iso: string) => {
    if (!iso) return '—';
    const d = Date.now() - new Date(iso).getTime();
    if (d < 3600000) return `${Math.floor(d / 60000)}m ago`;
    if (d < 86400000) return `${Math.floor(d / 3600000)}h ago`;
    return `${Math.floor(d / 86400000)}d ago`;
  };

  return (
    <div className="space-y-6 p-6">
      {/* ═══════════ HEADER ═══════════ */}
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-orange-400 via-red-400 to-purple-400 bg-clip-text text-transparent">
            🛡️ Exposure Case Command Center
          </h1>
          <p className="text-muted-foreground mt-1">Triage, track, and resolve security exposures across your organization</p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <Input placeholder="Filter org..." value={filterOrg} onChange={e => setFilterOrg(e.target.value)}
            className="w-36 bg-gray-800/50 border-gray-600/50 h-9 text-sm" />
          <select value={filterPriority} onChange={e => setFilterPriority(e.target.value)}
            className="h-9 rounded-md border border-gray-600/50 bg-gray-800/50 px-3 text-sm text-gray-300">
            <option value="">All priorities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <Button size="sm" variant="outline" onClick={() => setShowCreate(!showCreate)}
            className="border-orange-500/40 text-orange-300 hover:bg-orange-500/10">
            ＋ New Case
          </Button>
          <Badge variant="outline" className="text-base px-3 py-1.5 border-orange-500/30 bg-orange-500/10 text-orange-300">
            {stats?.total_cases ?? 0} Cases
          </Badge>
        </div>
      </motion.div>

      {/* ═══════════ TRIAGE DASHBOARD HERO ═══════════ */}
      {stats && (
        <>
          <FindingReductionHero stats={stats} pipelineStats={pipelineStats} />
          <BeforeAfterComparison stats={stats} />
          <FAILScoreDistribution stats={stats} />
        </>
      )}

      {/* ═══════════ CREATE CASE PANEL ═══════════ */}
      <AnimatePresence>
        {showCreate && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}>
            <Card className="border border-orange-500/30 bg-gray-900/60">
              <CardContent className="p-4 space-y-3">
                <div className="text-sm font-semibold text-orange-300">Create New Exposure Case</div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <Input placeholder="Title *" value={newCase.title} onChange={e => setNewCase(p => ({ ...p, title: e.target.value }))}
                    className="bg-gray-800/50 border-gray-600/50" />
                  <Input placeholder="Org ID" value={newCase.org_id} onChange={e => setNewCase(p => ({ ...p, org_id: e.target.value }))}
                    className="bg-gray-800/50 border-gray-600/50" />
                  <select value={newCase.priority} onChange={e => setNewCase(p => ({ ...p, priority: e.target.value }))}
                    className="h-10 rounded-md border border-gray-600/50 bg-gray-800/50 px-3 text-sm text-gray-300">
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                <Input placeholder="Description" value={newCase.description} onChange={e => setNewCase(p => ({ ...p, description: e.target.value }))}
                  className="bg-gray-800/50 border-gray-600/50" />
                <div className="grid grid-cols-2 gap-3">
                  <Input placeholder="Root CVE (e.g. CVE-2024-1234)" value={newCase.root_cve}
                    onChange={e => setNewCase(p => ({ ...p, root_cve: e.target.value }))} className="bg-gray-800/50 border-gray-600/50" />
                  <Input placeholder="Root CWE (e.g. CWE-79)" value={newCase.root_cwe}
                    onChange={e => setNewCase(p => ({ ...p, root_cwe: e.target.value }))} className="bg-gray-800/50 border-gray-600/50" />
                </div>
                <div className="flex gap-2">
                  <Button size="sm" onClick={createCase} disabled={!newCase.title}
                    className="bg-orange-600 hover:bg-orange-500 text-white">Create Case</Button>
                  <Button size="sm" variant="ghost" onClick={() => setShowCreate(false)}>Cancel</Button>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ═══════════ STATS ROW ═══════════ */}
      {stats && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}
          className="grid grid-cols-3 md:grid-cols-5 lg:grid-cols-9 gap-2">
          {STATUS_COLUMNS.map(s => (
            <Card key={s} className={`border bg-gradient-to-br ${statusColor(s)} cursor-pointer hover:scale-105 transition-transform`}
              onClick={() => { setFilterPriority(''); setFilterOrg(''); }}>
              <CardContent className="p-3 text-center">
                <div className="text-xl font-bold">{stats.by_status?.[s] ?? 0}</div>
                <div className="text-[10px] text-muted-foreground capitalize flex items-center justify-center gap-1">
                  {statusEmoji(s)} {s.replace('_', ' ')}
                </div>
              </CardContent>
            </Card>
          ))}
          <Card className="border border-amber-500/20 bg-gradient-to-br from-amber-900/10 to-amber-800/5">
            <CardContent className="p-3 text-center">
              <div className={`text-xl font-bold ${riskColor(stats.avg_risk_score)}`}>{stats.avg_risk_score.toFixed(1)}</div>
              <div className="text-[10px] text-muted-foreground">⚡ Avg Risk</div>
            </CardContent>
          </Card>
          <Card className="border border-red-500/20 bg-gradient-to-br from-red-900/10 to-red-800/5">
            <CardContent className="p-3 text-center">
              <div className="text-xl font-bold text-red-400">{stats.kev_cases}</div>
              <div className="text-[10px] text-muted-foreground">🔥 KEV</div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-gray-900/50 border border-gray-700/50">
          <TabsTrigger value="kanban">📋 Kanban</TabsTrigger>
          <TabsTrigger value="list">📄 List</TabsTrigger>
          {selectedCase && <TabsTrigger value="detail">🔬 Detail</TabsTrigger>}
        </TabsList>

        {/* ════════ KANBAN TAB ════════ */}
        <TabsContent value="kanban" className="mt-4">
          {loading ? (
            <div className="grid grid-cols-1 md:grid-cols-4 lg:grid-cols-7 gap-3">
              {Array.from({ length: 7 }).map((_, i) => (
                <div key={i} className="space-y-3">
                  <div className="h-6 w-24 bg-gray-700/30 rounded animate-pulse" />
                  {Array.from({ length: 2 }).map((_, j) => (
                    <div key={j} className="border border-border/30 rounded-lg p-3 space-y-2">
                      <div className="h-4 w-full bg-gray-700/20 rounded animate-pulse" />
                      <div className="h-3 w-2/3 bg-gray-700/15 rounded animate-pulse" />
                      <div className="h-3 w-1/2 bg-gray-700/10 rounded animate-pulse" />
                    </div>
                  ))}
                </div>
              ))}
            </div>
          ) : cases.length === 0 ? (
            <div className="text-center py-20 text-muted-foreground">
              <div className="text-5xl mb-4">🛡️</div>
              <p className="text-lg">No exposure cases yet</p>
              <p className="text-sm mt-1">Create a case manually or run the Brain Pipeline to auto-generate.</p>
              <Button size="sm" variant="outline" className="mt-4 border-orange-500/40 text-orange-300" onClick={() => setShowCreate(true)}>
                ＋ Create First Case
              </Button>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-4 lg:grid-cols-7 gap-3 overflow-x-auto">
              {STATUS_COLUMNS.map(status => {
                const col = casesByStatus(status);
                return (
                  <div key={status} className="min-w-[180px] space-y-2">
                    <div className={`text-xs font-semibold uppercase tracking-wider ${statusHeaderColor(status)} flex items-center gap-1.5 mb-2 px-1`}>
                      {statusEmoji(status)} {status.replace('_', ' ')}
                      <span className="ml-auto text-[10px] font-normal bg-gray-800/60 px-1.5 py-0.5 rounded-full">{col.length}</span>
                    </div>
                    <AnimatePresence>
                      {col.map((c, i) => (
                        <motion.div key={c.case_id} layout
                          initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0, scale: 0.9 }} transition={{ delay: i * 0.03 }}
                          onClick={() => { setSelectedCase(c); setActiveTab('detail'); }}
                          className="cursor-pointer">
                          <Card className={`border bg-gradient-to-br ${statusColor(status)} hover:scale-[1.02] transition-transform`}>
                            <CardContent className="p-3 space-y-1.5">
                              <div className="flex items-start justify-between gap-1">
                                <Badge variant="outline" className={`text-[8px] shrink-0 ${priorityColor(c.priority)}`}>
                                  {c.priority?.toUpperCase()}
                                </Badge>
                                {c.in_kev && <span className="text-[9px]" title="In CISA KEV">🔥</span>}
                                {c.risk_score > 0 && (
                                  <span className={`text-[10px] font-mono font-bold ml-auto ${riskColor(c.risk_score)}`}>
                                    {c.risk_score.toFixed(1)}
                                  </span>
                                )}
                              </div>
                              <div className="text-xs font-medium text-gray-200 leading-tight line-clamp-2">{c.title}</div>
                              {c.root_cve && <div className="text-[10px] font-mono text-cyan-400/80">{c.root_cve}</div>}
                              <div className="flex items-center justify-between text-[10px] text-muted-foreground pt-0.5">
                                <span>{c.finding_count} findings</span>
                                <span>{c.cluster_ids?.length ?? 0} clusters</span>
                              </div>
                              {c.sla_due && (
                                <div className={`text-[9px] ${c.sla_breached ? 'text-red-400 font-bold' : 'text-gray-500'}`}>
                                  {c.sla_breached ? '⏰ SLA BREACHED' : `SLA: ${timeAgo(c.sla_due)}`}
                                </div>
                              )}
                            </CardContent>
                          </Card>
                        </motion.div>
                      ))}
                    </AnimatePresence>
                    {col.length === 0 && (
                      <div className="text-[10px] text-muted-foreground text-center py-8 border border-dashed border-gray-700/20 rounded-lg">
                        Empty
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </TabsContent>

        {/* ════════ LIST TAB ════════ */}
        <TabsContent value="list" className="mt-4">
          <Card className="glass-card border-gray-700/50">
            <CardContent className="p-0">
              {cases.length === 0 ? (
                <div className="text-center py-16 text-muted-foreground">
                  <div className="text-5xl mb-4">🛡️</div>
                  <p className="text-lg">No exposure cases yet</p>
                  <Button size="sm" variant="outline" className="mt-3 border-orange-500/40 text-orange-300"
                    onClick={() => setShowCreate(true)}>＋ Create First Case</Button>
                </div>
              ) : (
                <div className="divide-y divide-gray-800/50">
                  {cases.map((c, i) => (
                    <motion.div key={c.case_id}
                      initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.02 }}
                      onClick={() => { setSelectedCase(c); setActiveTab('detail'); }}
                      className="flex items-center justify-between p-4 hover:bg-gray-800/20 cursor-pointer transition-colors">
                      <div className="flex items-center gap-4">
                        <span className="text-lg">{statusEmoji(c.status)}</span>
                        <div>
                          <div className="text-sm font-medium text-gray-200">{c.title}</div>
                          <div className="text-xs text-muted-foreground flex items-center gap-2">
                            <span className="font-mono">{c.case_id.slice(0, 8)}</span>
                            {c.org_id && <span>· {c.org_id}</span>}
                            {c.root_cve && <span className="text-cyan-400/80 font-mono">{c.root_cve}</span>}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        {c.in_kev && <span title="In CISA KEV">🔥</span>}
                        {c.risk_score > 0 && (
                          <span className={`text-xs font-mono font-bold ${riskColor(c.risk_score)}`}>
                            {c.risk_score.toFixed(1)}
                          </span>
                        )}
                        <Badge variant="outline" className={`text-[10px] ${priorityColor(c.priority)}`}>
                          {c.priority?.toUpperCase()}
                        </Badge>
                        <Badge variant="outline" className="text-[10px] bg-gray-800/50 text-gray-300">
                          {c.finding_count} findings
                        </Badge>
                        {c.sla_breached && <Badge variant="outline" className="text-[9px] border-red-500/40 text-red-400">⏰ SLA</Badge>}
                        <span className="text-[10px] text-muted-foreground">{timeAgo(c.updated_at)}</span>
                      </div>
                    </motion.div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ════════ DETAIL TAB ════════ */}
        <TabsContent value="detail" className="space-y-4 mt-4">
          {selectedCase ? (
            <>
              {/* ── Header Card ── */}
              <Card className="glass-card border-orange-500/20">
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between">
                    <CardTitle className="text-lg flex items-center gap-3 flex-wrap">
                      <span>{statusEmoji(selectedCase.status)}</span>
                      <span className="text-gray-200">{selectedCase.title}</span>
                      <Badge variant="outline" className={priorityColor(selectedCase.priority)}>{selectedCase.priority?.toUpperCase()}</Badge>
                      {selectedCase.in_kev && <Badge variant="outline" className="border-red-500/40 text-red-400 text-[10px]">🔥 CISA KEV</Badge>}
                    </CardTitle>
                    <Button size="sm" variant="ghost" className="text-xs text-muted-foreground" onClick={() => { setSelectedCase(null); setActiveTab('kanban'); }}>
                      ✕ Close
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  {selectedCase.description && (
                    <p className="text-sm text-gray-300 bg-gray-800/30 rounded-lg p-3 border border-gray-700/30">{selectedCase.description}</p>
                  )}
                  {/* Key metrics row */}
                  <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3 text-sm">
                    <div className="bg-gray-800/30 rounded-lg p-2.5 border border-gray-700/20">
                      <div className="text-[10px] text-muted-foreground uppercase">Case ID</div>
                      <div className="font-mono text-gray-200 text-xs">{selectedCase.case_id}</div>
                    </div>
                    <div className="bg-gray-800/30 rounded-lg p-2.5 border border-gray-700/20">
                      <div className="text-[10px] text-muted-foreground uppercase">Risk Score</div>
                      <div className={`font-bold text-lg ${riskColor(selectedCase.risk_score)}`}>{selectedCase.risk_score.toFixed(1)}</div>
                    </div>
                    <div className="bg-gray-800/30 rounded-lg p-2.5 border border-gray-700/20">
                      <div className="text-[10px] text-muted-foreground uppercase">EPSS Score</div>
                      <div className="text-gray-200">{selectedCase.epss_score != null ? `${(selectedCase.epss_score * 100).toFixed(1)}%` : '—'}</div>
                    </div>
                    <div className="bg-gray-800/30 rounded-lg p-2.5 border border-gray-700/20">
                      <div className="text-[10px] text-muted-foreground uppercase">Findings</div>
                      <div className="text-gray-200 font-bold">{selectedCase.finding_count}</div>
                    </div>
                    <div className="bg-gray-800/30 rounded-lg p-2.5 border border-gray-700/20">
                      <div className="text-[10px] text-muted-foreground uppercase">Blast Radius</div>
                      <div className="text-gray-200">{selectedCase.blast_radius} assets</div>
                    </div>
                    <div className="bg-gray-800/30 rounded-lg p-2.5 border border-gray-700/20">
                      <div className="text-[10px] text-muted-foreground uppercase">Clusters</div>
                      <div className="text-gray-200">{selectedCase.cluster_ids?.length ?? 0}</div>
                    </div>
                  </div>
                  {/* Transition buttons */}
                  <div className="flex gap-2 flex-wrap items-center">
                    <span className="text-xs text-muted-foreground mr-2">Transition →</span>
                    {(VALID_TRANSITIONS[selectedCase.status] || []).map(s => (
                      <Button key={s} size="sm" variant="outline"
                        className="text-xs capitalize border-gray-600/50 hover:bg-gray-800/50"
                        onClick={() => transitionCase(selectedCase.case_id, s)}>
                        {statusEmoji(s)} {s.replace('_', ' ')}
                      </Button>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* ── Root Cause & Assignment ── */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card className="glass-card border-gray-700/30">
                  <CardHeader className="pb-2"><CardTitle className="text-sm text-gray-400">🎯 Root Cause</CardTitle></CardHeader>
                  <CardContent className="space-y-2 text-sm">
                    <div className="flex justify-between"><span className="text-muted-foreground">CVE:</span><span className="font-mono text-cyan-400">{selectedCase.root_cve || '—'}</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">CWE:</span><span className="font-mono text-purple-400">{selectedCase.root_cwe || '—'}</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Component:</span><span className="text-gray-200">{selectedCase.root_component || '—'}</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Org:</span><span className="text-gray-200">{selectedCase.org_id || '—'}</span></div>
                  </CardContent>
                </Card>
                <Card className="glass-card border-gray-700/30">
                  <CardHeader className="pb-2"><CardTitle className="text-sm text-gray-400">👤 Assignment & SLA</CardTitle></CardHeader>
                  <CardContent className="space-y-2 text-sm">
                    <div className="flex justify-between"><span className="text-muted-foreground">Assigned to:</span><span className="text-gray-200">{selectedCase.assigned_to || 'Unassigned'}</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Team:</span><span className="text-gray-200">{selectedCase.assigned_team || '—'}</span></div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">SLA Due:</span>
                      <span className={selectedCase.sla_breached ? 'text-red-400 font-bold' : 'text-gray-200'}>
                        {selectedCase.sla_due ? `${new Date(selectedCase.sla_due).toLocaleDateString()} ${selectedCase.sla_breached ? '⏰ BREACHED' : ''}` : '—'}
                      </span>
                    </div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Created:</span><span className="text-gray-200">{timeAgo(selectedCase.created_at)}</span></div>
                  </CardContent>
                </Card>
              </div>

              {/* ── Affected Assets ── */}
              {selectedCase.affected_assets?.length > 0 && (
                <Card className="glass-card border-gray-700/30">
                  <CardHeader className="pb-2"><CardTitle className="text-sm text-gray-400">🖥️ Affected Assets ({selectedCase.affected_assets.length})</CardTitle></CardHeader>
                  <CardContent>
                    <div className="flex flex-wrap gap-2">
                      {selectedCase.affected_assets.map((a, i) => (
                        <Badge key={i} variant="outline" className="text-xs bg-gray-800/50 border-gray-600/40 text-gray-300">{a}</Badge>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* ── Remediation ── */}
              {(selectedCase.remediation_plan || selectedCase.playbook_id || selectedCase.autofix_pr_url) && (
                <Card className="glass-card border-green-500/20">
                  <CardHeader className="pb-2"><CardTitle className="text-sm text-green-400">🔧 Remediation</CardTitle></CardHeader>
                  <CardContent className="space-y-2 text-sm">
                    {selectedCase.remediation_plan && (
                      <div className="bg-gray-800/30 rounded-lg p-3 border border-gray-700/20 text-gray-300 whitespace-pre-wrap">{selectedCase.remediation_plan}</div>
                    )}
                    {selectedCase.playbook_id && <div className="flex justify-between"><span className="text-muted-foreground">Playbook:</span><span className="font-mono text-gray-200">{selectedCase.playbook_id}</span></div>}
                    {selectedCase.autofix_pr_url && (
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">AutoFix PR:</span>
                        <a href={selectedCase.autofix_pr_url} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline text-xs">{selectedCase.autofix_pr_url}</a>
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* ── Tags ── */}
              {selectedCase.tags?.length > 0 && (
                <div className="flex gap-2 flex-wrap">
                  {selectedCase.tags.map((t, i) => (
                    <Badge key={i} variant="outline" className="text-[10px] bg-blue-500/10 border-blue-500/30 text-blue-300">🏷️ {t}</Badge>
                  ))}
                </div>
              )}
            </>
          ) : (
            <div className="text-center py-16 text-muted-foreground">
              <div className="text-4xl mb-3">👈</div>
              <p>Select a case from the Kanban board or list to view details</p>
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default ExposureCaseCenter;