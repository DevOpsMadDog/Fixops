import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { useMemo } from 'react';
import {
  Shield,
  AlertTriangle,
  TrendingUp,
  Clock,
  Target,
  BarChart3,
  ArrowUpRight,
  ArrowDownRight,
  Zap,
  Lock,
  FileCheck,
  Activity,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { dashboardApi, analyticsApi, feedsApi, api } from '../lib/api';

// ── Helpers ──────────────────────────────────────────────────────────────────

const fmtDays = (hours: number) => {
  if (hours < 24) return `${Math.round(hours)}h`;
  return `${(hours / 24).toFixed(1)}d`;
};

const containerV = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.06 } },
};
const itemV = {
  hidden: { opacity: 0, y: 16 },
  visible: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 260, damping: 22 } },
};

// ── Animated Score Ring ──────────────────────────────────────────────────────

function ScoreRing({ score, label, color }: { score: number; label: string; color: string }) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  return (
    <div className="flex flex-col items-center gap-2">
      <svg width={140} height={140} viewBox="0 0 140 140">
        <circle cx={70} cy={70} r={radius} fill="none" stroke="currentColor" strokeWidth={10} className="text-gray-700/30" />
        <motion.circle
          cx={70} cy={70} r={radius} fill="none" stroke={color} strokeWidth={10}
          strokeLinecap="round" strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1.2, ease: 'easeOut' }}
          transform="rotate(-90 70 70)"
        />
        <text x={70} y={66} textAnchor="middle" className="fill-white text-2xl font-bold" fontSize={28}>{Math.round(score)}</text>
        <text x={70} y={88} textAnchor="middle" className="fill-gray-400 text-xs" fontSize={11}>/100</text>
      </svg>
      <span className="text-sm font-medium text-muted-foreground">{label}</span>
    </div>
  );
}

// ── Mini Sparkline ───────────────────────────────────────────────────────────

function Sparkline({ data, color = '#3b82f6' }: { data: number[]; color?: string }) {
  if (!data?.length) return null;
  const max = Math.max(...data, 1);
  const min = Math.min(...data, 0);
  const range = max - min || 1;
  const w = 120;
  const h = 32;
  const points = data.map((v, i) => `${(i / (data.length - 1)) * w},${h - ((v - min) / range) * h}`).join(' ');
  return (
    <svg width={w} height={h} className="inline-block">
      <polyline points={points} fill="none" stroke={color} strokeWidth={1.5} />
    </svg>
  );
}

// ── KPI Card ─────────────────────────────────────────────────────────────────

interface KPIProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: React.ElementType;
  trend?: { value: number; good: boolean };
  sparkline?: number[];
  accent?: string;
  loading?: boolean;
}

function KPICard({ title, value, subtitle, icon: Icon, trend, sparkline, accent = '#3b82f6', loading }: KPIProps) {
  return (
    <motion.div variants={itemV} whileHover={{ scale: 1.02, y: -3 }} transition={{ type: 'spring', stiffness: 300 }}>
      <Card className="glass-card backdrop-blur-md bg-gray-900/50 border-gray-700/40 hover:border-primary/30 transition-all h-full">
        <CardContent className="p-5">
          <div className="flex items-start justify-between">
            <div className="space-y-1.5 flex-1">
              <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">{title}</p>
              {loading ? (
                <div className="h-9 w-28 rounded-md animate-pulse bg-gray-700/30" />
              ) : (
                <motion.p className="text-3xl font-bold tracking-tight" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                  {value}
                </motion.p>
              )}
              {subtitle && <p className="text-xs text-muted-foreground">{subtitle}</p>}
              {trend && (
                <div className={`flex items-center gap-1 text-xs ${trend.good ? 'text-green-400' : 'text-red-400'}`}>
                  {trend.good ? <ArrowDownRight className="w-3 h-3" /> : <ArrowUpRight className="w-3 h-3" />}
                  <span>{Math.abs(trend.value)}% vs last period</span>
                </div>
              )}
            </div>
            <div className="flex flex-col items-end gap-2">
              <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ backgroundColor: `${accent}15` }}>
                <Icon className="w-5 h-5" style={{ color: accent }} />
              </div>
              {sparkline && <Sparkline data={sparkline} color={accent} />}
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ── Severity Bar ─────────────────────────────────────────────────────────────

function SeverityBar({ label, count, total, color }: { label: string; count: number; total: number; color: string }) {
  const pctVal = total > 0 ? (count / total) * 100 : 0;
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-xs">
        <span className="text-muted-foreground">{label}</span>
        <span className="font-medium">{count}</span>
      </div>
      <div className="h-2 rounded-full bg-gray-700/40 overflow-hidden">
        <motion.div
          className="h-full rounded-full"
          style={{ backgroundColor: color }}
          initial={{ width: 0 }}
          animate={{ width: `${pctVal}%` }}
          transition={{ duration: 0.8, ease: 'easeOut' }}
        />
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// CEO Executive Dashboard — the single page a CEO opens every morning
// ═══════════════════════════════════════════════════════════════════════════════

export default function CEODashboard() {
  // ── Data fetching ────────────────────────────────────────────────────────

  const { data: overview, isLoading: overviewLoading } = useQuery({
    queryKey: ['ceo-overview'],
    queryFn: () => dashboardApi.getOverview('default'),
    retry: 1,
    refetchInterval: 60_000,
  });

  useQuery({
    queryKey: ['ceo-trends'],
    queryFn: () => dashboardApi.getTrends('default'),
    retry: 1,
  });

  const { data: analyticsStats } = useQuery({
    queryKey: ['analytics-stats'],
    queryFn: analyticsApi.getStats,
    retry: 1,
  });

  const { data: mttrData } = useQuery({
    queryKey: ['analytics-mttr'],
    queryFn: () => api.get('/api/v1/analytics/mttr').then(r => r.data),
    retry: 1,
  });

  const { data: complianceData } = useQuery({
    queryKey: ['analytics-compliance'],
    queryFn: () => api.get('/api/v1/analytics/dashboard/compliance-status').then(r => r.data),
    retry: 1,
  });

  const { data: remMetrics } = useQuery({
    queryKey: ['remediation-metrics'],
    queryFn: () => api.get('/api/v1/remediation/metrics').then(r => r.data),
    retry: 1,
  });

  const { data: topRisks } = useQuery({
    queryKey: ['analytics-top-risks'],
    queryFn: () => api.get('/api/v1/analytics/dashboard/top-risks').then(r => r.data),
    retry: 1,
  });

  const { data: riskVelocity } = useQuery({
    queryKey: ['risk-velocity'],
    queryFn: () => api.get('/api/v1/analytics/risk-velocity').then(r => r.data),
    retry: 1,
  });

  const { data: feedStats } = useQuery({
    queryKey: ['feed-stats'],
    queryFn: feedsApi.getStats,
    retry: 1,
  });

  // ── Derived values ───────────────────────────────────────────────────────

  const riskScore = useMemo(() => {
    if (overview?.risk_score != null) return overview.risk_score;
    // Derive from findings severity distribution if available
    const sev = overview?.severity_distribution || analyticsStats?.severity_distribution;
    if (!sev) return 0;
    const weights: Record<string, number> = { critical: 40, high: 25, medium: 10, low: 2, info: 0 };
    let score = 0;
    let total = 0;
    for (const [k, v] of Object.entries(sev)) {
      score += (weights[k.toLowerCase()] || 0) * (v as number);
      total += v as number;
    }
    return total > 0 ? Math.min(100, Math.round((score / (total * 40)) * 100)) : 0;
  }, [overview, analyticsStats]);

  const complianceScore = complianceData?.compliance_score ?? complianceData?.score ?? 0;
  const mttrHours = mttrData?.mttr_hours ?? mttrData?.overall?.avg_hours ?? remMetrics?.mttr_hours ?? 0;

  const totalFindings = overview?.total_findings ?? analyticsStats?.total ?? 0;
  const openFindings = overview?.open_findings ?? analyticsStats?.open ?? totalFindings;
  const criticalCount = overview?.severity_distribution?.critical ?? analyticsStats?.severity_distribution?.critical ?? 0;
  const highCount = overview?.severity_distribution?.high ?? analyticsStats?.severity_distribution?.high ?? 0;
  const mediumCount = overview?.severity_distribution?.medium ?? analyticsStats?.severity_distribution?.medium ?? 0;
  const lowCount = overview?.severity_distribution?.low ?? analyticsStats?.severity_distribution?.low ?? 0;

  const slaCompliance = remMetrics?.sla_compliance_pct ?? remMetrics?.sla_compliance ?? 0;
  const overdueCount = remMetrics?.overdue_count ?? remMetrics?.overdue ?? 0;

  const riskTrend = riskVelocity?.daily_counts?.map((d: any) => d.count ?? d.value ?? 0) ?? [];

  return (
    <div className="relative space-y-6 max-w-[1440px] mx-auto">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} transition={{ type: 'spring', stiffness: 150 }}
        className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-emerald-400 via-blue-400 to-purple-400 bg-clip-text text-transparent">
            Executive Security Dashboard
          </h1>
          <p className="text-muted-foreground mt-1">
            Real-time risk posture for leadership — {new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
          </p>
        </div>
        <Badge variant="outline" className="text-xs border-emerald-500/40 text-emerald-400">
          Live
        </Badge>
      </motion.div>

      {/* ── Top-Level Score Rings ──────────────────────────────────────────── */}
      <motion.div variants={containerV} initial="hidden" animate="visible"
        className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <motion.div variants={itemV}>
          <Card className="glass-card backdrop-blur-md bg-gray-900/50 border-gray-700/40 hover:border-emerald-500/30 transition-all">
            <CardContent className="flex items-center justify-center py-8">
              <ScoreRing
                score={100 - riskScore}
                label="Security Posture"
                color={riskScore > 60 ? '#ef4444' : riskScore > 30 ? '#f59e0b' : '#22c55e'}
              />
            </CardContent>
          </Card>
        </motion.div>
        <motion.div variants={itemV}>
          <Card className="glass-card backdrop-blur-md bg-gray-900/50 border-gray-700/40 hover:border-blue-500/30 transition-all">
            <CardContent className="flex items-center justify-center py-8">
              <ScoreRing
                score={complianceScore}
                label="Compliance Score"
                color={complianceScore >= 80 ? '#22c55e' : complianceScore >= 50 ? '#f59e0b' : '#ef4444'}
              />
            </CardContent>
          </Card>
        </motion.div>
        <motion.div variants={itemV}>
          <Card className="glass-card backdrop-blur-md bg-gray-900/50 border-gray-700/40 hover:border-purple-500/30 transition-all">
            <CardContent className="flex items-center justify-center py-8">
              <ScoreRing
                score={slaCompliance}
                label="SLA Compliance"
                color={slaCompliance >= 90 ? '#22c55e' : slaCompliance >= 70 ? '#f59e0b' : '#ef4444'}
              />
            </CardContent>
          </Card>
        </motion.div>
      </motion.div>

      {/* ── KPI Strip ─────────────────────────────────────────────────────── */}
      <motion.div variants={containerV} initial="hidden" animate="visible"
        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <KPICard
          title="Mean Time to Remediate"
          value={fmtDays(mttrHours)}
          subtitle="Across all severities"
          icon={Clock}
          accent="#8b5cf6"
          loading={overviewLoading}
        />
        <KPICard
          title="Open Findings"
          value={openFindings}
          subtitle={`${totalFindings} total`}
          icon={AlertTriangle}
          accent="#f59e0b"
          loading={overviewLoading}
        />
        <KPICard
          title="Critical / High"
          value={`${criticalCount} / ${highCount}`}
          subtitle="Requires immediate action"
          icon={Zap}
          accent="#ef4444"
          loading={overviewLoading}
        />
        <KPICard
          title="Overdue Tasks"
          value={overdueCount}
          subtitle="Past SLA deadline"
          icon={Target}
          accent={overdueCount > 0 ? '#ef4444' : '#22c55e'}
          loading={overviewLoading}
        />
      </motion.div>

      {/* ── Two-Column Layout ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution (2-col) */}
        <Card className="glass-card lg:col-span-2 backdrop-blur-md bg-gray-900/50 border-gray-700/40">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <BarChart3 className="w-4 h-4 text-primary" />
              Risk Distribution
            </CardTitle>
            <CardDescription>Findings by severity level</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <SeverityBar label="Critical" count={criticalCount} total={totalFindings || 1} color="#ef4444" />
            <SeverityBar label="High" count={highCount} total={totalFindings || 1} color="#f97316" />
            <SeverityBar label="Medium" count={mediumCount} total={totalFindings || 1} color="#f59e0b" />
            <SeverityBar label="Low" count={lowCount} total={totalFindings || 1} color="#22c55e" />
          </CardContent>
        </Card>

        {/* Risk Velocity Sparkline */}
        <Card className="glass-card backdrop-blur-md bg-gray-900/50 border-gray-700/40">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Activity className="w-4 h-4 text-primary" />
              Risk Velocity
            </CardTitle>
            <CardDescription>New findings per day (trend)</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col items-center justify-center py-4 gap-4">
            {riskTrend.length > 0 ? (
              <svg width={220} height={80} viewBox="0 0 220 80">
                {(() => {
                  const max = Math.max(...riskTrend, 1);
                  const pts = riskTrend.map((v: number, i: number) =>
                    `${(i / Math.max(riskTrend.length - 1, 1)) * 210 + 5},${75 - (v / max) * 65}`
                  ).join(' ');
                  return (
                    <>
                      <polyline points={pts} fill="none" stroke="#3b82f6" strokeWidth={2} />
                      {riskTrend.map((v: number, i: number) => (
                        <circle
                          key={i}
                          cx={(i / Math.max(riskTrend.length - 1, 1)) * 210 + 5}
                          cy={75 - (v / max) * 65}
                          r={2.5}
                          fill="#3b82f6"
                        />
                      ))}
                    </>
                  );
                })()}
              </svg>
            ) : (
              <p className="text-sm text-muted-foreground">No velocity data yet</p>
            )}
            <p className="text-xs text-muted-foreground">Last {riskTrend.length} days</p>
          </CardContent>
        </Card>
      </div>

      {/* ── Top Risks Table ───────────────────────────────────────────────── */}
      <Card className="glass-card backdrop-blur-md bg-gray-900/50 border-gray-700/40">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Shield className="w-4 h-4 text-red-400" />
            Top Risks Requiring Attention
          </CardTitle>
        </CardHeader>
        <CardContent>
          {topRisks?.risks?.length > 0 || topRisks?.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700/40 text-left text-xs text-muted-foreground">
                    <th className="pb-2 pr-4">Finding</th>
                    <th className="pb-2 pr-4">Severity</th>
                    <th className="pb-2 pr-4">CVE</th>
                    <th className="pb-2 pr-4">App</th>
                    <th className="pb-2">Age</th>
                  </tr>
                </thead>
                <tbody>
                  {(topRisks?.risks || topRisks || []).slice(0, 10).map((r: any, i: number) => (
                    <motion.tr key={r.id || i} className="border-b border-gray-800/30"
                      initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.05 }}>
                      <td className="py-2 pr-4 max-w-[300px] truncate">{r.title || r.name || r.id}</td>
                      <td className="py-2 pr-4">
                        <Badge variant={r.severity === 'critical' ? 'destructive' : r.severity === 'high' ? 'medium' : 'outline'}>
                          {r.severity}
                        </Badge>
                      </td>
                      <td className="py-2 pr-4 font-mono text-xs">{r.cve_id || r.cve_ids?.[0] || '—'}</td>
                      <td className="py-2 pr-4 text-muted-foreground">{r.app_id || r.application || '—'}</td>
                      <td className="py-2 text-muted-foreground">{r.age_days ? `${r.age_days}d` : '—'}</td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground text-center py-6">No high-risk findings — looking good!</p>
          )}
        </CardContent>
      </Card>

      {/* ── Bottom Strip: Intel & Feeds ───────────────────────────────────── */}
      <motion.div variants={containerV} initial="hidden" animate="visible"
        className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <KPICard title="CVEs Tracked" value={feedStats?.total_cves ?? 0} icon={Lock} accent="#6366f1" subtitle="NVD + OSV + GitHub" />
        <KPICard title="EPSS Scores" value={feedStats?.epss_count ?? 0} icon={TrendingUp} accent="#06b6d4" subtitle="Exploit prediction data" />
        <KPICard title="KEV Entries" value={feedStats?.kev_count ?? 0} icon={FileCheck} accent="#f43f5e" subtitle="CISA known exploits" />
      </motion.div>
    </div>
  );
}
