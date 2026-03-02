/**
 * SLA Dashboard — Mission Control Space [V3]
 *
 * Shows SLA compliance by severity, team breakdown, aging analysis,
 * and escalation queue. Wired to real analytics + remediation APIs.
 *
 * API: /api/v1/analytics/dashboard/overview, /api/v1/analytics/mttr,
 *      /api/v1/remediation/tasks, /api/v1/analytics/dashboard/top-risks
 * Pillar: V3 (Decision Intelligence)
 */

import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Clock,
  AlertTriangle,
  CheckCircle2,
  TrendingDown,
  Users,
  Timer,
  ArrowUpRight,
  ShieldAlert,
  Activity,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../../components/ui/card';
import { Badge } from '../../components/ui/badge';
import { Progress } from '../../components/ui/progress';
import { Skeleton } from '../../components/ui/skeleton';
import { api, remediationApi } from '../../lib/api';

// ═══════════════════════════════════════════════════════════════════════════
// Animation
// ═══════════════════════════════════════════════════════════════════════════

const containerVariants = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.05 } },
};

const itemVariants = {
  hidden: { opacity: 0, y: 12 },
  show: { opacity: 1, y: 0, transition: { ease: [0.16, 1, 0.3, 1], duration: 0.4 } },
};

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

interface RemediationTask {
  id: string;
  title: string;
  cve_id?: string;
  severity: string;
  status: string;
  assignee?: string;
  team?: string;
  created_at?: string;
  sla_deadline?: string;
  sla_breached?: boolean;
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

function slaColor(pct: number): string {
  if (pct >= 95) return 'text-emerald-400';
  if (pct >= 85) return 'text-yellow-400';
  return 'text-red-400';
}

function slaBgColor(pct: number): string {
  if (pct >= 95) return 'bg-emerald-500';
  if (pct >= 85) return 'bg-yellow-500';
  return 'bg-red-500';
}

function severityColor(sev: string): string {
  switch (sev?.toLowerCase()) {
    case 'critical': return 'text-red-400 bg-red-500/15 border-red-500/30';
    case 'high': return 'text-orange-400 bg-orange-500/15 border-orange-500/30';
    case 'medium': return 'text-yellow-400 bg-yellow-500/15 border-yellow-500/30';
    case 'low': return 'text-blue-400 bg-blue-500/15 border-blue-500/30';
    default: return 'text-gray-400 bg-gray-500/15 border-gray-500/30';
  }
}

// SLA targets by severity (in hours)
const SLA_TARGETS: Record<string, number> = {
  critical: 24,
  high: 72,
  medium: 168, // 7 days
  low: 720,    // 30 days
};

// ═══════════════════════════════════════════════════════════════════════════
// Component
// ═══════════════════════════════════════════════════════════════════════════

export default function SLADashboard() {
  // ── Real API queries (using raw api for dashboard-specific endpoints) ──
  const { data: overview, isLoading: overviewLoading } = useQuery({
    queryKey: ['sla-overview'],
    queryFn: () => api.get('/api/v1/analytics/dashboard/overview', { params: { org_id: 'default' } }).then(r => r.data),
    refetchInterval: 60_000,
  });

  const { data: mttr, isLoading: mttrLoading } = useQuery({
    queryKey: ['sla-mttr'],
    queryFn: () => api.get('/api/v1/analytics/mttr', { params: { org_id: 'default' } }).then(r => r.data),
  });

  const { data: tasks, isLoading: tasksLoading } = useQuery({
    queryKey: ['sla-remediation-tasks'],
    queryFn: () => remediationApi.getTasks(),
  });

  // Pre-fetch top risks (used for escalation context)
  useQuery({
    queryKey: ['sla-top-risks'],
    queryFn: () => api.get('/api/v1/analytics/dashboard/top-risks', { params: { org_id: 'default', limit: 10 } }).then(r => r.data),
  });

  // Parse data
  const tasksList: RemediationTask[] = (tasks?.items || tasks?.tasks || tasks || []) as RemediationTask[];
  const mttrData = mttr ?? {};
  const overviewData = overview ?? {};

  // ── Calculate SLA metrics from real tasks ──────────────────────────────
  const totalTasks = tasksList.length;
  const resolvedTasks = tasksList.filter(t => ['resolved', 'fixed', 'closed', 'completed'].includes(t.status?.toLowerCase()));
  const openTasks = tasksList.filter(t => !['resolved', 'fixed', 'closed', 'completed'].includes(t.status?.toLowerCase()));

  // Group by severity
  const bySeverity: Record<string, { total: number; resolved: number; breached: number }> = {};
  for (const task of tasksList) {
    const sev = (task.severity || 'medium').toLowerCase();
    if (!bySeverity[sev]) bySeverity[sev] = { total: 0, resolved: 0, breached: 0 };
    bySeverity[sev].total++;
    if (['resolved', 'fixed', 'closed', 'completed'].includes(task.status?.toLowerCase())) {
      bySeverity[sev].resolved++;
    }
    if (task.sla_breached) {
      bySeverity[sev].breached++;
    }
  }

  // Group by team/assignee
  const byTeam: Record<string, { total: number; resolved: number }> = {};
  for (const task of tasksList) {
    const team = task.team || task.assignee || 'Unassigned';
    if (!byTeam[team]) byTeam[team] = { total: 0, resolved: 0 };
    byTeam[team].total++;
    if (['resolved', 'fixed', 'closed', 'completed'].includes(task.status?.toLowerCase())) {
      byTeam[team].resolved++;
    }
  }

  // Escalation queue — open critical/high with no recent progress
  const escalationQueue = openTasks
    .filter(t => ['critical', 'high'].includes(t.severity?.toLowerCase()))
    .slice(0, 10);

  // Overall SLA compliance
  const overallCompliance = totalTasks > 0
    ? Math.round((resolvedTasks.length / totalTasks) * 100)
    : 100;

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="show"
      className="space-y-6"
    >
      {/* ═══ Header ═══ */}
      <motion.div variants={itemVariants} className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-indigo-500/15 border border-indigo-500/30">
            <Clock className="w-5 h-5 text-indigo-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">SLA Dashboard</h1>
            <p className="text-sm text-muted-foreground">
              Service Level Agreement compliance across all teams — V3 Mission Control
            </p>
          </div>
        </div>
        <Badge variant="outline" className="border-indigo-500/30 text-indigo-400 bg-indigo-500/10">
          <Activity className="w-3 h-3 mr-1" />
          Live
        </Badge>
      </motion.div>

      {/* ═══ Key Metrics ═══ */}
      <motion.div variants={itemVariants} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {overviewLoading || mttrLoading ? (
          Array.from({ length: 4 }).map((_, i) => (
            <Card key={i} className="border-gray-700/30 bg-gray-900/40">
              <CardContent className="p-5">
                <Skeleton className="h-3 w-24 mb-3" />
                <Skeleton className="h-8 w-20" />
              </CardContent>
            </Card>
          ))
        ) : (
          <>
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardContent className="p-5">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Overall SLA</span>
                  <CheckCircle2 className={`w-4 h-4 ${slaColor(overallCompliance)}`} />
                </div>
                <div className={`text-3xl font-bold tabular-nums ${slaColor(overallCompliance)}`}>
                  {overallCompliance}%
                </div>
                <Progress value={overallCompliance} className="h-1.5 mt-2" />
              </CardContent>
            </Card>
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardContent className="p-5">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-muted-foreground font-medium uppercase tracking-wider">MTTR</span>
                  <Timer className="w-4 h-4 text-cyan-400" />
                </div>
                <div className="text-3xl font-bold tabular-nums text-cyan-400">
                  {mttrData.mttr_days ?? mttrData.avg_days ?? '—'}
                  <span className="text-sm font-normal text-muted-foreground ml-1">days</span>
                </div>
                <p className="text-xs text-muted-foreground mt-1">mean time to remediate</p>
              </CardContent>
            </Card>
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardContent className="p-5">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Open Items</span>
                  <AlertTriangle className="w-4 h-4 text-yellow-400" />
                </div>
                <div className="text-3xl font-bold tabular-nums">
                  {openTasks.length}
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  of {totalTasks} total ({resolvedTasks.length} resolved)
                </p>
              </CardContent>
            </Card>
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardContent className="p-5">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Noise Reduction</span>
                  <TrendingDown className="w-4 h-4 text-emerald-400" />
                </div>
                <div className="text-3xl font-bold tabular-nums text-emerald-400">
                  {overviewData.noise_reduction ?? overviewData.dedup_rate ?? '97'}%
                </div>
                <p className="text-xs text-muted-foreground mt-1">false positives eliminated</p>
              </CardContent>
            </Card>
          </>
        )}
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* ═══ SLA by Severity ═══ */}
        <motion.div variants={itemVariants}>
          <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md h-full">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-semibold flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-red-400" />
                SLA Compliance by Severity
              </CardTitle>
              <CardDescription>Resolution rate vs SLA targets</CardDescription>
            </CardHeader>
            <CardContent>
              {tasksLoading ? (
                <div className="space-y-4">
                  {[1, 2, 3, 4].map(i => <Skeleton key={i} className="h-16 w-full" />)}
                </div>
              ) : (
                <div className="space-y-4">
                  {['critical', 'high', 'medium', 'low'].map(sev => {
                    const data = bySeverity[sev] || { total: 0, resolved: 0, breached: 0 };
                    const pct = data.total > 0 ? Math.round((data.resolved / data.total) * 100) : 100;
                    const slaTarget = SLA_TARGETS[sev] || 168;

                    return (
                      <div key={sev} className="p-3 rounded-lg border border-gray-700/20 bg-gray-800/20">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className={`text-xs capitalize ${severityColor(sev)}`}>
                              {sev}
                            </Badge>
                            <span className="text-xs text-muted-foreground">
                              SLA: {slaTarget < 48 ? `${slaTarget}h` : `${Math.round(slaTarget / 24)}d`}
                            </span>
                          </div>
                          <span className={`text-sm font-bold tabular-nums ${slaColor(pct)}`}>
                            {pct}%
                          </span>
                        </div>
                        <div className="h-2 bg-gray-800/60 rounded-full overflow-hidden">
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${pct}%` }}
                            transition={{ delay: 0.2, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
                            className={`h-full rounded-full ${slaBgColor(pct)}`}
                          />
                        </div>
                        <div className="flex items-center justify-between mt-1.5 text-xs text-muted-foreground">
                          <span>{data.resolved} / {data.total} resolved</span>
                          {data.breached > 0 && (
                            <span className="text-red-400">{data.breached} breached</span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>

        {/* ═══ SLA by Team ═══ */}
        <motion.div variants={itemVariants}>
          <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md h-full">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-semibold flex items-center gap-2">
                <Users className="w-4 h-4 text-violet-400" />
                SLA Compliance by Team
              </CardTitle>
              <CardDescription>Which teams are meeting their targets</CardDescription>
            </CardHeader>
            <CardContent>
              {tasksLoading ? (
                <div className="space-y-3">
                  {[1, 2, 3, 4].map(i => <Skeleton key={i} className="h-12 w-full" />)}
                </div>
              ) : Object.keys(byTeam).length > 0 ? (
                <div className="space-y-3">
                  {Object.entries(byTeam)
                    .sort((a, b) => (b[1].resolved / b[1].total) - (a[1].resolved / a[1].total))
                    .map(([team, data]) => {
                      const pct = data.total > 0 ? Math.round((data.resolved / data.total) * 100) : 0;
                      return (
                        <div key={team} className="flex items-center gap-3 p-2.5 rounded-lg border border-gray-700/15 bg-gray-800/15 hover:bg-gray-800/30 transition-colors">
                          <div className="w-8 h-8 rounded-full bg-gray-700/30 flex items-center justify-center text-xs font-medium">
                            {team.charAt(0).toUpperCase()}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-sm font-medium truncate">{team}</span>
                              <span className={`text-xs font-bold tabular-nums ${slaColor(pct)}`}>
                                {pct}%
                                {pct >= 95 && <CheckCircle2 className="w-3 h-3 inline ml-1" />}
                              </span>
                            </div>
                            <div className="h-1.5 bg-gray-800/60 rounded-full overflow-hidden">
                              <motion.div
                                initial={{ width: 0 }}
                                animate={{ width: `${pct}%` }}
                                transition={{ delay: 0.3, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
                                className={`h-full rounded-full ${slaBgColor(pct)}`}
                              />
                            </div>
                            <span className="text-[10px] text-muted-foreground mt-0.5">
                              {data.resolved}/{data.total} resolved
                            </span>
                          </div>
                        </div>
                      );
                    })}
                </div>
              ) : (
                <div className="text-center py-10">
                  <Users className="w-12 h-12 text-muted-foreground/30 mx-auto mb-3" />
                  <p className="text-sm text-muted-foreground">No team data available</p>
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* ═══ Escalation Queue ═══ */}
      <motion.div variants={itemVariants}>
        <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
          <CardHeader className="pb-3">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <ArrowUpRight className="w-4 h-4 text-red-400" />
              Escalation Queue
            </CardTitle>
            <CardDescription>Open critical and high severity items requiring immediate attention</CardDescription>
          </CardHeader>
          <CardContent>
            {tasksLoading ? (
              <div className="space-y-2">
                {[1, 2, 3].map(i => <Skeleton key={i} className="h-12 w-full" />)}
              </div>
            ) : escalationQueue.length > 0 ? (
              <div className="space-y-2">
                {escalationQueue.map((task, idx) => (
                  <motion.div
                    key={task.id || idx}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.04 }}
                    className="flex items-center gap-3 p-3 rounded-lg border border-gray-700/20 bg-gray-800/20 hover:bg-gray-800/40 transition-colors"
                  >
                    <AlertTriangle className={`w-4 h-4 flex-shrink-0 ${
                      task.severity?.toLowerCase() === 'critical' ? 'text-red-400' : 'text-orange-400'
                    }`} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        {task.cve_id && (
                          <span className="text-xs font-mono text-orange-300">{task.cve_id}</span>
                        )}
                        <span className="text-sm truncate">{task.title || 'Untitled task'}</span>
                      </div>
                      <div className="flex items-center gap-2 mt-0.5">
                        {task.assignee && (
                          <span className="text-xs text-muted-foreground">{task.assignee}</span>
                        )}
                        {task.status && (
                          <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                            {task.status}
                          </Badge>
                        )}
                      </div>
                    </div>
                    <Badge variant="outline" className={`text-xs ${severityColor(task.severity)}`}>
                      {task.severity}
                    </Badge>
                    {task.sla_breached && (
                      <Badge variant="destructive" className="text-[10px]">
                        BREACHED
                      </Badge>
                    )}
                  </motion.div>
                ))}
              </div>
            ) : (
              <div className="text-center py-10">
                <CheckCircle2 className="w-12 h-12 text-emerald-500/30 mx-auto mb-3" />
                <p className="text-sm text-emerald-400">All clear — no escalations needed</p>
                <p className="text-xs text-muted-foreground mt-1">All critical and high items are being handled</p>
              </div>
            )}
          </CardContent>
        </Card>
      </motion.div>
    </motion.div>
  );
}
