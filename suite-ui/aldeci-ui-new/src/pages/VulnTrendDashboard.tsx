/**
 * Vulnerability Trends Dashboard
 *
 * Trend analysis, SLA tracking, and cohort management.
 *   1. KPIs: Total Tracked, SLA Breach Rate, Critical Mean Age, Resolved This Week
 *   2. 30-day trend chart (6 weekly snapshots, stacked bars)
 *   3. Trend analysis panel (pct_change per severity, overall trend)
 *   4. SLA tracking table (12 vulns)
 *   5. Cohort analysis (5 cohorts)
 */

import { useState, useEffect } from "react";
import { getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { motion } from "framer-motion";
import { Bug, TrendingUp, TrendingDown, AlertTriangle, RefreshCw, BarChart3, Clock, Users, Inbox } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

// ── API config ─────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const ORG_ID = "default";

async function apiFetch(path: string) {
  const key = (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) ||
    import.meta.env.VITE_API_KEY || (getStoredAuthToken() ?? "");
  const res = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": key } });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

// ── Static config (chart colours / legend — not domain data) ──

// ── Helpers ────────────────────────────────────────────────────

function SeverityBadge({ sev }: { sev: string }) {
  const cls =
    sev === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    sev === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    sev === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                         "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{sev}</Badge>;
}

const STACKED_MAX = 550; // scale denominator for bar widths

// ── Component ──────────────────────────────────────────────────

export default function VulnTrendDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  const fetchAll = () =>
    Promise.allSettled([
      apiFetch(`/api/v1/vuln-trends/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/vuln-trends/snapshots?org_id=${ORG_ID}&limit=6`),
      apiFetch(`/api/v1/vuln-trends/analysis?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/vuln-trends/cohorts?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/vuln-trends/sla/breaches?org_id=${ORG_ID}`),
    ]).then(([statsRes, snapshotsRes, analysisRes, cohortsRes, slaBreach]) => {
      const stats     = statsRes.status     === "fulfilled" ? statsRes.value     : null;
      const snapshots = snapshotsRes.status === "fulfilled" ? snapshotsRes.value : null;
      const analysis  = analysisRes.status  === "fulfilled" ? analysisRes.value  : null;
      const cohorts   = cohortsRes.status   === "fulfilled" ? cohortsRes.value   : null;
      const breaches  = slaBreach.status    === "fulfilled" ? slaBreach.value    : null;
      if (stats || snapshots || analysis || cohorts || breaches) {
        setLiveData({ stats, snapshots, analysis, cohorts, breaches });
      }
    });

  useEffect(() => {
    setDataLoading(true);
    fetchAll().finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setDataLoading(true);
    fetchAll().finally(() => { setRefreshing(false); setDataLoading(false); });
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Vulnerability Trends"
        description="Trend analysis, SLA tracking, and cohort management"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Tracked"       value={liveData?.stats?.total_vulns ?? liveData?.stats?.total_tracked ?? "—"}             icon={Bug}          trend="up" />
        <KpiCard title="SLA Breach Rate"     value={liveData?.stats?.sla_breach_rate != null ? `${liveData.stats.sla_breach_rate}%` : "—"} icon={AlertTriangle} trend="up"  className="border-red-500/20" />
        <KpiCard title="Critical Mean Age"   value={liveData?.stats?.critical_mean_age != null ? `${liveData.stats.critical_mean_age}d` : "—"} icon={Clock}        trend="down" className="border-amber-500/20" />
        <KpiCard title="Resolved This Week"  value={liveData?.stats?.resolved_this_week ?? "—"}                                              icon={TrendingDown}  trend="up" />
      </div>

      {/* 30-day trend + Trend Analysis */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Stacked bar chart */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-blue-400" />
              30-Day Volume Trend (weekly)
            </CardTitle>
            <CardDescription className="text-xs">Open vuln counts by severity — stacked bars</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {(liveData?.snapshots ?? []).length === 0 ? (
                <EmptyState icon={BarChart3} title="No trend snapshots yet" description="Snapshots will appear once the vulnerability trend engine has run." />
              ) : (liveData.snapshots.map((s: any) => ({
                week: s.taken_at ? s.taken_at.slice(0, 10) : "—",
                critical: s.critical ?? 0,
                high: s.high ?? 0,
                medium: s.medium ?? 0,
                low: s.low ?? 0,
              }))).map((w: any) => {
                const total = w.critical + w.high + w.medium + w.low;
                const scale = STACKED_MAX;
                return (
                  <div key={w.week} className="flex items-center gap-2">
                    <span className="text-[10px] text-muted-foreground w-16 shrink-0">{w.week}</span>
                    <div className="flex-1 flex h-5 rounded overflow-hidden gap-px">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${(w.critical / scale) * 100}%` }}
                        transition={{ duration: 0.7, ease: "easeOut" }}
                        className="bg-red-500/80 flex items-center justify-center"
                        title={`Critical: ${w.critical}`}
                      />
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${(w.high / scale) * 100}%` }}
                        transition={{ duration: 0.7, ease: "easeOut", delay: 0.05 }}
                        className="bg-amber-500/80 flex items-center justify-center"
                        title={`High: ${w.high}`}
                      />
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${(w.medium / scale) * 100}%` }}
                        transition={{ duration: 0.7, ease: "easeOut", delay: 0.1 }}
                        className="bg-yellow-500/70 flex items-center justify-center"
                        title={`Medium: ${w.medium}`}
                      />
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${(w.low / scale) * 100}%` }}
                        transition={{ duration: 0.7, ease: "easeOut", delay: 0.15 }}
                        className="bg-green-500/40 flex items-center justify-center"
                        title={`Low: ${w.low}`}
                      />
                    </div>
                    <span className="text-[10px] text-muted-foreground w-10 text-right tabular-nums shrink-0">{total}</span>
                  </div>
                );
              })}
            </div>
            <div className="flex items-center gap-4 mt-3 text-[10px] text-muted-foreground">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-red-500/80 inline-block" />Critical</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-amber-500/80 inline-block" />High</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-yellow-500/70 inline-block" />Medium</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-green-500/40 inline-block" />Low</span>
            </div>
          </CardContent>
        </Card>

        {/* Trend Analysis */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <TrendingUp className="h-4 w-4 text-purple-400" />
                  Trend Analysis
                </CardTitle>
                <CardDescription className="text-xs">Week-over-week change per severity</CardDescription>
              </div>
              <Badge className={cn("text-[10px] border", liveData?.analysis?.overall_trend === "increasing" ? "border-red-500/30 text-red-400 bg-red-500/10" : liveData?.analysis?.overall_trend === "stable" ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" : "border-border text-muted-foreground")}>
                Overall: {liveData?.analysis?.overall_trend ?? "—"}
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-4 pt-2">
            {!(liveData?.analysis?.by_severity) || (liveData.analysis.by_severity as any[]).length === 0 ? (
              <EmptyState icon={TrendingUp} title="No trend analysis yet" description="Week-over-week data will appear once multiple snapshots exist." />
            ) : (liveData.analysis.by_severity as any[]).map((t: any) => {
              const pct: number = t.pct_change ?? t.pct ?? 0;
              const dir = pct < 0 ? "down" : pct > 0 ? "up" : "flat";
              const label = dir === "down" ? `↓ ${Math.abs(pct).toFixed(1)}%` : dir === "up" ? `↑ ${pct.toFixed(1)}%` : `→ 0.0%`;
              const cls = dir === "down" ? "text-green-400" : dir === "up" ? "text-red-400" : "text-yellow-400";
              return (
                <div key={t.sev ?? t.severity} className="flex items-center justify-between">
                  <SeverityBadge sev={t.sev ?? t.severity} />
                  <div className="flex items-center gap-2">
                    {dir === "down" && <TrendingDown className="h-4 w-4 text-green-400" />}
                    {dir === "up"   && <TrendingUp   className="h-4 w-4 text-red-400" />}
                    {dir === "flat" && <span className="h-4 w-4 text-yellow-400 text-sm font-bold leading-4">→</span>}
                    <span className={cn("text-sm font-bold tabular-nums", cls)}>{label}</span>
                  </div>
                </div>
              );
            })}
            <div className="pt-2 border-t border-border/40 text-xs text-muted-foreground">
              Week-over-week change. Data from vulnerability scanner aggregation.
            </div>
          </CardContent>
        </Card>
      </div>

      {/* SLA Tracking Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Clock className="h-4 w-4 text-amber-400" />
              SLA Tracking
            </CardTitle>
            <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">
              {liveData?.breaches?.length ?? 0} breached
            </Badge>
          </div>
          <CardDescription className="text-xs">Days remaining vs SLA deadline — red bars indicate breach</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Discovered</TableHead>
                  <TableHead className="text-[11px] h-8">SLA (days)</TableHead>
                  <TableHead className="text-[11px] h-8">Remaining</TableHead>
                  <TableHead className="text-[11px] h-8">Resolved</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.breaches ?? []).length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="py-6">
                      <EmptyState icon={Clock} title="No SLA tracking data yet" description="SLA breach data will appear once the vulnerability SLA engine has run." />
                    </TableCell>
                  </TableRow>
                ) : (liveData.breaches as any[]).map((row: any) => {
                  const breached = row.days_remaining < 0 && !row.resolved;
                  const barPct = Math.max(0, Math.min(100, (row.days_remaining / row.sla_days) * 100));
                  return (
                    <TableRow key={row.id} className={cn("hover:bg-muted/30", breached && "bg-red-500/5")}>
                      <TableCell className="text-xs font-mono py-2.5">{row.id}</TableCell>
                      <TableCell className="py-2.5"><SeverityBadge sev={row.sev ?? row.severity} /></TableCell>
                      <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{row.discovered ?? row.discovered_at}</TableCell>
                      <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{row.sla_days}d</TableCell>
                      <TableCell className="py-2.5">
                        {row.resolved ? (
                          <span className="text-xs text-muted-foreground">—</span>
                        ) : (
                          <div className="flex items-center gap-2">
                            <div className="h-1.5 w-20 rounded-full bg-muted/30 overflow-hidden">
                              <div
                                className={cn("h-full rounded-full", breached ? "bg-red-500" : barPct < 20 ? "bg-amber-500" : "bg-green-500")}
                                style={{ width: breached ? "100%" : `${barPct}%` }}
                              />
                            </div>
                            <span className={cn("text-xs font-bold tabular-nums", breached ? "text-red-400" : "text-muted-foreground")}>
                              {row.days_remaining}d
                            </span>
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="text-xs py-2.5 tabular-nums">
                        {row.resolved
                          ? <span className="text-green-400">{row.resolved}</span>
                          : <span className="text-muted-foreground">OPEN</span>
                        }
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Cohort Analysis */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Users className="h-4 w-4 text-indigo-400" />
            Cohort Analysis
          </CardTitle>
          <CardDescription className="text-xs">Vulnerability cohorts grouped by discovery source or period</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="text-[11px] h-8">Cohort</TableHead>
                <TableHead className="text-[11px] h-8 text-right">Count</TableHead>
                <TableHead className="text-[11px] h-8 text-right">Avg Age (days)</TableHead>
                <TableHead className="text-[11px] h-8 text-right">Avg CVSS</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(liveData?.cohorts ?? []).length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="py-6">
                    <EmptyState icon={Users} title="No cohort data yet" description="Cohorts will appear once the vulnerability cohort engine has grouped findings." />
                  </TableCell>
                </TableRow>
              ) : (liveData.cohorts as any[]).map((c: any) => (
                <TableRow key={c.name ?? c.cohort_name ?? c.cohort_id} className="hover:bg-muted/30">
                  <TableCell className="text-xs font-medium py-2.5">{c.name ?? c.cohort_name}</TableCell>
                  <TableCell className="text-xs tabular-nums py-2.5 text-right">{c.vuln_count ?? (c.vuln_ids?.length ?? 0)}</TableCell>
                  <TableCell className={cn("text-xs tabular-nums py-2.5 text-right font-medium", (c.avg_age ?? c.avg_age_days ?? 0) > 30 ? "text-red-400" : (c.avg_age ?? c.avg_age_days ?? 0) > 14 ? "text-amber-400" : "text-muted-foreground")}>
                    {c.avg_age ?? c.avg_age_days ?? 0}d
                  </TableCell>
                  <TableCell className={cn("text-xs tabular-nums py-2.5 text-right font-bold", (c.avg_cvss ?? 0) >= 7 ? "text-red-400" : (c.avg_cvss ?? 0) >= 5 ? "text-amber-400" : "text-muted-foreground")}>
                    {c.avg_cvss ?? 0}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </motion.div>
  );
}
