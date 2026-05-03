// FOLDED into NetworkMonitoringHub hero (monitoring tab) 2026-05-02 — preserve for git history
/**
 * Network Monitoring Dashboard
 *
 * Interface-level network monitoring with alert feed and utilization metrics.
 *   1. KPIs: Interfaces Monitored, Active Alerts, Total Traffic (GB), Avg Utilization %
 *   2. Alert feed: interface name, severity, metric, value
 *   3. Interface table: name, status, traffic, utilization bar
 *
 * API: GET /api/v1/network-monitoring/...
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Activity, AlertTriangle, Network, RefreshCw, Wifi } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

async function apiFetch<T = any>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

// ── Helpers ──────────────────────────────────────────────────

function SeverityBadge({ sev }: { sev: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    low:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[sev] ?? "border-border text-muted-foreground")}>
      {sev}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    up:       "border-green-500/30 text-green-400 bg-green-500/10",
    degraded: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    error:    "border-red-500/30 text-red-400 bg-red-500/10",
    down:     "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

// ── Component ────────────────────────────────────────────────

export default function NetworkMonitoringDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [ifaces, setIfaces] = useState<any[]>([]);
  const [stats, setStats] = useState<any>({ interfaces_monitored: 0, active_alerts: 0, total_traffic_gb: 0, avg_utilization_pct: 0 });

  const load = async () => {
    setRefreshing(true);
    setError(null);
    try {
      const [ifacesRes, alertRulesRes] = await Promise.allSettled([
        apiFetch<any>("/api/v1/network-monitoring/interfaces"),
        apiFetch<any>("/api/v1/network-monitoring/alert-rules"),
      ]);
      let ifArr: any[] = [];
      if (ifacesRes.status === "fulfilled") {
        const v = ifacesRes.value;
        ifArr = Array.isArray(v) ? v : (v?.interfaces ?? v?.items ?? []);
        setIfaces(ifArr);
      } else {
        setError((ifacesRes.reason as Error).message);
      }
      let alertsArr: any[] = [];
      if (alertRulesRes.status === "fulfilled") {
        const v = alertRulesRes.value;
        alertsArr = Array.isArray(v) ? v : (v?.alerts ?? v?.rules ?? v?.items ?? []);
        setAlerts(alertsArr);
      }
      const totalTraffic = ifArr.reduce((s, i) => s + (Number(i.traffic_gb ?? i.bytes_total ?? 0) || 0), 0);
      const avgUtil = ifArr.length > 0
        ? Math.round(ifArr.reduce((s, i) => s + (Number(i.utilization ?? i.utilization_pct ?? 0) || 0), 0) / ifArr.length)
        : 0;
      setStats({
        interfaces_monitored: ifArr.length,
        active_alerts: alertsArr.length,
        total_traffic_gb: Number(totalTraffic.toFixed(1)),
        avg_utilization_pct: avgUtil,
      });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const handleRefresh = () => { load(); };

  if (loading) return <PageSkeleton />;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Network Monitoring"
        description="Interface health, traffic utilization, and real-time alert feed"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {error && <ErrorState message={error} onRetry={load} />}

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Interfaces Monitored" value={stats.interfaces_monitored} icon={Wifi}          trend="up"   />
        <KpiCard title="Active Alerts"         value={stats.active_alerts}        icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="Total Traffic (GB)"    value={`${stats.total_traffic_gb} GB`} icon={Activity}  trend="up"   />
        <KpiCard title="Avg Utilization"       value={`${stats.avg_utilization_pct}%`} icon={Network}  trend="down" className="border-amber-500/20" />
      </div>

      {/* Alert Feed */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              Active Alerts
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">Live</Badge>
          </div>
          <CardDescription className="text-xs">Interface alerts sorted by severity</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {alerts.length === 0 && !error ? <EmptyState icon={AlertTriangle} title="No active alerts" description="No alert rules have triggered for monitored interfaces." /> : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Interface</TableHead>
                  <TableHead className="text-[11px] h-8">Metric</TableHead>
                  <TableHead className="text-[11px] h-8">Value</TableHead>
                  <TableHead className="text-[11px] h-8">Detected</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {alerts.map((a: any, i: number) => (
                  <TableRow key={a.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2"><SeverityBadge sev={a.severity ?? "medium"} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px]">{a.interface_name ?? a.interface_id ?? "—"}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{(a.metric ?? a.metric_type ?? "")?.replace(/_/g, " ")}</TableCell>
                    <TableCell className="py-2 text-[11px] font-medium tabular-nums">{a.value ?? a.threshold ?? "—"}</TableCell>
                    <TableCell className="py-2 text-xs tabular-nums text-muted-foreground">{a.detected_at ?? a.created_at ?? "—"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          )}
        </CardContent>
      </Card>

      {/* Interface Table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Network className="h-4 w-4 text-cyan-400" />
            Interface Overview
          </CardTitle>
          <CardDescription className="text-xs">Traffic and utilization per monitored interface</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {ifaces.length === 0 && !error ? <EmptyState icon={Network} title="No interfaces" description="Register a network interface to begin monitoring." /> : (
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="text-[11px] h-8">Interface</TableHead>
                <TableHead className="text-[11px] h-8">Status</TableHead>
                <TableHead className="text-[11px] h-8 text-right">Traffic</TableHead>
                <TableHead className="text-[11px] h-8 min-w-[140px]">Utilization</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {ifaces.map((iface: any, i: number) => {
                const util = Number(iface.utilization ?? iface.utilization_pct ?? 0) || 0;
                return (
                <TableRow key={iface.id ?? iface.name ?? i} className="hover:bg-muted/30">
                  <TableCell className="py-2 font-mono text-[11px]">{iface.name ?? iface.id}</TableCell>
                  <TableCell className="py-2"><StatusBadge status={iface.status ?? "up"} /></TableCell>
                  <TableCell className="py-2 text-right text-[11px] tabular-nums text-muted-foreground">{iface.traffic_gb ?? 0} GB</TableCell>
                  <TableCell className="py-2">
                    <div className="flex items-center gap-2">
                      <div className="relative flex-1 h-1.5 rounded-full bg-muted/30 overflow-hidden min-w-[80px]">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${util}%` }}
                          transition={{ duration: 0.5, delay: i * 0.05 }}
                          className={cn("h-full rounded-full",
                            util >= 90 ? "bg-red-500" :
                            util >= 70 ? "bg-amber-500" : "bg-green-500"
                          )}
                        />
                      </div>
                      <span className={cn("text-xs tabular-nums font-medium w-8 text-right",
                        util >= 90 ? "text-red-400" :
                        util >= 70 ? "text-amber-400" : "text-green-400"
                      )}>{util}%</span>
                    </div>
                  </TableCell>
                </TableRow>
              );})}
            </TableBody>
          </Table>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
