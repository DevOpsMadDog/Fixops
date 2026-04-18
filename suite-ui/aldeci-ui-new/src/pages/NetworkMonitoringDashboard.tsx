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
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_ALERTS = [
  { id: "NM-001", interface_name: "eth0",    severity: "critical", metric: "packet_loss",    value: "18.4%",  detected_at: "14:52:01" },
  { id: "NM-002", interface_name: "bond0",   severity: "high",     metric: "utilization",    value: "94.2%",  detected_at: "14:48:33" },
  { id: "NM-003", interface_name: "eth2",    severity: "high",     metric: "error_rate",     value: "3.1%",   detected_at: "14:41:12" },
  { id: "NM-004", interface_name: "vlan100", severity: "medium",   metric: "latency_ms",     value: "312ms",  detected_at: "14:35:07" },
  { id: "NM-005", interface_name: "eth1",    severity: "medium",   metric: "utilization",    value: "81.0%",  detected_at: "14:29:44" },
  { id: "NM-006", interface_name: "tun0",    severity: "low",      metric: "throughput_drop", value: "22%",   detected_at: "14:18:55" },
];

const MOCK_INTERFACES = [
  { name: "eth0",    status: "degraded", traffic_gb: 142.3, utilization: 94 },
  { name: "bond0",   status: "up",       traffic_gb: 98.7,  utilization: 81 },
  { name: "eth1",    status: "up",       traffic_gb: 76.2,  utilization: 63 },
  { name: "eth2",    status: "error",    traffic_gb: 12.4,  utilization: 11 },
  { name: "vlan100", status: "up",       traffic_gb: 54.1,  utilization: 47 },
  { name: "tun0",    status: "up",       traffic_gb: 8.9,   utilization: 29 },
];

const MOCK_STATS = {
  interfaces_monitored: 24,
  active_alerts: 6,
  total_traffic_gb: 392.6,
  avg_utilization_pct: 54,
};

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
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/network-monitoring/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/network-monitoring/alerts?org_id=${ORG_ID}&limit=20`),
    ]).then(([statsR, alertsR]) => {
      const stats  = statsR.status  === "fulfilled" ? statsR.value  : null;
      const alerts = alertsR.status === "fulfilled" ? alertsR.value : null;
      if (stats || alerts) setLiveData({ stats, alerts 
    setLoading(false);});
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const stats     = liveData?.stats  ?? MOCK_STATS;
  const alerts    = liveData?.alerts?.items ?? liveData?.alerts ?? MOCK_ALERTS;
  const ifaces    = MOCK_INTERFACES;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

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
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

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
                {alerts.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  alerts.map((a: any, i: number) => (
                  <TableRow key={a.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2"><SeverityBadge sev={a.severity} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px]">{a.interface_name}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{a.metric?.replace(/_/g, " ")}</TableCell>
                    <TableCell className="py-2 text-[11px] font-medium tabular-nums">{a.value}</TableCell>
                    <TableCell className="py-2 text-xs tabular-nums text-muted-foreground">{a.detected_at}</TableCell>
                  </TableRow>
                ))}
                )}
              </TableBody>
            </Table>
          </div>
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
              {ifaces.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                ifaces.map((iface: any, i: number) => (
                <TableRow key={iface.name ?? i} className="hover:bg-muted/30">
                  <TableCell className="py-2 font-mono text-[11px]">{iface.name}</TableCell>
                  <TableCell className="py-2"><StatusBadge status={iface.status} /></TableCell>
                  <TableCell className="py-2 text-right text-[11px] tabular-nums text-muted-foreground">{iface.traffic_gb} GB</TableCell>
                  <TableCell className="py-2">
                    <div className="flex items-center gap-2">
                      <div className="relative flex-1 h-1.5 rounded-full bg-muted/30 overflow-hidden min-w-[80px]">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${iface.utilization}%` }}
                          transition={{ duration: 0.5, delay: i * 0.05 }}
                          className={cn("h-full rounded-full",
                            iface.utilization >= 90 ? "bg-red-500" :
                            iface.utilization >= 70 ? "bg-amber-500" : "bg-green-500"
                          )}
                        />
                      </div>
                      <span className={cn("text-xs tabular-nums font-medium w-8 text-right",
                        iface.utilization >= 90 ? "text-red-400" :
                        iface.utilization >= 70 ? "text-amber-400" : "text-green-400"
                      )}>{iface.utilization}%</span>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </motion.div>
  );
}
