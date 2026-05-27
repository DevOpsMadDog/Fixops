/**
 * NDR Dashboard
 *
 * Network Detection & Response — traffic analysis, anomaly detection, network threat hunting.
 *   1. KPIs: Monitored Flows, High-Risk Flows, C2 Suspects, Open Alerts
 *   2. Network alert feed (live)
 *   3. Top talkers table (live)
 *   4. Network segments grid (live)
 *   5. Anomaly detection panel (live)
 *
 * API: GET /api/v1/ndr/stats, /api/v1/ndr/alerts, /api/v1/ndr/flows
 * NOTE: /ndr/segments and /ndr/anomalies not yet in the API fetch — renders EmptyState when absent.
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Network, AlertTriangle, Activity, Shield, RefreshCw, Eye, Radio } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const ORG_ID = "default";

function getApiKey() {
  return (
    (typeof window !== "undefined" && localStorage.getItem("aldeci_api_key")) ||
    import.meta.env.VITE_API_KEY ||
    "dev-key"
  );
}

async function apiFetch(path: string) {
  const res = await fetch(`/api/v1${path}`, {
    headers: { "X-API-Key": getApiKey() },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

// ── Static config (badge colour maps — not domain data) ──

// ── Helpers ────────────────────────────────────────────────────

function AlertTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    port_scan:        "border-blue-500/30 text-blue-400 bg-blue-500/10",
    data_exfil:       "border-red-500/30 text-red-400 bg-red-500/10",
    c2_beacon:        "border-purple-500/30 text-purple-400 bg-purple-500/10",
    lateral_movement: "border-orange-500/30 text-orange-400 bg-orange-500/10",
    dns_tunneling:    "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    brute_force:      "border-amber-500/30 text-amber-400 bg-amber-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono", map[type] ?? "border-border text-muted-foreground")}>
      {type.replace(/_/g, " ")}
    </Badge>
  );
}

function SevDot({ sev }: { sev: string }) {
  const cls = sev === "critical" ? "bg-red-500" : sev === "high" ? "bg-amber-500" : sev === "medium" ? "bg-yellow-400" : "bg-slate-400";
  return <span className={cn("inline-block h-2 w-2 rounded-full shrink-0", cls)} />;
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:          "border-red-500/30 text-red-400 bg-red-500/10",
    investigating: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    blocked:       "border-blue-500/30 text-blue-400 bg-blue-500/10",
    closed:        "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>{status}</Badge>;
}

function SegTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    DMZ:      "border-orange-500/30 text-orange-400 bg-orange-500/10",
    internal: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    cloud:    "border-purple-500/30 text-purple-400 bg-purple-500/10",
    OT:       "border-red-500/30 text-red-400 bg-red-500/10",
    guest:    "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return <Badge className={cn("text-[10px] border uppercase", map[type] ?? "border-border")}>{type}</Badge>;
}

function RiskBadge({ risk }: { risk: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[risk] ?? "border-border")}>{risk}</Badge>;
}

function FlowTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    external: "border-red-500/30 text-red-400 bg-red-500/10",
    lateral:  "border-orange-500/30 text-orange-400 bg-orange-500/10",
    internal: "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border")}>{type}</Badge>;
}

function fmtBytes(b: number): string {
  if (b >= 1073741824) return `${(b / 1073741824).toFixed(1)} GB`;
  if (b >= 1048576) return `${(b / 1048576).toFixed(0)} MB`;
  return `${(b / 1024).toFixed(0)} KB`;
}

// ── Component ──────────────────────────────────────────────────

export default function NDRDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/ndr/stats?org_id=${ORG_ID}`),
      apiFetch(`/ndr/alerts?org_id=${ORG_ID}&limit=20`),
      apiFetch(`/ndr/flows?org_id=${ORG_ID}&limit=10`),
    ]).then(([statsResult, alertsResult, flowsResult]) => {
      const stats  = statsResult.status  === "fulfilled" ? statsResult.value  : null;
      const alerts = alertsResult.status === "fulfilled" ? alertsResult.value : null;
      const flows  = flowsResult.status  === "fulfilled" ? flowsResult.value  : null;
      if (stats || alerts || flows) {
        setLiveData({ stats, alerts, flows });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
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
        title="Network Detection & Response"
        description="Traffic analysis, anomaly detection, and network threat hunting"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Monitored Flows"  value={liveData?.stats?.monitored_segments ?? liveData?.stats?.total_flows ?? "—"} icon={Activity}      trend="up"   />
        <KpiCard title="High-Risk Flows"  value={liveData?.stats?.active_threats ?? "—"}   icon={AlertTriangle} trend="up"   className="border-amber-500/20" />
        <KpiCard title="C2 Suspects"      value={liveData?.stats?.detection_rate ?? "—"}   icon={Radio}         trend="up"   className="border-red-500/20" />
        <KpiCard title="Open Alerts"      value={liveData?.stats?.total_alerts ?? "—"}     icon={Shield}        trend="down" className="border-orange-500/20" />
      </div>

      {/* Network Alert Feed */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              Network Alert Feed
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">Live</Badge>
          </div>
          <CardDescription className="text-xs">Real-time network threat detections</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8 w-4"></TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Source → Destination</TableHead>
                  <TableHead className="text-[11px] h-8 max-w-[220px]">Description</TableHead>
                  <TableHead className="text-[11px] h-8">MITRE</TableHead>
                  <TableHead className="text-[11px] h-8">Time</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.alerts?.items ?? liveData?.alerts ?? []).length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="py-6">
                      <EmptyState icon={AlertTriangle} title="No network alerts yet" description="Alerts will appear once NDR detection rules fire." />
                    </TableCell>
                  </TableRow>
                ) : (liveData?.alerts?.items ?? liveData?.alerts as any[]).map((a: any) => (
                  <TableRow key={a.id} className="hover:bg-muted/30">
                    <TableCell className="py-2"><SevDot sev={a.severity} /></TableCell>
                    <TableCell className="py-2"><AlertTypeBadge type={a.alert_type} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground whitespace-nowrap">
                      {a.src_ip} <span className="text-muted-foreground/50">→</span> {a.dst_ip}
                    </TableCell>
                    <TableCell className="py-2 text-xs max-w-[220px] truncate text-muted-foreground">{a.description}</TableCell>
                    <TableCell className="py-2">
                      <span className="font-mono text-[10px] bg-muted/40 px-1.5 py-0.5 rounded text-blue-400">{a.mitre}</span>
                    </TableCell>
                    <TableCell className="py-2 text-xs tabular-nums text-muted-foreground">{a.detected_at}</TableCell>
                    <TableCell className="py-2"><StatusBadge status={a.status} /></TableCell>
                    <TableCell className="py-2 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] border-blue-500/30 text-blue-400 hover:bg-blue-500/10">
                        Investigate
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Top Talkers */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Activity className="h-4 w-4 text-amber-400" />
            Top Talkers by Bytes Sent
          </CardTitle>
          <CardDescription className="text-xs">Highest-volume flows sorted by outbound traffic</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Source IP</TableHead>
                  <TableHead className="text-[11px] h-8">Dest IP</TableHead>
                  <TableHead className="text-[11px] h-8">Protocol</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[140px]">Bytes Sent</TableHead>
                  <TableHead className="text-[11px] h-8">Bytes Recv</TableHead>
                  <TableHead className="text-[11px] h-8">Flow Type</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Risk</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(() => {
                  const flows: any[] = liveData?.flows?.items ?? liveData?.flows ?? [];
                  if (flows.length === 0) {
                    return (
                      <TableRow>
                        <TableCell colSpan={7} className="py-6">
                          <EmptyState icon={Activity} title="No flow data yet" description="Top talkers will appear once network flow data is ingested." />
                        </TableCell>
                      </TableRow>
                    );
                  }
                  const maxBytes: number = Math.max(...flows.map((f: any) => f.bytes_sent ?? 0), 1);
                  return flows.map((f: any, i: number) => (
                    <TableRow key={i} className="hover:bg-muted/30">
                      <TableCell className="py-2 font-mono text-[11px]">{f.src_ip}</TableCell>
                      <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{f.dst_ip}</TableCell>
                      <TableCell className="py-2">
                        <Badge className="text-[10px] border border-border text-muted-foreground">{f.protocol}</Badge>
                      </TableCell>
                      <TableCell className="py-2">
                        <div className="flex items-center gap-2">
                          <div className="relative h-1.5 flex-1 rounded-full bg-muted/30 overflow-hidden min-w-[80px]">
                            <motion.div
                              initial={{ width: 0 }}
                              animate={{ width: `${((f.bytes_sent ?? 0) / maxBytes) * 100}%` }}
                              transition={{ duration: 0.7, delay: i * 0.04 }}
                              className={cn("h-full rounded-full", f.risk_score > 70 ? "bg-red-500" : f.risk_score > 40 ? "bg-amber-500" : "bg-green-500")}
                            />
                          </div>
                          <span className="text-[11px] tabular-nums font-medium w-14 text-right">{fmtBytes(f.bytes_sent ?? 0)}</span>
                        </div>
                      </TableCell>
                      <TableCell className="py-2 text-[11px] tabular-nums text-muted-foreground">{fmtBytes(f.bytes_recv ?? 0)}</TableCell>
                      <TableCell className="py-2"><FlowTypeBadge type={f.flow_type} /></TableCell>
                      <TableCell className="py-2 text-right">
                        <span className={cn("text-xs font-bold tabular-nums", f.risk_score >= 80 ? "text-red-400" : f.risk_score >= 50 ? "text-amber-400" : "text-green-400")}>
                          {f.risk_score}
                        </span>
                      </TableCell>
                    </TableRow>
                  ));
                })()}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Segments + Anomalies */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Network Segments */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Network className="h-4 w-4 text-blue-400" />
              Network Segments
            </CardTitle>
            <CardDescription className="text-xs">Monitored segments, sensitivity, and alert counts</CardDescription>
          </CardHeader>
          <CardContent>
            {(liveData?.stats?.segments ?? []).length === 0 ? (
              <EmptyState icon={Network} title="No segment data yet" description="Segment topology will appear once the NDR engine reports network maps." />
            ) : (
              <div className="grid grid-cols-2 gap-3">
                {(liveData.stats.segments as any[]).map((seg: any) => (
                  <div key={seg.name} className="rounded-lg border border-border bg-muted/20 p-3 space-y-2">
                    <div className="flex items-center justify-between gap-1">
                      <span className="text-xs font-semibold truncate">{seg.name}</span>
                      <SegTypeBadge type={seg.type} />
                    </div>
                    <div className="font-mono text-[10px] text-muted-foreground">{seg.cidr}</div>
                    <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                      <span>Sensitivity: <span className={cn("font-medium", seg.sensitivity === "Critical" ? "text-red-400" : seg.sensitivity === "High" ? "text-amber-400" : "text-foreground")}>{seg.sensitivity}</span></span>
                    </div>
                    <div className="flex items-center justify-between text-[10px]">
                      <span className="text-muted-foreground">Flows: <span className="text-foreground font-medium tabular-nums">{(seg.flow_count ?? 0).toLocaleString()}</span></span>
                      <Badge className={cn("text-[10px] border", (seg.alert_count ?? 0) > 5 ? "border-red-500/30 text-red-400 bg-red-500/10" : "border-amber-500/30 text-amber-400 bg-amber-500/10")}>
                        {seg.alert_count ?? 0} alerts
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Anomaly Detection */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Eye className="h-4 w-4 text-purple-400" />
              Anomaly Detection
            </CardTitle>
            <CardDescription className="text-xs">Baseline deviation alerts — normal range vs observed</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {(liveData?.stats?.anomalies ?? []).length === 0 ? (
              <EmptyState icon={Eye} title="No anomalies detected" description="Baseline deviations will appear once the NDR anomaly engine has established profiles." />
            ) : (liveData.stats.anomalies as any[]).map((a: any, i: number) => (
              <div key={i} className="rounded-lg border border-border bg-muted/20 p-3 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-semibold">{a.ip ?? a.src_ip}</span>
                  <RiskBadge risk={a.risk ?? a.risk_level} />
                </div>
                <div className="text-[11px] text-muted-foreground capitalize">{(a.metric ?? a.metric_name ?? "").replace(/_/g, " ")}</div>
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-muted-foreground">Normal: <span className="text-foreground">{a.normal_range}</span></span>
                  <span className="text-red-400 font-semibold">{a.observed ?? a.observed_value}</span>
                </div>
                <div className="text-[10px] text-amber-400 font-medium">+{a.deviation}% above baseline</div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
