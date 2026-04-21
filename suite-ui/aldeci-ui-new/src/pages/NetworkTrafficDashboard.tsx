/**
 * Network Traffic Dashboard
 *
 * Network flow analysis, anomaly detection, traffic rules, and protocol breakdown.
 *   1. KPIs: Total Flows (24h), Flagged Flows, Anomaly Rate, Avg Risk Score
 *   2. Anomaly feed: flagged flows with type badge, src/dst IPs, risk score bar
 *   3. Top talkers table: src_ip, bytes_sent, bytes_received, connections, risk score
 *   4. Traffic rules panel: rule name, src/dst, action badge, hit count
 *   5. Protocol distribution: horizontal bars
 *
 * API: GET /api/v1/network-traffic/...
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  Shield,
  RefreshCw,
  Network,
  Radio,
  Filter,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, { headers: { "X-API-Key": API_KEY } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const ANOMALOUS_FLOWS = [
  { id: "FL-001", anomaly_type: "c2_traffic",   src_ip: "10.4.22.17",    dst_ip: "185.220.101.34", risk_score: 97, flagged: true,  detected_at: "14:32:11", bytes: 4512000000 },
  { id: "FL-002", anomaly_type: "data_exfil",   src_ip: "192.168.1.44",  dst_ip: "203.0.113.99",   risk_score: 91, flagged: true,  detected_at: "14:28:47", bytes: 3758096384 },
  { id: "FL-003", anomaly_type: "port_scan",    src_ip: "10.5.12.100",   dst_ip: "10.0.0.0/24",    risk_score: 68, flagged: true,  detected_at: "14:18:55", bytes: 524288 },
  { id: "FL-004", anomaly_type: "brute_force",  src_ip: "45.33.32.156",  dst_ip: "10.0.1.5",       risk_score: 74, flagged: true,  detected_at: "14:12:09", bytes: 1048576 },
  { id: "FL-005", anomaly_type: "beacon",       src_ip: "10.3.15.88",    dst_ip: "91.108.4.175",   risk_score: 79, flagged: true,  detected_at: "14:08:44", bytes: 157286400 },
  { id: "FL-006", anomaly_type: "data_exfil",   src_ip: "10.1.9.33",     dst_ip: "104.21.44.99",   risk_score: 55, flagged: true,  detected_at: "13:58:05", bytes: 209715200 },
  { id: "FL-007", anomaly_type: "port_scan",    src_ip: "198.51.100.22", dst_ip: "10.0.2.0/24",    risk_score: 48, flagged: true,  detected_at: "14:05:31", bytes: 131072 },
  { id: "FL-008", anomaly_type: "c2_traffic",   src_ip: "10.2.11.5",     dst_ip: "77.88.55.60",    risk_score: 62, flagged: true,  detected_at: "13:38:20", bytes: 52428800 },
];

const TOP_TALKERS = [
  { src_ip: "10.4.22.17",    bytes_sent: 4512000000, bytes_received: 12582912,  connections: 1847, risk_score: 97 },
  { src_ip: "192.168.1.44",  bytes_sent: 3758096384, bytes_received: 5242880,   connections: 412,  risk_score: 91 },
  { src_ip: "10.3.15.88",    bytes_sent: 1610612736, bytes_received: 943718400, connections: 892,  risk_score: 79 },
  { src_ip: "10.5.12.100",   bytes_sent: 524288000,  bytes_received: 1048576,   connections: 3102, risk_score: 68 },
  { src_ip: "10.1.9.33",     bytes_sent: 209715200,  bytes_received: 52428800,  connections: 228,  risk_score: 55 },
];

const TRAFFIC_RULES = [
  { id: "R-001", name: "Block known C2 CIDRs",    src: "any",             dst: "185.220.0.0/16",  action: "deny",    hit_count: 2341, enabled: true  },
  { id: "R-002", name: "Allow HTTPS outbound",    src: "10.0.0.0/8",      dst: "any",             action: "allow",   hit_count: 892144, enabled: true },
  { id: "R-003", name: "Monitor large transfers",  src: "10.0.0.0/8",     dst: "any",             action: "monitor", hit_count: 184,  enabled: true  },
  { id: "R-004", name: "Block Tor exit nodes",     src: "any",            dst: "Tor-exits",       action: "deny",    hit_count: 47,   enabled: true  },
  { id: "R-005", name: "Alert on DNS anomaly",     src: "10.2.0.0/16",    dst: "8.8.8.8/32",     action: "monitor", hit_count: 62,   enabled: true  },
  { id: "R-006", name: "Allow internal NFS",       src: "10.0.2.0/24",    dst: "10.0.2.1/32",    action: "allow",   hit_count: 44208, enabled: true },
];

const PROTOCOLS = [
  { name: "HTTPS", pct: 68 },
  { name: "HTTP",  pct: 12 },
  { name: "DNS",   pct: 8  },
  { name: "TCP",   pct: 6  },
  { name: "UDP",   pct: 4  },
  { name: "Other", pct: 2  },
];

const PROTO_COLORS: Record<string, string> = {
  HTTPS: "bg-blue-500",
  HTTP:  "bg-amber-500",
  DNS:   "bg-cyan-500",
  TCP:   "bg-purple-500",
  UDP:   "bg-green-500",
  Other: "bg-slate-500",
};

// ── Helpers ──────────────────────────────────────────────────

function AnomalyTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    c2_traffic:  "border-purple-500/30 text-purple-400 bg-purple-500/10",
    data_exfil:  "border-red-500/30 text-red-400 bg-red-500/10",
    port_scan:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    brute_force: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    beacon:      "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono", map[type] ?? "border-border text-muted-foreground")}>
      {type.replace(/_/g, " ")}
    </Badge>
  );
}

function ActionBadge({ action }: { action: string }) {
  const map: Record<string, string> = {
    allow:   "border-green-500/30 text-green-400 bg-green-500/10",
    deny:    "border-red-500/30 text-red-400 bg-red-500/10",
    monitor: "border-amber-500/30 text-amber-400 bg-amber-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[action] ?? "border-border")}>{action}</Badge>;
}

function fmtBytes(b: number): string {
  if (b >= 1073741824) return `${(b / 1073741824).toFixed(1)} GB`;
  if (b >= 1048576) return `${(b / 1048576).toFixed(0)} MB`;
  if (b >= 1024) return `${(b / 1024).toFixed(0)} KB`;
  return `${b} B`;
}

const MAX_BYTES = TOP_TALKERS[0].bytes_sent;

// ── Component ────────────────────────────────────────────────

export default function NetworkTrafficDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/network-traffic/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/network-traffic/anomalies?org_id=${ORG_ID}&limit=20`),
      apiFetch(`/api/v1/network-traffic/top-talkers?org_id=${ORG_ID}&limit=10`),
      apiFetch(`/api/v1/network-traffic/rules?org_id=${ORG_ID}`),
    ]).then(([statsR, anomR, talkR, rulesR]) => {
      const stats    = statsR.status  === "fulfilled" ? statsR.value  : null;
      const anomalies= anomR.status   === "fulfilled" ? anomR.value   : null;
      const talkers  = talkR.status   === "fulfilled" ? talkR.value   : null;
      const rules    = rulesR.status  === "fulfilled" ? rulesR.value  : null;
      if (stats || anomalies || talkers || rules) setLiveData({ stats, anomalies, talkers, rules });
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const anomalies   = liveData?.anomalies?.items ?? liveData?.anomalies ?? ANOMALOUS_FLOWS;
  const topTalkers  = liveData?.talkers?.items   ?? liveData?.talkers   ?? TOP_TALKERS;
  const rules       = liveData?.rules?.items     ?? liveData?.rules     ?? TRAFFIC_RULES;

  const totalFlows  = liveData?.stats?.total_flows    ?? "1.24M";
  const flaggedFlows= liveData?.stats?.flagged_flows  ?? anomalies.length;
  const anomalyRate = liveData?.stats?.anomaly_rate   ?? "0.64%";
  const avgRisk     = liveData?.stats?.avg_risk_score ?? Math.round(anomalies.reduce((s: number, f: any) => s + (f.risk_score ?? 0), 0) / anomalies.length);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Network Traffic"
        description="Flow analysis, anomaly detection, traffic rules, and protocol breakdown"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Flows (24h)"  value={totalFlows}                icon={Activity}      trend="up"   />
        <KpiCard title="Flagged Flows"      value={flaggedFlows}              icon={AlertTriangle} trend="up"   className="border-amber-500/20" />
        <KpiCard title="Anomaly Rate"       value={anomalyRate}               icon={Radio}         trend="up"   className="border-red-500/20" />
        <KpiCard title="Avg Risk Score"     value={avgRisk}                   icon={Shield}        trend="down" className="border-orange-500/20" />
      </div>

      {/* Anomaly Feed */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              Anomaly Feed
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">Live</Badge>
          </div>
          <CardDescription className="text-xs">Most recent flagged flows with anomaly classification and risk score</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Source IP</TableHead>
                  <TableHead className="text-[11px] h-8">Destination IP</TableHead>
                  <TableHead className="text-[11px] h-8">Volume</TableHead>
                  <TableHead className="text-[11px] h-8">Detected</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[100px]">Risk Score</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {anomalies.map((f: any, i: number) => (
                  <TableRow key={f.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2"><AnomalyTypeBadge type={f.anomaly_type} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px]">{f.src_ip}</TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{f.dst_ip}</TableCell>
                    <TableCell className="py-2 text-[11px] tabular-nums text-muted-foreground">{fmtBytes(f.bytes ?? f.bytes_sent ?? 0)}</TableCell>
                    <TableCell className="py-2 text-xs tabular-nums text-muted-foreground">{f.detected_at}</TableCell>
                    <TableCell className="py-2">
                      <div className="flex items-center gap-2">
                        <div className="relative flex-1 h-1.5 rounded-full bg-muted/30 overflow-hidden min-w-[60px]">
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${f.risk_score}%` }}
                            transition={{ duration: 0.5, delay: i * 0.04 }}
                            className={cn("h-full rounded-full", f.risk_score >= 80 ? "bg-red-500" : f.risk_score >= 60 ? "bg-amber-500" : "bg-yellow-500")}
                          />
                        </div>
                        <span className={cn("text-xs font-bold tabular-nums w-6 text-right", f.risk_score >= 80 ? "text-red-400" : f.risk_score >= 60 ? "text-amber-400" : "text-yellow-400")}>
                          {f.risk_score}
                        </span>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Top Talkers + Rules */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Top Talkers */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-amber-400" />
              Top Talkers
            </CardTitle>
            <CardDescription className="text-xs">Highest-volume source IPs by bytes sent</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Source IP</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[120px]">Bytes Sent</TableHead>
                  <TableHead className="text-[11px] h-8">Recv</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Conns</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Risk</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {topTalkers.map((t: any, i: number) => (
                  <TableRow key={t.src_ip ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px]">{t.src_ip}</TableCell>
                    <TableCell className="py-2">
                      <div className="flex items-center gap-1.5">
                        <div className="relative h-1.5 flex-1 rounded-full bg-muted/30 overflow-hidden min-w-[50px]">
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${((t.bytes_sent ?? 0) / MAX_BYTES) * 100}%` }}
                            transition={{ duration: 0.6, delay: i * 0.06 }}
                            className={cn("h-full rounded-full", (t.risk_score ?? 0) >= 80 ? "bg-red-500" : (t.risk_score ?? 0) >= 60 ? "bg-amber-500" : "bg-green-500")}
                          />
                        </div>
                        <span className="text-[11px] tabular-nums font-medium w-12 text-right">{fmtBytes(t.bytes_sent ?? 0)}</span>
                      </div>
                    </TableCell>
                    <TableCell className="py-2 text-[11px] tabular-nums text-muted-foreground">{fmtBytes(t.bytes_received ?? t.bytes_recv ?? 0)}</TableCell>
                    <TableCell className="py-2 text-right text-[11px] tabular-nums text-muted-foreground">{(t.connections ?? t.connection_count ?? 0).toLocaleString()}</TableCell>
                    <TableCell className="py-2 text-right">
                      <span className={cn("text-xs font-bold tabular-nums", (t.risk_score ?? 0) >= 80 ? "text-red-400" : (t.risk_score ?? 0) >= 60 ? "text-amber-400" : "text-green-400")}>
                        {t.risk_score ?? 0}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Traffic Rules */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Filter className="h-4 w-4 text-blue-400" />
              Traffic Rules
            </CardTitle>
            <CardDescription className="text-xs">Active allow / deny / monitor rules and hit counts</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Rule</TableHead>
                  <TableHead className="text-[11px] h-8">Src → Dst</TableHead>
                  <TableHead className="text-[11px] h-8">Action</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Hits</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.map((r: any) => (
                  <TableRow key={r.id ?? r.rule_name} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-xs font-medium max-w-[130px] truncate">{r.name ?? r.rule_name}</TableCell>
                    <TableCell className="py-2 font-mono text-[10px] text-muted-foreground">
                      <span className="truncate block max-w-[120px]">{r.src} → {r.dst ?? r.dst_cidr}</span>
                    </TableCell>
                    <TableCell className="py-2"><ActionBadge action={r.action} /></TableCell>
                    <TableCell className="py-2 text-right text-xs tabular-nums text-muted-foreground">{(r.hit_count ?? r.hits ?? 0).toLocaleString()}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      {/* Protocol Distribution */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Network className="h-4 w-4 text-cyan-400" />
            Protocol Distribution
          </CardTitle>
          <CardDescription className="text-xs">Traffic breakdown by protocol (% of total flows)</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {PROTOCOLS.map((p, i) => (
            <div key={p.name} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium w-12">{p.name}</span>
                <span className="tabular-nums text-muted-foreground">{p.pct}%</span>
              </div>
              <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${p.pct}%` }}
                  transition={{ duration: 0.6, delay: i * 0.08 }}
                  className={cn("h-full rounded-full", PROTO_COLORS[p.name] ?? "bg-slate-500")}
                />
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </motion.div>
  );
}
