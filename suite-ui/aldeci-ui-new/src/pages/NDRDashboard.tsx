/**
 * NDR Dashboard
 *
 * Network Detection & Response — traffic analysis, anomaly detection, network threat hunting.
 *   1. KPIs: Monitored Flows, High-Risk Flows, C2 Suspects, Open Alerts
 *   2. Network alert feed (15 alerts)
 *   3. Top talkers table (10 flows)
 *   4. Network segments grid (6 cards)
 *   5. Anomaly detection panel (6 baseline deviations)
 *
 * API stubs: GET /api/v1/ndr/alerts, /api/v1/ndr/flows, /api/v1/ndr/segments
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
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const ALERTS = [
  { id: "NDR-001", alert_type: "c2_beacon",         severity: "critical", src_ip: "10.4.22.17",    dst_ip: "185.220.101.34", description: "Periodic C2 beacon to known Cobalt Strike server",        mitre: "T1071.001", detected_at: "14:32:11", status: "open" },
  { id: "NDR-002", alert_type: "data_exfil",        severity: "critical", src_ip: "192.168.1.44",  dst_ip: "203.0.113.99",   description: "Abnormal outbound data transfer — 4.2 GB in 12 minutes",   mitre: "T1041",     detected_at: "14:28:47", status: "investigating" },
  { id: "NDR-003", alert_type: "lateral_movement",  severity: "high",     src_ip: "10.4.22.17",    dst_ip: "10.4.30.5",      description: "SMB lateral movement detected across subnet boundary",        mitre: "T1021.002", detected_at: "14:22:03", status: "open" },
  { id: "NDR-004", alert_type: "port_scan",         severity: "high",     src_ip: "10.5.12.100",   dst_ip: "10.0.0.0/24",    description: "Internal host scanning entire /24 subnet on port 22/445",   mitre: "T1046",     detected_at: "14:18:55", status: "open" },
  { id: "NDR-005", alert_type: "dns_tunneling",     severity: "high",     src_ip: "10.2.8.14",     dst_ip: "8.8.8.8",        description: "High-entropy DNS TXT queries — possible DNS tunneling",      mitre: "T1071.004", detected_at: "14:15:22", status: "open" },
  { id: "NDR-006", alert_type: "brute_force",       severity: "medium",   src_ip: "45.33.32.156",  dst_ip: "10.0.1.5",       description: "SSH brute force — 847 attempts in 3 minutes",               mitre: "T1110.001", detected_at: "14:12:09", status: "blocked" },
  { id: "NDR-007", alert_type: "c2_beacon",         severity: "high",     src_ip: "10.3.15.88",    dst_ip: "91.108.4.175",   description: "Suspected Metasploit beacon on non-standard port 4444",     mitre: "T1071.001", detected_at: "14:08:44", status: "open" },
  { id: "NDR-008", alert_type: "port_scan",         severity: "medium",   src_ip: "198.51.100.22", dst_ip: "10.0.2.0/24",    description: "External SYN scan on web-tier hosts — 12 ports probed",     mitre: "T1046",     detected_at: "14:05:31", status: "open" },
  { id: "NDR-009", alert_type: "lateral_movement",  severity: "high",     src_ip: "10.4.30.5",     dst_ip: "10.4.30.201",    description: "Pass-the-hash attempt detected via NTLMv2 negotiation",      mitre: "T1550.002", detected_at: "14:01:17", status: "investigating" },
  { id: "NDR-010", alert_type: "data_exfil",        severity: "medium",   src_ip: "10.1.9.33",     dst_ip: "104.21.44.99",   description: "Slow-drip exfiltration pattern — 200 MB over 6 hours",      mitre: "T1048.003", detected_at: "13:58:05", status: "open" },
  { id: "NDR-011", alert_type: "dns_tunneling",     severity: "medium",   src_ip: "10.5.2.67",     dst_ip: "1.1.1.1",        description: "Anomalous subdomain length in DNS queries — avg 58 chars",  mitre: "T1071.004", detected_at: "13:52:49", status: "open" },
  { id: "NDR-012", alert_type: "brute_force",       severity: "medium",   src_ip: "192.0.2.100",   dst_ip: "10.0.1.20",      description: "RDP brute force from external IP — credential stuffing",     mitre: "T1110.004", detected_at: "13:44:33", status: "blocked" },
  { id: "NDR-013", alert_type: "c2_beacon",         severity: "medium",   src_ip: "10.2.11.5",     dst_ip: "77.88.55.60",    description: "Periodic HTTPS beacon with jitter — TLS JA3 match",         mitre: "T1071.001", detected_at: "13:38:20", status: "open" },
  { id: "NDR-014", alert_type: "port_scan",         severity: "low",      src_ip: "10.6.0.44",     dst_ip: "10.0.0.1",       description: "Internal ICMP sweep — possible network mapping activity",   mitre: "T1018",     detected_at: "13:31:08", status: "closed" },
  { id: "NDR-015", alert_type: "lateral_movement",  severity: "low",      src_ip: "10.4.22.50",    dst_ip: "10.4.22.100",    description: "WMI remote execution within same segment",                  mitre: "T1047",     detected_at: "13:25:44", status: "closed" },
];

const TOP_TALKERS = [
  { src_ip: "10.4.22.17",   dst_ip: "185.220.101.34", protocol: "HTTPS", bytes_sent: 4294967296, bytes_recv: 12582912,  flow_type: "external",  risk_score: 97 },
  { src_ip: "192.168.1.44", dst_ip: "203.0.113.99",   protocol: "HTTP",  bytes_sent: 3758096384, bytes_recv: 5242880,   flow_type: "external",  risk_score: 91 },
  { src_ip: "10.4.30.5",    dst_ip: "10.4.22.17",     protocol: "SMB",   bytes_sent: 1610612736, bytes_recv: 943718400, flow_type: "lateral",   risk_score: 85 },
  { src_ip: "10.2.8.14",    dst_ip: "10.2.8.200",     protocol: "DNS",   bytes_sent: 943718400,  bytes_recv: 524288000, flow_type: "internal",  risk_score: 72 },
  { src_ip: "10.5.12.100",  dst_ip: "10.0.0.0/24",    protocol: "TCP",   bytes_sent: 524288000,  bytes_recv: 1048576,   flow_type: "lateral",   risk_score: 68 },
  { src_ip: "10.1.9.33",    dst_ip: "104.21.44.99",   protocol: "HTTPS", bytes_sent: 209715200,  bytes_recv: 52428800,  flow_type: "external",  risk_score: 55 },
  { src_ip: "10.3.15.88",   dst_ip: "91.108.4.175",   protocol: "TCP",   bytes_sent: 157286400,  bytes_recv: 10485760,  flow_type: "external",  risk_score: 79 },
  { src_ip: "10.6.44.20",   dst_ip: "10.6.44.1",      protocol: "UDP",   bytes_sent: 104857600,  bytes_recv: 209715200, flow_type: "internal",  risk_score: 20 },
  { src_ip: "10.0.1.5",     dst_ip: "172.217.5.110",  protocol: "HTTPS", bytes_sent: 73400320,   bytes_recv: 524288000, flow_type: "external",  risk_score: 15 },
  { src_ip: "10.0.2.55",    dst_ip: "10.0.2.1",       protocol: "NFS",   bytes_sent: 52428800,   bytes_recv: 314572800, flow_type: "internal",  risk_score: 12 },
];

const SEGMENTS = [
  { name: "DMZ",               cidr: "10.0.1.0/24",   type: "DMZ",      sensitivity: "High",    flow_count: 12847, alert_count: 7 },
  { name: "Internal Network",  cidr: "10.4.0.0/16",   type: "internal", sensitivity: "Critical",flow_count: 47291, alert_count: 12 },
  { name: "Cloud (AWS VPC)",   cidr: "172.31.0.0/16", type: "cloud",    sensitivity: "High",    flow_count: 8934,  alert_count: 3 },
  { name: "OT/SCADA",          cidr: "192.168.50.0/24",type: "OT",      sensitivity: "Critical",flow_count: 1247,  alert_count: 2 },
  { name: "Guest WiFi",        cidr: "10.6.0.0/24",   type: "guest",    sensitivity: "Low",     flow_count: 3822,  alert_count: 1 },
  { name: "Dev / Lab",         cidr: "10.5.0.0/24",   type: "internal", sensitivity: "Medium",  flow_count: 5619,  alert_count: 5 },
];

const ANOMALIES = [
  { ip: "10.4.22.17",   metric: "bytes_sent",   deviation: 847, normal_range: "50 MB – 200 MB",  observed: "4.2 GB",  risk: "critical" },
  { ip: "10.2.8.14",    metric: "dns_queries",  deviation: 412, normal_range: "100 – 500/hr",    observed: "2,062/hr",risk: "high" },
  { ip: "10.5.12.100",  metric: "connections",  deviation: 310, normal_range: "10 – 50/min",     observed: "205/min", risk: "high" },
  { ip: "192.168.1.44", metric: "bytes_sent",   deviation: 193, normal_range: "1 GB – 2 GB/day", observed: "5.9 GB",  risk: "high" },
  { ip: "10.3.15.88",   metric: "tcp_sessions", deviation: 88,  normal_range: "20 – 80/hr",      observed: "151/hr",  risk: "medium" },
  { ip: "10.6.0.44",    metric: "icmp_packets", deviation: 44,  normal_range: "0 – 10/hr",       observed: "14/hr",   risk: "low" },
];

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

const MAX_BYTES = TOP_TALKERS[0].bytes_sent;

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
        <KpiCard title="Monitored Flows"  value={liveData?.stats?.monitored_segments ?? liveData?.stats?.total_flows ?? "47.2K"} icon={Activity}      trend="up"   />
        <KpiCard title="High-Risk Flows"  value={liveData?.stats?.active_threats ?? 234}   icon={AlertTriangle} trend="up"   className="border-amber-500/20" />
        <KpiCard title="C2 Suspects"      value={liveData?.stats?.detection_rate ?? 8}     icon={Radio}         trend="up"   className="border-red-500/20" />
        <KpiCard title="Open Alerts"      value={liveData?.stats?.total_alerts ?? 34}      icon={Shield}        trend="down" className="border-orange-500/20" />
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
                {(liveData?.alerts?.items ?? liveData?.alerts ?? ALERTS).map((a: any) => (
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
          <CardDescription className="text-xs">10 highest-volume flows sorted by outbound traffic</CardDescription>
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
                {(liveData?.flows?.items ?? liveData?.flows ?? TOP_TALKERS).map((f: any, i: number) => (
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
                            animate={{ width: `${(f.bytes_sent / MAX_BYTES) * 100}%` }}
                            transition={{ duration: 0.7, delay: i * 0.04 }}
                            className={cn("h-full rounded-full", f.risk_score > 70 ? "bg-red-500" : f.risk_score > 40 ? "bg-amber-500" : "bg-green-500")}
                          />
                        </div>
                        <span className="text-[11px] tabular-nums font-medium w-14 text-right">{fmtBytes(f.bytes_sent)}</span>
                      </div>
                    </TableCell>
                    <TableCell className="py-2 text-[11px] tabular-nums text-muted-foreground">{fmtBytes(f.bytes_recv)}</TableCell>
                    <TableCell className="py-2"><FlowTypeBadge type={f.flow_type} /></TableCell>
                    <TableCell className="py-2 text-right">
                      <span className={cn("text-xs font-bold tabular-nums", f.risk_score >= 80 ? "text-red-400" : f.risk_score >= 50 ? "text-amber-400" : "text-green-400")}>
                        {f.risk_score}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
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
            <div className="grid grid-cols-2 gap-3">
              {SEGMENTS.map((seg) => (
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
                    <span className="text-muted-foreground">Flows: <span className="text-foreground font-medium tabular-nums">{seg.flow_count.toLocaleString()}</span></span>
                    <Badge className={cn("text-[10px] border", seg.alert_count > 5 ? "border-red-500/30 text-red-400 bg-red-500/10" : "border-amber-500/30 text-amber-400 bg-amber-500/10")}>
                      {seg.alert_count} alerts
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
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
            {ANOMALIES.map((a, i) => (
              <div key={i} className="rounded-lg border border-border bg-muted/20 p-3 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-semibold">{a.ip}</span>
                  <RiskBadge risk={a.risk} />
                </div>
                <div className="text-[11px] text-muted-foreground capitalize">{a.metric.replace(/_/g, " ")}</div>
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-muted-foreground">Normal: <span className="text-foreground">{a.normal_range}</span></span>
                  <span className="text-red-400 font-semibold">{a.observed}</span>
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
