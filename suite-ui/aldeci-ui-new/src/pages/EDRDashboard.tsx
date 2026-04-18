/**
 * EDR Dashboard
 *
 * Endpoint Detection & Response — process telemetry, malware detection, and endpoint isolation.
 *   1. KPIs: Endpoints Online, Isolated, New Detections, Critical Alerts
 *   2. Endpoint inventory (12 rows)
 *   3. Live detection feed (10 detections)
 *   4. Suspicious process events (12 rows)
 *   5. Isolation log (5 endpoints)
 *
 * API stubs: GET /api/v1/edr/endpoints, /api/v1/edr/detections, /api/v1/edr/processes
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Monitor, AlertTriangle, Shield, Lock, RefreshCw, Activity, Terminal } from "lucide-react";

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

const ENDPOINTS = [
  { hostname: "WINDC-01",    ip: "10.4.22.5",   os: "Windows", status: "compromised", risk_score: 97, last_seen: "2 min ago",  agent: "7.3.1" },
  { hostname: "FS-SERVER-02",ip: "192.168.1.44", os: "Windows", status: "isolated",   risk_score: 91, last_seen: "5 min ago",  agent: "7.3.1" },
  { hostname: "WORKST-047",  ip: "10.4.22.47",  os: "Windows", status: "isolated",   risk_score: 88, last_seen: "8 min ago",  agent: "7.3.1" },
  { hostname: "WORKST-012",  ip: "10.4.22.12",  os: "Windows", status: "online",     risk_score: 72, last_seen: "1 min ago",  agent: "7.3.1" },
  { hostname: "linux-app-03",ip: "10.0.2.33",   os: "Linux",   status: "online",     risk_score: 45, last_seen: "30 sec ago", agent: "7.3.0" },
  { hostname: "macbook-eng1",ip: "10.5.12.100", os: "macOS",   status: "online",     risk_score: 61, last_seen: "1 min ago",  agent: "7.3.1" },
  { hostname: "WEB-SRV-01",  ip: "10.0.1.10",   os: "Linux",   status: "online",     risk_score: 38, last_seen: "45 sec ago", agent: "7.3.0" },
  { hostname: "DB-SRV-01",   ip: "10.4.30.5",   os: "Linux",   status: "isolated",   risk_score: 83, last_seen: "12 min ago", agent: "7.3.1" },
  { hostname: "WORKST-099",  ip: "10.4.22.99",  os: "Windows", status: "online",     risk_score: 22, last_seen: "2 min ago",  agent: "7.3.1" },
  { hostname: "linux-dev-07",ip: "10.5.0.44",   os: "Linux",   status: "online",     risk_score: 18, last_seen: "1 min ago",  agent: "7.2.9" },
  { hostname: "macbook-sec1",ip: "10.5.12.55",  os: "macOS",   status: "online",     risk_score: 12, last_seen: "30 sec ago", agent: "7.3.1" },
  { hostname: "BACKUP-SRV",  ip: "10.4.30.201", os: "Windows", status: "offline",    risk_score: 55, last_seen: "2h ago",     agent: "7.2.8" },
];

const DETECTIONS = [
  { name: "Cobalt Strike Beacon",        type: "c2_implant",        hostname: "WINDC-01",     severity: "critical", confidence: 98, auto_isolated: true,  detected_at: "14:32:11" },
  { name: "Mimikatz LSASS Dump",         type: "credential_dumper", hostname: "WORKST-047",   severity: "critical", confidence: 96, auto_isolated: true,  detected_at: "14:28:44" },
  { name: "BlackCat Ransomware Stub",    type: "ransomware",        hostname: "FS-SERVER-02", severity: "critical", confidence: 94, auto_isolated: true,  detected_at: "14:22:09" },
  { name: "Rootkit Kernel Module",       type: "rootkit",           hostname: "DB-SRV-01",    severity: "critical", confidence: 91, auto_isolated: true,  detected_at: "14:18:33" },
  { name: "PsExec Lateral Tool",         type: "lateral_tool",      hostname: "WORKST-012",   severity: "high",     confidence: 87, auto_isolated: false, detected_at: "14:14:22" },
  { name: "PowerShell Empire Agent",     type: "c2_implant",        hostname: "WORKST-099",   severity: "high",     confidence: 83, auto_isolated: false, detected_at: "14:10:55" },
  { name: "WDigest Plaintext Cred Dump", type: "credential_dumper", hostname: "WINDC-01",     severity: "high",     confidence: 89, auto_isolated: false, detected_at: "14:06:30" },
  { name: "XMRig Cryptominer",           type: "malware",           hostname: "linux-dev-07", severity: "medium",   confidence: 76, auto_isolated: false, detected_at: "14:02:14" },
  { name: "Netcat Reverse Shell",        type: "lateral_tool",      hostname: "linux-app-03", severity: "medium",   confidence: 72, auto_isolated: false, detected_at: "13:58:47" },
  { name: "Meterpreter Payload",         type: "c2_implant",        hostname: "macbook-eng1", severity: "high",     confidence: 85, auto_isolated: false, detected_at: "13:52:21" },
];

const PROCESS_EVENTS = [
  { process: "lsass.exe",        parent: "cmd.exe",          user: "SYSTEM",        event_type: "memory_access",  mitre: "T1003.001", severity: "critical", hostname: "WINDC-01",     observed_at: "14:31:05" },
  { process: "powershell.exe",   parent: "wscript.exe",      user: "jsmith",        event_type: "suspicious_cmd", mitre: "T1059.001", severity: "critical", hostname: "WORKST-047",   observed_at: "14:28:12" },
  { process: "psexec.exe",       parent: "explorer.exe",     user: "Administrator", event_type: "lateral_exec",   mitre: "T1021.002", severity: "high",     hostname: "WORKST-012",   observed_at: "14:24:33" },
  { process: "certutil.exe",     parent: "cmd.exe",          user: "jdoe",          event_type: "download",       mitre: "T1105",     severity: "high",     hostname: "WINDC-01",     observed_at: "14:20:18" },
  { process: "mshta.exe",        parent: "outlook.exe",      user: "asmith",        event_type: "script_exec",    mitre: "T1218.005", severity: "high",     hostname: "WORKST-099",   observed_at: "14:16:44" },
  { process: "netsh.exe",        parent: "powershell.exe",   user: "SYSTEM",        event_type: "fw_rule_mod",    mitre: "T1562.004", severity: "high",     hostname: "FS-SERVER-02", observed_at: "14:12:09" },
  { process: "reg.exe",          parent: "cmd.exe",          user: "Administrator", event_type: "persistence",    mitre: "T1547.001", severity: "medium",   hostname: "WORKST-012",   observed_at: "14:08:55" },
  { process: "wmic.exe",         parent: "powershell.exe",   user: "svc-backup",    event_type: "enum",           mitre: "T1047",     severity: "medium",   hostname: "DB-SRV-01",    observed_at: "14:05:30" },
  { process: "schtasks.exe",     parent: "cmd.exe",          user: "jsmith",        event_type: "persistence",    mitre: "T1053.005", severity: "medium",   hostname: "WORKST-047",   observed_at: "14:01:16" },
  { process: "/bin/bash",        parent: "sshd",             user: "root",          event_type: "suspicious_cmd", mitre: "T1059.004", severity: "medium",   hostname: "linux-app-03", observed_at: "13:57:43" },
  { process: "curl",             parent: "/bin/bash",        user: "www-data",      event_type: "download",       mitre: "T1105",     severity: "low",      hostname: "WEB-SRV-01",   observed_at: "13:53:28" },
  { process: "crontab",          parent: "/bin/bash",        user: "deploy",        event_type: "persistence",    mitre: "T1053.003", severity: "low",      hostname: "linux-dev-07", observed_at: "13:49:55" },
];

const ISOLATION_LOG = [
  { hostname: "FS-SERVER-02", reason: "BlackCat ransomware staging detected",   isolated_by: "Auto-EDR",  duration: "47 min",  status: "isolated" },
  { hostname: "WORKST-047",   reason: "LSASS credential dump — Mimikatz sig",   isolated_by: "Auto-EDR",  duration: "1h 12m",  status: "isolated" },
  { hostname: "DB-SRV-01",    reason: "Rootkit kernel module loaded",            isolated_by: "Auto-EDR",  duration: "1h 54m",  status: "isolated" },
  { hostname: "WORKST-033",   reason: "Lateral movement via PsExec confirmed",   isolated_by: "analyst1",  duration: "3h 20m",  status: "released" },
  { hostname: "WORKST-021",   reason: "Cryptominer process terminated and clean", isolated_by: "analyst2", duration: "5h 41m",  status: "released" },
];

// ── Helpers ────────────────────────────────────────────────────

function OsBadge({ os }: { os: string }) {
  const map: Record<string, string> = {
    Windows: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    Linux:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    macOS:   "border-purple-500/30 text-purple-400 bg-purple-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[os] ?? "border-border")}>{os}</Badge>;
}

function EndpointStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    online:      "border-green-500/30 text-green-400 bg-green-500/10",
    isolated:    "border-orange-500/30 text-orange-400 bg-orange-500/10",
    compromised: "border-red-500/30 text-red-400 bg-red-500/10",
    offline:     "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>{status}</Badge>;
}

function DetectionTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    malware:           "border-red-500/30 text-red-400 bg-red-500/10",
    ransomware:        "border-red-600/30 text-red-300 bg-red-600/10",
    rootkit:           "border-purple-500/30 text-purple-400 bg-purple-500/10",
    credential_dumper: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    lateral_tool:      "border-orange-500/30 text-orange-400 bg-orange-500/10",
    c2_implant:        "border-rose-500/30 text-rose-400 bg-rose-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[type] ?? "border-border")}>{type.replace(/_/g, " ")}</Badge>;
}

function EventTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    memory_access:  "border-red-500/30 text-red-400 bg-red-500/10",
    suspicious_cmd: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    lateral_exec:   "border-orange-500/30 text-orange-400 bg-orange-500/10",
    download:       "border-blue-500/30 text-blue-400 bg-blue-500/10",
    script_exec:    "border-purple-500/30 text-purple-400 bg-purple-500/10",
    fw_rule_mod:    "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    persistence:    "border-teal-500/30 text-teal-400 bg-teal-500/10",
    enum:           "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[type] ?? "border-border")}>{type.replace(/_/g, " ")}</Badge>;
}

function SevDot({ sev }: { sev: string }) {
  const cls = sev === "critical" ? "bg-red-500" : sev === "high" ? "bg-amber-500" : sev === "medium" ? "bg-yellow-400" : "bg-slate-400";
  return <span className={cn("inline-block h-2 w-2 rounded-full shrink-0", cls)} />;
}

function RiskBar({ score }: { score: number }) {
  const color = score >= 80 ? "bg-red-500" : score >= 60 ? "bg-amber-500" : score >= 40 ? "bg-yellow-400" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="relative h-1.5 w-16 rounded-full bg-muted/30 overflow-hidden">
        <div className={cn("h-full rounded-full", color)} style={{ width: `${score}%` }} />
      </div>
      <span className={cn("text-xs font-bold tabular-nums", score >= 80 ? "text-red-400" : score >= 60 ? "text-amber-400" : "text-green-400")}>{score}</span>
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function EDRDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/edr/stats?org_id=${ORG_ID}`),
      apiFetch(`/edr/endpoints?org_id=${ORG_ID}&limit=20`),
      apiFetch(`/edr/detections?org_id=${ORG_ID}&limit=20`),
    ]).then(([statsResult, endpointsResult, detectionsResult]) => {
      const stats      = statsResult.status      === "fulfilled" ? statsResult.value      : null;
      const endpoints  = endpointsResult.status  === "fulfilled" ? endpointsResult.value  : null;
      const detections = detectionsResult.status === "fulfilled" ? detectionsResult.value : null;
      if (stats || endpoints || detections) {
        setLiveData({ stats, endpoints, detections });
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
        title="Endpoint Detection & Response"
        description="Process telemetry, malware detection, and endpoint isolation"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Endpoints Online"  value={liveData?.stats?.endpoint_count ?? liveData?.stats?.total ?? 847} icon={Monitor}       trend="up"   />
        <KpiCard title="Isolated"          value={liveData?.stats?.isolated_count ?? 3}   icon={Lock}          trend="up"   className="border-orange-500/20" />
        <KpiCard title="New Detections"    value={liveData?.stats?.total_detections ?? 12}  icon={Activity}      trend="up"   className="border-amber-500/20" />
        <KpiCard title="Critical Alerts"   value={liveData?.stats?.detection_rate ?? 4}   icon={AlertTriangle} trend="up"   className="border-red-500/20" />
      </div>

      {/* Endpoint Inventory */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Monitor className="h-4 w-4 text-blue-400" />
              Endpoint Inventory
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {(liveData?.endpoints?.items ?? liveData?.endpoints ?? ENDPOINTS).filter((e: any) => e.status === "isolated" || e.status === "compromised").length} need attention
            </Badge>
          </div>
          <CardDescription className="text-xs">All managed endpoints with status, risk, and agent version</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Hostname</TableHead>
                  <TableHead className="text-[11px] h-8">IP Address</TableHead>
                  <TableHead className="text-[11px] h-8">OS</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[110px]">Risk Score</TableHead>
                  <TableHead className="text-[11px] h-8">Last Seen</TableHead>
                  <TableHead className="text-[11px] h-8">Agent</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.endpoints?.items ?? liveData?.endpoints ?? ENDPOINTS).map((ep: any) => (
                  <TableRow key={ep.hostname} className={cn("hover:bg-muted/30", ep.status === "compromised" && "bg-red-500/5")}>
                    <TableCell className="py-2 font-mono text-xs font-semibold">{ep.hostname}</TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{ep.ip}</TableCell>
                    <TableCell className="py-2"><OsBadge os={ep.os} /></TableCell>
                    <TableCell className="py-2"><EndpointStatusBadge status={ep.status} /></TableCell>
                    <TableCell className="py-2"><RiskBar score={ep.risk_score} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{ep.last_seen}</TableCell>
                    <TableCell className="py-2 text-[11px] font-mono text-muted-foreground">{ep.agent}</TableCell>
                    <TableCell className="py-2 text-right">
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={ep.status === "isolated" || ep.status === "offline"}
                        className="h-6 px-2 text-[10px] border-red-500/30 text-red-400 hover:bg-red-500/10 disabled:opacity-30"
                      >
                        Isolate
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Detections + Isolation Log */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Live Detection Feed */}
        <Card className="border-amber-500/20">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
                <Shield className="h-4 w-4" />
                Live Detection Feed
              </CardTitle>
              <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">Live</Badge>
            </div>
            <CardDescription className="text-xs">Malware and threat detections across all endpoints</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {(liveData?.detections?.items ?? liveData?.detections ?? DETECTIONS).map((d: any, i: number) => (
              <div key={i} className="rounded-lg border border-border bg-muted/20 p-3 space-y-1.5">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <SevDot sev={d.severity} />
                    <span className="text-xs font-semibold truncate">{d.name}</span>
                  </div>
                  {d.auto_isolated && (
                    <Badge className="text-[10px] border border-orange-500/30 text-orange-400 bg-orange-500/10 shrink-0">Auto-Isolated</Badge>
                  )}
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  <DetectionTypeBadge type={d.type} />
                  <span className="font-mono text-[10px] text-muted-foreground">{d.hostname}</span>
                </div>
                <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                  <div className="flex items-center gap-1.5">
                    <span>Confidence:</span>
                    <span className={cn("font-bold", d.confidence >= 90 ? "text-red-400" : d.confidence >= 75 ? "text-amber-400" : "text-green-400")}>{d.confidence}%</span>
                  </div>
                  <span className="tabular-nums">{d.detected_at}</span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Isolation Log */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Lock className="h-4 w-4 text-orange-400" />
              Isolation Log
            </CardTitle>
            <CardDescription className="text-xs">Isolated and recently released endpoints</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {ISOLATION_LOG.map((iso, i) => (
              <div key={i} className={cn("rounded-lg border bg-muted/20 p-3 space-y-1.5", iso.status === "isolated" ? "border-orange-500/30" : "border-border")}>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-semibold">{iso.hostname}</span>
                  <Badge className={cn("text-[10px] border capitalize",
                    iso.status === "isolated" ? "border-orange-500/30 text-orange-400 bg-orange-500/10" : "border-green-500/30 text-green-400 bg-green-500/10"
                  )}>{iso.status}</Badge>
                </div>
                <div className="text-[11px] text-muted-foreground">{iso.reason}</div>
                <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                  <span>By: <span className="text-foreground font-medium">{iso.isolated_by}</span></span>
                  <span>Duration: <span className="text-foreground tabular-nums font-medium">{iso.duration}</span></span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Suspicious Process Events */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Terminal className="h-4 w-4 text-red-400" />
            Suspicious Process Events
          </CardTitle>
          <CardDescription className="text-xs">High-fidelity process telemetry with MITRE ATT&CK mapping</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8 w-4"></TableHead>
                  <TableHead className="text-[11px] h-8">Process</TableHead>
                  <TableHead className="text-[11px] h-8">Parent</TableHead>
                  <TableHead className="text-[11px] h-8">User</TableHead>
                  <TableHead className="text-[11px] h-8">Event</TableHead>
                  <TableHead className="text-[11px] h-8">MITRE</TableHead>
                  <TableHead className="text-[11px] h-8">Endpoint</TableHead>
                  <TableHead className="text-[11px] h-8">Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {PROCESS_EVENTS.map((pe, i) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2"><SevDot sev={pe.severity} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px] font-semibold">{pe.process}</TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{pe.parent}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{pe.user}</TableCell>
                    <TableCell className="py-2"><EventTypeBadge type={pe.event_type} /></TableCell>
                    <TableCell className="py-2">
                      <span className="font-mono text-[10px] bg-muted/40 px-1.5 py-0.5 rounded text-blue-400">{pe.mitre}</span>
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{pe.hostname}</TableCell>
                    <TableCell className="py-2 text-[11px] tabular-nums text-muted-foreground">{pe.observed_at}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
