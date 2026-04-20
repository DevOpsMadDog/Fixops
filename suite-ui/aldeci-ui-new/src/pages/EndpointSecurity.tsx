/**
 * Endpoint Security / EDR Dashboard
 *
 * EDR coverage, threat detections, and endpoint health monitoring.
 * Route: /endpoints
 *
 * API: GET /api/v1/endpoints  GET /api/v1/endpoints/threats
 * Falls back to mock data on failure.
 */

import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  AlertTriangle,
  Shield,
  Monitor,
  Activity,
  CheckCircle2,
  XCircle,
  Clock,
  RefreshCw,
  Wifi,
  WifiOff,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type ThreatStatus = "Active" | "Contained" | "Investigating";
type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
type PatchStatus = "Up to date" | "Needs patch" | "Critical patch missing";

interface ThreatDetection {
  id: string;
  hostname: string;
  threat_name: string;
  tactic: string;
  detection_time: string;
  status: ThreatStatus;
  severity: Severity;
}

interface EndpointRow {
  id: string;
  hostname: string;
  os: string;
  last_seen: string;
  agent_version: string;
  threat_score: number;
  patch_status: PatchStatus;
  issues_count: number;
}

// ═══════════════════════════════════════════════════════════
// Mock data
// ═══════════════════════════════════════════════════════════

const MOCK_THREATS: ThreatDetection[] = [
  { id: "t1", hostname: "WORKSTATION-042", threat_name: "POWERSHELL EMPIRE", tactic: "Execution", detection_time: "2026-04-16 09:14", status: "Active", severity: "CRITICAL" },
  { id: "t2", hostname: "SERVER-DB-01", threat_name: "MIMIKATZ Attempt", tactic: "Credential Access", detection_time: "2026-04-16 08:51", status: "Contained", severity: "HIGH" },
  { id: "t3", hostname: "LAPTOP-HR-07", threat_name: "Cobalt Strike Beacon", tactic: "C2", detection_time: "2026-04-16 07:33", status: "Investigating", severity: "CRITICAL" },
  { id: "t4", hostname: "SERVER-APP-03", threat_name: "RDP Brute Force", tactic: "Initial Access", detection_time: "2026-04-15 23:12", status: "Contained", severity: "MEDIUM" },
  { id: "t5", hostname: "WORKSTATION-118", threat_name: "Suspicious Registry Mod", tactic: "Persistence", detection_time: "2026-04-15 21:44", status: "Investigating", severity: "HIGH" },
];

const MOCK_ENDPOINTS: EndpointRow[] = [
  { id: "e1",  hostname: "SERVER-DB-01",     os: "Windows Server 2022", last_seen: "1 min ago",  agent_version: "7.14.2", threat_score: 8.2, patch_status: "Critical patch missing", issues_count: 3 },
  { id: "e2",  hostname: "WORKSTATION-042",  os: "Windows 11",          last_seen: "2 min ago",  agent_version: "7.14.2", threat_score: 9.1, patch_status: "Critical patch missing", issues_count: 5 },
  { id: "e3",  hostname: "SERVER-APP-03",    os: "Ubuntu 22.04",        last_seen: "3 min ago",  agent_version: "7.14.1", threat_score: 4.1, patch_status: "Up to date",              issues_count: 1 },
  { id: "e4",  hostname: "LAPTOP-HR-07",     os: "macOS 14.4",          last_seen: "5 min ago",  agent_version: "7.14.2", threat_score: 7.8, patch_status: "Needs patch",             issues_count: 2 },
  { id: "e5",  hostname: "WORKSTATION-118",  os: "Windows 10",          last_seen: "8 min ago",  agent_version: "7.13.9", threat_score: 6.3, patch_status: "Needs patch",             issues_count: 2 },
  { id: "e6",  hostname: "SERVER-AUTH-01",   os: "Ubuntu 20.04",        last_seen: "12 min ago", agent_version: "7.14.2", threat_score: 1.2, patch_status: "Up to date",              issues_count: 0 },
  { id: "e7",  hostname: "BUILD-AGENT-02",   os: "Ubuntu 22.04",        last_seen: "15 min ago", agent_version: "7.14.2", threat_score: 0.8, patch_status: "Up to date",              issues_count: 0 },
  { id: "e8",  hostname: "MACBOOK-DEV-03",   os: "macOS 15.2",          last_seen: "18 min ago", agent_version: "7.14.0", threat_score: 2.4, patch_status: "Needs patch",             issues_count: 1 },
  { id: "e9",  hostname: "WORKSTATION-055",  os: "Windows 11",          last_seen: "22 min ago", agent_version: "7.14.2", threat_score: 1.9, patch_status: "Up to date",              issues_count: 0 },
  { id: "e10", hostname: "SERVER-MAIL-01",   os: "Windows Server 2019", last_seen: "31 min ago", agent_version: "7.13.8", threat_score: 5.7, patch_status: "Critical patch missing", issues_count: 4 },
  { id: "e11", hostname: "LAPTOP-FIN-11",    os: "Windows 11",          last_seen: "45 min ago", agent_version: "7.14.1", threat_score: 3.1, patch_status: "Up to date",              issues_count: 0 },
  { id: "e12", hostname: "WORKSTATION-201",  os: "Windows 10",          last_seen: "1 hr ago",   agent_version: "7.13.9", threat_score: 4.6, patch_status: "Needs patch",             issues_count: 1 },
  { id: "e13", hostname: "BUILD-AGENT-04",   os: "Ubuntu 22.04",        last_seen: "1 hr ago",   agent_version: "7.14.2", threat_score: 0.5, patch_status: "Up to date",              issues_count: 0 },
  { id: "e14", hostname: "MACBOOK-EXEC-01",  os: "macOS 15.1",          last_seen: "2 hr ago",   agent_version: "7.14.2", threat_score: 1.1, patch_status: "Up to date",              issues_count: 0 },
  { id: "e15", hostname: "SERVER-BACKUP-01", os: "Ubuntu 20.04",        last_seen: "3 hr ago",   agent_version: "7.14.0", threat_score: 2.9, patch_status: "Needs patch",             issues_count: 1 },
];

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

function severityBadge(s: Severity) {
  const cls = {
    CRITICAL: "bg-red-500/20 text-red-400 border-red-500/40",
    HIGH:     "bg-orange-500/20 text-orange-400 border-orange-500/40",
    MEDIUM:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/40",
    LOW:      "bg-green-500/20 text-green-400 border-green-500/40",
  }[s];
  return <Badge variant="outline" className={cn("text-xs font-semibold", cls)}>{s}</Badge>;
}

function statusBadge(s: ThreatStatus) {
  const cfg = {
    Active:       { cls: "bg-red-500/20 text-red-400 border-red-500/40",    icon: <XCircle className="h-3 w-3 mr-1" /> },
    Contained:    { cls: "bg-green-500/20 text-green-400 border-green-500/40", icon: <CheckCircle2 className="h-3 w-3 mr-1" /> },
    Investigating:{ cls: "bg-yellow-500/20 text-yellow-400 border-yellow-500/40", icon: <Clock className="h-3 w-3 mr-1" /> },
  }[s];
  return (
    <Badge variant="outline" className={cn("text-xs font-semibold flex items-center w-fit", cfg.cls)}>
      {cfg.icon}{s}
    </Badge>
  );
}

function patchBadge(p: PatchStatus) {
  const cls = {
    "Up to date":             "bg-green-500/20 text-green-400 border-green-500/40",
    "Needs patch":            "bg-yellow-500/20 text-yellow-400 border-yellow-500/40",
    "Critical patch missing": "bg-red-500/20 text-red-400 border-red-500/40",
  }[p];
  return <Badge variant="outline" className={cn("text-xs", cls)}>{p}</Badge>;
}

function ThreatScoreBar({ score }: { score: number }) {
  const color = score >= 8 ? "bg-red-500" : score >= 5 ? "bg-orange-400" : score >= 3 ? "bg-yellow-400" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 rounded-full bg-white/10 overflow-hidden">
        <div className={cn("h-full rounded-full", color)} style={{ width: `${score * 10}%` }} />
      </div>
      <span className={cn("text-xs font-mono font-semibold", score >= 8 ? "text-red-400" : score >= 5 ? "text-orange-400" : "text-slate-300")}>
        {score.toFixed(1)}
      </span>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Main Component
// ═══════════════════════════════════════════════════════════

export default function EndpointSecurity() {
  const { data: endpointsData, isLoading: epLoading } = useQuery({
    queryKey: ["endpoints"],
    queryFn: async () => {
      const r = await fetch(`${API}/api/v1/endpoints?org_id=default`);
      if (!r.ok) throw new Error("unavailable");
      return r.json();
    },
    retry: 0,
  });

  const { data: threatsData, isLoading: thLoading } = useQuery({
    queryKey: ["endpoints-threats"],
    queryFn: async () => {
      const r = await fetch(`${API}/api/v1/endpoints/threats?org_id=default`);
      if (!r.ok) throw new Error("unavailable");
      return r.json();
    },
    retry: 0,
  });

  const threats: ThreatDetection[] = threatsData?.threats ?? MOCK_THREATS;
  const endpoints: EndpointRow[]   = endpointsData?.endpoints ?? MOCK_ENDPOINTS;
  const isLoading = epLoading || thLoading;

  const policies = [
    { label: "Disk Encryption",  pct: 89, color: "bg-blue-500" },
    { label: "Firewall Active",  pct: 97, color: "bg-green-500" },
    { label: "Auto-Update",      pct: 76, color: "bg-yellow-500" },
    { label: "Screen Lock",      pct: 91, color: "bg-purple-500" },
  ];

  const coverage = [
    { os: "Windows", count: 1892, covered: 96, color: "bg-blue-500" },
    { os: "macOS",   count: 647,  covered: 91, color: "bg-slate-400" },
    { os: "Linux",   count: 308,  covered: 99, color: "bg-orange-400" },
    { os: "Mobile",  count: 0,    covered: 0,  color: "bg-slate-600" },
  ];

  return (
    <div className="flex flex-col gap-6 p-6 min-h-screen bg-slate-950 text-slate-100">
      <PageHeader
        title="Endpoint Security"
        description="EDR coverage, threat detections, and endpoint health monitoring"
        icon={<Monitor className="h-6 w-6 text-blue-400" />}
      />

      {/* Unmanaged endpoints alert */}
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center gap-3 rounded-lg border border-red-500/50 bg-red-500/10 px-4 py-3"
      >
        <WifiOff className="h-5 w-5 text-red-400 shrink-0" />
        <p className="text-sm font-medium text-red-300">
          <span className="font-bold text-red-400">47 unmanaged endpoints detected on network.</span>{" "}
          These have no EDR coverage.
        </p>
      </motion.div>

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <KpiCard title="Managed Endpoints" value="2,847" icon={<Monitor className="h-4 w-4" />} trend="up" trendValue="+12 this week" />
        <KpiCard title="EDR Coverage"      value="94%"   icon={<Shield className="h-4 w-4" />}  trend="up" trendValue="+2% vs last month" />
        <KpiCard title="Active Threats"    value="3"     icon={<AlertTriangle className="h-4 w-4" />} trend="down" trendValue="Was 7 yesterday" className="border-red-500/30" />
        <KpiCard title="Unpatched Critical" value="47"   icon={<Activity className="h-4 w-4" />} trend="down" trendValue="Down from 61" />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Coverage breakdown */}
        <Card className="border-white/10 bg-slate-900/60">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold text-slate-300 flex items-center gap-2">
              <Wifi className="h-4 w-4 text-blue-400" /> Coverage by OS
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {coverage.map((c) => (
              <div key={c.os} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-300 font-medium">{c.os}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-slate-500">{c.count.toLocaleString()} endpoints</span>
                    <Badge variant="outline" className={cn("text-xs", c.covered >= 95 ? "border-green-500/40 text-green-400" : c.covered >= 80 ? "border-yellow-500/40 text-yellow-400" : "border-red-500/40 text-red-400")}>
                      {c.covered}%
                    </Badge>
                  </div>
                </div>
                <div className="h-1.5 w-full rounded-full bg-white/10 overflow-hidden">
                  <div className={cn("h-full rounded-full", c.color)} style={{ width: `${c.covered}%` }} />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Policy compliance */}
        <Card className="border-white/10 bg-slate-900/60">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold text-slate-300 flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-green-400" /> Policy Compliance
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {policies.map((p) => (
              <div key={p.label} className="space-y-1">
                <div className="flex justify-between text-xs">
                  <span className="text-slate-300">{p.label}</span>
                  <span className={cn("font-semibold", p.pct >= 95 ? "text-green-400" : p.pct >= 80 ? "text-yellow-400" : "text-red-400")}>{p.pct}%</span>
                </div>
                <Progress value={p.pct} className="h-1.5" />
              </div>
            ))}
          </CardContent>
        </Card>

        {/* EDR vendor status */}
        <Card className="border-white/10 bg-slate-900/60">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold text-slate-300 flex items-center gap-2">
              <Shield className="h-4 w-4 text-blue-400" /> EDR Vendor
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-3 rounded-lg border border-green-500/30 bg-green-500/10 px-4 py-3">
              <CheckCircle2 className="h-5 w-5 text-green-400 shrink-0" />
              <div>
                <p className="text-sm font-semibold text-green-300">CrowdStrike Falcon</p>
                <p className="text-xs text-slate-500">Connected</p>
              </div>
            </div>
            <div className="space-y-2 text-xs text-slate-400">
              <div className="flex justify-between">
                <span>Last sync</span>
                <span className="text-slate-200 font-mono">2026-04-16 09:21</span>
              </div>
              <div className="flex justify-between">
                <span>Sensor version</span>
                <span className="text-slate-200 font-mono">7.14.2</span>
              </div>
              <div className="flex justify-between">
                <span>Policy mode</span>
                <span className="text-green-400 font-semibold">Prevent</span>
              </div>
              <div className="flex justify-between">
                <span>Endpoints reporting</span>
                <span className="text-slate-200">2,847 / 2,894</span>
              </div>
            </div>
            <Button size="sm" variant="outline" className="w-full text-xs gap-1.5">
              <RefreshCw className="h-3 w-3" /> Force Sync
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Active threat detections */}
      <Card className="border-white/10 bg-slate-900/60">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold text-slate-300 flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-red-400" /> Active Threat Detections
            {isLoading && <RefreshCw className="h-3 w-3 animate-spin text-slate-500 ml-1" />}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="border-white/10 hover:bg-transparent">
                <TableHead className="text-xs text-slate-500 font-semibold pl-6">Hostname</TableHead>
                <TableHead className="text-xs text-slate-500 font-semibold">Threat</TableHead>
                <TableHead className="text-xs text-slate-500 font-semibold">MITRE Tactic</TableHead>
                <TableHead className="text-xs text-slate-500 font-semibold">Detected</TableHead>
                <TableHead className="text-xs text-slate-500 font-semibold">Status</TableHead>
                <TableHead className="text-xs text-slate-500 font-semibold">Severity</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {threats.map((t) => (
                <TableRow key={t.id} className="border-white/5 hover:bg-white/5">
                  <TableCell className="pl-6 font-mono text-xs text-slate-200">{t.hostname}</TableCell>
                  <TableCell className="text-xs font-semibold text-slate-100">{t.threat_name}</TableCell>
                  <TableCell className="text-xs text-slate-400">{t.tactic}</TableCell>
                  <TableCell className="text-xs text-slate-400 font-mono">{t.detection_time}</TableCell>
                  <TableCell>{statusBadge(t.status)}</TableCell>
                  <TableCell>{severityBadge(t.severity)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Endpoint health */}
      <Card className="border-white/10 bg-slate-900/60">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold text-slate-300 flex items-center gap-2">
            <Activity className="h-4 w-4 text-blue-400" /> Endpoint Health
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="border-white/10 hover:bg-transparent">
                <TableHead className="text-xs text-slate-500 font-semibold pl-6">Hostname</TableHead>
                <TableHead className="text-xs text-slate-500 font-semibold">OS</TableHead>
                <TableHead className="text-xs text-slate-500 font-semibold">Last Seen</TableHead>
                <TableHead className="text-xs text-slate-500 font-semibold">Agent</TableHead>
                <TableHead className="text-xs text-slate-500 font-semibold">Threat Score</TableHead>
                <TableHead className="text-xs text-slate-500 font-semibold">Patch Status</TableHead>
                <TableHead className="text-xs text-slate-500 font-semibold text-right pr-6">Issues</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {endpoints.map((ep) => (
                <TableRow key={ep.id} className="border-white/5 hover:bg-white/5">
                  <TableCell className="pl-6 font-mono text-xs text-slate-200">{ep.hostname}</TableCell>
                  <TableCell className="text-xs text-slate-400">{ep.os}</TableCell>
                  <TableCell className="text-xs text-slate-400">{ep.last_seen}</TableCell>
                  <TableCell className="text-xs font-mono text-slate-400">{ep.agent_version}</TableCell>
                  <TableCell><ThreatScoreBar score={ep.threat_score} /></TableCell>
                  <TableCell>{patchBadge(ep.patch_status)}</TableCell>
                  <TableCell className="text-right pr-6">
                    <span className={cn("text-xs font-semibold", ep.issues_count > 3 ? "text-red-400" : ep.issues_count > 0 ? "text-yellow-400" : "text-green-400")}>
                      {ep.issues_count}
                    </span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
