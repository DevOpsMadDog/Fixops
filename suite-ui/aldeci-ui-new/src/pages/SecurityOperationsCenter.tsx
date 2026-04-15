/**
 * Security Operations Center
 *
 * 24/7 monitoring, triage and response dashboard.
 *   1. KPIs: Open Alerts, Critical, In Triage, MTTD, MTTR, SLA Met
 *   2. Live alert queue (15 rows)
 *   3. Analyst workload cards (6 analysts)
 *   4. Alert source breakdown (8 sources, count bars)
 *   5. Shift handoff panel (3 critical items)
 *
 * API stubs: GET /api/v1/soc/alerts, /api/v1/soc/analysts, /api/v1/soc/sources
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, Users, Activity, Clock, RefreshCw, ArrowRightLeft, Zap } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ───────────────────────────────────────────────────

const ALERTS = [
  { id: "ALT-8821", priority: "P1", type: "Ransomware C2 Beacon",          source: "EDR",   asset: "WIN-PROD-04",    analyst: "J. Rivera",   open: "0h 12m", status: "investigating" },
  { id: "ALT-8822", priority: "P1", type: "Lateral Movement Detected",      source: "NDR",   asset: "10.0.1.45",      analyst: "A. Patel",    open: "0h 31m", status: "investigating" },
  { id: "ALT-8823", priority: "P1", type: "Privilege Escalation — root",    source: "SIEM",  asset: "linux-api-02",   analyst: "T. Chen",     open: "1h 05m", status: "acknowledged" },
  { id: "ALT-8824", priority: "P2", type: "Brute Force — SSH (500+ tries)", source: "SIEM",  asset: "bastion-01",     analyst: "M. Kim",      open: "1h 22m", status: "acknowledged" },
  { id: "ALT-8825", priority: "P2", type: "Data Exfil — 8GB outbound",      source: "NDR",   asset: "192.168.2.110",  analyst: "J. Rivera",   open: "2h 10m", status: "investigating" },
  { id: "ALT-8826", priority: "P2", type: "Malicious PowerShell Exec",      source: "EDR",   asset: "WIN-DEV-12",     analyst: "Unassigned",  open: "2h 45m", status: "new" },
  { id: "ALT-8827", priority: "P2", type: "WAF — SQLi Burst (1k reqs)",     source: "WAF",   asset: "api.aldeci.io",  analyst: "A. Patel",    open: "3h 01m", status: "acknowledged" },
  { id: "ALT-8828", priority: "P3", type: "Suspicious Login — New Country", source: "IAM",   asset: "ceo@aldeci.io",  analyst: "S. Okafor",   open: "3h 18m", status: "investigating" },
  { id: "ALT-8829", priority: "P3", type: "CSPM — Public RDS Instance",     source: "CSPM",  asset: "rds-prod-main",  analyst: "T. Chen",     open: "4h 02m", status: "acknowledged" },
  { id: "ALT-8830", priority: "P3", type: "Phishing Email Cluster (23)",    source: "Email", asset: "Exchange",       analyst: "M. Kim",      open: "4h 55m", status: "acknowledged" },
  { id: "ALT-8831", priority: "P3", type: "CVE-2025-1234 Exploit Attempt",  source: "WAF",   asset: "web-prod-01",    analyst: "Unassigned",  open: "5h 10m", status: "new" },
  { id: "ALT-8832", priority: "P3", type: "Anomalous API Key Usage",        source: "IAM",   asset: "svc-data-export",analyst: "S. Okafor",   open: "5h 40m", status: "investigating" },
  { id: "ALT-8833", priority: "P4", type: "Port Scan from Internal Host",   source: "NDR",   asset: "10.0.3.22",      analyst: "Unassigned",  open: "6h 15m", status: "new" },
  { id: "ALT-8834", priority: "P4", type: "Failed MFA — Admin Account",     source: "IAM",   asset: "admin@aldeci.io",analyst: "Unassigned",  open: "7h 00m", status: "new" },
  { id: "ALT-8835", priority: "P4", type: "Log Forwarding Gap — 15min",     source: "SIEM",  asset: "dc-01",          analyst: "T. Chen",     open: "8h 22m", status: "resolved" },
];

const ANALYSTS = [
  { name: "J. Rivera", open: 12, closedToday: 8,  avgResponse: "18m", status: "online" },
  { name: "A. Patel",  open: 9,  closedToday: 11, avgResponse: "22m", status: "online" },
  { name: "T. Chen",   open: 15, closedToday: 6,  avgResponse: "31m", status: "online" },
  { name: "M. Kim",    open: 7,  closedToday: 14, avgResponse: "15m", status: "away"   },
  { name: "S. Okafor", open: 10, closedToday: 9,  avgResponse: "27m", status: "online" },
  { name: "R. Hassan", open: 0,  closedToday: 3,  avgResponse: "—",   status: "offline" },
];

const SOURCES = [
  { name: "SIEM",   count: 87  },
  { name: "EDR",    count: 64  },
  { name: "NDR",    count: 41  },
  { name: "CSPM",   count: 28  },
  { name: "WAF",    count: 23  },
  { name: "Email",  count: 18  },
  { name: "IAM",    count: 15  },
  { name: "Manual", count: 8   },
];

const HANDOFF_ITEMS = [
  { priority: "P1", note: "ALT-8821: Ransomware beacon on WIN-PROD-04 — containment in progress, do NOT reimage yet, forensics pending." },
  { priority: "P1", note: "ALT-8822: Lateral movement from 10.0.1.45 traced to compromised svc account 'svc-jenkins'. Password reset initiated." },
  { priority: "P2", note: "ALT-8825: 8GB exfil to 185.220.x.x (known TOR exit). Blocking rule deployed on perimeter — confirm no re-egress at 06:00." },
];

const SOURCE_MAX = Math.max(...SOURCES.map(s => s.count));

// ── Helpers ────────────────────────────────────────────────────

function PriorityBadge({ p }: { p: string }) {
  const map: Record<string, string> = {
    P1: "border-red-500/50 text-red-400 bg-red-500/15 font-bold",
    P2: "border-orange-500/50 text-orange-400 bg-orange-500/15",
    P3: "border-yellow-500/50 text-yellow-400 bg-yellow-500/10",
    P4: "border-border text-muted-foreground",
  };
  return <Badge className={cn("text-[10px] border", map[p] ?? "")}>{p}</Badge>;
}

function AlertStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    new:           "border-blue-500/30 text-blue-400 bg-blue-500/10",
    acknowledged:  "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    investigating: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    resolved:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[status] ?? "")}>{status}</Badge>;
}

function StatusDot({ status }: { status: string }) {
  const map: Record<string, string> = {
    online:  "bg-green-500",
    away:    "bg-yellow-500",
    offline: "bg-muted-foreground",
  };
  return <span className={cn("inline-block w-2 h-2 rounded-full", map[status] ?? "bg-muted-foreground")} />;
}

// ── Component ──────────────────────────────────────────────────

export default function SecurityOperationsCenter() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/soar/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/soar/executions?org_id=${ORG_ID}&limit=20`),
    ]).then(([soarStatsResult, soarExecutionsResult]) => {
      const soarStats      = soarStatsResult.status      === "fulfilled" ? soarStatsResult.value      : null;
      const soarExecutions = soarExecutionsResult.status === "fulfilled" ? soarExecutionsResult.value : null;
      if (soarStats || soarExecutions) {
        setLiveData({ soarStats, soarCases: soarExecutions, insiderStats: null });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  const liveOpenAlerts  = liveData?.soarStats?.open_alerts   ?? liveData?.soarStats?.total_alerts  ?? liveData?.insiderStats?.total_alerts  ?? 234;
  const liveCritical    = liveData?.soarStats?.critical       ?? liveData?.soarStats?.critical_alerts ?? liveData?.insiderStats?.high_risk   ?? 18;
  const liveInTriage    = liveData?.soarStats?.in_triage      ?? liveData?.soarStats?.pending        ?? 47;
  const liveMttd        = liveData?.soarStats?.mttd           ?? liveData?.insiderStats?.avg_mttd    ?? "4.2h";
  const liveMttr        = liveData?.soarStats?.mttr           ?? liveData?.insiderStats?.avg_mttr    ?? "6.8h";
  const liveSla         = liveData?.soarStats?.sla_met        ?? liveData?.soarStats?.sla_compliance ?? "94.3%";

  const liveAlerts: typeof ALERTS =
    Array.isArray(liveData?.soarCases)
      ? liveData.soarCases.slice(0, 15).map((c: any) => ({
          id: c.case_id ?? c.id ?? "ALT-????",
          priority: c.priority ?? c.severity ?? "P3",
          type: c.title ?? c.type ?? c.name ?? "Unknown alert",
          source: c.source ?? c.detection_source ?? "SIEM",
          asset: c.asset ?? c.target ?? "—",
          analyst: c.assigned_to ?? c.analyst ?? "Unassigned",
          open: c.age ?? c.open_duration ?? "—",
          status: c.status ?? "new",
        }))
      : Array.isArray(liveData?.soarCases?.items)
        ? liveData.soarCases.items.slice(0, 15).map((c: any) => ({
            id: c.case_id ?? c.id ?? "ALT-????",
            priority: c.priority ?? "P3",
            type: c.title ?? "Unknown alert",
            source: c.source ?? "SIEM",
            asset: c.asset ?? "—",
            analyst: c.assigned_to ?? "Unassigned",
            open: c.age ?? "—",
            status: c.status ?? "new",
          }))
        : ALERTS;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Security Operations Center"
        description="24/7 monitoring, triage and response"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs — 2 rows of 3 */}
      <div className="grid grid-cols-3 gap-3 lg:grid-cols-6">
        <KpiCard title="Open Alerts"  value={liveOpenAlerts} icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="Critical"     value={liveCritical}   icon={Zap}           trend="up"   className="border-red-500/20" />
        <KpiCard title="In Triage"    value={liveInTriage}   icon={Activity}      trend="up"   className="border-amber-500/20" />
        <KpiCard title="MTTD"         value={liveMttd}       icon={Clock}         trend="down" />
        <KpiCard title="MTTR"         value={liveMttr}       icon={Clock}         trend="down" />
        <KpiCard title="SLA Met"      value={liveSla}        icon={Users}         trend="up"   className="border-green-500/20" />
      </div>

      {/* Live Alert Queue */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-red-400" />
              Live Alert Queue
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10 animate-pulse">
              LIVE
            </Badge>
          </div>
          <CardDescription className="text-xs">Real-time alert triage queue sorted by priority and age</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Priority</TableHead>
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Alert Type</TableHead>
                  <TableHead className="text-[11px] h-8">Source</TableHead>
                  <TableHead className="text-[11px] h-8">Asset</TableHead>
                  <TableHead className="text-[11px] h-8">Analyst</TableHead>
                  <TableHead className="text-[11px] h-8">Open</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {liveAlerts.map((row) => (
                  <TableRow
                    key={row.id}
                    className={cn(
                      "hover:bg-muted/30",
                      row.priority === "P1" && "bg-red-500/5 border-l-2 border-l-red-500"
                    )}
                  >
                    <TableCell className="py-2"><PriorityBadge p={row.priority} /></TableCell>
                    <TableCell className="text-xs font-mono py-2">{row.id}</TableCell>
                    <TableCell className="text-xs py-2 max-w-[200px] truncate">{row.type}</TableCell>
                    <TableCell className="py-2">
                      <Badge className="text-[10px] border border-border text-muted-foreground">{row.source}</Badge>
                    </TableCell>
                    <TableCell className="text-xs py-2 font-mono text-muted-foreground">{row.asset}</TableCell>
                    <TableCell className={cn(
                      "text-xs py-2",
                      row.analyst === "Unassigned" ? "text-muted-foreground italic" : ""
                    )}>
                      {row.analyst}
                    </TableCell>
                    <TableCell className="text-xs py-2 tabular-nums text-muted-foreground">{row.open}</TableCell>
                    <TableCell className="py-2"><AlertStatusBadge status={row.status} /></TableCell>
                    <TableCell className="py-2 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">Assign</Button>
                        <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] border-green-500/30 text-green-400 hover:bg-green-500/10">Resolve</Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Analyst Workload + Source Breakdown */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Analyst Workload */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Users className="h-4 w-4 text-indigo-400" />
              Analyst Workload
            </CardTitle>
            <CardDescription className="text-xs">Current shift — open tickets, closed today, avg response time</CardDescription>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-3">
            {ANALYSTS.map((a) => (
              <div
                key={a.name}
                className="rounded-lg border border-border bg-muted/10 p-3 flex flex-col gap-2"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold">{a.name}</span>
                  <StatusDot status={a.status} />
                </div>
                <div className="grid grid-cols-3 gap-1 text-center">
                  <div>
                    <div className="text-base font-bold tabular-nums text-amber-400">{a.open}</div>
                    <div className="text-[9px] text-muted-foreground">Open</div>
                  </div>
                  <div>
                    <div className="text-base font-bold tabular-nums text-green-400">{a.closedToday}</div>
                    <div className="text-[9px] text-muted-foreground">Closed</div>
                  </div>
                  <div>
                    <div className="text-base font-bold tabular-nums text-blue-400">{a.avgResponse}</div>
                    <div className="text-[9px] text-muted-foreground">Avg Resp</div>
                  </div>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Alert Source Breakdown */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan-400" />
              Alert Source Breakdown
            </CardTitle>
            <CardDescription className="text-xs">Alert volume by detection source — last 24 hours</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {SOURCES.map((src) => (
              <div key={src.name} className="flex items-center gap-3">
                <span className="text-xs font-medium w-12 shrink-0">{src.name}</span>
                <div className="flex-1 h-4 rounded bg-muted/30 overflow-hidden relative">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${(src.count / SOURCE_MAX) * 100}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className="h-full rounded bg-blue-500/60"
                  />
                </div>
                <span className="text-xs tabular-nums font-bold w-8 text-right">{src.count}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Shift Handoff Panel */}
      <Card className="border-amber-500/20">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
            <ArrowRightLeft className="h-4 w-4" />
            Shift Handoff — Critical Items
          </CardTitle>
          <CardDescription className="text-xs">Items flagged for incoming shift — requires immediate attention</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {HANDOFF_ITEMS.map((item, idx) => (
            <div
              key={idx}
              className="flex items-start gap-3 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3"
            >
              <PriorityBadge p={item.priority} />
              <p className="text-xs text-muted-foreground leading-relaxed">{item.note}</p>
            </div>
          ))}
        </CardContent>
      </Card>
    </motion.div>
  );
}
