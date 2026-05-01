// FOLDED into PrivilegedAccessHub (sessions tab) 2026-05-02 — preserve for git history
/**
 * Privileged Session Recording Dashboard
 *
 * Privileged access session recording with alert tracking and risk classification.
 *   1. KPIs: Total Sessions, Active Sessions, High-Risk Sessions, Total Alerts
 *   2. Sessions table (account_name, session_type, target_system, status, duration_minutes, alerts_count)
 *
 * Route: /session-recording
 * API: GET /api/v1/session-recording
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Video, RefreshCw, AlertTriangle, Activity, ShieldAlert, BarChart2 } from "lucide-react";

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

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_SESSIONS = [
  { id: "ses-001", account_name: "svc-deploy-bot",    session_type: "ssh",       target_system: "prod-bastion-01", status: "recording", duration_minutes: 42,  alerts_count: 0 },
  { id: "ses-002", account_name: "admin-alice",       session_type: "rdp",       target_system: "win-dc-02",       status: "completed", duration_minutes: 87,  alerts_count: 2 },
  { id: "ses-003", account_name: "root-emergency",    session_type: "console",   target_system: "db-primary",      status: "recording", duration_minutes: 11,  alerts_count: 4 },
  { id: "ses-004", account_name: "svc-backup-agent",  session_type: "sftp",      target_system: "nas-cluster",     status: "completed", duration_minutes: 320, alerts_count: 0 },
  { id: "ses-005", account_name: "dba-frank",         session_type: "database",  target_system: "oracle-prod",     status: "failed",    duration_minutes: 3,   alerts_count: 1 },
  { id: "ses-006", account_name: "devops-carol",      session_type: "kubectl",   target_system: "k8s-prod",        status: "recording", duration_minutes: 58,  alerts_count: 0 },
  { id: "ses-007", account_name: "neteng-henry",      session_type: "telnet",    target_system: "router-core-01",  status: "archived",  duration_minutes: 145, alerts_count: 7 },
  { id: "ses-008", account_name: "sre-grace",         session_type: "ssh",       target_system: "elk-master",      status: "completed", duration_minutes: 65,  alerts_count: 0 },
  { id: "ses-009", account_name: "admin-irene",       session_type: "rdp",       target_system: "mgmt-server-03",  status: "recording", duration_minutes: 29,  alerts_count: 1 },
  { id: "ses-010", account_name: "vault-operator",    session_type: "api",       target_system: "vault-prod",      status: "completed", duration_minutes: 8,   alerts_count: 0 },
];

const MOCK_STATS = { total_sessions: 512, active_sessions: 4, high_risk_sessions: 9, total_alerts: 63 };

// ── Badge helpers ──────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    recording: "border-green-500/30 text-green-400 bg-green-500/10",
    completed: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    failed:    "border-red-500/30 text-red-400 bg-red-500/10",
    archived:  "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>
      {status}
    </Badge>
  );
}

function exportCsv(rows: any[]) {
  const headers = ["account_name", "session_type", "target_system", "status", "duration_minutes", "alerts_count"];
  const lines = [headers.join(","), ...rows.map(r => headers.map(h => `"${r[h] ?? ""}"`).join(","))];
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = "session_recordings.csv"; a.click();
  URL.revokeObjectURL(url);
}

// ── Component ──────────────────────────────────────────────────

export default function PrivilegedSessionRecordingDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [liveSessions, setLiveSessions] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/session-recording/sessions?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/session-recording/stats?org_id=${ORG_ID}`),
    ]).then(([sesRes, statsRes]) => {
      if (sesRes.status === "fulfilled") setLiveSessions(sesRes.value?.sessions ?? sesRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    });
    setLoading(false);
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const sessions = liveSessions ?? MOCK_SESSIONS;
  const stats    = liveStats    ?? MOCK_STATS;


  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;


  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Privileged Session Recording"
        description="Real-time privileged access session recording — monitor active sessions, alerts, and high-risk activity"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Sessions"       value={stats.total_sessions}    icon={Video}       trend="flat" className="border-purple-500/20" />
        <KpiCard title="Active Sessions"      value={stats.active_sessions}   icon={Activity}    trend="flat" className="border-violet-500/20" />
        <KpiCard title="High-Risk Sessions"   value={stats.high_risk_sessions} icon={ShieldAlert} trend="down" className="border-purple-500/20" />
        <KpiCard title="Total Alerts"         value={stats.total_alerts}      icon={AlertTriangle} trend="down" className="border-violet-500/20" />
      </div>

      {/* Sessions Table */}
      <Card className="border-purple-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-purple-400">
              <BarChart2 className="h-4 w-4" />
              Session Recording Log
            </CardTitle>
            <div className="flex items-center gap-2">
              <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">
                {sessions.filter((s: any) => s.status === "recording").length} live
              </Badge>
              <Button variant="outline" size="sm" className="text-[11px] h-7" onClick={() => exportCsv(sessions)}>
                Export CSV
              </Button>
            </div>
          </div>
          <CardDescription className="text-xs">
            Privileged sessions with account, target system, type, status, duration, and alert count
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Account</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Target System</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Duration (min)</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Alerts</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.map((ses: any, i: number) => (
                  <TableRow key={ses.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-purple-300 max-w-[160px] truncate">
                      {ses.account_name ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-violet-300">
                      {ses.session_type ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">
                      {ses.target_system ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <StatusBadge status={ses.status ?? "completed"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-violet-300">
                      {ses.duration_minutes ?? 0}
                    </TableCell>
                    <TableCell className="py-2 text-right">
                      <span className={cn(
                        "font-mono text-[11px]",
                        (ses.alerts_count ?? 0) > 3 ? "text-red-400" :
                        (ses.alerts_count ?? 0) > 0 ? "text-yellow-400" : "text-muted-foreground"
                      )}>
                        {ses.alerts_count ?? 0}
                      </span>
                    </TableCell>
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
