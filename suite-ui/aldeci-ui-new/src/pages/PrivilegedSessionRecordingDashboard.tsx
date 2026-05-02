// FOLDED into PrivilegedAccessHub (sessions tab) 2026-05-02 — preserve for git history
/**
 * Privileged Session Recording Dashboard
 * Route: /session-recording
 * API: GET /api/v1/session-recording/sessions
 *      GET /api/v1/session-recording/stats
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
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

interface SessionRecord {
  id?: string;
  account_name?: string;
  session_type?: string;
  target_system?: string;
  status?: string;
  duration_minutes?: number;
  alerts_count?: number;
}

interface SessionStats {
  total_sessions?: number;
  active_sessions?: number;
  high_risk_sessions?: number;
  total_alerts?: number;
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    recording: "border-green-500/30 text-green-400 bg-green-500/10",
    completed: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    failed:    "border-red-500/30 text-red-400 bg-red-500/10",
    archived:  "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>{status}</Badge>
  );
}

function exportCsv(rows: SessionRecord[]) {
  const headers: (keyof SessionRecord)[] = ["account_name", "session_type", "target_system", "status", "duration_minutes", "alerts_count"];
  const lines = [headers.join(","), ...rows.map(r => headers.map(h => `"${r[h] ?? ""}"`).join(","))];
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = "session_recordings.csv"; a.click();
  URL.revokeObjectURL(url);
}

export default function PrivilegedSessionRecordingDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [stats, setStats] = useState<SessionStats>({});
  const [error, setError] = useState<string | null>(null);

  function load() {
    setLoading(true);
    setError(null);
    Promise.allSettled([
      apiFetch("/api/v1/session-recording/sessions?org_id=default"),
      apiFetch("/api/v1/session-recording/stats?org_id=default"),
    ]).then(([sesRes, statsRes]) => {
      if (sesRes.status === "fulfilled") {
        const val = sesRes.value;
        setSessions(val?.sessions ?? val?.items ?? (Array.isArray(val) ? val : []));
      } else {
        setError("Session recording API unavailable");
      }
      if (statsRes.status === "fulfilled") setStats(statsRes.value ?? {});
      setLoading(false);
    });
  }

  useEffect(() => { load(); }, []);

  const handleRefresh = () => { setRefreshing(true); load(); setTimeout(() => setRefreshing(false), 800); };

  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-500" /></div>;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Privileged Session Recording"
        description="Real-time privileged access session recording — monitor active sessions, alerts, and high-risk activity"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Sessions"     value={stats.total_sessions ?? 0}     icon={Video}         trend="flat" className="border-purple-500/20" />
        <KpiCard title="Active Sessions"    value={stats.active_sessions ?? 0}    icon={Activity}      trend="flat" className="border-violet-500/20" />
        <KpiCard title="High-Risk Sessions" value={stats.high_risk_sessions ?? 0} icon={ShieldAlert}   trend="down" className="border-purple-500/20" />
        <KpiCard title="Total Alerts"       value={stats.total_alerts ?? 0}       icon={AlertTriangle} trend="down" className="border-violet-500/20" />
      </div>
      <Card className="border-purple-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-purple-400">
              <BarChart2 className="h-4 w-4" />Session Recording Log
            </CardTitle>
            <div className="flex items-center gap-2">
              <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">
                {sessions.filter((s) => s.status === "recording").length} live
              </Badge>
              {sessions.length > 0 && (
                <Button variant="outline" size="sm" className="text-[11px] h-7" onClick={() => exportCsv(sessions)}>Export CSV</Button>
              )}
            </div>
          </div>
          <CardDescription className="text-xs">Privileged sessions with account, target system, type, status, duration, and alert count</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {error || sessions.length === 0 ? (
            <EmptyState icon={Video} title={error ?? "No sessions recorded"} description="Privileged session recordings will appear here once PAM monitoring is active." />
          ) : (
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
                  {sessions.map((ses, i) => (
                    <TableRow key={ses.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 font-semibold text-[11px] text-purple-300 max-w-[160px] truncate">{ses.account_name ?? "—"}</TableCell>
                      <TableCell className="py-2 font-mono text-[11px] text-violet-300">{ses.session_type ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{ses.target_system ?? "—"}</TableCell>
                      <TableCell className="py-2"><StatusBadge status={ses.status ?? "completed"} /></TableCell>
                      <TableCell className="py-2 font-mono text-[11px] text-violet-300">{ses.duration_minutes ?? 0}</TableCell>
                      <TableCell className="py-2 text-right">
                        <span className={cn("font-mono text-[11px]",
                          (ses.alerts_count ?? 0) > 3 ? "text-red-400" :
                          (ses.alerts_count ?? 0) > 0 ? "text-yellow-400" : "text-muted-foreground")}>
                          {ses.alerts_count ?? 0}
                        </span>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
