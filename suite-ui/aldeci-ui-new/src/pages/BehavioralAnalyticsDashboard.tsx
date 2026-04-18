/**
 * Behavioral Analytics Dashboard
 *
 * User behavior monitoring, anomaly detection, and threat confirmation.
 *   1. KPIs: Users Monitored, Total Anomalies, Open Anomalies, Confirmed Threats
 *   2. Anomalies table (user_id, behavior_type, severity, deviation_score, status, detected_at)
 *
 * Route: /behavioral-analytics
 * API: GET /api/v1/behavioral-analytics
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Brain, RefreshCw, Users, Activity, AlertTriangle, ShieldAlert } from "lucide-react";

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

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_ANOMALIES = [
  { id: "anm-001", user_id: "u.chen@corp",     behavior_type: "impossible_travel",    severity: "critical", deviation_score: 9.8, status: "confirmed_threat", detected_at: "2026-04-16T02:14:00Z" },
  { id: "anm-002", user_id: "r.patel@corp",    behavior_type: "bulk_download",        severity: "high",     deviation_score: 7.4, status: "open",             detected_at: "2026-04-16T06:30:00Z" },
  { id: "anm-003", user_id: "m.kim@corp",      behavior_type: "off_hours_access",     severity: "medium",   deviation_score: 5.1, status: "open",             detected_at: "2026-04-16T03:45:00Z" },
  { id: "anm-004", user_id: "l.nguyen@corp",   behavior_type: "privilege_escalation", severity: "critical", deviation_score: 9.2, status: "confirmed_threat", detected_at: "2026-04-15T22:10:00Z" },
  { id: "anm-005", user_id: "d.smith@corp",    behavior_type: "unusual_geo_login",    severity: "high",     deviation_score: 6.8, status: "investigating",    detected_at: "2026-04-15T18:55:00Z" },
  { id: "anm-006", user_id: "a.jones@corp",    behavior_type: "repeated_auth_failure",severity: "medium",   deviation_score: 4.3, status: "resolved",         detected_at: "2026-04-15T14:20:00Z" },
  { id: "anm-007", user_id: "t.brown@corp",    behavior_type: "data_staging",         severity: "high",     deviation_score: 8.1, status: "open",             detected_at: "2026-04-15T11:05:00Z" },
  { id: "anm-008", user_id: "k.davis@corp",    behavior_type: "lateral_movement",     severity: "critical", deviation_score: 9.5, status: "confirmed_threat", detected_at: "2026-04-15T08:33:00Z" },
  { id: "anm-009", user_id: "p.wilson@corp",   behavior_type: "off_hours_access",     severity: "low",      deviation_score: 2.7, status: "resolved",         detected_at: "2026-04-14T23:50:00Z" },
  { id: "anm-010", user_id: "s.taylor@corp",   behavior_type: "bulk_email_forward",   severity: "high",     deviation_score: 7.9, status: "investigating",    detected_at: "2026-04-14T20:15:00Z" },
];

const MOCK_STATS = { users_monitored: 2847, total_anomalies: 341, open_anomalies: 78, confirmed_threats: 23 };

// ── Badge helpers ──────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border")}>
      {severity}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    confirmed_threat: "border-red-500/30 text-red-400 bg-red-500/10",
    open:             "border-orange-500/30 text-orange-400 bg-orange-500/10",
    investigating:    "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    resolved:         "border-green-500/30 text-green-400 bg-green-500/10",
  };
  const label: Record<string, string> = {
    confirmed_threat: "Confirmed Threat",
    open:             "Open",
    investigating:    "Investigating",
    resolved:         "Resolved",
  };
  return (
    <Badge className={cn("text-[10px] border", map[status] ?? "border-border")}>
      {label[status] ?? status}
    </Badge>
  );
}

function formatTs(ts: string) {
  return new Date(ts).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

// ── Component ──────────────────────────────────────────────────

export default function BehavioralAnalyticsDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveAnomalies, setLiveAnomalies] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/behavioral-analytics/anomalies?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/behavioral-analytics/stats?org_id=${ORG_ID}`),
    ]).then(([anomalyRes, statsRes]) => {
      if (anomalyRes.status === "fulfilled") setLiveAnomalies(anomalyRes.value?.anomalies ?? anomalyRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    });
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); 
    setLoading(false);};

  const anomalies = liveAnomalies ?? MOCK_ANOMALIES;
  const stats     = liveStats     ?? MOCK_STATS;

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
        title="Behavioral Analytics"
        description="User and entity behavior analytics (UEBA) with anomaly detection, deviation scoring, and threat confirmation"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Users Monitored"   value={stats.users_monitored}  icon={Users}       trend="up"   className="border-violet-500/20" />
        <KpiCard title="Total Anomalies"   value={stats.total_anomalies}  icon={Activity}    trend="up"   className="border-purple-500/20" />
        <KpiCard title="Open Anomalies"    value={stats.open_anomalies}   icon={AlertTriangle} trend="down" className="border-violet-500/20" />
        <KpiCard title="Confirmed Threats" value={stats.confirmed_threats} icon={ShieldAlert} trend="down" className="border-purple-500/20" />
      </div>

      {/* Anomalies Table */}
      <Card className="border-violet-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-violet-400">
              <Brain className="h-4 w-4" />
              Behavioral Anomalies
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {anomalies.filter((a: any) => a.status === "confirmed_threat").length} confirmed threats
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Detected behavioral anomalies with deviation scores, severity, and investigation status
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">User</TableHead>
                  <TableHead className="text-[11px] h-8">Behavior Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Deviation Score</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Detected At</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {anomalies.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  anomalies.map((anm: any, i: number) => (
                  <TableRow key={anm.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-violet-300">
                      {anm.user_id ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground capitalize">
                      {(anm.behavior_type ?? "—").replace(/_/g, " ")}
                    </TableCell>
                    <TableCell className="py-2">
                      <SeverityBadge severity={anm.severity ?? "low"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-purple-300">
                      {anm.deviation_score?.toFixed(1) ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <StatusBadge status={anm.status ?? "open"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground text-right">
                      {anm.detected_at ? formatTs(anm.detected_at) : "—"}
                    </TableCell>
                  </TableRow>
                ))}
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
