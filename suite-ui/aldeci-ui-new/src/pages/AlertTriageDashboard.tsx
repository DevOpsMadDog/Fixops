/**
 * Alert Triage Dashboard
 *
 * Alert triage queue with priority management and escalation tracking.
 *   1. KPIs: New Alerts, Escalated, False Positive Rate %, Avg Triage Time (min)
 *   2. Alerts table (title, source_system, severity, priority, status, ingested_at)
 *
 * Route: /alert-triage
 * API: GET /api/v1/alert-triage
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Bell, RefreshCw, AlertTriangle, Clock, Filter, BarChart2 } from "lucide-react";

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

const MOCK_ALERTS = [
  { id: "alt-001", title: "Brute Force Login Detected",       source_system: "SIEM",       severity: "critical", priority: "p1", status: "open",        ingested_at: "2026-04-16T09:55:00Z" },
  { id: "alt-002", title: "Malware Signature Match",           source_system: "EDR",        severity: "high",     priority: "p1", status: "escalated",   ingested_at: "2026-04-16T09:48:00Z" },
  { id: "alt-003", title: "Unusual Outbound Traffic",          source_system: "NDR",        severity: "high",     priority: "p2", status: "open",        ingested_at: "2026-04-16T09:42:00Z" },
  { id: "alt-004", title: "Privileged Account Anomaly",        source_system: "IAM",        severity: "high",     priority: "p2", status: "in_progress", ingested_at: "2026-04-16T09:35:00Z" },
  { id: "alt-005", title: "Ransomware Indicator Detected",     source_system: "EDR",        severity: "critical", priority: "p1", status: "escalated",   ingested_at: "2026-04-16T09:30:00Z" },
  { id: "alt-006", title: "Unauthorized API Access",           source_system: "APIGW",      severity: "medium",   priority: "p2", status: "open",        ingested_at: "2026-04-16T09:22:00Z" },
  { id: "alt-007", title: "Port Scan from External IP",        source_system: "Firewall",   severity: "medium",   priority: "p3", status: "false_positive", ingested_at: "2026-04-16T09:15:00Z" },
  { id: "alt-008", title: "Cloud Storage Public Exposure",     source_system: "CSPM",       severity: "high",     priority: "p2", status: "in_progress", ingested_at: "2026-04-16T09:10:00Z" },
  { id: "alt-009", title: "Certificate About to Expire",       source_system: "PKI",        severity: "low",      priority: "p4", status: "open",        ingested_at: "2026-04-16T08:55:00Z" },
  { id: "alt-010", title: "SQL Injection Attempt",             source_system: "WAF",        severity: "high",     priority: "p2", status: "resolved",    ingested_at: "2026-04-16T08:40:00Z" },
];

const MOCK_STATS = {
  new_alerts: 847,
  escalated: 34,
  false_positive_rate: 12.4,
  avg_triage_time: 8.3,
};

// ── Badge helpers ──────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border")}>
      {severity}
    </Badge>
  );
}

function PriorityBadge({ priority }: { priority: string }) {
  const map: Record<string, string> = {
    p1: "border-red-500/50 text-red-300 bg-red-500/15 font-bold",
    p2: "border-orange-500/50 text-orange-300 bg-orange-500/15",
    p3: "border-yellow-500/50 text-yellow-300 bg-yellow-500/15",
    p4: "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border uppercase", map[priority] ?? "border-border")}>
      {priority}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:           "border-blue-500/30 text-blue-400 bg-blue-500/10",
    in_progress:    "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    escalated:      "border-red-500/30 text-red-400 bg-red-500/10",
    resolved:       "border-green-500/30 text-green-400 bg-green-500/10",
    false_positive: "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
  };
  const label = status.replace(/_/g, " ");
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>
      {label}
    </Badge>
  );
}

function formatTs(ts: string) {
  return new Date(ts).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

// ── Component ──────────────────────────────────────────────────

export default function AlertTriageDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveAlerts, setLiveAlerts] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/alert-triage/alerts?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/alert-triage/stats?org_id=${ORG_ID}`),
    ]).then(([alertsRes, statsRes]) => {
      if (alertsRes.status === "fulfilled") setLiveAlerts(alertsRes.value?.alerts ?? alertsRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const alerts = liveAlerts ?? MOCK_ALERTS;
  const stats  = liveStats  ?? MOCK_STATS;

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
        title="Alert Triage"
        description="Security alert queue with priority classification, escalation tracking, and false positive management"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="New Alerts"          value={stats.new_alerts}                              icon={Bell}          trend="up"   className="border-red-500/20" />
        <KpiCard title="Escalated"           value={stats.escalated}                               icon={AlertTriangle} trend="up"   className="border-orange-500/20" />
        <KpiCard title="False Positive Rate" value={`${stats.false_positive_rate}%`}               icon={Filter}        trend="down" className="border-red-500/20" />
        <KpiCard title="Avg Triage Time"     value={`${stats.avg_triage_time} min`}                icon={Clock}         trend="down" className="border-orange-500/20" />
      </div>

      {/* Alerts Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <BarChart2 className="h-4 w-4" />
              Alert Queue
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {alerts.filter((a: any) => a.priority === "p1").length} P1 active
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Incoming security alerts sorted by priority with source system, severity, and triage status
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Alert Title</TableHead>
                  <TableHead className="text-[11px] h-8">Source</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Priority</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Ingested</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {alerts.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  alerts.map((alert: any, i: number) => (
                  <TableRow key={alert.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-red-300 max-w-[220px] truncate">
                      {alert.title ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground font-mono">
                      {alert.source_system ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <SeverityBadge severity={alert.severity ?? "low"} />
                    </TableCell>
                    <TableCell className="py-2">
                      <PriorityBadge priority={alert.priority ?? "p4"} />
                    </TableCell>
                    <TableCell className="py-2">
                      <StatusBadge status={alert.status ?? "open"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground text-right">
                      {alert.ingested_at ? formatTs(alert.ingested_at) : "—"}
                    </TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
