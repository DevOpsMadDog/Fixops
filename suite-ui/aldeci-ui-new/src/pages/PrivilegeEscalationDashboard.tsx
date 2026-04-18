/**
 * Privilege Escalation Dashboard
 *
 * Route: /privilege-escalation
 * API: GET /api/v1/privilege-escalation/stats, /api/v1/privilege-escalation/events
 *
 * KPIs: Total Events, Anomalies Detected, Blocked Attempts, Alert Rate
 * Table: Recent events = user, from_role = to_role, method, anomaly score, timestamp
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ShieldAlert, TrendingUp, Ban, Activity, RefreshCw, ArrowRight } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "default";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// == Mock data ==================================================

const MOCK_STATS = {
  total_events: 342,
  anomalies: 28,
  blocked_attempts: 15,
};

const MOCK_EVENTS = [
  { id: "EVT-001", user: "j.smith",       from_role: "developer",   to_role: "admin",          method: "sudo",        anomaly_score: 0.91, timestamp: "14:32:05", anomaly: true  },
  { id: "EVT-002", user: "ci-runner",     from_role: "ci-agent",    to_role: "deploy-prod",    method: "iam_assume",  anomaly_score: 0.42, timestamp: "14:28:11", anomaly: false },
  { id: "EVT-003", user: "m.chen",        from_role: "analyst",     to_role: "security_admin", method: "rbac_update", anomaly_score: 0.87, timestamp: "14:15:33", anomaly: true  },
  { id: "EVT-004", user: "svc-scanner",   from_role: "read-only",   to_role: "read-write",     method: "api_key",     anomaly_score: 0.21, timestamp: "14:10:00", anomaly: false },
  { id: "EVT-005", user: "a.kumar",       from_role: "support",     to_role: "root",           method: "cve-exploit", anomaly_score: 0.99, timestamp: "13:58:47", anomaly: true  },
  { id: "EVT-006", user: "deploy-bot",    from_role: "deployer",    to_role: "db-admin",       method: "iam_assume",  anomaly_score: 0.55, timestamp: "13:41:02", anomaly: false },
  { id: "EVT-007", user: "r.johnson",     from_role: "manager",     to_role: "billing-admin",  method: "sudo",        anomaly_score: 0.72, timestamp: "13:30:19", anomaly: true  },
  { id: "EVT-008", user: "infra-agent",   from_role: "infra",       to_role: "network-admin",  method: "api_key",     anomaly_score: 0.33, timestamp: "13:20:55", anomaly: false },
  { id: "EVT-009", user: "s.lee",         from_role: "readonly",    to_role: "admin",          method: "rbac_update", anomaly_score: 0.88, timestamp: "12:55:01", anomaly: true  },
  { id: "EVT-010", user: "backup-runner", from_role: "backup",      to_role: "storage-admin",  method: "iam_assume",  anomaly_score: 0.18, timestamp: "12:30:44", anomaly: false },
];

// == Badge helpers ==============================================

function MethodBadge({ method }: { method: string }) {
  const map: Record<string, string> = {
    sudo:        "border-red-500/30 text-red-400 bg-red-500/10",
    iam_assume:  "border-blue-500/30 text-blue-400 bg-blue-500/10",
    rbac_update: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    api_key:     "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    "cve-exploit":"border-rose-500/30 text-rose-400 bg-rose-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono", map[method] ?? "border-border text-muted-foreground")}>
      {method.replace(/_/g, " ")}
    </Badge>
  );
}

function AnomalyScore({ score, isAnomaly }: { score: number; isAnomaly: boolean }) {
  const cls = score >= 0.85 ? "text-red-400" : score >= 0.6 ? "text-amber-400" : "text-slate-400";
  return (
    <span className={cn("text-xs tabular-nums font-bold", cls)}>
      {score.toFixed(2)}
      {isAnomaly && <span className="ml-1 text-[9px] text-red-400">!</span>}
    </span>
  );
}

// == Component ==================================================

export default function PrivilegeEscalationDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [stats, setStats]           = useState<typeof MOCK_STATS>(MOCK_STATS);
  const [events, setEvents]         = useState<typeof MOCK_EVENTS>(MOCK_EVENTS);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/privilege-escalation/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/privilege-escalation/events?org_id=${ORG_ID}&limit=10`),
    ]).then(([statsRes, eventsRes]) => {
      if (statsRes.status === "fulfilled" && statsRes.value) setStats(statsRes.value);
      if (eventsRes.status === "fulfilled" && eventsRes.value) setEvents(eventsRes.value);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const alertRate = stats.total_events > 0
    ? ((stats.anomalies / stats.total_events) * 100).toFixed(1) + "%"
    : "0%";

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
        title="Privilege Escalation Monitor"
        description="Detect and block unauthorized privilege escalation attempts across users and services"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Events"       value={stats.total_events}      icon={Activity}    trend="up" />
        <KpiCard title="Anomalies Detected" value={stats.anomalies}         icon={ShieldAlert} trend="up" className="border-red-500/20" />
        <KpiCard title="Blocked Attempts"   value={stats.blocked_attempts}  icon={Ban}         trend="neutral" className="border-amber-500/20" />
        <KpiCard title="Alert Rate"         value={alertRate}               icon={TrendingUp}  trend="up" className="border-purple-500/20" />
      </div>

      {/* Events Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <ShieldAlert className="h-4 w-4" />
              Recent Escalation Events
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {events.filter((e: any) => e.anomaly).length} anomalies
            </Badge>
          </div>
          <CardDescription className="text-xs">Last 10 privilege change events with anomaly scores</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">User</TableHead>
                  <TableHead className="text-[11px] h-8">Role Change</TableHead>
                  <TableHead className="text-[11px] h-8">Method</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Anomaly Score</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  events.map((evt: any) => (
                  <TableRow
                    key={evt.id}
                    className={cn("hover:bg-muted/30", evt.anomaly && "bg-red-500/5")}
                  >
                    <TableCell className="py-2 font-mono text-[11px]">{evt.user}</TableCell>
                    <TableCell className="py-2">
                      <span className="flex items-center gap-1 text-[11px] text-muted-foreground font-mono">
                        <span className="text-blue-400">{evt.from_role}</span>
                        <ArrowRight className="h-3 w-3 text-muted-foreground/50 flex-shrink-0" />
                        <span className={evt.anomaly ? "text-red-400" : "text-green-400"}>{evt.to_role}</span>
                      </span>
                    </TableCell>
                    <TableCell className="py-2"><MethodBadge method={evt.method} /></TableCell>
                    <TableCell className="py-2 text-right">
                      <AnomalyScore score={evt.anomaly_score} isAnomaly={evt.anomaly} />
                    </TableCell>
                    <TableCell className="py-2 text-right font-mono text-[11px] text-muted-foreground">{evt.timestamp}</TableCell>
                  </TableRow>
                ))
              )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
