/**
 * UBA Dashboard — User Behavior Analytics
 *
 * Insider threat detection and anomaly scoring.
 *   1. KPIs: Total Users, High Risk, Anomalies Today, Alerts Open
 *   2. High-risk user table (12 rows) with risk score bar + badges
 *   3. Risk score distribution (5 buckets, horizontal bars)
 *   4. Anomaly event feed (15 recent events)
 *   5. Department risk heatmap (8 departments)
 *
 * Route: /uba
 * API stubs: GET /api/v1/uba/users  GET /api/v1/uba/events
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY  = import.meta.env.VITE_API_KEY  || "dev-key";
const ORG_ID   = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
import {
  Users,
  AlertTriangle,
  Activity,
  Bell,
  RefreshCw,
  Eye,
  Building2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const HIGH_RISK_USERS = [
  { username: "j.doe",      dept: "Finance",   role: "Finance Analyst",   score: 92, anomalies: 14, lastAlert: "data_download",   status: "active" },
  { username: "m.chen",     dept: "IT",        role: "Sys Admin",         score: 88, anomalies: 11, lastAlert: "privilege_use",   status: "active" },
  { username: "r.patel",    dept: "HR",        role: "HR Manager",        score: 84, anomalies:  9, lastAlert: "after_hours",     status: "suspended" },
  { username: "s.kim",      dept: "DevOps",    role: "DevOps Engineer",   score: 81, anomalies:  8, lastAlert: "usb_use",         status: "active" },
  { username: "a.wright",   dept: "Legal",     role: "Legal Counsel",     score: 79, anomalies:  7, lastAlert: "data_download",   status: "active" },
  { username: "t.nguyen",   dept: "Sales",     role: "Account Exec",      score: 76, anomalies:  6, lastAlert: "failed_login",    status: "active" },
  { username: "l.garcia",   dept: "Finance",   role: "Controller",        score: 74, anomalies:  6, lastAlert: "after_hours",     status: "active" },
  { username: "k.wilson",   dept: "IT",        role: "Network Eng",       score: 71, anomalies:  5, lastAlert: "privilege_use",   status: "suspended" },
  { username: "b.johnson",  dept: "R&D",       role: "Research Lead",     score: 68, anomalies:  5, lastAlert: "usb_use",         status: "active" },
  { username: "d.smith",    dept: "Marketing", role: "Marketing Dir",     score: 55, anomalies:  4, lastAlert: "data_download",   status: "active" },
  { username: "p.brown",    dept: "Ops",       role: "Operations Mgr",    score: 47, anomalies:  3, lastAlert: "failed_login",    status: "active" },
  { username: "n.taylor",   dept: "Support",   role: "Support Lead",      score: 42, anomalies:  2, lastAlert: "after_hours",     status: "active" },
];

const SCORE_BUCKETS = [
  { label: "0–20",  count: 1842, color: "bg-green-500/70" },
  { label: "21–40", count:  963, color: "bg-blue-500/70" },
  { label: "41–60", count:  724, color: "bg-yellow-500/70" },
  { label: "61–80", count:  295, color: "bg-amber-500/70" },
  { label: "81–100", count:   23, color: "bg-red-500/70" },
];

const SCORE_MAX = 1842;

const ANOMALY_EVENTS = [
  { username: "j.doe",     type: "data_download",  ip: "10.0.12.44",   ts: "2026-04-16 09:47" },
  { username: "m.chen",    type: "privilege_use",   ip: "10.0.4.12",    ts: "2026-04-16 09:31" },
  { username: "s.kim",     type: "usb_use",         ip: "10.0.8.77",    ts: "2026-04-16 09:15" },
  { username: "r.patel",   type: "after_hours",     ip: "192.168.1.55", ts: "2026-04-16 02:48" },
  { username: "a.wright",  type: "data_download",   ip: "10.0.2.99",    ts: "2026-04-16 08:53" },
  { username: "t.nguyen",  type: "failed_login",    ip: "10.0.5.33",    ts: "2026-04-16 08:22" },
  { username: "l.garcia",  type: "after_hours",     ip: "192.168.3.12", ts: "2026-04-16 01:17" },
  { username: "m.chen",    type: "privilege_use",   ip: "10.0.4.12",    ts: "2026-04-15 23:44" },
  { username: "k.wilson",  type: "privilege_use",   ip: "10.0.9.80",    ts: "2026-04-15 22:58" },
  { username: "j.doe",     type: "data_download",   ip: "10.0.12.44",   ts: "2026-04-15 22:11" },
  { username: "b.johnson", type: "usb_use",         ip: "10.0.7.20",    ts: "2026-04-15 21:03" },
  { username: "d.smith",   type: "data_download",   ip: "10.0.6.14",    ts: "2026-04-15 19:40" },
  { username: "n.taylor",  type: "after_hours",     ip: "192.168.2.88", ts: "2026-04-15 18:55" },
  { username: "p.brown",   type: "failed_login",    ip: "10.0.3.61",    ts: "2026-04-15 17:30" },
  { username: "s.kim",     type: "usb_use",         ip: "10.0.8.77",    ts: "2026-04-15 16:12" },
];

const DEPT_HEATMAP = [
  { dept: "Finance",   avgScore: 71, users: 142, color: "bg-red-500/20 border-red-500/30", text: "text-red-400" },
  { dept: "IT",        avgScore: 64, users: 88,  color: "bg-amber-500/20 border-amber-500/30", text: "text-amber-400" },
  { dept: "HR",        avgScore: 52, users: 54,  color: "bg-yellow-500/20 border-yellow-500/30", text: "text-yellow-400" },
  { dept: "DevOps",    avgScore: 58, users: 63,  color: "bg-yellow-500/20 border-yellow-500/30", text: "text-yellow-400" },
  { dept: "Legal",     avgScore: 45, users: 29,  color: "bg-blue-500/20 border-blue-500/30", text: "text-blue-400" },
  { dept: "Sales",     avgScore: 33, users: 218, color: "bg-green-500/20 border-green-500/30", text: "text-green-400" },
  { dept: "Marketing", avgScore: 28, users: 97,  color: "bg-green-500/20 border-green-500/30", text: "text-green-400" },
  { dept: "Support",   avgScore: 19, users: 174, color: "bg-emerald-500/20 border-emerald-500/30", text: "text-emerald-400" },
];

// ── Helpers ────────────────────────────────────────────────────

function scoreColor(score: number) {
  if (score >= 70) return "bg-red-500";
  if (score >= 40) return "bg-yellow-500";
  return "bg-green-500";
}

function scoreTextColor(score: number) {
  if (score >= 70) return "text-red-400";
  if (score >= 40) return "text-yellow-400";
  return "text-green-400";
}

const EVENT_TYPE_COLORS: Record<string, string> = {
  after_hours:    "border-purple-500/30 text-purple-400 bg-purple-500/10",
  data_download:  "border-amber-500/30 text-amber-400 bg-amber-500/10",
  failed_login:   "border-red-500/30 text-red-400 bg-red-500/10",
  usb_use:        "border-blue-500/30 text-blue-400 bg-blue-500/10",
  privilege_use:  "border-orange-500/30 text-orange-400 bg-orange-500/10",
};

function EventTypeBadge({ type }: { type: string }) {
  return (
    <Badge className={cn("text-[10px] border font-mono", EVENT_TYPE_COLORS[type] ?? "border-border text-muted-foreground")}>
      {type.replace(/_/g, " ")}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function UBADashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  const loadData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/uba/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/uba/users?org_id=${ORG_ID}&min_risk_score=40`),
      apiFetch(`/api/v1/uba/events?org_id=${ORG_ID}&is_anomalous=true`),
      apiFetch(`/api/v1/uba/alerts?org_id=${ORG_ID}&status=open`),
    ]).then(([statsRes, usersRes, eventsRes, alertsRes]) => {
      const stats  = statsRes.status  === "fulfilled" ? statsRes.value  : null;
      const users  = usersRes.status  === "fulfilled" ? usersRes.value  : null;
      const events = eventsRes.status === "fulfilled" ? eventsRes.value : null;
      const alerts = alertsRes.status === "fulfilled" ? alertsRes.value : null;
      if (stats || users || events || alerts) {
        setLiveData({ stats, users, events, alerts });
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { loadData(); 
    setLoading(false);}, []);

  const handleRefresh = () => {
    setRefreshing(true);
    loadData();
    setTimeout(() => setRefreshing(false), 800);
  };

  // Resolve KPI values — prefer live, fall back to mock counts
  const liveUsers  = Array.isArray(liveData?.users)  ? liveData.users  : null;
  const liveEvents = Array.isArray(liveData?.events) ? liveData.events : null;
  const liveAlerts = Array.isArray(liveData?.alerts) ? liveData.alerts : null;

  const kpiTotalUsers      = liveData?.stats?.total_users     ?? "3,847";
  const kpiHighRisk        = liveData?.stats?.high_risk_count ?? liveData?.stats?.users_at_risk ?? 23;
  const kpiAnomaliestoday  = liveData?.stats?.anomalies_today ?? liveData?.stats?.total_events  ?? 47;
  const kpiAlertsOpen      = liveData?.stats?.open_alerts     ?? (liveAlerts?.length)            ?? 12;

  // Table data — map API shape to mock shape if live data available
  const tableUsers = liveUsers && liveUsers.length > 0
    ? liveUsers.map((u: any) => ({
        username:  u.username ?? u.user_id ?? "—",
        dept:      u.department ?? "—",
        role:      u.role ?? "—",
        score:     Math.round(u.risk_score ?? u.score ?? 0),
        anomalies: u.anomaly_count ?? u.anomalies ?? 0,
        lastAlert: u.last_alert_type ?? u.last_event_type ?? "failed_login",
        status:    u.status ?? "active",
      }))
    : HIGH_RISK_USERS;

  // Anomaly events feed
  const tableEvents = liveEvents && liveEvents.length > 0
    ? liveEvents.map((e: any) => ({
        username: e.user_id ?? e.username ?? "—",
        type:     e.event_type ?? "failed_login",
        ip:       e.source_ip ?? "—",
        ts:       e.timestamp ?? e.created_at ?? "—",
      }))
    : ANOMALY_EVENTS;

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
      {/* Header */}
      <PageHeader
        title="User Behavior Analytics"
        description="Insider threat detection and anomaly scoring"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Users"      value={kpiTotalUsers}     icon={Users}         trend="up" />
        <KpiCard title="High Risk (≥70)"  value={kpiHighRisk}       icon={AlertTriangle}  trend="up"   className="border-red-500/20" />
        <KpiCard title="Anomalies Today"  value={kpiAnomaliestoday} icon={Activity}       trend="up"   className="border-amber-500/20" />
        <KpiCard title="Alerts Open"      value={kpiAlertsOpen}     icon={Bell}           trend="down" className="border-yellow-500/20" />
      </div>

      {/* High-risk user table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              High-Risk Users
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {HIGH_RISK_USERS.length} users
            </Badge>
          </div>
          <CardDescription className="text-xs">Users with risk score ≥ 40, sorted by score descending</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Username</TableHead>
                  <TableHead className="text-[11px] h-8">Department</TableHead>
                  <TableHead className="text-[11px] h-8">Role</TableHead>
                  <TableHead className="text-[11px] h-8 w-32">Risk Score</TableHead>
                  <TableHead className="text-[11px] h-8">Anomalies</TableHead>
                  <TableHead className="text-[11px] h-8">Last Alert</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tableUsers.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  tableUsers.map((u) => (
                  <TableRow key={u.username} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5">{u.username}</TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{u.dept}</TableCell>
                    <TableCell className="text-xs py-2.5">{u.role}</TableCell>
                    <TableCell className="py-2.5">
                      <div className="flex items-center gap-2">
                        <div className="relative h-1.5 flex-1 rounded-full bg-muted/30 overflow-hidden">
                          <div
                            className={cn("h-full rounded-full", scoreColor(u.score))}
                )}
                            style={{ width: `${u.score}%` }}
                          />
                        </div>
                        <span className={cn("text-xs font-bold tabular-nums w-6 text-right", scoreTextColor(u.score))}>
                          {u.score}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-center">{u.anomalies}</TableCell>
                    <TableCell className="py-2.5">
                      <EventTypeBadge type={u.lastAlert} />
                    </TableCell>
                    <TableCell className="py-2.5">
                      {u.status === "suspended"
                        ? <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">suspended</Badge>
                        : <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">active</Badge>}
                    </TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">
                        <Eye className="h-3 w-3 mr-1" />Investigate
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Risk distribution + Anomaly feed */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Risk score distribution */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-blue-400" />
              Risk Score Distribution
            </CardTitle>
            <CardDescription className="text-xs">Users grouped by risk score bucket</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {SCORE_BUCKETS.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              SCORE_BUCKETS.map((b) => (
              <div key={b.label} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground tabular-nums w-14">{b.label}</span>
                  <span className="font-semibold tabular-nums">{b.count.toLocaleString()} users</span>
                </div>
                <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${(b.count / SCORE_MAX) * 100}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={cn("h-full rounded-full", b.color)}
                  />
                </div>
              </div>
            ))}
            )}
          </CardContent>
        </Card>

        {/* Anomaly event feed */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Bell className="h-4 w-4 text-amber-400" />
              Anomaly Event Feed
            </CardTitle>
            <CardDescription className="text-xs">15 most recent anomalous user events</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-border/50 max-h-80 overflow-y-auto">
              {tableEvents.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                tableEvents.map((e, i) => (
                <div key={i} className="flex items-center gap-2 px-4 py-2 hover:bg-muted/20">
                  <span className="text-xs font-mono text-muted-foreground w-16 shrink-0">{e.username}</span>
                  <EventTypeBadge type={e.type} />
                  <span className="text-[10px] text-muted-foreground font-mono flex-1 truncate">{e.ip}</span>
                  <span className="text-[10px] text-muted-foreground tabular-nums shrink-0">{e.ts.split(" ")[1]}</span>
                  <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10 shrink-0">anomalous</Badge>
                </div>
              ))}
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Department risk heatmap */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Building2 className="h-4 w-4 text-indigo-400" />
            Department Risk Heatmap
          </CardTitle>
          <CardDescription className="text-xs">Average risk score per department — higher score = greater insider threat exposure</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {DEPT_HEATMAP.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              DEPT_HEATMAP.map((d) => (
              <div
                key={d.dept}
                className={cn(
                  "rounded-lg border p-3 flex flex-col gap-1",
                  d.color
                )}
              >
                <span className="text-xs font-semibold text-foreground">{d.dept}</span>
                <span className={cn("text-2xl font-bold tabular-nums", d.text)}>{d.avgScore}</span>
                <span className="text-[10px] text-muted-foreground">avg score</span>
                <span className="text-[10px] text-muted-foreground">{d.users} users</span>
              </div>
            ))}
            )}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
