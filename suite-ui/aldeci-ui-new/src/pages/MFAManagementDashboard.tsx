/**
 * MFA Management Dashboard
 *
 * Multi-Factor Authentication enrollment and compliance tracking.
 *   1. KPI cards: Total Enrolled, Compliance Rate, Failed Auths (24h), Active Policies
 *   2. MFA Enrollments table
 *   3. Recent MFA Events table
 *
 * API: GET /api/v1/mfa/{stats,enrollments,events}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Shield, RefreshCw, CheckCircle, XCircle, Lock, Key,
} from "lucide-react";
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

// ── Mock data (fallback) ───────────────────────────────────────

const MOCK_STATS = {
  total_enrolled: 342,
  compliance_rate: 87.4,
  failed_auths_24h: 14,
  active_policies: 5,
};

const MOCK_ENROLLMENTS = [
  { user_id: "usr-001", mfa_type: "totp",         status: "active",   enrolled_at: "2026-01-15" },
  { user_id: "usr-002", mfa_type: "hardware_key",  status: "active",   enrolled_at: "2026-02-03" },
  { user_id: "usr-003", mfa_type: "sms",           status: "active",   enrolled_at: "2026-02-18" },
  { user_id: "usr-004", mfa_type: "push",          status: "pending",  enrolled_at: "2026-03-29" },
  { user_id: "usr-005", mfa_type: "email",         status: "disabled", enrolled_at: "2025-11-10" },
];

const MOCK_EVENTS = [
  { user_id: "usr-001", event_type: "verification", mfa_type: "totp",         success: true,  timestamp: "2026-04-16T09:14:22Z" },
  { user_id: "usr-007", event_type: "failure",      mfa_type: "sms",          success: false, timestamp: "2026-04-16T09:02:11Z" },
  { user_id: "usr-002", event_type: "enrollment",   mfa_type: "hardware_key", success: true,  timestamp: "2026-04-16T08:55:00Z" },
  { user_id: "usr-009", event_type: "bypass",       mfa_type: "email",        success: false, timestamp: "2026-04-16T08:30:44Z" },
  { user_id: "usr-003", event_type: "verification", mfa_type: "push",         success: true,  timestamp: "2026-04-16T08:21:07Z" },
  { user_id: "usr-010", event_type: "failure",      mfa_type: "totp",         success: false, timestamp: "2026-04-16T07:58:33Z" },
  { user_id: "usr-004", event_type: "enrollment",   mfa_type: "push",         success: true,  timestamp: "2026-04-16T07:40:19Z" },
  { user_id: "usr-012", event_type: "verification", mfa_type: "sms",          success: true,  timestamp: "2026-04-16T07:22:55Z" },
  { user_id: "usr-005", event_type: "failure",      mfa_type: "email",        success: false, timestamp: "2026-04-16T06:45:12Z" },
  { user_id: "usr-001", event_type: "verification", mfa_type: "totp",         success: true,  timestamp: "2026-04-16T06:10:08Z" },
];

// ── Badge helpers ──────────────────────────────────────────────

function MFATypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    totp:         "border-blue-500/30 text-blue-400 bg-blue-500/10",
    sms:          "border-green-500/30 text-green-400 bg-green-500/10",
    hardware_key: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    push:         "border-orange-500/30 text-orange-400 bg-orange-500/10",
    email:        "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono uppercase", map[type] ?? "border-border text-muted-foreground")}>
      {type.replace(/_/g, " ")}
    </Badge>
  );
}

function EnrollmentStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:   "border-green-500/30 text-green-400 bg-green-500/10",
    pending:  "border-amber-500/30 text-amber-400 bg-amber-500/10",
    disabled: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

function EventTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    enrollment:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    verification: "border-green-500/30 text-green-400 bg-green-500/10",
    bypass:       "border-orange-500/30 text-orange-400 bg-orange-500/10",
    failure:      "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border text-muted-foreground")}>
      {type}
    </Badge>
  );
}

function fmtTime(ts: string): string {
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

// ── Component ──────────────────────────────────────────────────

export default function MFAManagementDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
  const [loading, setLoading] = useState(true);
    stats: any | null;
    enrollments: any[] | null;
    events: any[] | null;
  }>({ stats: null, enrollments: null, events: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/mfa/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/mfa/enrollments?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/mfa/events?org_id=${ORG_ID}`),
    ]).then(([statsRes, enrollRes, eventsRes]) => {
      setLiveData({
        stats:       statsRes.status   === "fulfilled" ? statsRes.value   : null,
        enrollments: enrollRes.status  === "fulfilled" ? enrollRes.value  : null,
        events:      eventsRes.status  === "fulfilled" ? eventsRes.value  : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats       = liveData.stats       ?? MOCK_STATS;
  const enrollments = liveData.enrollments ?? MOCK_ENROLLMENTS;
  const events      = liveData.events      ?? MOCK_EVENTS;

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
        title="MFA Management"
        description="Multi-Factor Authentication enrollment and compliance"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Enrolled"         value={stats.total_enrolled}                            icon={Shield}       trend="up"   />
        <KpiCard title="Compliance Rate"        value={`${stats.compliance_rate}%`}                     icon={CheckCircle}  trend="up"   className="border-green-500/20" />
        <KpiCard title="Failed Auths (24h)"     value={stats.failed_auths_24h}                          icon={XCircle}      trend="down" className="border-red-500/20" />
        <KpiCard title="Active Policies"        value={stats.active_policies}                           icon={Lock}         trend="flat" className="border-blue-500/20" />
      </div>

      {/* Enrollments Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Key className="h-4 w-4 text-blue-400" />
              MFA Enrollments
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {enrollments.length} records
            </Badge>
          </div>
          <CardDescription className="text-xs">User MFA method registrations and status</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">User ID</TableHead>
                  <TableHead className="text-[11px] h-8">MFA Type</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Enrolled At</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {enrollments.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  enrollments.map((e: any, i: number) => (
                  <TableRow key={e.user_id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{e.user_id}</TableCell>
                    <TableCell className="py-2"><MFATypeBadge type={e.mfa_type ?? "totp"} /></TableCell>
                    <TableCell className="py-2"><EnrollmentStatusBadge status={e.status ?? "active"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{e.enrolled_at}</TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* MFA Events Table */}
      <Card className="border-amber-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
              <Shield className="h-4 w-4" />
              Recent MFA Events
            </CardTitle>
            <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">
              {events.filter((ev: any) => !ev.success).length} failures
            </Badge>
          </div>
          <CardDescription className="text-xs">Authentication events including failures and bypasses</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">User ID</TableHead>
                  <TableHead className="text-[11px] h-8">Event Type</TableHead>
                  <TableHead className="text-[11px] h-8">MFA Type</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Success</TableHead>
                  <TableHead className="text-[11px] h-8">Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  events.map((ev: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{ev.user_id}</TableCell>
                    <TableCell className="py-2"><EventTypeBadge type={ev.event_type ?? "verification"} /></TableCell>
                    <TableCell className="py-2"><MFATypeBadge type={ev.mfa_type ?? "totp"} /></TableCell>
                    <TableCell className="py-2 text-center">
                      {ev.success
                        ? <CheckCircle className="h-3.5 w-3.5 text-green-400 inline" />
                        : <XCircle    className="h-3.5 w-3.5 text-red-400 inline" />}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{fmtTime(ev.timestamp)}</TableCell>
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
