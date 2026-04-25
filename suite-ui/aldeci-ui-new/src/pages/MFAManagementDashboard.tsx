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
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

async function apiFetch<T = any>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

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
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<any>({ total_enrolled: 0, compliance_rate: 0, failed_auths_24h: 0, active_policies: 0 });
  const [enrollments, setEnrollments] = useState<any[]>([]);
  const [events, setEvents] = useState<any[]>([]);

  const load = async () => {
    setRefreshing(true);
    setError(null);
    try {
      const [enrollRes, eventsRes, policiesRes] = await Promise.allSettled([
        apiFetch<any>("/api/v1/mfa/enrollments"),
        apiFetch<any>("/api/v1/mfa/events"),
        apiFetch<any>("/api/v1/mfa/policies"),
      ]);
      let total = 0, compliantCnt = 0;
      if (enrollRes.status === "fulfilled") {
        const v = enrollRes.value;
        const arr = Array.isArray(v) ? v : (v?.enrollments ?? v?.items ?? []);
        setEnrollments(arr);
        total = arr.length;
        compliantCnt = arr.filter((e: any) => e.status === "active").length;
      } else {
        setError((enrollRes.reason as Error).message);
      }
      let failed = 0;
      if (eventsRes.status === "fulfilled") {
        const v = eventsRes.value;
        const arr = Array.isArray(v) ? v : (v?.events ?? v?.items ?? []);
        setEvents(arr);
        failed = arr.filter((e: any) => e.success === false).length;
      }
      let policyCount = 0;
      if (policiesRes.status === "fulfilled") {
        const v = policiesRes.value;
        const arr = Array.isArray(v) ? v : (v?.policies ?? v?.items ?? []);
        policyCount = arr.length;
      }
      setStats({
        total_enrolled: total,
        compliance_rate: total > 0 ? Number(((compliantCnt / total) * 100).toFixed(1)) : 0,
        failed_auths_24h: failed,
        active_policies: policyCount,
      });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const handleRefresh = () => { load(); };

  if (loading) return <PageSkeleton />;

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
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {error && <ErrorState message={error} onRetry={load} />}

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
          {enrollments.length === 0 && !error ? <EmptyState icon={Key} title="No MFA enrollments" description="No users have enrolled in MFA for this org." /> : (
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
                {enrollments.map((e: any, i: number) => (
                  <TableRow key={e.user_id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{e.user_id}</TableCell>
                    <TableCell className="py-2"><MFATypeBadge type={e.mfa_type ?? "totp"} /></TableCell>
                    <TableCell className="py-2"><EnrollmentStatusBadge status={e.status ?? "active"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{e.enrolled_at}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          )}
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
          {events.length === 0 && !error ? <EmptyState icon={Shield} title="No MFA events" description="No recent MFA verification events." /> : (
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
                {events.map((ev: any, i: number) => (
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
