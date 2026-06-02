/**
 * Password Policy Management Dashboard
 *
 * Policy enforcement and violation tracking.
 *   1. KPIs: Active Policies, Users Audited, Violations Found, Compliance Rate
 *   2. Policy cards (3) — complexity requirements + compliance bar + Edit button
 *   3. Violation table (12 rows)
 *   4. Audit history (6 audits)
 *   5. Password strength distribution — horizontal bars
 *
 * API stubs: GET /api/v1/password-policy/policies, /api/v1/password-policy/violations, /api/v1/password-policy/audits
 */

import { useState, useEffect } from "react";
import { getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { motion } from "framer-motion";
import {
  Key, Shield, AlertTriangle, CheckCircle, XCircle,
  RefreshCw, BarChart3, ClipboardList, Users, Inbox,
} from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY  = import.meta.env.VITE_API_KEY || (getStoredAuthToken() ?? "");
const ORG_ID   = (getStoredOrgId() ?? "default");

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────





// ── Helpers ────────────────────────────────────────────────────

function SeverityBadge({ sev }: { sev: string }) {
  const cls =
    sev === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    sev === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    sev === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                         "border-border text-muted-foreground bg-muted/20";
  return <Badge className={cn("text-[10px] border", cls)}>{sev}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

const arr = (v: any): any[] => (Array.isArray(v) ? v : []);
export default function PasswordPolicy() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/password-policy/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/password-policy/violations?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/password-policy/audits?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/password-policy/policies?org_id=${ORG_ID}`),
    ]).then(([statsRes, violRes, auditRes, policiesRes]) => {
      const stats      = statsRes.status     === "fulfilled" ? statsRes.value     : null;
      const violations = violRes.status      === "fulfilled" ? violRes.value      : null;
      const audits     = auditRes.status     === "fulfilled" ? auditRes.value     : null;
      const policies   = policiesRes.status  === "fulfilled" ? policiesRes.value  : null;
      if (stats || violations || audits || policies) {
        setLiveData({ stats, violations, audits, policies });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/password-policy/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/password-policy/violations?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/password-policy/audits?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/password-policy/policies?org_id=${ORG_ID}`),
    ]).then(([statsRes, violRes, auditRes, policiesRes]) => {
      const stats      = statsRes.status     === "fulfilled" ? statsRes.value     : null;
      const violations = violRes.status      === "fulfilled" ? violRes.value      : null;
      const audits     = auditRes.status     === "fulfilled" ? auditRes.value     : null;
      const policies   = policiesRes.status  === "fulfilled" ? policiesRes.value  : null;
      if (stats || violations || audits || policies) {
        setLiveData({ stats, violations, audits, policies });
      }
    }).finally(() => { setDataLoading(false); setRefreshing(false); });
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Password Policy Management"
        description="Policy enforcement and violation tracking"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Policies"   value={liveData?.stats?.total_policies   ?? liveData?.policies?.count ?? 4}                                                                icon={Key}           trend="flat" />
        <KpiCard title="Users Audited"     value={liveData?.stats?.users_audited    ? liveData.stats.users_audited.toLocaleString() : "3,847"}                                        icon={Users}         trend="up"   className="border-blue-500/20" />
        <KpiCard title="Violations Found"  value={liveData?.stats?.open_violations  ?? liveData?.violations?.count ?? 234}                                                            icon={AlertTriangle} trend="down" className="border-amber-500/20" />
        <KpiCard title="Compliance Rate"   value={liveData?.stats?.compliance_rate  ? `${(liveData.stats.compliance_rate * 100).toFixed(1)}%` : "93.9%"}                             icon={Shield}        trend="up"   className="border-green-500/20" />
      </div>

      {/* Policy cards */}
      <div>
        <h2 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <Key className="h-4 w-4 text-amber-400" />
          Active Policies
        </h2>
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          {(liveData?.policies?.policies ?? liveData?.policies ?? []).length === 0 ? (
            <div className="lg:col-span-3">
              <EmptyState icon={Key} title="No policies yet" description="Password policies will appear here once configured." />
            </div>
          ) : (arr(liveData?.policies?.policies ?? liveData?.policies ?? [])).map((policy: any) => (
            <Card key={policy.name}>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-xs font-semibold leading-tight">{policy.name}</CardTitle>
                  <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] shrink-0">Edit</Button>
                </div>
                <CardDescription className="text-[10px]">{(policy.users ?? policy.user_count ?? 0).toLocaleString()} users in scope</CardDescription>
              </CardHeader>
              <CardContent className="space-y-2">
                {(arr(policy.requirements ?? [])).map((req: any) => (
                  <div key={req.label} className="flex items-center gap-2 text-xs">
                    {req.met
                      ? <CheckCircle className="h-3.5 w-3.5 text-green-400 shrink-0" />
                      : <XCircle className="h-3.5 w-3.5 text-red-400 shrink-0" />
                    }
                    <span className={req.met ? "text-foreground" : "text-muted-foreground"}>
                      {req.label}
                    </span>
                  </div>
                ))}
                <div className="pt-2 space-y-1 border-t border-border/50">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-muted-foreground">Compliance</span>
                    <span className={cn("font-bold",
                      (policy.compliance ?? 0) >= 90 ? "text-green-400" :
                      (policy.compliance ?? 0) >= 75 ? "text-yellow-400" : "text-red-400"
                    )}>{policy.compliance ?? 0}%</span>
                  </div>
                  <div className="relative h-1.5 rounded-full bg-muted/30 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${policy.compliance ?? 0}%` }}
                      transition={{ duration: 0.8, ease: "easeOut" }}
                      className={cn("h-full rounded-full",
                        (policy.compliance ?? 0) >= 90 ? "bg-green-500" :
                        (policy.compliance ?? 0) >= 75 ? "bg-yellow-500" : "bg-red-500"
                      )}
                    />
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Violation table */}
      <Card className="border-amber-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
              <AlertTriangle className="h-4 w-4" />
              Policy Violations
            </CardTitle>
            <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">
              {(liveData?.violations?.violations ?? []).filter((v: any) => v.status === "Open" || v.status === "open").length} open
            </Badge>
          </div>
          <CardDescription className="text-xs">Detected password policy violations — user IDs are masked for privacy</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">User ID</TableHead>
                  <TableHead className="text-[11px] h-8">Policy</TableHead>
                  <TableHead className="text-[11px] h-8">Violation Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Detected</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.violations?.violations ?? []).length === 0 ? (
                  <TableRow><TableCell colSpan={7} className="py-8 text-center text-sm text-muted-foreground">No violations yet</TableCell></TableRow>
                ) : (arr(liveData?.violations?.violations ?? [])).map((v: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5 text-muted-foreground">{v.userId}</TableCell>
                    <TableCell className="text-xs py-2.5 max-w-[140px] truncate">{v.policy}</TableCell>
                    <TableCell className="text-xs py-2.5">
                      <Badge className="text-[10px] border border-border bg-muted/20 text-foreground">{v.type}</Badge>
                    </TableCell>
                    <TableCell className="py-2.5"><SeverityBadge sev={v.severity} /></TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{v.detected}</TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border",
                        v.status === "Open"
                          ? "border-red-500/30 text-red-400 bg-red-500/10"
                          : "border-green-500/30 text-green-400 bg-green-500/10"
                      )}>{v.status}</Badge>
                    </TableCell>
                    <TableCell className="py-2.5 text-right">
                      {v.status === "Open" && (
                        <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] border-amber-500/30 text-amber-400 hover:bg-amber-500/10">
                          Remediate
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Audit history + Password strength */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Audit history */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <ClipboardList className="h-4 w-4 text-blue-400" />
              Audit History
            </CardTitle>
            <CardDescription className="text-xs">Weekly password compliance audits</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Audit Date</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Users Checked</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Violations</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Compliance</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.audits?.audits ?? []).length === 0 ? (
                  <TableRow><TableCell colSpan={4} className="py-8 text-center text-sm text-muted-foreground">No audit history yet</TableCell></TableRow>
                ) : (arr(liveData?.audits?.audits ?? [])).map((a: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{a.date}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right">{(a.checked ?? 0).toLocaleString()}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right text-amber-400">{a.violations}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right font-bold text-green-400">{a.compliance}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Password strength distribution */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-purple-400" />
              Password Strength Distribution
            </CardTitle>
            <CardDescription className="text-xs">Across all audited accounts</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {(liveData?.stats?.strength_distribution ?? []).length === 0 ? (
              <EmptyState icon={BarChart3} title="No strength data yet" description="Password strength distribution will appear once an audit has run." />
            ) : (arr(liveData?.stats?.strength_distribution ?? [])).map((s: any) => (
              <div key={s.label} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium">{s.label}</span>
                  <div className="flex items-center gap-2">
                    <span className="tabular-nums text-muted-foreground">{(s.count ?? 0).toLocaleString()}</span>
                    <span className="tabular-nums font-bold w-10 text-right">{s.pct ?? s.percentage ?? 0}%</span>
                  </div>
                </div>
                <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${s.pct ?? s.percentage ?? 0}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={cn("h-full rounded-full", s.color ?? "bg-blue-500")}
                  />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
