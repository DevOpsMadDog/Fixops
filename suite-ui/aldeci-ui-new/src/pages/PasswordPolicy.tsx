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
import { motion } from "framer-motion";
import {
  Key, Shield, AlertTriangle, CheckCircle, XCircle,
  RefreshCw, BarChart3, ClipboardList, Users,
} from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY  = import.meta.env.VITE_API_KEY || "dev-key";
const ORG_ID   = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
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
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const POLICIES = [
  {
    name: "Corporate Standard Policy",
    requirements: [
      { label: "Minimum 12 characters", met: true },
      { label: "At least 1 uppercase letter", met: true },
      { label: "At least 1 lowercase letter", met: true },
      { label: "At least 1 number", met: true },
      { label: "At least 1 special symbol", met: true },
      { label: "No dictionary words", met: true },
      { label: "No previous 10 passwords", met: false },
    ],
    compliance: 91,
    users: 2104,
  },
  {
    name: "Privileged Account Policy",
    requirements: [
      { label: "Minimum 16 characters", met: true },
      { label: "At least 2 uppercase letters", met: true },
      { label: "At least 2 special symbols", met: true },
      { label: "No dictionary words", met: true },
      { label: "No previous 24 passwords", met: true },
      { label: "Rotation every 30 days", met: true },
      { label: "MFA required alongside", met: false },
    ],
    compliance: 88,
    users: 142,
  },
  {
    name: "Guest / Contractor Policy",
    requirements: [
      { label: "Minimum 8 characters", met: true },
      { label: "At least 1 uppercase letter", met: true },
      { label: "At least 1 number", met: true },
      { label: "At least 1 special symbol", met: false },
      { label: "No previous 5 passwords", met: true },
      { label: "Rotation every 90 days", met: false },
    ],
    compliance: 74,
    users: 1601,
  },
];

const VIOLATIONS = [
  { userId: "usr_a7k3***", policy: "Corporate Standard", type: "Weak Password",         severity: "High",   detected: "2026-04-16 09:02", status: "Open" },
  { userId: "usr_b2m9***", policy: "Privileged Account", type: "Expired Password",       severity: "High",   detected: "2026-04-16 08:45", status: "Open" },
  { userId: "usr_c5q1***", policy: "Corporate Standard", type: "Password Reuse",          severity: "Medium", detected: "2026-04-16 07:30", status: "Open" },
  { userId: "usr_d8r4***", policy: "Guest/Contractor",   type: "No Special Symbol",       severity: "Medium", detected: "2026-04-15 22:14", status: "Open" },
  { userId: "usr_e1s7***", policy: "Corporate Standard", type: "Dictionary Word Found",   severity: "High",   detected: "2026-04-15 20:55", status: "Open" },
  { userId: "usr_f9t2***", policy: "Privileged Account", type: "Rotation Overdue 15d",    severity: "Critical", detected: "2026-04-15 18:00", status: "Open" },
  { userId: "usr_g3u8***", policy: "Corporate Standard", type: "Minimum Length Fail",     severity: "Medium", detected: "2026-04-15 15:42", status: "Remediated" },
  { userId: "usr_h6v5***", policy: "Guest/Contractor",   type: "No Rotation in 95d",      severity: "Medium", detected: "2026-04-15 13:20", status: "Remediated" },
  { userId: "usr_i4w1***", policy: "Privileged Account", type: "Rotation Overdue 7d",     severity: "High",   detected: "2026-04-15 11:05", status: "Open" },
  { userId: "usr_j7x3***", policy: "Corporate Standard", type: "Common Pattern (123…)",   severity: "Medium", detected: "2026-04-14 23:50", status: "Remediated" },
  { userId: "usr_k2y9***", policy: "Corporate Standard", type: "No Uppercase Letter",     severity: "Low",    detected: "2026-04-14 19:30", status: "Remediated" },
  { userId: "usr_l5z6***", policy: "Guest/Contractor",   type: "Weak Password",           severity: "High",   detected: "2026-04-14 16:15", status: "Remediated" },
];

const AUDITS = [
  { date: "2026-04-16 00:00", checked: 3847, violations: 234, compliance: "93.9%" },
  { date: "2026-04-09 00:00", checked: 3812, violations: 258, compliance: "93.2%" },
  { date: "2026-04-02 00:00", checked: 3790, violations: 271, compliance: "92.9%" },
  { date: "2026-03-26 00:00", checked: 3765, violations: 289, compliance: "92.3%" },
  { date: "2026-03-19 00:00", checked: 3741, violations: 312, compliance: "91.7%" },
  { date: "2026-03-12 00:00", checked: 3718, violations: 334, compliance: "91.0%" },
];

const STRENGTH_DIST = [
  { label: "Very Weak", count: 47,  color: "bg-red-600",    pct: 1.2 },
  { label: "Weak",      count: 156, color: "bg-red-400",    pct: 4.1 },
  { label: "Fair",      count: 412, color: "bg-amber-400",  pct: 10.7 },
  { label: "Strong",    count: 2198,color: "bg-green-500",  pct: 57.1 },
  { label: "Very Strong",count: 1034,color: "bg-green-400", pct: 26.9 },
];

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
          {POLICIES.map((policy) => (
            <Card key={policy.name}>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-xs font-semibold leading-tight">{policy.name}</CardTitle>
                  <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] shrink-0">Edit</Button>
                </div>
                <CardDescription className="text-[10px]">{policy.users.toLocaleString()} users in scope</CardDescription>
              </CardHeader>
              <CardContent className="space-y-2">
                {policy.requirements.map((req) => (
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
                      policy.compliance >= 90 ? "text-green-400" :
                      policy.compliance >= 75 ? "text-yellow-400" : "text-red-400"
                    )}>{policy.compliance}%</span>
                  </div>
                  <div className="relative h-1.5 rounded-full bg-muted/30 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${policy.compliance}%` }}
                      transition={{ duration: 0.8, ease: "easeOut" }}
                      className={cn("h-full rounded-full",
                        policy.compliance >= 90 ? "bg-green-500" :
                        policy.compliance >= 75 ? "bg-yellow-500" : "bg-red-500"
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
              {(liveData?.violations?.violations ?? VIOLATIONS).filter((v: any) => v.status === "Open" || v.status === "open").length} open
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
                {(liveData?.violations?.violations ?? VIOLATIONS).map((v: any, i: number) => (
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
                {(liveData?.audits?.audits ?? AUDITS).map((a: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{a.date}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right">{a.checked.toLocaleString()}</TableCell>
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
            <CardDescription className="text-xs">Across all {(3847).toLocaleString()} audited accounts</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {STRENGTH_DIST.map((s) => (
              <div key={s.label} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium">{s.label}</span>
                  <div className="flex items-center gap-2">
                    <span className="tabular-nums text-muted-foreground">{s.count.toLocaleString()}</span>
                    <span className="tabular-nums font-bold w-10 text-right">{s.pct}%</span>
                  </div>
                </div>
                <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${s.pct}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={cn("h-full rounded-full", s.color)}
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
