/**
 * SLA Dashboard
 *
 * Remediation SLAs, breach tracking, and MTTR analytics.
 *   1. KPIs: SLA Compliance, Active Breaches, At Risk, Avg MTTR
 *   2. SLA Compliance by Severity — horizontal bars
 *   3. Active Breaches table (8 rows)
 *   4. At-Risk items table (10 rows, sorted by time remaining)
 *   5. MTTR Trend chart — 6-month div-based bars by severity
 *   6. Team Performance table
 *   7. Policy Configuration card
 *
 * API stubs: GET /api/v1/sla/compliance, /api/v1/sla/breached, /api/v1/sla/at-risk
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Clock, AlertTriangle, Shield, Users, Settings, RefreshCw, BarChart3 } from "lucide-react";

// ── API ────────────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const key =
    (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) ||
    (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
    import.meta.env.VITE_API_KEY ||
    "dev-key";
  const url = path.startsWith("/api") ? `${API_BASE}${path}` : `${API_BASE}/api/v1${path}`;
  const res = await fetch(url, { headers: { "X-API-Key": key } });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const SEVERITY_BARS = [
  { label: "Critical", sla: "24h SLA", pct: 65, color: "bg-red-500", text: "text-red-400" },
  { label: "High",     sla: "72h SLA", pct: 78, color: "bg-amber-500", text: "text-amber-400" },
  { label: "Medium",   sla: "7d SLA",  pct: 89, color: "bg-green-500", text: "text-green-400" },
  { label: "Low",      sla: "30d SLA", pct: 94, color: "bg-green-400", text: "text-green-400" },
];

const BREACHES = [
  { id: "FND-1042", title: "SQL Injection in auth endpoint", severity: "Critical", type: "Resolve",   owner: "AppSec",   due: "2026-04-14 09:00", overdue: "49h" },
  { id: "FND-1039", title: "Exposed admin credentials",      severity: "Critical", type: "Contain",   owner: "CloudOps", due: "2026-04-14 11:30", overdue: "47h" },
  { id: "FND-1051", title: "Log4Shell unpatched instance",   severity: "High",     type: "Response",  owner: "InfraSec", due: "2026-04-15 08:00", overdue: "22h" },
  { id: "FND-1058", title: "Publicly accessible S3 bucket",  severity: "High",     type: "Resolve",   owner: "CloudOps", due: "2026-04-15 14:00", overdue: "16h" },
  { id: "FND-1064", title: "Insecure deserialization",       severity: "High",     type: "Contain",   owner: "AppSec",   due: "2026-04-15 16:00", overdue: "14h" },
  { id: "FND-1071", title: "Missing MFA on admin accounts",  severity: "Medium",   type: "Response",  owner: "IAM Team", due: "2026-04-15 18:00", overdue: "12h" },
  { id: "FND-1077", title: "Outdated TLS 1.0 in use",        severity: "Medium",   type: "Resolve",   owner: "NetSec",   due: "2026-04-15 20:00", overdue: "10h" },
  { id: "FND-1083", title: "CVE-2025-29927 in next.js",      severity: "High",     type: "Response",  owner: "AppSec",   due: "2026-04-15 22:00", overdue: "8h" },
];

const AT_RISK = [
  { id: "FND-1094", title: "RCE in image processor",          severity: "Critical", deadline: "2026-04-16 10:30", remaining: "1h 22m",  owner: "AppSec",   urgent: true },
  { id: "FND-1101", title: "SSRF in webhook handler",         severity: "Critical", deadline: "2026-04-16 11:00", remaining: "1h 52m",  owner: "AppSec",   urgent: true },
  { id: "FND-1108", title: "Hardcoded JWT secret",            severity: "High",     deadline: "2026-04-16 14:00", remaining: "4h 52m",  owner: "DevSec",   urgent: false },
  { id: "FND-1115", title: "Path traversal in file upload",   severity: "High",     deadline: "2026-04-16 15:30", remaining: "6h 22m",  owner: "AppSec",   urgent: false },
  { id: "FND-1122", title: "Unencrypted PII in S3",           severity: "High",     deadline: "2026-04-16 17:00", remaining: "7h 52m",  owner: "CloudOps", urgent: false },
  { id: "FND-1129", title: "XXE in XML parser",               severity: "Medium",   deadline: "2026-04-17 09:00", remaining: "23h 52m", owner: "AppSec",   urgent: false },
  { id: "FND-1136", title: "Insecure direct object ref",      severity: "Medium",   deadline: "2026-04-17 11:00", remaining: "25h 52m", owner: "DevSec",   urgent: false },
  { id: "FND-1143", title: "CORS misconfiguration",           severity: "Medium",   deadline: "2026-04-17 13:00", remaining: "27h 52m", owner: "NetSec",   urgent: false },
  { id: "FND-1150", title: "Outdated OpenSSL library",        severity: "Low",      deadline: "2026-04-18 10:00", remaining: "2d 0h",   owner: "InfraSec", urgent: false },
  { id: "FND-1157", title: "HTTP security headers missing",   severity: "Low",      deadline: "2026-04-18 14:00", remaining: "2d 4h",   owner: "NetSec",   urgent: false },
];

const MTTR_TREND = [
  { month: "Nov", critical: 4.1, high: 6.8, medium: 9.2 },
  { month: "Dec", critical: 3.8, high: 7.2, medium: 8.6 },
  { month: "Jan", critical: 4.4, high: 6.5, medium: 8.9 },
  { month: "Feb", critical: 3.5, high: 6.1, medium: 8.1 },
  { month: "Mar", critical: 3.2, high: 5.8, medium: 7.4 },
  { month: "Apr", critical: 2.9, high: 5.3, medium: 7.0 },
];

const TEAMS = [
  { name: "AppSec",   compliance: 71, open: 34 },
  { name: "CloudOps", compliance: 85, open: 18 },
  { name: "InfraSec", compliance: 79, open: 22 },
  { name: "DevSec",   compliance: 91, open: 11 },
  { name: "NetSec",   compliance: 88, open: 15 },
];

const SLA_POLICY = [
  { severity: "Critical", response: "1h",  contain: "4h",  resolve: "24h" },
  { severity: "High",     response: "4h",  contain: "24h", resolve: "72h" },
  { severity: "Medium",   response: "24h", contain: "72h", resolve: "7d"  },
  { severity: "Low",      response: "72h", contain: "7d",  resolve: "30d" },
];

// ── Helpers ────────────────────────────────────────────────────

function SeverityBadge({ sev }: { sev: string }) {
  const cls =
    sev === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    sev === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    sev === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                         "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{sev}</Badge>;
}

const MTTR_MAX = 10; // days — for bar scaling

// ── Component ──────────────────────────────────────────────────

export default function SLADashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/sla/dashboard?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/sla/breached?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/sla/at-risk?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/sla/compliance?org_id=${ORG_ID}`),
    ]).then(([dashRes, breachedRes, atRiskRes, complianceRes]) => {
      const dashboard  = dashRes.status      === "fulfilled" ? dashRes.value      : null;
      const breached   = breachedRes.status  === "fulfilled" ? breachedRes.value  : null;
      const atRisk     = atRiskRes.status    === "fulfilled" ? atRiskRes.value    : null;
      const compliance = complianceRes.status === "fulfilled" ? complianceRes.value : null;
      if (dashboard || breached || atRisk || compliance) {
        setLiveData({ dashboard, breached, atRisk, compliance });
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  // Derived KPI values — prefer live, fall back to mock
  const complianceRate = liveData?.compliance?.compliance_rate != null
    ? `${Math.round(liveData.compliance.compliance_rate)}%`
    : liveData?.dashboard?.compliance_rate != null
      ? `${Math.round(liveData.dashboard.compliance_rate)}%`
      : "78%";

  const activeBreaches = Array.isArray(liveData?.breached)
    ? liveData.breached.length
    : liveData?.dashboard?.breached ?? 12;

  const atRiskCount = Array.isArray(liveData?.atRisk)
    ? liveData.atRisk.length
    : liveData?.dashboard?.at_risk ?? 23;

  const avgMttr = liveData?.compliance?.mttr_by_severity
    ? (() => {
        const vals = Object.values(liveData.compliance.mttr_by_severity) as number[];
        const avg = vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : 0;
        return `${avg.toFixed(1)}d`;
      })()
    : liveData?.dashboard?.avg_mttr_days != null
      ? `${liveData.dashboard.avg_mttr_days.toFixed(1)}d`
      : "4.2d";

  // Live breach rows — map SLARecord fields to display shape
  const liveBreaches = Array.isArray(liveData?.breached) && liveData.breached.length > 0
    ? liveData.breached.slice(0, 8).map((r: any, i: number) => ({
        id:      r.finding_id ?? `FND-${i}`,
        title:   r.title     ?? r.finding_id ?? "—",
        severity: r.severity ?? "High",
        type:    "Resolve",
        owner:   r.assigned_to ?? "—",
        due:     r.deadline   ?? "—",
        overdue: r.hours_overdue != null ? `${Math.round(r.hours_overdue)}h` : "—",
      }))
    : BREACHES;

  const liveAtRisk = Array.isArray(liveData?.atRisk) && liveData.atRisk.length > 0
    ? liveData.atRisk.slice(0, 10).map((r: any, i: number) => ({
        id:        r.finding_id ?? `FND-${i}`,
        title:     r.title ?? r.finding_id ?? "—",
        severity:  r.severity ?? "Medium",
        deadline:  r.deadline ?? "—",
        remaining: r.hours_remaining != null ? `${Math.round(r.hours_remaining)}h` : "—",
        owner:     r.assigned_to ?? "—",
        urgent:    (r.hours_remaining ?? 999) < 2,
      }))
    : AT_RISK;

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
        title="SLA Dashboard"
        description="Remediation SLAs, breach tracking, and MTTR analytics"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="SLA Compliance"   value={complianceRate} icon={Shield}        trend="down" className="border-amber-500/20" />
        <KpiCard title="Active Breaches"  value={activeBreaches} icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="At Risk (≤20%)"   value={atRiskCount}    icon={Clock}         trend="up"   className="border-yellow-500/20" />
        <KpiCard title="Avg MTTR"         value={avgMttr}        icon={BarChart3}     trend="down" />
      </div>

      {/* Severity bars + MTTR trend */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Severity bars */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Shield className="h-4 w-4 text-blue-400" />
              SLA Compliance by Severity
            </CardTitle>
            <CardDescription className="text-xs">% of findings resolved within SLA window</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {SEVERITY_BARS.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              SEVERITY_BARS.map((bar) => (
              <div key={bar.label} className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span className={cn("font-semibold", bar.text)}>{bar.label}</span>
                    <span className="text-muted-foreground text-[10px]">{bar.sla}</span>
                  </div>
                  <span className="font-bold tabular-nums">{bar.pct}%</span>
                </div>
                <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${bar.pct}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={cn("h-full rounded-full", bar.color)}
                  />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* MTTR trend — div-based bars */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-purple-400" />
              MTTR Trend (6 months)
            </CardTitle>
            <CardDescription className="text-xs">Avg days to remediate by severity</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-3 h-36">
              {MTTR_TREND.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                MTTR_TREND.map((m) => (
                <div key={m.month} className="flex-1 flex flex-col items-center gap-0.5">
                  <div className="w-full flex items-end gap-0.5 h-28">
                    <div
                      className="flex-1 rounded-t bg-red-500/70 transition-all"
                      style={{ height: `${(m.critical / MTTR_MAX) * 100}%` }}
                      title={`Critical: ${m.critical}d`}
                    />
                    <div
                      className="flex-1 rounded-t bg-amber-500/70 transition-all"
                      style={{ height: `${(m.high / MTTR_MAX) * 100}%` }}
                      title={`High: ${m.high}d`}
                    />
                    <div
                      className="flex-1 rounded-t bg-green-500/70 transition-all"
                      style={{ height: `${(m.medium / MTTR_MAX) * 100}%` }}
                      title={`Medium: ${m.medium}d`}
                    />
                  </div>
                  <span className="text-[10px] text-muted-foreground">{m.month}</span>
                </div>
              ))
            )}
            </div>
            <div className="flex items-center gap-4 mt-3 text-[10px] text-muted-foreground">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-red-500/70 inline-block" />Critical</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-amber-500/70 inline-block" />High</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-green-500/70 inline-block" />Medium</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Active Breaches table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              Active Breaches
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {liveBreaches.length} breached
            </Badge>
          </div>
          <CardDescription className="text-xs">Findings that have exceeded their SLA deadline</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Finding ID</TableHead>
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Breach Type</TableHead>
                  <TableHead className="text-[11px] h-8">Owner</TableHead>
                  <TableHead className="text-[11px] h-8">SLA Due</TableHead>
                  <TableHead className="text-[11px] h-8">Overdue By</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {liveBreaches.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  liveBreaches.map((row) => (
                  <TableRow key={row.id} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5">{row.id}</TableCell>
                    <TableCell className="text-xs py-2.5 max-w-[200px] truncate">{row.title}</TableCell>
                    <TableCell className="py-2.5"><SeverityBadge sev={row.severity} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{row.type}</TableCell>
                    <TableCell className="text-xs py-2.5">{row.owner}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{row.due}</TableCell>
                    <TableCell className="text-xs py-2.5 font-bold tabular-nums text-red-400">{row.overdue}</TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] border-red-500/30 text-red-400 hover:bg-red-500/10">
                        Escalate
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* At-Risk table */}
      <Card className="border-yellow-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-yellow-400">
              <Clock className="h-4 w-4" />
              At-Risk Items
            </CardTitle>
            <Badge className="text-[10px] border border-yellow-500/30 text-yellow-400 bg-yellow-500/10">
              {liveAtRisk.length} items
            </Badge>
          </div>
          <CardDescription className="text-xs">Findings within 20% of their SLA deadline — sorted by time remaining</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Finding ID</TableHead>
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">SLA Deadline</TableHead>
                  <TableHead className="text-[11px] h-8">Time Remaining</TableHead>
                  <TableHead className="text-[11px] h-8">Owner</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {liveAtRisk.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  liveAtRisk.map((row) => (
                  <TableRow
                    key={row.id}
                    className={cn(
                      "hover:bg-muted/30",
                      row.urgent && "bg-red-500/5 border-l-2 border-l-red-500"
                    )}
                  >
                    <TableCell className="text-xs font-mono py-2.5">{row.id}</TableCell>
                    <TableCell className="text-xs py-2.5 max-w-[200px] truncate">{row.title}</TableCell>
                    <TableCell className="py-2.5"><SeverityBadge sev={row.severity} /></TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{row.deadline}</TableCell>
                    <TableCell className={cn("text-xs py-2.5 font-bold tabular-nums", row.urgent ? "text-red-400" : "text-yellow-400")}>
                      {row.remaining}
                    </TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{row.owner}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Team Performance + Policy */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Team performance */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Users className="h-4 w-4 text-indigo-400" />
              Team Performance
            </CardTitle>
            <CardDescription className="text-xs">SLA compliance rate and open findings per team</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Team</TableHead>
                  <TableHead className="text-[11px] h-8">SLA Compliance</TableHead>
                  <TableHead className="text-[11px] h-8">Rate</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Open</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {TEAMS.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  TEAMS.map((t) => (
                  <TableRow key={t.name} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5">{t.name}</TableCell>
                    <TableCell className="py-2.5 w-32">
                      <Progress value={t.compliance} className="h-1.5" />
                    </TableCell>
                    <TableCell className={cn(
                      "text-xs font-bold tabular-nums py-2.5",
                      t.compliance >= 90 ? "text-green-400" : t.compliance >= 80 ? "text-yellow-400" : "text-red-400"
                    )}>
                      {t.compliance}%
                    </TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right text-muted-foreground">{t.open}</TableCell>
                  </TableRow>
                ))
              )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* SLA Policy */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Settings className="h-4 w-4 text-muted-foreground" />
                  SLA Policy Configuration
                </CardTitle>
                <CardDescription className="text-xs">Current SLA thresholds by severity tier</CardDescription>
              </div>
              <Button variant="outline" size="sm" className="h-7 text-xs">Edit Policy</Button>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Response</TableHead>
                  <TableHead className="text-[11px] h-8">Containment</TableHead>
                  <TableHead className="text-[11px] h-8">Resolution</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {SLA_POLICY.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  SLA_POLICY.map((p) => (
                  <TableRow key={p.severity} className="hover:bg-muted/30">
                    <TableCell className="py-2.5"><SeverityBadge sev={p.severity} /></TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 font-medium">{p.response}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 font-medium">{p.contain}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 font-medium">{p.resolve}</TableCell>
                  </TableRow>
                ))
              )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
