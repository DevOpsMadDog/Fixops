/**
 * CCMDashboard — Continuous Control Monitoring
 *
 * Automated control testing, failure detection, and remediation tracking.
 *   1. KPIs: Controls Monitored, Pass Rate, Open Failures, Untested Controls
 *   2. Control coverage by framework — 6 framework rows
 *   3. Control test results table — 15 rows
 *   4. Failure tracker — 10 open failures
 *   5. Test history — last 8 test runs as timeline
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ShieldCheck, XCircle, AlertTriangle, CheckCircle, RefreshCw, BarChart3, Play, Clock } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "aldeci-demo";

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
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ───────────────────────────────────────────────────

const FRAMEWORKS = [
  { name: "SOC 2",      total: 64,  passing: 58, failing: 4,  passRate: 91, status: "pass" },
  { name: "ISO 27001",  total: 93,  passing: 79, failing: 8,  passRate: 85, status: "warn" },
  { name: "NIST CSF",   total: 108, passing: 88, failing: 12, passRate: 81, status: "warn" },
  { name: "PCI DSS",    total: 78,  passing: 72, failing: 4,  passRate: 92, status: "pass" },
  { name: "HIPAA",      total: 54,  passing: 43, failing: 7,  passRate: 80, status: "warn" },
  { name: "CIS v8",     total: 153, passing: 138, failing: 9, passRate: 90, status: "pass" },
];

const CONTROLS = [
  { ref: "CC6.1",   name: "Logical and physical access controls",    fw: "SOC 2",    type: "automated",       status: "pass", lastRun: "2026-04-16 08:00", nextRun: "2026-04-17 08:00" },
  { ref: "CC7.2",   name: "System monitoring and anomaly detection",  fw: "SOC 2",    type: "automated",       status: "pass", lastRun: "2026-04-16 06:00", nextRun: "2026-04-17 06:00" },
  { ref: "A.9.2.3", name: "Management of privileged access rights",   fw: "ISO 27001",type: "automated",       status: "fail", lastRun: "2026-04-16 04:00", nextRun: "2026-04-17 04:00" },
  { ref: "PR.AC-1", name: "Identity and credential management",       fw: "NIST CSF", type: "automated",       status: "pass", lastRun: "2026-04-15 22:00", nextRun: "2026-04-16 22:00" },
  { ref: "Req 8.3", name: "Authenticate all user access",             fw: "PCI DSS",  type: "automated",       status: "pass", lastRun: "2026-04-15 20:00", nextRun: "2026-04-16 20:00" },
  { ref: "164.312", name: "PHI access audit controls",                fw: "HIPAA",    type: "automated",       status: "warn", lastRun: "2026-04-15 18:00", nextRun: "2026-04-16 18:00" },
  { ref: "CIS 4.1", name: "Establish and maintain secure config",     fw: "CIS v8",   type: "automated",       status: "pass", lastRun: "2026-04-15 16:00", nextRun: "2026-04-16 16:00" },
  { ref: "A.12.6",  name: "Management of technical vulnerabilities",  fw: "ISO 27001",type: "automated",       status: "fail", lastRun: "2026-04-15 14:00", nextRun: "2026-04-16 14:00" },
  { ref: "CC9.2",   name: "Vendor and business partner risk mgmt",    fw: "SOC 2",    type: "manual",          status: "pass", lastRun: "2026-04-14 10:00", nextRun: "2026-05-14 10:00" },
  { ref: "DE.CM-3", name: "Personnel activity monitoring",            fw: "NIST CSF", type: "automated",       status: "pass", lastRun: "2026-04-16 09:00", nextRun: "2026-04-17 09:00" },
  { ref: "Req 10.3", name: "Protect audit logs from modification",      fw: "PCI DSS",  type: "automated",       status: "pass", lastRun: "2026-04-16 07:00", nextRun: "2026-04-17 07:00" },
  { ref: "164.308", name: "Security awareness and training",          fw: "HIPAA",    type: "self_assessment", status: "pass", lastRun: "2026-04-01 09:00", nextRun: "2026-07-01 09:00" },
  { ref: "CIS 12.1", name: "Ensure network infrastructure up-to-date", fw: "CIS v8",   type: "automated",       status: "fail", lastRun: "2026-04-16 05:00", nextRun: "2026-04-17 05:00" },
  { ref: "A.18.2",  name: "Compliance with security policies",        fw: "ISO 27001",type: "manual",          status: "none", lastRun: "2026-03-15 10:00", nextRun: "2026-06-15 10:00" },
  { ref: "PR.DS-5", name: "Protections against data leaks",           fw: "NIST CSF", type: "automated",       status: "warn", lastRun: "2026-04-16 03:00", nextRun: "2026-04-17 03:00" },
];

const FAILURES = [
  { type: "regression",          severity: "critical", control: "A.9.2.3 — Privileged access rights",       detected: "2026-04-16 04:12" },
  { type: "gap",                 severity: "high",     control: "A.12.6 — Technical vuln management",       detected: "2026-04-15 14:33" },
  { type: "gap",                 severity: "high",     control: "CIS 12.1 — Network infra patching",        detected: "2026-04-16 05:07" },
  { type: "exception",           severity: "medium",   control: "164.312 — PHI access audit controls",      detected: "2026-04-15 18:44" },
  { type: "design_deficiency",   severity: "high",     control: "PR.DS-5 — Data leak protections",          detected: "2026-04-16 03:55" },
  { type: "regression",          severity: "medium",   control: "CC7.2 — System monitoring (partial)",      detected: "2026-04-14 22:11" },
  { type: "gap",                 severity: "critical",  control: "Req 8.6 — User account management",        detected: "2026-04-13 09:30" },
  { type: "exception",           severity: "low",      control: "CC9.2 — Vendor risk assessment gap",       detected: "2026-04-12 16:00" },
  { type: "design_deficiency",   severity: "medium",   control: "A.18.2 — Policy compliance self-assess",   detected: "2026-04-11 11:20" },
  { type: "regression",          severity: "high",     control: "DE.CM-7 — Unauthorized device monitoring", detected: "2026-04-10 08:45" },
];

const TEST_HISTORY = [
  { runId: "RUN-2026-0416-AM", time: "2026-04-16 08:00", passed: 71, failed: 4,  warned: 3, total: 78 },
  { runId: "RUN-2026-0415-PM", time: "2026-04-15 20:00", passed: 70, failed: 5,  warned: 3, total: 78 },
  { runId: "RUN-2026-0415-AM", time: "2026-04-15 08:00", passed: 69, failed: 6,  warned: 3, total: 78 },
  { runId: "RUN-2026-0414-PM", time: "2026-04-14 20:00", passed: 68, failed: 7,  warned: 3, total: 78 },
  { runId: "RUN-2026-0414-AM", time: "2026-04-14 08:00", passed: 67, failed: 8,  warned: 3, total: 78 },
  { runId: "RUN-2026-0413-PM", time: "2026-04-13 20:00", passed: 66, failed: 9,  warned: 3, total: 78 },
  { runId: "RUN-2026-0413-AM", time: "2026-04-13 08:00", passed: 65, failed: 10, warned: 3, total: 78 },
  { runId: "RUN-2026-0412-PM", time: "2026-04-12 20:00", passed: 64, failed: 11, warned: 3, total: 78 },
];

// ── Helpers ─────────────────────────────────────────────────────

function ControlStatusIcon({ status }: { status: string }) {
  if (status === "pass") return <CheckCircle className="h-4 w-4 text-green-400" />;
  if (status === "fail") return <XCircle className="h-4 w-4 text-red-400" />;
  if (status === "warn") return <AlertTriangle className="h-4 w-4 text-amber-400" />;
  return <span className="text-muted-foreground text-xs">—</span>;
}

function TestTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    automated:       "border-blue-500/30 text-blue-400 bg-blue-500/10",
    manual:          "border-purple-500/30 text-purple-400 bg-purple-500/10",
    self_assessment: "border-amber-500/30 text-amber-400 bg-amber-500/10",
  };
  const label: Record<string, string> = {
    automated: "Auto", manual: "Manual", self_assessment: "Self-Assess",
  };
  return <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>{label[type] ?? type}</Badge>;
}

function FwBadge({ fw }: { fw: string }) {
  return <Badge className="text-[10px] border border-border text-muted-foreground">{fw}</Badge>;
}

function FrameworkStatusBadge({ status }: { status: string }) {
  if (status === "pass") return <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Passing</Badge>;
  if (status === "warn") return <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">Needs Attention</Badge>;
  return <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">Failing</Badge>;
}

function FailureTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    gap:               "border-red-500/30 text-red-400 bg-red-500/10",
    regression:        "border-orange-500/30 text-orange-400 bg-orange-500/10",
    exception:         "border-amber-500/30 text-amber-400 bg-amber-500/10",
    design_deficiency: "border-purple-500/30 text-purple-400 bg-purple-500/10",
  };
  const label: Record<string, string> = {
    gap: "Gap", regression: "Regression", exception: "Exception", design_deficiency: "Design Deficiency",
  };
  return <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>{label[type] ?? type}</Badge>;
}

function SeverityDot({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "bg-red-500", high: "bg-amber-500", medium: "bg-yellow-500", low: "bg-muted-foreground",
  };
  return <span className={cn("inline-block h-2 w-2 rounded-full shrink-0", map[severity] ?? "bg-muted")} title={severity} />;
}

function PassRateBar({ rate }: { rate: number }) {
  const color = rate >= 90 ? "bg-green-500" : rate >= 80 ? "bg-amber-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full bg-muted/30 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${rate}%` }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          className={cn("h-full rounded-full", color)}
        />
      </div>
      <span className={cn("text-xs font-bold tabular-nums w-8 text-right", rate >= 90 ? "text-green-400" : rate >= 80 ? "text-amber-400" : "text-red-400")}>
        {rate}%
      </span>
    </div>
  );
}

// ── Component ───────────────────────────────────────────────────

export default function CCMDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/ccm/orgs/${ORG_ID}/stats`),
      apiFetch(`/api/v1/ccm/orgs/${ORG_ID}/controls`),
      apiFetch(`/api/v1/ccm/orgs/${ORG_ID}/failures?remediated=false`),
    ]).then(([statsResult, controlsResult, failuresResult]) => {
      const stats    = statsResult.status    === "fulfilled" ? statsResult.value    : null;
      const controls = controlsResult.status === "fulfilled" ? controlsResult.value : null;
      const failures = failuresResult.status === "fulfilled" ? failuresResult.value : null;
      if (stats || controls || failures) {
        setLiveData({ stats, controls, failures });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Continuous Control Monitoring"
        description="Automated control testing, failure detection, and remediation tracking"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Controls Monitored" value={liveData?.stats?.total_controls ?? 87}    icon={ShieldCheck}   className="border-blue-500/20" />
        <KpiCard title="Pass Rate"          value={liveData?.stats?.pass_rate != null ? `${liveData.stats.pass_rate}%` : "81%"}   icon={CheckCircle}   trend="up" className="border-green-500/20" />
        <KpiCard title="Open Failures"      value={liveData?.stats?.open_failures ?? liveData?.stats?.total_failures ?? 12}    icon={XCircle}       trend="up" className="border-red-500/20" />
        <KpiCard title="Untested Controls"  value={liveData?.stats?.untested_controls ?? 9}     icon={AlertTriangle} className="border-amber-500/20" />
      </div>

      {/* Framework coverage */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-blue-400" />
            Control Coverage by Framework
          </CardTitle>
          <CardDescription className="text-xs">Pass / fail counts and pass rate per compliance framework</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="text-[11px] h-8">Framework</TableHead>
                <TableHead className="text-[11px] h-8 text-right">Total</TableHead>
                <TableHead className="text-[11px] h-8 text-right">Passing</TableHead>
                <TableHead className="text-[11px] h-8 text-right">Failing</TableHead>
                <TableHead className="text-[11px] h-8">Pass Rate</TableHead>
                <TableHead className="text-[11px] h-8">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {FRAMEWORKS.map((fw) => (
                <TableRow key={fw.name} className="hover:bg-muted/30">
                  <TableCell className="text-xs font-medium py-2.5">{fw.name}</TableCell>
                  <TableCell className="text-xs py-2.5 text-right tabular-nums text-muted-foreground">{fw.total}</TableCell>
                  <TableCell className="text-xs py-2.5 text-right tabular-nums text-green-400 font-medium">{fw.passing}</TableCell>
                  <TableCell className="text-xs py-2.5 text-right tabular-nums text-red-400 font-medium">{fw.failing}</TableCell>
                  <TableCell className="py-2.5 w-40"><PassRateBar rate={fw.passRate} /></TableCell>
                  <TableCell className="py-2.5"><FrameworkStatusBadge status={fw.status} /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Control test results */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-green-400" />
              Control Test Results
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">{CONTROLS.length} controls shown</Badge>
          </div>
          <CardDescription className="text-xs">Latest test status for each monitored control</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Control Ref</TableHead>
                  <TableHead className="text-[11px] h-8">Name</TableHead>
                  <TableHead className="text-[11px] h-8">Framework</TableHead>
                  <TableHead className="text-[11px] h-8">Test Type</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Last Run</TableHead>
                  <TableHead className="text-[11px] h-8">Next Run</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.controls?.items ?? liveData?.controls ?? CONTROLS).map((row: any, i: number) => (
                  <TableRow key={i} className={cn("hover:bg-muted/30", row.status === "fail" && "bg-red-500/5")}>
                    <TableCell className="text-xs font-mono py-2.5">{row.ref}</TableCell>
                    <TableCell className="text-xs py-2.5 max-w-[200px] truncate">{row.name}</TableCell>
                    <TableCell className="py-2.5"><FwBadge fw={row.fw} /></TableCell>
                    <TableCell className="py-2.5"><TestTypeBadge type={row.type} /></TableCell>
                    <TableCell className="py-2.5 text-center"><ControlStatusIcon status={row.status} /></TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{row.lastRun}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{row.nextRun}</TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">
                        <Play className="h-3 w-3 mr-1" /> Run Now
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Failure tracker + Test history */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Failure tracker */}
        <Card className="border-red-500/20">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
                <XCircle className="h-4 w-4" />
                Open Failure Tracker
              </CardTitle>
              <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">{(liveData?.failures?.items ?? liveData?.failures ?? FAILURES).length} open</Badge>
            </div>
            <CardDescription className="text-xs">Active control failures requiring remediation</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {(liveData?.failures?.items ?? liveData?.failures ?? FAILURES).map((f: any, i: number) => (
              <div key={i} className="flex items-start gap-3 rounded-lg border border-border bg-muted/20 px-3 py-2.5">
                <SeverityDot severity={f.severity} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <FailureTypeBadge type={f.type} />
                  </div>
                  <p className="text-xs mt-1 truncate font-medium">{f.control}</p>
                  <p className="text-[10px] text-muted-foreground mt-0.5">Detected: {f.detected}</p>
                </div>
                <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] shrink-0">
                  Remediate
                </Button>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Test history */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Clock className="h-4 w-4 text-purple-400" />
              Test Run History
            </CardTitle>
            <CardDescription className="text-xs">Last 8 automated test runs with pass/fail summary</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {TEST_HISTORY.map((run, i) => {
              const passRate = Math.round((run.passed / run.total) * 100);
              return (
                <div key={i} className="flex items-center gap-3 rounded-lg border border-border bg-muted/20 px-3 py-2.5">
                  <div className="flex items-center gap-1.5 shrink-0">
                    {run.failed > 0 ? (
                      <XCircle className="h-3.5 w-3.5 text-red-400" />
                    ) : (
                      <CheckCircle className="h-3.5 w-3.5 text-green-400" />
                    )}
                    {run.warned > 0 && <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono text-muted-foreground truncate">{run.runId}</span>
                      <span className={cn("font-bold tabular-nums ml-2 shrink-0", passRate >= 90 ? "text-green-400" : "text-amber-400")}>{passRate}%</span>
                    </div>
                    <p className="text-[10px] text-muted-foreground mt-0.5">{run.time}</p>
                    <div className="flex items-center gap-3 mt-1.5 text-[10px]">
                      <span className="text-green-400">✓ {run.passed} passed</span>
                      {run.failed > 0 && <span className="text-red-400">✗ {run.failed} failed</span>}
                      {run.warned > 0 && <span className="text-amber-400">⚠ {run.warned} warned</span>}
                    </div>
                  </div>
                  <div className="w-20 shrink-0">
                    <Progress value={passRate} className="h-1.5" />
                  </div>
                </div>
              );
            })}
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
