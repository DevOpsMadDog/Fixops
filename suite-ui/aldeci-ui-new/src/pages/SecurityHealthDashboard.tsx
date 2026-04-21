/**
 * Security Health Dashboard
 *
 * Continuous health monitoring across all security domains.
 *   1. Overall health score (large centered gauge) + 7 domain health cards
 *   2. Health check details table (15 checks)
 *   3. 6 open incidents
 *   4. 30-day health trend (6 weekly bars)
 *
 * API stubs: GET /api/v1/security-health/score, /api/v1/security-health/domains, /api/v1/security-health/checks
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Shield, AlertTriangle, RefreshCw, Activity, CheckCircle, XCircle, BarChart3, Clock } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

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

const OVERALL_SCORE = 82;

const DOMAINS = [
  { name: "Network",     score: 88, status: "healthy",  last_checked: "2m ago" },
  { name: "Endpoint",    score: 74, status: "degraded", last_checked: "5m ago" },
  { name: "Identity",    score: 91, status: "healthy",  last_checked: "2m ago" },
  { name: "Cloud",       score: 79, status: "degraded", last_checked: "3m ago" },
  { name: "Data",        score: 85, status: "healthy",  last_checked: "4m ago" },
  { name: "Application", score: 68, status: "degraded", last_checked: "6m ago" },
  { name: "Compliance",  score: 78, status: "degraded", last_checked: "8m ago" },
];

const CHECKS = [
  { name: "Firewall Rule Integrity",        category: "Network",     status: "pass", score: 94, last_checked: "2m ago",  interval: "5m" },
  { name: "IDS/IPS Alert Rate",             category: "Network",     status: "pass", score: 87, last_checked: "2m ago",  interval: "5m" },
  { name: "EDR Agent Coverage",             category: "Endpoint",    status: "warn", score: 74, last_checked: "5m ago",  interval: "10m" },
  { name: "Patch Compliance Rate",          category: "Endpoint",    status: "warn", score: 71, last_checked: "5m ago",  interval: "1h" },
  { name: "MFA Enrollment Rate",            category: "Identity",    status: "pass", score: 95, last_checked: "2m ago",  interval: "15m" },
  { name: "Privileged Account Monitoring",  category: "Identity",    status: "pass", score: 91, last_checked: "2m ago",  interval: "5m" },
  { name: "Cloud Config Drift",             category: "Cloud",       status: "warn", score: 78, last_checked: "3m ago",  interval: "15m" },
  { name: "S3 Bucket ACL Hygiene",          category: "Cloud",       status: "fail", score: 52, last_checked: "3m ago",  interval: "1h" },
  { name: "DLP Policy Enforcement",         category: "Data",        status: "pass", score: 86, last_checked: "4m ago",  interval: "10m" },
  { name: "Encryption Key Rotation",        category: "Data",        status: "pass", score: 89, last_checked: "4m ago",  interval: "24h" },
  { name: "SAST Scan Coverage",             category: "Application", status: "warn", score: 69, last_checked: "6m ago",  interval: "1h" },
  { name: "API Rate Limit Violations",      category: "Application", status: "warn", score: 66, last_checked: "6m ago",  interval: "5m" },
  { name: "DAST Last Run Age",              category: "Application", status: "fail", score: 44, last_checked: "6m ago",  interval: "24h" },
  { name: "SOC2 Control Status",            category: "Compliance",  status: "pass", score: 84, last_checked: "8m ago",  interval: "1h" },
  { name: "PCI DSS Scan Currency",          category: "Compliance",  status: "warn", score: 62, last_checked: "8m ago",  interval: "24h" },
];

const INCIDENTS = [
  { id: "INC-081", sev: "High",   title: "S3 bucket ACL check failing — public read detected",   check: "S3 Bucket ACL Hygiene",    detected: "18m ago" },
  { id: "INC-082", sev: "High",   title: "DAST scan not run in 72h — coverage gap",             check: "DAST Last Run Age",         detected: "2h ago" },
  { id: "INC-083", sev: "Medium", title: "EDR agent offline on 12 endpoints",                   check: "EDR Agent Coverage",        detected: "34m ago" },
  { id: "INC-084", sev: "Medium", title: "Cloud config drift detected — 4 resources",           check: "Cloud Config Drift",        detected: "1h ago" },
  { id: "INC-085", sev: "Medium", title: "API abuse rate threshold breached on /v1/auth",       check: "API Rate Limit Violations", detected: "45m ago" },
  { id: "INC-086", sev: "Low",    title: "SAST coverage dropped below 70% threshold",           check: "SAST Scan Coverage",        detected: "3h ago" },
];

const TREND = [
  { week: "Mar 18", score: 71 },
  { week: "Mar 25", score: 74 },
  { week: "Apr 1",  score: 76 },
  { week: "Apr 8",  score: 79 },
  { week: "Apr 15", score: 80 },
  { week: "Apr 16", score: 82 },
];

const TREND_MAX = 100;

// ── Helpers ────────────────────────────────────────────────────

function DomainStatus({ s }: { s: string }) {
  const map: Record<string, string> = {
    healthy:  "border-green-500/30 text-green-400 bg-green-500/10",
    degraded: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[s] ?? "border-border text-muted-foreground")}>{s}</Badge>;
}

function CategoryBadge({ cat }: { cat: string }) {
  const map: Record<string, string> = {
    Network:     "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    Endpoint:    "border-purple-500/30 text-purple-400 bg-purple-500/10",
    Identity:    "border-blue-500/30 text-blue-400 bg-blue-500/10",
    Cloud:       "border-sky-500/30 text-sky-400 bg-sky-500/10",
    Data:        "border-indigo-500/30 text-indigo-400 bg-indigo-500/10",
    Application: "border-orange-500/30 text-orange-400 bg-orange-500/10",
    Compliance:  "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[cat] ?? "border-border text-muted-foreground")}>{cat}</Badge>;
}

function CheckStatusDot({ status }: { status: string }) {
  if (status === "pass") return <CheckCircle className="h-4 w-4 text-green-400" />;
  if (status === "fail") return <XCircle className="h-4 w-4 text-red-400" />;
  return <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />;
}

function SeverityBadge({ sev }: { sev: string }) {
  const cls =
    sev === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    sev === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    sev === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                         "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{sev}</Badge>;
}

function domainScoreColor(score: number) {
  if (score >= 80) return { bar: "bg-green-500", text: "text-green-400" };
  if (score >= 60) return { bar: "bg-amber-500", text: "text-amber-400" };
  return { bar: "bg-red-500", text: "text-red-400" };
}

// ── Component ──────────────────────────────────────────────────

export default function SecurityHealthDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<Record<string, any> | null>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/security-health/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/security-health/checks?org_id=${ORG_ID}&limit=20`),
      apiFetch(`/api/v1/security-health/incidents?org_id=${ORG_ID}&status=open`),
    ]).then(([statsResult, checksResult, incidentsResult]) => {
      const stats     = statsResult.status     === "fulfilled" ? statsResult.value     : null;
      const checks    = checksResult.status    === "fulfilled" ? checksResult.value    : null;
      const incidents = incidentsResult.status === "fulfilled" ? incidentsResult.value : null;
      if (stats || checks || incidents) {
        setLiveData({ stats, checks, incidents });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  const liveScore = liveData?.stats?.overall_score ?? liveData?.stats?.health_score ?? OVERALL_SCORE;
  const overallScore = typeof liveScore === "number" ? liveScore : OVERALL_SCORE;

  const overallColor =
    overallScore >= 80 ? "text-green-400" :
    overallScore >= 60 ? "text-amber-400" : "text-red-400";

  const overallLabel =
    overallScore >= 80 ? "Good" :
    overallScore >= 60 ? "Fair" : "Poor";

  const overallRingColor =
    overallScore >= 80 ? "stroke-green-500" :
    overallScore >= 60 ? "stroke-amber-500" : "stroke-red-500";

  // SVG circle gauge params
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (overallScore / 100) * circumference;

  const liveChecks    = liveData?.checks?.items    ?? liveData?.checks    ?? CHECKS;
  const liveIncidents = liveData?.incidents?.items ?? liveData?.incidents ?? INCIDENTS;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Security Health"
        description="Continuous health monitoring across all security domains"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* Overall Score + Domain Cards */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        {/* Gauge */}
        <Card className="flex flex-col items-center justify-center py-6 lg:col-span-1">
          <CardHeader className="pb-2 text-center">
            <CardTitle className="text-sm font-semibold flex items-center justify-center gap-2">
              <Shield className="h-4 w-4 text-blue-400" />
              Overall Health
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col items-center gap-2">
            <div className="relative w-36 h-36">
              <svg className="w-full h-full -rotate-90" viewBox="0 0 128 128">
                {/* Track */}
                <circle
                  cx="64" cy="64" r={radius}
                  fill="none"
                  strokeWidth="10"
                  className="stroke-muted/30"
                />
                {/* Progress */}
                <motion.circle
                  cx="64" cy="64" r={radius}
                  fill="none"
                  strokeWidth="10"
                  strokeLinecap="round"
                  strokeDasharray={circumference}
                  initial={{ strokeDashoffset: circumference }}
                  animate={{ strokeDashoffset: dashOffset }}
                  transition={{ duration: 1.2, ease: "easeOut" }}
                  className={overallRingColor}
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className={cn("text-4xl font-black tabular-nums", overallColor)}>{overallScore}</span>
                <span className={cn("text-sm font-semibold", overallColor)}>{overallLabel}</span>
              </div>
            </div>
            <span className="text-xs text-muted-foreground">out of 100</span>
          </CardContent>
        </Card>

        {/* Domain health cards (7 domains, 2 cols for remaining 3 cols) */}
        <div className="lg:col-span-3 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-3 xl:grid-cols-4">
          {DOMAINS.map((d) => {
            const colors = domainScoreColor(d.score);
            return (
              <Card key={d.name} className="p-3 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold">{d.name}</span>
                  <DomainStatus s={d.status} />
                </div>
                <div className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground">Score</span>
                    <span className={cn("font-bold tabular-nums", colors.text)}>{d.score}</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-muted/30 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${d.score}%` }}
                      transition={{ duration: 0.7, ease: "easeOut" }}
                      className={cn("h-full rounded-full", colors.bar)}
                    />
                  </div>
                </div>
                <div className="flex items-center gap-1 text-[10px] text-muted-foreground">
                  <Clock className="h-2.5 w-2.5" />
                  <span>{d.last_checked}</span>
                </div>
              </Card>
            );
          })}
        </div>
      </div>

      {/* Health Checks + Incidents */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Health Check Details */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-blue-400" />
              Health Check Details
            </CardTitle>
            <CardDescription className="text-xs">Individual control check status across all domains</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8 w-8" />
                    <TableHead className="text-[11px] h-8">Check Name</TableHead>
                    <TableHead className="text-[11px] h-8">Category</TableHead>
                    <TableHead className="text-[11px] h-8">Score</TableHead>
                    <TableHead className="text-[11px] h-8">Last Run</TableHead>
                    <TableHead className="text-[11px] h-8">Interval</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {liveChecks.map((row: any) => {
                    const colors = domainScoreColor(row.score);
                    return (
                      <TableRow key={row.name} className="hover:bg-muted/30">
                        <TableCell className="py-2.5 pl-4"><CheckStatusDot status={row.status} /></TableCell>
                        <TableCell className="text-xs py-2.5 font-medium max-w-[180px] truncate">{row.name}</TableCell>
                        <TableCell className="py-2.5"><CategoryBadge cat={row.category} /></TableCell>
                        <TableCell className="py-2.5 w-28">
                          <div className="flex items-center gap-2">
                            <div className="flex-1 h-1.5 rounded-full bg-muted/30 overflow-hidden">
                              <motion.div
                                initial={{ width: 0 }}
                                animate={{ width: `${row.score}%` }}
                                transition={{ duration: 0.6, ease: "easeOut" }}
                                className={cn("h-full rounded-full", colors.bar)}
                              />
                            </div>
                            <span className={cn("text-xs font-bold tabular-nums w-5", colors.text)}>{row.score}</span>
                          </div>
                        </TableCell>
                        <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{row.last_checked}</TableCell>
                        <TableCell className="text-xs py-2.5 text-muted-foreground">{row.interval}</TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Open Incidents + Trend */}
        <div className="flex flex-col gap-4">
          {/* Open Incidents */}
          <Card className="border-amber-500/20">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
                  <AlertTriangle className="h-4 w-4" />
                  Open Incidents
                </CardTitle>
                <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">{liveIncidents.length}</Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-2">
              {liveIncidents.map((inc: any) => (
                <div key={inc.id} className="rounded-lg border border-border/50 bg-muted/20 p-2.5 space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <SeverityBadge sev={inc.sev} />
                    <span className="text-[10px] text-muted-foreground">{inc.detected}</span>
                  </div>
                  <p className="text-xs leading-snug">{inc.title}</p>
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-muted-foreground font-mono">{inc.check}</span>
                    <Button variant="outline" size="sm" className="h-5 px-2 text-[9px]">Resolve</Button>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* 30-Day Trend */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <BarChart3 className="h-4 w-4 text-green-400" />
                30-Day Health Trend
              </CardTitle>
              <CardDescription className="text-xs">Weekly health score snapshots</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-end gap-2 h-28">
                {TREND.map((w, i) => {
                  const heightPct = (w.score / TREND_MAX) * 100;
                  const isLatest = i === TREND.length - 1;
                  return (
                    <div key={w.week} className="flex-1 flex flex-col items-center gap-1">
                      <span className={cn("text-[9px] font-bold tabular-nums", isLatest ? "text-green-400" : "text-muted-foreground")}>
                        {w.score}
                      </span>
                      <div className="w-full flex flex-col justify-end" style={{ height: "80px" }}>
                        <motion.div
                          initial={{ height: 0 }}
                          animate={{ height: `${heightPct}%` }}
                          transition={{ duration: 0.7, ease: "easeOut", delay: i * 0.05 }}
                          className={cn("w-full rounded-t", isLatest ? "bg-green-500" : "bg-blue-500/50")}
                          title={`${w.week}: ${w.score}`}
                        />
                      </div>
                      <span className="text-[9px] text-muted-foreground text-center leading-tight">{w.week}</span>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </motion.div>
  );
}
