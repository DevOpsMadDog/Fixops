/**
 * Executive Briefing
 *
 * Board-level security posture summary — Q2 2026.
 *   1. Top risk indicators (3 large colored boxes)
 *   2. Security investment ROI table
 *   3. Regulatory compliance grid (6 frameworks)
 *   4. Incident trend year-over-year
 *   5. Top 5 risks for board review
 *   6. Security budget utilization bars
 *
 * Route: /executive-briefing
 * API stub: GET /api/v1/executive/briefing
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";

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
import {
  Shield, AlertTriangle, CheckCircle2, TrendingDown,
  TrendingUp, Download, RefreshCw, DollarSign,
  BarChart3, FileText,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const ROI_TABLE = [
  { control: "EDR / Endpoint Protection",   cost: "$42K/yr",  prevented: 18, avoided: "$1.8M", roi: 4186 },
  { control: "SIEM + SOC Coverage",         cost: "$85K/yr",  prevented: 12, avoided: "$2.4M", roi: 2724 },
  { control: "Identity & Access Mgmt (IAM)",cost: "$28K/yr",  prevented: 9,  avoided: "$720K",  roi: 2471 },
  { control: "Vulnerability Management",    cost: "$35K/yr",  prevented: 31, avoided: "$620K",  roi: 1671 },
  { control: "Security Awareness Training", cost: "$12K/yr",  prevented: 7,  avoided: "$140K",  roi: 1067 },
];

const FRAMEWORKS = [
  { name: "SOC 2 Type II", pct: 94, status: "compliant"     },
  { name: "ISO 27001",     pct: 88, status: "compliant"     },
  { name: "PCI-DSS v4",   pct: 71, status: "at-risk"       },
  { name: "HIPAA",         pct: 83, status: "compliant"     },
  { name: "GDPR",          pct: 79, status: "at-risk"       },
  { name: "NIST CSF 2.0",  pct: 62, status: "non-compliant" },
];

const BOARD_RISKS = [
  {
    title: "Ransomware targeting finance division",
    impact: "$4.2M",
    likelihood: "High",
    action: "Mitigate",
    color: "border-red-500/30 bg-red-500/5",
  },
  {
    title: "Third-party supplier data breach exposure",
    impact: "$2.8M",
    likelihood: "High",
    action: "Transfer",
    color: "border-red-500/30 bg-red-500/5",
  },
  {
    title: "Cloud misconfiguration leading to data loss",
    impact: "$1.9M",
    likelihood: "Medium",
    action: "Mitigate",
    color: "border-amber-500/30 bg-amber-500/5",
  },
  {
    title: "Regulatory non-compliance penalty (NIST CSF)",
    impact: "$850K",
    likelihood: "Medium",
    action: "Mitigate",
    color: "border-amber-500/30 bg-amber-500/5",
  },
  {
    title: "Insider threat — privileged account misuse",
    impact: "$320K",
    likelihood: "Low",
    action: "Accept",
    color: "border-border bg-muted/10",
  },
];

const BUDGET = [
  { category: "Prevention",  allocated: 380, spent: 312, color: "bg-blue-500"   },
  { category: "Detection",   allocated: 220, spent: 198, color: "bg-purple-500" },
  { category: "Response",    allocated: 140, spent: 89,  color: "bg-amber-500"  },
  { category: "Compliance",  allocated: 95,  spent: 87,  color: "bg-green-500"  },
  { category: "Training",    allocated: 45,  spent: 31,  color: "bg-cyan-500"   },
];

const BUDGET_MAX = 380;

// ── Helpers ────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === "compliant"     ? "border-green-500/30 text-green-400 bg-green-500/10" :
    status === "at-risk"       ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
                                 "border-red-500/30 text-red-400 bg-red-500/10";
  const label =
    status === "compliant"     ? "Compliant" :
    status === "at-risk"       ? "At Risk"   :
                                 "Non-Compliant";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{label}</Badge>;
}

function ActionBadge({ action }: { action: string }) {
  const cls =
    action === "Mitigate" ? "border-blue-500/30 text-blue-400 bg-blue-500/10"     :
    action === "Transfer" ? "border-purple-500/30 text-purple-400 bg-purple-500/10" :
                            "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{action}</Badge>;
}

function LikelihoodBadge({ l }: { l: string }) {
  const cls =
    l === "High"   ? "border-red-500/30 text-red-400 bg-red-500/10"     :
    l === "Medium" ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
                     "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{l}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function ExecutiveBriefing() {
  const [refreshing, setRefreshing]   = useState(false);
  const [liveData, setLiveData]       = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/kpis/executive?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/posture-advisor/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/incidents/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/executive/kpis?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/executive/risk-summary?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/executive/trends?weeks=12`),
      apiFetch(`/api/v1/ciso-report/executive-summary?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/ciso-report/top-risks?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/compliance-evidence/stats?org_id=${ORG_ID}`),
    ]).then(([kpiResult, postureResult, incidentResult, execKpiResult, riskResult, trendResult, cisoSummaryResult, cisoRisksResult, evidenceStatsResult]) => {
      const kpis          = kpiResult.status           === "fulfilled" ? kpiResult.value           : null;
      const posture       = postureResult.status       === "fulfilled" ? postureResult.value       : null;
      const incidents     = incidentResult.status      === "fulfilled" ? incidentResult.value      : null;
      const execKpis      = execKpiResult.status       === "fulfilled" ? execKpiResult.value       : null;
      const riskSummary   = riskResult.status          === "fulfilled" ? riskResult.value          : null;
      const trends        = trendResult.status         === "fulfilled" ? trendResult.value         : null;
      const cisoSummary   = cisoSummaryResult.status   === "fulfilled" ? cisoSummaryResult.value   : null;
      const cisoRisks     = cisoRisksResult.status     === "fulfilled" ? cisoRisksResult.value     : null;
      const evidenceStats = evidenceStatsResult.status === "fulfilled" ? evidenceStatsResult.value : null;
      if (kpis || posture || incidents || execKpis || riskSummary || trends || cisoSummary || cisoRisks || evidenceStats) {
        setLiveData({ kpis, posture, incidents, execKpis, riskSummary, trends, cisoSummary, cisoRisks, evidenceStats });
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); 
    setLoading(false);}, []);

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
        title="Executive Security Briefing"
        description="Board-level security posture summary — Q2 2026"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => { setRefreshing(true); fetchData(); setTimeout(() => setRefreshing(false), 800); }} disabled={refreshing || dataLoading}>
              <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
            </Button>
            <Button size="sm" className="gap-1.5">
              <Download className="h-4 w-4" />
              Export PDF
            </Button>
          </div>
        }
      />

      {/* Top risk indicators */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-6 flex flex-col items-center gap-2">
          <AlertTriangle className="h-8 w-8 text-red-400" />
          <span className="text-5xl font-black text-red-400 tabular-nums">
            {liveData?.incidents?.critical_count ?? liveData?.execKpis?.breached_count ?? liveData?.kpis?.critical_findings ?? 4}
          </span>
          <span className="text-sm font-semibold text-red-300">Critical Threats</span>
          <span className="text-[11px] text-muted-foreground text-center">Require immediate board attention</span>
        </div>
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-6 flex flex-col items-center gap-2">
          <Shield className="h-8 w-8 text-amber-400" />
          <span className="text-5xl font-black text-amber-400 tabular-nums">
            {liveData?.kpis?.open_findings ?? liveData?.incidents?.open_count ?? 47}
          </span>
          <span className="text-sm font-semibold text-amber-300">High Findings</span>
          <span className="text-[11px] text-muted-foreground text-center">Open security vulnerabilities</span>
        </div>
        <div className="rounded-xl border border-green-500/30 bg-green-500/10 p-6 flex flex-col items-center gap-2">
          <CheckCircle2 className="h-8 w-8 text-green-400" />
          <span className="text-5xl font-black text-green-400 tabular-nums">
            {liveData?.evidenceStats?.overall_readiness_pct != null
              ? `${liveData.evidenceStats.overall_readiness_pct}%`
              : liveData?.posture?.overall_score != null
              ? `${liveData.posture.overall_score}%`
              : liveData?.execKpis?.overall_health_score != null
              ? `${Math.round(liveData.execKpis.overall_health_score)}%`
              : liveData?.kpis?.compliance_score != null
              ? `${liveData.kpis.compliance_score}%`
              : "87%"
    setLoading(false);}
          </span>
          <span className="text-sm font-semibold text-green-300">Compliance Score</span>
          <span className="text-[11px] text-muted-foreground text-center">Across 6 regulatory frameworks</span>
        </div>
      </div>

      {/* ROI table + Compliance grid */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* ROI table */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <DollarSign className="h-4 w-4 text-green-400" />
              Security Investment ROI
            </CardTitle>
            <CardDescription className="text-xs">Cost vs. incidents prevented — sorted by ROI descending</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Control</TableHead>
                    <TableHead className="text-[11px] h-8">Cost</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Prevented</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Cost Avoided</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">ROI</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {ROI_TABLE.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                      <p className="text-lg font-medium">No data available</p>
                      <p className="text-sm">Data will appear here once available</p>
                    </div>
                  ) : (
                    ROI_TABLE.map((r) => (
                    <TableRow key={r.control} className="hover:bg-muted/30">
                      <TableCell className="text-xs py-2.5 max-w-[140px] truncate">{r.control}</TableCell>
                      <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{r.cost}</TableCell>
                      <TableCell className="text-xs py-2.5 tabular-nums text-right">{r.prevented}</TableCell>
                      <TableCell className="text-xs py-2.5 tabular-nums text-right text-green-400 font-medium">{r.avoided}</TableCell>
                      <TableCell className="text-xs py-2.5 tabular-nums text-right font-bold text-green-400">{r.roi}%</TableCell>
                    </TableRow>
                  ))}
                  )}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Compliance grid */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <FileText className="h-4 w-4 text-blue-400" />
              Regulatory Compliance Grid
            </CardTitle>
            <CardDescription className="text-xs">6 framework compliance status</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {FRAMEWORKS.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              FRAMEWORKS.map((f) => (
              <div key={f.name} className="flex items-center gap-3">
                <span className="text-xs font-medium w-32 flex-shrink-0">{f.name}</span>
                <div className="flex-1 relative h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${f.pct}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={cn(
                      "h-full rounded-full",
                      f.status === "compliant"     ? "bg-green-500" :
                      f.status === "at-risk"       ? "bg-amber-500" : "bg-red-500"
                    )}
                  />
                </div>
                <span className="text-xs tabular-nums font-bold w-8 text-right">{f.pct}%</span>
                <StatusBadge status={f.status} />
              </div>
            ))}
            )}
          </CardContent>
        </Card>
      </div>

      {/* Incident trend YoY */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <TrendingDown className="h-4 w-4 text-green-400" />
            Incident Trend — Year-over-Year
          </CardTitle>
          <CardDescription className="text-xs">Security incidents: 2025 full year vs. 2026 YTD (Jan–Apr)</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-end gap-8 justify-center py-4">
            <div className="flex flex-col items-center gap-3">
              <div className="relative flex items-end justify-center">
                <motion.div
                  initial={{ height: 0 }}
                  animate={{ height: 140 }}
                  transition={{ duration: 0.8 }}
                  className="w-24 rounded-t-lg bg-red-500/40 border border-red-500/30 flex items-start justify-center pt-3"
                >
                  <span className="text-3xl font-black text-red-400">23</span>
                </motion.div>
              </div>
              <div className="text-center">
                <p className="text-sm font-semibold text-foreground">2025 Full Year</p>
                <p className="text-[11px] text-muted-foreground">23 total incidents</p>
              </div>
            </div>
            <div className="flex flex-col items-center gap-2 pb-8">
              <TrendingDown className="h-6 w-6 text-green-400" />
              <span className="text-lg font-bold text-green-400">-65%</span>
              <span className="text-[10px] text-muted-foreground">YoY pace</span>
            </div>
            <div className="flex flex-col items-center gap-3">
              <div className="relative flex items-end justify-center">
                <motion.div
                  initial={{ height: 0 }}
                  animate={{ height: 49 }}
                  transition={{ duration: 0.8 }}
                  className="w-24 rounded-t-lg bg-green-500/40 border border-green-500/30 flex items-start justify-center pt-3"
                >
                  <span className="text-3xl font-black text-green-400">8</span>
                </motion.div>
              </div>
              <div className="text-center">
                <p className="text-sm font-semibold text-foreground">2026 YTD</p>
                <p className="text-[11px] text-muted-foreground">8 incidents (Jan–Apr)</p>
              </div>
            </div>
          </div>
          <p className="text-center text-xs text-muted-foreground">
            At current pace: projected <strong className="text-green-400">24 incidents</strong> for full year 2026 — vs. 23 in 2025
          </p>
        </CardContent>
      </Card>

      {/* Board risks */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
            <AlertTriangle className="h-4 w-4" />
            Top 5 Risks for Board Review
          </CardTitle>
          <CardDescription className="text-xs">Business-impact risks requiring board-level awareness or decision</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {BOARD_RISKS.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            BOARD_RISKS.map((r, i) => (
            <div key={r.title} className={cn("flex items-start gap-3 p-3 rounded-lg border", r.color)}>
              <div className="flex-shrink-0 w-6 h-6 rounded-full bg-background border border-border flex items-center justify-center text-xs font-bold text-foreground">
                {i + 1}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium text-foreground">{r.title}</p>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-[11px] text-muted-foreground">Business impact:</span>
                  <span className="text-[11px] font-bold text-amber-400">{r.impact}</span>
                </div>
              </div>
              <div className="flex flex-col items-end gap-1.5 flex-shrink-0">
                <LikelihoodBadge l={r.likelihood} />
                <ActionBadge action={r.action} />
              </div>
            </div>
          ))}
          )}
        </CardContent>
      </Card>

      {/* Budget utilization */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-cyan-400" />
            Security Budget Utilization
          </CardTitle>
          <CardDescription className="text-xs">YTD spend vs. allocated budget by category (USD thousands)</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {BUDGET.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            BUDGET.map((b) => {
            const pctSpent = Math.round((b.spent / b.allocated) * 100);
            return (
              <div key={b.category} className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium">{b.category}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-muted-foreground tabular-nums">${b.spent}K / ${b.allocated}K</span>
                    <span className={cn(
                      "font-bold tabular-nums",
                      pctSpent > 90 ? "text-amber-400" : "text-muted-foreground"
                    )}>{pctSpent}%</span>
                  </div>
                </div>
                <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                  {/* Allocated track */}
                  <div className="absolute inset-0 rounded-full bg-muted/20" />
                  {/* Spent bar */}
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${(b.spent / BUDGET_MAX) * 100}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={cn("h-full rounded-full absolute left-0", b.color)}
                  />
                  {/* Allocated marker */}
                  <div
                    className="absolute top-0 bottom-0 w-0.5 bg-white/40"
                    style={{ left: `${(b.allocated / BUDGET_MAX) * 100}%` }}
                  />
                </div>
              </div>
            );
          })}
          )}
          <div className="flex items-center gap-4 pt-1 text-[10px] text-muted-foreground">
            <span className="flex items-center gap-1"><span className="w-3 h-1.5 rounded-sm bg-blue-500 inline-block" />Spent</span>
            <span className="flex items-center gap-1"><span className="w-0.5 h-3 bg-white/40 inline-block" />Allocated limit</span>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
