/**
 * GRC Dashboard
 *
 * Governance, Risk & Compliance management.
 *   1. KPIs: Frameworks, Avg Compliance Score, Open Risks, Controls Implemented
 *   2. Framework compliance bars
 *   3. Risk register table
 *   4. Control status breakdown
 *   5. Recent assessments
 *
 * API: GET /api/v1/grc/frameworks, /api/v1/grc/risks, /api/v1/grc/controls,
 *          /api/v1/grc/assessments, /api/v1/grc/stats
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Shield, AlertTriangle, CheckCircle, BarChart3, FileText, RefreshCw, ClipboardList } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
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
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

// ── Static config (colour maps only — no domain data) ──────────

// Control status colour map keyed by label from API
const CONTROL_COLOR: Record<string, string> = {
  implemented:     "bg-green-500/20 border-green-500/30 text-green-400",
  partial:         "bg-yellow-500/20 border-yellow-500/30 text-yellow-400",
  "not implemented": "bg-red-500/20 border-red-500/30 text-red-400",
  "n/a":           "bg-muted/30 border-border text-muted-foreground",
};

// ── Helpers ────────────────────────────────────────────────────

function CategoryBadge({ cat }: { cat: string }) {
  return (
    <Badge className="text-[10px] border border-border text-muted-foreground bg-muted/30 capitalize">
      {cat}
    </Badge>
  );
}

function TreatmentBadge({ t }: { t: string }) {
  const cls =
    t === "mitigate" ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
    t === "transfer" ? "border-purple-500/30 text-purple-400 bg-purple-500/10" :
                       "border-amber-500/30 text-amber-400 bg-amber-500/10";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{t}</Badge>;
}

function StatusBadge({ s }: { s: string }) {
  const cls =
    s === "resolved" || s === "passed"      ? "border-green-500/30 text-green-400 bg-green-500/10" :
    s === "in-progress" || s === "in-review" ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
    s === "remediate"                        ? "border-red-500/30 text-red-400 bg-red-500/10" :
    s === "accepted"                         ? "border-purple-500/30 text-purple-400 bg-purple-500/10" :
                                               "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{s}</Badge>;
}

function scoreColor(score: number) {
  if (score >= 80) return "text-green-400";
  if (score >= 60) return "text-yellow-400";
  return "text-red-400";
}

// ── Component ──────────────────────────────────────────────────

export default function GRCDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  const load = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/grc/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/grc/frameworks?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/grc/risks?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/grc/controls?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/grc/assessments?org_id=${ORG_ID}`),
    ]).then(([statsRes, frameworksRes, risksRes, controlsRes, assessmentsRes]) => {
      const stats       = statsRes.status       === "fulfilled" ? statsRes.value       : null;
      const frameworks  = frameworksRes.status  === "fulfilled" ? frameworksRes.value  : null;
      const risks       = risksRes.status       === "fulfilled" ? risksRes.value       : null;
      const controls    = controlsRes.status    === "fulfilled" ? controlsRes.value    : null;
      const assessments = assessmentsRes.status === "fulfilled" ? assessmentsRes.value : null;
      if (stats || frameworks || risks || controls || assessments) {
        setLiveData({ stats, frameworks, risks, controls, assessments });
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { load(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleRefresh = () => {
    setRefreshing(true);
    load();
    setTimeout(() => setRefreshing(false), 800);
  };

  // Resolve live arrays — empty array when API hasn't returned data
  const frameworks:  any[] = liveData?.frameworks  ?? [];
  const risks:       any[] = liveData?.risks        ?? [];
  const controls:    any[] = liveData?.controls     ?? [];
  const assessments: any[] = liveData?.assessments  ?? [];

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="GRC Dashboard"
        description="Governance, Risk & Compliance management"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard
          title="Frameworks"
          value={liveData?.stats?.total_frameworks ?? frameworks.length}
          icon={ClipboardList}
          trend="up"
          className="border-blue-500/20"
        />
        <KpiCard
          title="Avg Compliance"
          value={liveData?.stats?.avg_compliance_score != null
            ? `${liveData.stats.avg_compliance_score.toFixed(1)}%`
            : "—"}
          icon={Shield}
          trend="up"
          className="border-green-500/20"
        />
        <KpiCard
          title="Open Risks"
          value={liveData?.stats?.open_risks
            ?? risks.filter((r: any) => r.status === "open").length}
          icon={AlertTriangle}
          trend="down"
          className="border-amber-500/20"
        />
        <KpiCard
          title="Controls Impl."
          value={liveData?.stats?.implemented_pct != null
            ? `${liveData.stats.implemented_pct.toFixed(1)}%`
            : "—"}
          icon={CheckCircle}
          trend="up"
          className="border-purple-500/20"
        />
      </div>

      {/* Framework bars + Control status */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Framework compliance */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-blue-400" />
              Framework Compliance
            </CardTitle>
            <CardDescription className="text-xs">
              Current compliance score per framework (green ≥80%, yellow ≥60%, red &lt;60%)
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {frameworks.length === 0
              ? <EmptyState icon={BarChart3} title="No frameworks yet" description="Framework compliance data will appear here once synced." />
              : frameworks.map((f: any) => {
                  const score = f.compliance_score ?? f.score ?? 0;
                  const name  = f.name ?? f.framework_id ?? "—";
                  const colorCls = score >= 80 ? "bg-green-500" : score >= 60 ? "bg-yellow-500" : "bg-red-500";
                  const textCls  = score >= 80 ? "text-green-400" : score >= 60 ? "text-yellow-400" : "text-red-400";
                  return (
                    <div key={name} className="space-y-1.5">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-medium">{name}</span>
                        <span className={cn("font-bold tabular-nums", textCls)}>{score}%</span>
                      </div>
                      <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${score}%` }}
                          transition={{ duration: 0.8, ease: "easeOut" }}
                          className={cn("h-full rounded-full", colorCls)}
                        />
                      </div>
                    </div>
                  );
                })
            }
          </CardContent>
        </Card>

        {/* Control status + Recent assessments */}
        <div className="flex flex-col gap-4">
          {/* Control status */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-green-400" />
                Control Status Breakdown
              </CardTitle>
              <CardDescription className="text-xs">Controls across all frameworks</CardDescription>
            </CardHeader>
            <CardContent>
              {controls.length === 0
                ? <EmptyState icon={CheckCircle} title="No control data yet" description="Control status will appear once the compliance engine has run." />
                : (
                  <div className="grid grid-cols-2 gap-3">
                    {controls.map((c: any) => {
                      const label = c.label ?? c.status ?? "—";
                      const colorCls = CONTROL_COLOR[label.toLowerCase()] ?? "bg-muted/30 border-border text-muted-foreground";
                      return (
                        <div key={label} className={cn("rounded-lg border p-3 text-center", colorCls)}>
                          <div className="text-2xl font-bold tabular-nums">{c.count ?? 0}</div>
                          <div className="text-[10px] font-medium mt-0.5 capitalize">{label}</div>
                        </div>
                      );
                    })}
                  </div>
                )
              }
            </CardContent>
          </Card>

          {/* Recent assessments */}
          <Card className="flex-1">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <FileText className="h-4 w-4 text-indigo-400" />
                Recent Assessments
              </CardTitle>
              <CardDescription className="text-xs">Latest compliance assessments</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {assessments.length === 0
                ? <EmptyState icon={FileText} title="No assessments yet" description="Assessment results will appear here once completed." />
                : assessments.map((a: any, idx: number) => (
                    <div key={a.id ?? a.framework ?? idx} className="flex items-center justify-between p-2 rounded-lg bg-muted/20 border border-border/50">
                      <div className="min-w-0">
                        <div className="text-xs font-medium truncate">{a.framework_id ?? a.framework}</div>
                        <div className="text-[10px] text-muted-foreground">{a.assessor} · {a.assessment_date ?? a.date}</div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0 ml-2">
                        <span className={cn("text-xs font-bold tabular-nums", scoreColor(a.overall_score ?? a.score ?? 0))}>
                          {a.overall_score ?? a.score ?? 0}%
                        </span>
                        <StatusBadge s={a.status} />
                        <Button variant="ghost" size="sm" className="h-5 px-1.5 text-[9px]">View</Button>
                      </div>
                    </div>
                  ))
              }
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Risk register */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              Risk Register
            </CardTitle>
            <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">
              {risks.filter((r: any) => r.status === "open").length} open
            </Badge>
          </div>
          <CardDescription className="text-xs">Enterprise risk inventory — score = likelihood × impact</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {risks.length === 0
            ? (
              <div className="px-4 pb-4">
                <EmptyState icon={AlertTriangle} title="No risks yet" description="Risk register entries will appear here once imported." />
              </div>
            )
            : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="text-[11px] h-8">Risk Title</TableHead>
                      <TableHead className="text-[11px] h-8">Category</TableHead>
                      <TableHead className="text-[11px] h-8 text-center">L</TableHead>
                      <TableHead className="text-[11px] h-8 text-center">I</TableHead>
                      <TableHead className="text-[11px] h-8 text-center">Score</TableHead>
                      <TableHead className="text-[11px] h-8">Treatment</TableHead>
                      <TableHead className="text-[11px] h-8">Owner</TableHead>
                      <TableHead className="text-[11px] h-8">Status</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {risks.map((row: any) => {
                      const score = (row.likelihood ?? 1) * (row.impact ?? 1);
                      const scoreClr = score >= 16 ? "text-red-400" : score >= 9 ? "text-amber-400" : "text-yellow-400";
                      return (
                        <TableRow key={row.id ?? row.title} className="hover:bg-muted/30">
                          <TableCell className="text-xs py-2.5 max-w-[200px] truncate font-medium">{row.title}</TableCell>
                          <TableCell className="py-2.5"><CategoryBadge cat={row.category} /></TableCell>
                          <TableCell className="text-xs tabular-nums py-2.5 text-center">{row.likelihood}</TableCell>
                          <TableCell className="text-xs tabular-nums py-2.5 text-center">{row.impact}</TableCell>
                          <TableCell className={cn("text-xs tabular-nums py-2.5 font-bold text-center", scoreClr)}>{score}</TableCell>
                          <TableCell className="py-2.5"><TreatmentBadge t={row.treatment} /></TableCell>
                          <TableCell className="text-xs py-2.5 text-muted-foreground">{row.owner}</TableCell>
                          <TableCell className="py-2.5"><StatusBadge s={row.status} /></TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
            )
          }
        </CardContent>
      </Card>
    </motion.div>
  );
}
