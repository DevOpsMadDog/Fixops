/**
 * Configuration Benchmarks Dashboard
 *
 * CIS, DISA STIG, and custom hardening assessments.
 *   1. KPIs: Profiles, Assessments Run, Avg Score, Critical Failures
 *   2. Assessment profiles table (8 rows)
 *   3. Latest assessment results (12 check results)
 *   4. Failed checks drill-down (8 failed checks, expandable accordion)
 *   5. Score by standard bar chart (5 bars)
 */

import { useState, useEffect } from "react";
import { getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { motion } from "framer-motion";
import { ClipboardCheck, Shield, AlertTriangle, RefreshCw, BarChart3, ChevronDown, ChevronRight, CheckCircle2, XCircle, Minus } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY;
const ORG_ID = (getStoredOrgId() ?? "default");

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────





// ── Helpers ────────────────────────────────────────────────────

const STANDARD_COLORS: Record<string, string> = {
  "CIS":          "border-blue-500/30 text-blue-400 bg-blue-500/10",
  "DISA STIG":    "border-purple-500/30 text-purple-400 bg-purple-500/10",
  "NIST 800-53":  "border-green-500/30 text-green-400 bg-green-500/10",
  "PCI DSS":      "border-orange-500/30 text-orange-400 bg-orange-500/10",
};

const TARGET_COLORS: Record<string, string> = {
  "Linux":      "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  "Cloud":      "border-blue-500/30 text-blue-400 bg-blue-500/10",
  "Container":  "border-purple-500/30 text-purple-400 bg-purple-500/10",
  "Network":    "border-green-500/30 text-green-400 bg-green-500/10",
  "Web Server": "border-amber-500/30 text-amber-400 bg-amber-500/10",
  "Full Stack": "border-red-500/30 text-red-400 bg-red-500/10",
};

function ScoreBar({ score }: { score: number }) {
  const color = score >= 80 ? "bg-green-500" : score >= 60 ? "bg-amber-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-24 rounded-full bg-muted/30 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          className={cn("h-full rounded-full", color)}
        />
      </div>
      <span className={cn("text-xs font-bold tabular-nums", score >= 80 ? "text-green-400" : score >= 60 ? "text-amber-400" : "text-red-400")}>
        {score}%
      </span>
    </div>
  );
}

const CATEGORY_COLORS: Record<string, string> = {
  "Filesystem":  "border-blue-500/30 text-blue-400 bg-blue-500/10",
  "Services":    "border-purple-500/30 text-purple-400 bg-purple-500/10",
  "Network":     "border-green-500/30 text-green-400 bg-green-500/10",
  "Logging":     "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  "SSH":         "border-amber-500/30 text-amber-400 bg-amber-500/10",
  "Access":      "border-red-500/30 text-red-400 bg-red-500/10",
  "Permissions": "border-orange-500/30 text-orange-400 bg-orange-500/10",
  "Accounts":    "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
};

function SevBadge({ sev }: { sev: string }) {
  const cls =
    sev === "High"   ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    sev === "Medium" ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                       "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{sev}</Badge>;
}

function StatusIcon({ status }: { status: string }) {
  if (status === "pass") return <CheckCircle2 className="h-4 w-4 text-green-400" />;
  if (status === "fail") return <XCircle className="h-4 w-4 text-red-400" />;
  if (status === "warn") return <AlertTriangle className="h-4 w-4 text-amber-400" />;
  return <Minus className="h-4 w-4 text-muted-foreground" />;
}

// ── Component ──────────────────────────────────────────────────

const arr = (v: any): any[] => (Array.isArray(v) ? v : []);
export default function ConfigBenchmarkDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [expandedCheck, setExpandedCheck] = useState<string | null>(null);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/config-benchmark/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/config-benchmark/profiles?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/config-benchmark/assessments?org_id=${ORG_ID}`),
    ]).then(([statsResult, profilesResult, assessmentsResult]) => {
      const stats       = statsResult.status       === "fulfilled" ? statsResult.value       : null;
      const profiles    = profilesResult.status    === "fulfilled" ? profilesResult.value    : null;
      const assessments = assessmentsResult.status === "fulfilled" ? assessmentsResult.value : null;
      if (stats || profiles || assessments) {
        setLiveData({ stats, profiles, assessments });
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
      {/* Header */}
      <PageHeader
        title="Configuration Benchmarks"
        description="CIS, DISA STIG, and custom hardening assessments"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Profiles"          value={liveData?.stats?.total_profiles ?? liveData?.profiles?.length ?? 8}      icon={ClipboardCheck} trend="up" />
        <KpiCard title="Assessments Run"   value={liveData?.stats?.total_assessments ?? liveData?.assessments?.length ?? 34}     icon={Shield}         trend="up" />
        <KpiCard title="Avg Score"         value={liveData?.stats?.avg_score ? `${liveData.stats.avg_score.toFixed(1)}%` : "65.2%"}  icon={BarChart3}      trend="up"   className="border-amber-500/20" />
        <KpiCard title="Critical Failures" value={liveData?.stats?.critical_failures ?? liveData?.stats?.failed_checks ?? 23}     icon={AlertTriangle}  trend="down" className="border-red-500/20" />
      </div>

      {/* Assessment Profiles */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <ClipboardCheck className="h-4 w-4 text-blue-400" />
              Assessment Profiles
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">{(liveData?.profiles ?? []).length} profiles</Badge>
          </div>
          <CardDescription className="text-xs">Hardening standard configurations and last assessment results</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Profile Name</TableHead>
                  <TableHead className="text-[11px] h-8">Standard</TableHead>
                  <TableHead className="text-[11px] h-8">Target</TableHead>
                  <TableHead className="text-[11px] h-8">Version</TableHead>
                  <TableHead className="text-[11px] h-8">Last Assessed</TableHead>
                  <TableHead className="text-[11px] h-8">Score</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.profiles ?? []).length === 0 ? (
                  <TableRow><TableCell colSpan={7}><EmptyState icon={ClipboardCheck} title="No profiles yet" description="Assessment profiles will appear here once configured." /></TableCell></TableRow>
                ) : (arr(liveData?.profiles ?? [])).map((p: any) => (
                  <TableRow key={p.name ?? p.profile_id} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5 max-w-[180px] truncate">{p.name}</TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", STANDARD_COLORS[p.standard] ?? "border-border text-muted-foreground")}>{p.standard}</Badge>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", TARGET_COLORS[p.target ?? p.target_type] ?? "border-border text-muted-foreground")}>{p.target ?? p.target_type}</Badge>
                    </TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground font-mono">{p.version}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{p.last_assessed ?? p.created_at ?? "—"}</TableCell>
                    <TableCell className="py-2.5"><ScoreBar score={p.score ?? 0} /></TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">Assess Now</Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Latest Assessment Results + Score by Standard */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Check Results — spans 2 cols */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Shield className="h-4 w-4 text-purple-400" />
                Latest Assessment Results
              </CardTitle>
              <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                <CheckCircle2 className="h-3 w-3 text-green-400" /> Pass
                <XCircle className="h-3 w-3 text-red-400" /> Fail
                <AlertTriangle className="h-3 w-3 text-amber-400" /> Warn
              </div>
            </div>
            <CardDescription className="text-xs">CIS Ubuntu 22.04 L2 — Apr 15 2026</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8 w-8"></TableHead>
                    <TableHead className="text-[11px] h-8">Ref</TableHead>
                    <TableHead className="text-[11px] h-8">Title</TableHead>
                    <TableHead className="text-[11px] h-8">Category</TableHead>
                    <TableHead className="text-[11px] h-8">Severity</TableHead>
                    <TableHead className="text-[11px] h-8">Actual</TableHead>
                    <TableHead className="text-[11px] h-8">Expected</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(liveData?.assessments?.items ?? liveData?.assessments ?? liveData?.check_results ?? []).length === 0 ? (
                    <TableRow><TableCell colSpan={7}><EmptyState icon={Shield} title="No assessment results yet" description="Check results will appear here once an assessment runs." /></TableCell></TableRow>
                  ) : (arr(liveData?.assessments?.items ?? liveData?.assessments ?? liveData?.check_results ?? [])).map((c: any) => (
                    <TableRow key={c.ref ?? c.id} className="hover:bg-muted/30">
                      <TableCell className="py-2.5 w-8"><StatusIcon status={c.status} /></TableCell>
                      <TableCell className="text-[10px] font-mono py-2.5 text-muted-foreground whitespace-nowrap">{c.ref}</TableCell>
                      <TableCell className="text-xs py-2.5 max-w-[200px] truncate">{c.title}</TableCell>
                      <TableCell className="py-2.5">
                        <Badge className={cn("text-[10px] border", CATEGORY_COLORS[c.category] ?? "border-border text-muted-foreground")}>{c.category}</Badge>
                      </TableCell>
                      <TableCell className="py-2.5"><SevBadge sev={c.severity} /></TableCell>
                      <TableCell className="text-[10px] py-2.5 font-mono text-muted-foreground max-w-[100px] truncate">{c.actual}</TableCell>
                      <TableCell className="text-[10px] py-2.5 font-mono text-muted-foreground max-w-[100px] truncate">{c.expected}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Score by Standard */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-green-400" />
              Score by Standard
            </CardTitle>
            <CardDescription className="text-xs">Average score across all profiles per standard</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 pt-2">
            {(liveData?.stats?.score_by_standard ?? liveData?.score_by_standard ?? []).length === 0 ? (
              <EmptyState icon={BarChart3} title="No score data yet" description="Scores by standard will appear here once assessments run." />
            ) : (arr(liveData?.stats?.score_by_standard ?? liveData?.score_by_standard ?? [])).map((s: any) => (
              <div key={s.standard} className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">{s.standard}</span>
                  <span className={cn("font-bold tabular-nums", s.score >= 80 ? "text-green-400" : s.score >= 60 ? "text-amber-400" : "text-red-400")}>
                    {s.score}%
                  </span>
                </div>
                <div className="h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${s.score}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={cn("h-full rounded-full", s.score >= 80 ? "bg-green-500" : s.score >= 60 ? "bg-amber-500" : "bg-red-500")}
                  />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Failed Checks Accordion */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <XCircle className="h-4 w-4" />
              Failed Checks — Remediation Guide
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">{(liveData?.failed_checks?.items ?? liveData?.failed_checks ?? []).length} failed</Badge>
          </div>
          <CardDescription className="text-xs">Click a check to expand remediation steps</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {(liveData?.failed_checks?.items ?? liveData?.failed_checks ?? []).length === 0 ? (
            <EmptyState icon={XCircle} title="No failed checks" description="Failed checks with remediation guidance will appear here once assessments run." />
          ) : (arr(liveData?.failed_checks?.items ?? liveData?.failed_checks ?? [])).map((fc: any) => {
            const isOpen = expandedCheck === fc.ref;
            return (
              <div key={fc.ref ?? fc.id} className="rounded-md border border-border/60 overflow-hidden">
                <button
                  className="w-full flex items-center gap-3 px-3 py-2.5 text-left hover:bg-muted/30 transition-colors"
                  onClick={() => setExpandedCheck(isOpen ? null : (fc.ref ?? fc.id))}
                >
                  {isOpen
                    ? <ChevronDown className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                    : <ChevronRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                  }
                  <span className="text-[10px] font-mono text-muted-foreground w-24 shrink-0">{fc.ref}</span>
                  <span className="text-xs flex-1 truncate">{fc.title}</span>
                  <SevBadge sev={fc.severity} />
                </button>
                {isOpen && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.2 }}
                    className="px-4 pb-3 pt-1 border-t border-border/40 bg-muted/10"
                  >
                    <p className="text-xs text-muted-foreground leading-relaxed font-mono whitespace-pre-wrap">{fc.remediation}</p>
                  </motion.div>
                )}
              </div>
            );
          })}
        </CardContent>
      </Card>
    </motion.div>
  );
}
