/**
 * DevSecOps Dashboard
 *
 * Pipeline security gates, SAST/SCA/secrets scanning, and gate policies.
 *   1. KPIs: Active Pipelines, Pass Rate, Blocked Builds, Critical Findings
 *   2. Pipeline table (live)
 *   3. Build history timeline (live recent runs)
 *   4. Security findings table (live)
 *   5. Gate policies (static config — rule names, thresholds, CSS classes)
 */

import { useState, useEffect } from "react";
import { getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { motion } from "framer-motion";
import { GitBranch, Shield, AlertTriangle, RefreshCw, Code2, CheckCircle2, XCircle, Clock, Inbox } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  (getStoredAuthToken() ?? "");
const ORG_ID = (getStoredOrgId() ?? "default");

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

// ── Static config (NOT domain data — CSS maps, rule strings, threshold labels) ─

const GATE_POLICIES = [
  { name: "Critical Block",   rule: "block_on_critical = true",     threshold: "0 critical",    color: "text-red-400",    bg: "bg-red-500/10 border-red-500/20"       },
  { name: "High Threshold",   rule: "max_high = 5",                 threshold: "≤5 high",       color: "text-amber-400",  bg: "bg-amber-500/10 border-amber-500/20"   },
  { name: "Secrets Gate",     rule: "block_on_secrets = true",      threshold: "0 secrets",     color: "text-purple-400", bg: "bg-purple-500/10 border-purple-500/20" },
  { name: "SCA OSS Gate",     rule: "block_on_oss_critical = true", threshold: "0 OSS critical",color: "text-blue-400",   bg: "bg-blue-500/10 border-blue-500/20"     },
  { name: "Medium Threshold", rule: "max_medium = 20",              threshold: "≤20 medium",    color: "text-yellow-400", bg: "bg-yellow-500/10 border-yellow-500/20" },
  { name: "Coverage Gate",    rule: "min_sast_coverage = 80",       threshold: "≥80% coverage", color: "text-green-400",  bg: "bg-green-500/10 border-green-500/20"   },
];

const CI_COLORS: Record<string, string> = {
  "GitHub Actions": "border-purple-500/30 text-purple-400 bg-purple-500/10",
  "GitLab CI":      "border-orange-500/30 text-orange-400 bg-orange-500/10",
  "Jenkins":        "border-blue-500/30 text-blue-400 bg-blue-500/10",
  "CircleCI":       "border-green-500/30 text-green-400 bg-green-500/10",
  "Azure DevOps":   "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
};

const MAX_DURATION = 7;

// ── Helpers ────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === "passed"  ? "border-green-500/30 text-green-400 bg-green-500/10" :
    status === "failed"  ? "border-red-500/30 text-red-400 bg-red-500/10" :
    status === "blocked" ? "border-orange-500/30 text-orange-400 bg-orange-500/10" :
                           "border-border text-muted-foreground";
  const icon =
    status === "passed"  ? <CheckCircle2 className="h-3 w-3" /> :
    status === "failed"  ? <XCircle className="h-3 w-3" /> :
    status === "blocked" ? <AlertTriangle className="h-3 w-3" /> : null;
  return (
    <Badge className={cn("text-[10px] border flex items-center gap-1", cls)}>
      {icon}{status}
    </Badge>
  );
}

function SevDot({ sev }: { sev: string }) {
  const cls =
    sev === "Critical" ? "bg-red-500" :
    sev === "High"     ? "bg-amber-500" :
    sev === "Medium"   ? "bg-yellow-500" : "bg-green-500";
  return <span className={cn("inline-block h-2 w-2 rounded-full shrink-0", cls)} />;
}

function ScannerBadge({ type }: { type: string }) {
  const cls =
    type === "SAST"    ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
    type === "SCA"     ? "border-purple-500/30 text-purple-400 bg-purple-500/10" :
    type === "Secrets" ? "border-red-500/30 text-red-400 bg-red-500/10" :
                         "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{type}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function DevSecOpsDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/devsecops/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/devsecops/pipelines?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/devsecops/findings?org_id=${ORG_ID}&suppressed=false`),
    ]).then(([statsResult, pipelinesResult, findingsResult]) => {
      const stats     = statsResult.status     === "fulfilled" ? statsResult.value     : null;
      const pipelines = pipelinesResult.status === "fulfilled" ? pipelinesResult.value : null;
      const findings  = findingsResult.status  === "fulfilled" ? findingsResult.value  : null;
      if (stats || pipelines || findings) {
        setLiveData({ stats, pipelines, findings });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  const _arr = (v: any): any[] => (Array.isArray(v) ? v : []);
  const pipelines: any[] = _arr(liveData?.pipelines?.items ?? liveData?.pipelines);
  const builds: any[]    = _arr(liveData?.stats?.recent_builds ?? liveData?.pipelines?.recent_builds);
  const findings: any[]  = _arr(liveData?.findings?.items ?? liveData?.findings);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="DevSecOps"
        description="Pipeline security gates, SAST/SCA/secrets scanning, and gate policies"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Pipelines"  value={liveData?.stats?.total_pipelines ?? "—"}                                                          icon={GitBranch}     trend="up" />
        <KpiCard title="Pass Rate"         value={liveData?.stats?.pass_rate != null ? `${liveData.stats.pass_rate}%` : "—"}                        icon={CheckCircle2}  trend="down" className="border-amber-500/20" />
        <KpiCard title="Blocked Builds"    value={liveData?.stats?.blocked_runs ?? liveData?.stats?.total_blocked ?? "—"}                           icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="Critical Findings" value={liveData?.stats?.critical_findings ?? liveData?.stats?.findings_critical ?? "—"}                  icon={Shield}        trend="up"   className="border-red-500/20" />
      </div>

      {/* Pipeline Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <GitBranch className="h-4 w-4 text-blue-400" />
              Active Pipelines
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">{pipelines.length} pipelines</Badge>
          </div>
          <CardDescription className="text-xs">Current scan gate configuration per pipeline</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Pipeline</TableHead>
                  <TableHead className="text-[11px] h-8">CI Platform</TableHead>
                  <TableHead className="text-[11px] h-8">Branch</TableHead>
                  <TableHead className="text-[11px] h-8">SAST</TableHead>
                  <TableHead className="text-[11px] h-8">SCA</TableHead>
                  <TableHead className="text-[11px] h-8">Secrets</TableHead>
                  <TableHead className="text-[11px] h-8">Last Run</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pipelines.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="py-8">
                      <EmptyState icon={Inbox} title="No pipelines" description="Pipeline data will appear here once available." />
                    </TableCell>
                  </TableRow>
                ) : pipelines.map((row: any) => (
                  <TableRow key={row.name} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5">{row.name}</TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", CI_COLORS[row.ci] ?? "border-border text-muted-foreground")}>{row.ci}</Badge>
                    </TableCell>
                    <TableCell className="text-xs py-2.5 font-mono text-muted-foreground">{row.branch}</TableCell>
                    <TableCell className="py-2.5">
                      <span className={cn("text-[10px] font-bold", row.sast ? "text-green-400" : "text-muted-foreground/40")}>{row.sast ? "ON" : "OFF"}</span>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <span className={cn("text-[10px] font-bold", row.sca ? "text-green-400" : "text-muted-foreground/40")}>{row.sca ? "ON" : "OFF"}</span>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <span className={cn("text-[10px] font-bold", row.secrets ? "text-green-400" : "text-muted-foreground/40")}>{row.secrets ? "ON" : "OFF"}</span>
                    </TableCell>
                    <TableCell className="py-2.5"><StatusBadge status={row.status} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Build History Timeline */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Clock className="h-4 w-4 text-purple-400" />
            Build History Timeline
          </CardTitle>
          <CardDescription className="text-xs">Most recent pipeline runs — bar width proportional to duration</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {builds.length === 0 ? (
            <EmptyState icon={Inbox} title="No build history" description="Recent pipeline run history will appear here once available." />
          ) : (
            <>
              {builds.map((run: any) => {
                const widthPct = Math.max(8, (run.duration / MAX_DURATION) * 100);
                const barColor =
                  run.status === "passed"  ? "bg-green-500/70" :
                  run.status === "blocked" ? "bg-orange-500/70" : "bg-red-500/70";
                return (
                  <div key={run.id} className="flex items-center gap-3">
                    <span className="text-[10px] font-mono text-muted-foreground w-12 shrink-0">{run.id}</span>
                    <span className="text-[10px] text-muted-foreground w-40 shrink-0 truncate">{run.pipeline}</span>
                    <div className="flex-1 h-5 bg-muted/20 rounded overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${widthPct}%` }}
                        transition={{ duration: 0.7, ease: "easeOut" }}
                        className={cn("h-full rounded flex items-center px-2", barColor)}
                      >
                        <span className="text-[9px] text-white font-medium whitespace-nowrap">{run.duration}min</span>
                      </motion.div>
                    </div>
                    <span className={cn("text-[10px] font-bold w-8 text-right tabular-nums shrink-0", run.findings > 0 ? "text-red-400" : "text-muted-foreground")}>
                      {run.findings > 0 ? `+${run.findings}` : "0"}
                    </span>
                    <StatusBadge status={run.status} />
                  </div>
                );
              })}
              <div className="flex items-center gap-4 pt-2 text-[10px] text-muted-foreground">
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-green-500/70 inline-block" />Passed</span>
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-orange-500/70 inline-block" />Blocked</span>
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-red-500/70 inline-block" />Failed</span>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Security Findings Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Code2 className="h-4 w-4 text-red-400" />
              Security Findings
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">{findings.length} findings</Badge>
          </div>
          <CardDescription className="text-xs">Aggregated SAST, SCA, and secrets findings across all pipelines</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8 w-4"></TableHead>
                  <TableHead className="text-[11px] h-8">Scanner</TableHead>
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8">File</TableHead>
                  <TableHead className="text-[11px] h-8">Line</TableHead>
                  <TableHead className="text-[11px] h-8">CVE</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {findings.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="py-8">
                      <EmptyState icon={Inbox} title="No findings" description="Security findings will appear here once pipelines have run." />
                    </TableCell>
                  </TableRow>
                ) : findings.map((f: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2.5 w-4"><SevDot sev={f.sev} /></TableCell>
                    <TableCell className="py-2.5"><ScannerBadge type={f.scanner} /></TableCell>
                    <TableCell className="text-xs py-2.5 max-w-[180px] truncate">{f.title}</TableCell>
                    <TableCell className="text-[10px] py-2.5 font-mono text-muted-foreground max-w-[160px] truncate">{f.file}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{f.line}</TableCell>
                    <TableCell className="text-[10px] py-2.5 font-mono text-muted-foreground">{f.cve}</TableCell>
                    <TableCell className="py-2.5">
                      {f.suppressed
                        ? <Badge className="text-[10px] border border-border text-muted-foreground">suppressed</Badge>
                        : <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">active</Badge>
                      }
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Gate Policies — static config: rule strings, threshold labels, CSS classes */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Shield className="h-4 w-4 text-green-400" />
            Gate Policies
          </CardTitle>
          <CardDescription className="text-xs">Active security gate rules — violations block the pipeline</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {GATE_POLICIES.map((p) => (
              <div key={p.name} className={cn("rounded-lg border p-3 space-y-1.5", p.bg)}>
                <span className={cn("text-xs font-semibold", p.color)}>{p.name}</span>
                <div className="font-mono text-[10px] text-muted-foreground bg-muted/30 rounded px-2 py-1">{p.rule}</div>
                <Badge className={cn("text-[10px] border mt-1", p.bg, p.color)}>{p.threshold}</Badge>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
