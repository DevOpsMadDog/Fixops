/**
 * Compliance Automation Dashboard
 *
 * Automated compliance job execution and control testing lifecycle tracking.
 *   1. KPIs: Total Jobs, Completed Jobs, Controls Tested, Pass Rate %
 *   2. Jobs table (framework, automation_type, status, started_at, completed_at)
 *
 * Route: /compliance-automation
 * API: GET /api/v1/compliance-automation
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ShieldCheck, RefreshCw, CheckCircle, Play, BarChart2, Layers } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// == Mock data ==================================================

const MOCK_JOBS = [
  { id: "job-001", framework: "SOC 2",       automation_type: "evidence_collection", status: "completed", started_at: "2026-04-16T08:00:00Z", completed_at: "2026-04-16T08:14:00Z" },
  { id: "job-002", framework: "PCI-DSS",     automation_type: "control_testing",     status: "completed", started_at: "2026-04-16T08:15:00Z", completed_at: "2026-04-16T08:29:00Z" },
  { id: "job-003", framework: "ISO 27001",   automation_type: "gap_analysis",        status: "running",   started_at: "2026-04-16T09:00:00Z", completed_at: null },
  { id: "job-004", framework: "NIST CSF",    automation_type: "evidence_collection", status: "queued",    started_at: null,                   completed_at: null },
  { id: "job-005", framework: "HIPAA",       automation_type: "control_testing",     status: "completed", started_at: "2026-04-15T14:00:00Z", completed_at: "2026-04-15T14:22:00Z" },
  { id: "job-006", framework: "GDPR",        automation_type: "risk_assessment",     status: "failed",    started_at: "2026-04-15T16:00:00Z", completed_at: "2026-04-15T16:05:00Z" },
  { id: "job-007", framework: "CIS Benchmark",automation_type: "control_testing",    status: "completed", started_at: "2026-04-16T07:30:00Z", completed_at: "2026-04-16T07:48:00Z" },
  { id: "job-008", framework: "FedRAMP",     automation_type: "gap_analysis",        status: "queued",    started_at: null,                   completed_at: null },
  { id: "job-009", framework: "SOC 2",       automation_type: "continuous_monitoring",status: "running",  started_at: "2026-04-16T09:30:00Z", completed_at: null },
  { id: "job-010", framework: "CMMC",        automation_type: "evidence_collection", status: "completed", started_at: "2026-04-15T11:00:00Z", completed_at: "2026-04-15T11:19:00Z" },
];

const MOCK_STATS = { total_jobs: 142, completed_jobs: 117, controls_tested: 892, pass_rate: 94.3 };

// == Badge helpers ==============================================

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    completed: "border-green-500/30 text-green-400 bg-green-500/10",
    running:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    failed:    "border-red-500/30 text-red-400 bg-red-500/10",
    queued:    "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
  };
  const label: Record<string, string> = {
    completed: "Completed",
    running:   "Running",
    failed:    "Failed",
    queued:    "Queued",
  };
  return (
    <Badge className={cn("text-[10px] border", map[status] ?? "border-border")}>
      {label[status] ?? status}
    </Badge>
  );
}

function formatTs(ts: string | null) {
  if (!ts) return "=";
  return new Date(ts).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

// == Component ==================================================

export default function ComplianceAutomationDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveJobs, setLiveJobs] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/compliance-automation/jobs?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/compliance-automation/stats?org_id=${ORG_ID}`),
    ]).then(([jobsRes, statsRes]) => {
      if (jobsRes.status === "fulfilled") setLiveJobs(jobsRes.value?.jobs ?? jobsRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const jobs  = liveJobs  ?? MOCK_JOBS;
  const stats = liveStats ?? MOCK_STATS;

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
      <PageHeader
        title="Compliance Automation"
        description="Automated compliance job execution, control testing, and evidence collection across all frameworks"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Jobs"       value={stats.total_jobs}      icon={Layers}       trend="flat" className="border-indigo-500/20" />
        <KpiCard title="Completed Jobs"   value={stats.completed_jobs}  icon={CheckCircle}  trend="up"   className="border-blue-500/20" />
        <KpiCard title="Controls Tested"  value={stats.controls_tested} icon={ShieldCheck}  trend="up"   className="border-indigo-500/20" />
        <KpiCard title="Pass Rate %"      value={`${stats.pass_rate}%`} icon={BarChart2}    trend="up"   className="border-blue-500/20" />
      </div>

      {/* Jobs Table */}
      <Card className="border-indigo-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-indigo-400">
              <Play className="h-4 w-4" />
              Automation Jobs
            </CardTitle>
            <Badge className="text-[10px] border border-blue-500/30 text-blue-400 bg-blue-500/10">
              {jobs.filter((j: any) => j.status === "running").length} running
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Compliance automation jobs with framework, type, and execution status
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Framework</TableHead>
                  <TableHead className="text-[11px] h-8">Automation Type</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Started</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Completed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {jobs.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  jobs.map((job: any, i: number) => (
                  <TableRow key={job.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-indigo-300">
                      {job.framework ?? "="}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground capitalize">
                      {(job.automation_type ?? "=").replace(/_/g, " ")}
                    </TableCell>
                    <TableCell className="py-2">
                      <StatusBadge status={job.status ?? "queued"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-blue-300">
                      {formatTs(job.started_at)}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-blue-300 text-right">
                      {formatTs(job.completed_at)}
                    </TableCell>
                  </TableRow>
                ))
              )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
