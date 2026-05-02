// FOLDED into Remediate hero 2026-04-27 — preserve for git history
// Tab path: /remediate?tab=risk-treatment
/**
 * Risk Treatment Dashboard
 *
 * Risk treatment workflow tracking — progress, overdue items, and owner accountability.
 *   1. KPIs: Total Treatments, In Progress, Overdue, Avg Progress %
 *   2. Treatments table (title, treatment_type, treatment_status, risk_level, owner, progress_pct)
 *
 * Route: /risk-treatment
 * API: GET /api/v1/risk-treatment/treatments  GET /api/v1/risk-treatment/stats
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ShieldOff, RefreshCw, Clock, AlertTriangle, TrendingUp, BarChart2 } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    planned:     "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
    in_progress: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    completed:   "border-green-500/30 text-green-400 bg-green-500/10",
    deferred:    "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  };
  const label: Record<string, string> = {
    planned: "Planned", in_progress: "In Progress", completed: "Completed", deferred: "Deferred",
  };
  return (
    <Badge className={cn("text-[10px] border", map[status] ?? "border-border")}>
      {label[status] ?? status}
    </Badge>
  );
}

function RiskBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border")}>
      {level}
    </Badge>
  );
}

function ProgressBar({ pct }: { pct: number }) {
  const color = pct >= 75 ? "bg-green-500" : pct >= 40 ? "bg-amber-500" : "bg-orange-500";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 rounded-full bg-muted overflow-hidden">
        <div className={cn("h-full rounded-full transition-all", color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="font-mono text-[10px] text-muted-foreground">{pct}%</span>
    </div>
  );
}

function exportCsv(treatments: Array<Record<string, unknown>>) {
  const headers = ["title", "treatment_type", "treatment_status", "risk_level", "owner", "progress_pct"];
  const rows = treatments.map((t) => headers.map((h) => t[h] ?? "").join(","));
  const csv = [headers.join(","), ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "risk_treatments.csv"; a.click();
  URL.revokeObjectURL(url);
}

interface Treatment {
  id?: string;
  title?: string;
  treatment_type?: string;
  treatment_status?: string;
  risk_level?: string;
  owner?: string;
  progress_pct?: number;
}

interface TreatmentStats {
  total_treatments?: number;
  in_progress?: number;
  overdue?: number;
  avg_progress_pct?: number;
}

export default function RiskTreatmentDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [treatments, setTreatments] = useState<Treatment[]>([]);
  const [stats, setStats] = useState<TreatmentStats>({});
  const [error, setError] = useState<string | null>(null);

  const fetchData = () => {
    setLoading(true);
    setError(null);
    Promise.allSettled([
      apiFetch("/api/v1/risk-treatment/treatments?org_id=default"),
      apiFetch("/api/v1/risk-treatment/stats?org_id=default"),
    ]).then(([treatRes, statsRes]) => {
      if (treatRes.status === "fulfilled") {
        const v = treatRes.value;
        setTreatments(Array.isArray(v) ? v : (v?.treatments ?? v?.items ?? []));
      } else {
        setError("Failed to load treatment data");
      }
      if (statsRes.status === "fulfilled") {
        setStats(statsRes.value ?? {});
      }
    }).finally(() => setLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  if (loading) {
    return (
      <div className="flex flex-col gap-6">
        <div className="h-10 w-64 rounded bg-muted animate-pulse" />
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => <div key={i} className="h-24 rounded bg-muted animate-pulse" />)}
        </div>
        <div className="h-64 rounded bg-muted animate-pulse" />
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Risk Treatment"
        description="Risk treatment workflow — track remediation, control implementation, acceptance, and transfer activities by owner"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Treatments" value={stats.total_treatments ?? 0}       icon={ShieldOff}  trend="flat" className="border-amber-500/20" />
        <KpiCard title="In Progress"      value={stats.in_progress ?? 0}            icon={TrendingUp} trend="up"   className="border-orange-500/20" />
        <KpiCard title="Overdue"          value={stats.overdue ?? 0}                icon={Clock}      trend="down" className="border-amber-500/20" />
        <KpiCard title="Avg Progress"     value={`${stats.avg_progress_pct ?? 0}%`} icon={BarChart2}  trend="up"   className="border-orange-500/20" />
      </div>

      <Card className="border-amber-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
              <AlertTriangle className="h-4 w-4" />
              Treatment Registry
            </CardTitle>
            <div className="flex items-center gap-2">
              <Badge className="text-[10px] border border-orange-500/30 text-orange-400 bg-orange-500/10">
                {treatments.filter((t) => t.treatment_status === "in_progress").length} in progress
              </Badge>
              <Button variant="outline" size="sm" className="text-[11px] h-7"
                onClick={() => exportCsv(treatments as Array<Record<string, unknown>>)}>
                Export CSV
              </Button>
            </div>
          </div>
          <CardDescription className="text-xs">
            Risk treatments with type, status, risk level, owner assignment, and completion progress
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {error ? (
            <div className="p-6">
              <EmptyState
                title="Failed to load treatments"
                description={error}
                icon={AlertTriangle}
              />
            </div>
          ) : treatments.length === 0 ? (
            <div className="p-6">
              <EmptyState
                title="No risk treatments found"
                description="Create risk treatments to track remediation, control implementation, and acceptance workflows."
                icon={ShieldOff}
              />
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Treatment</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                    <TableHead className="text-[11px] h-8">Risk Level</TableHead>
                    <TableHead className="text-[11px] h-8">Owner</TableHead>
                    <TableHead className="text-[11px] h-8">Progress</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {treatments.map((t, i) => (
                    <TableRow key={t.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 font-semibold text-[11px] text-amber-300 max-w-[200px] truncate">
                        {t.title ?? "—"}
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">
                        {t.treatment_type ?? "—"}
                      </TableCell>
                      <TableCell className="py-2">
                        <StatusBadge status={t.treatment_status ?? "planned"} />
                      </TableCell>
                      <TableCell className="py-2">
                        <RiskBadge level={t.risk_level ?? "medium"} />
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">
                        {t.owner ?? "—"}
                      </TableCell>
                      <TableCell className="py-2">
                        <ProgressBar pct={t.progress_pct ?? 0} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
