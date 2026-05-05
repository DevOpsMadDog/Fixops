/**
 * ScorePanel — AwarenessHub "score" tab
 *
 * Wired to real backend:
 *   GET /api/v1/awareness-score/orgs/{org}/stats              → KPI bar
 *   GET /api/v1/awareness-score/orgs/{org}/scores             → per-employee scores
 *   GET /api/v1/awareness-score/orgs/{org}/department-summary → dept breakdown
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { Trophy, Users, Star, TrendingUp, RefreshCw } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";

interface OrgStats {
  total_employees?: number;
  avg_score?: number;
  top_score?: number;
  low_score?: number;
}

interface EmployeeScore {
  employee_id: string;
  name?: string;
  department?: string;
  score?: number;
  training_completed?: number;
  phishing_tests?: number;
  last_updated?: string;
}

interface DeptSummary {
  department?: string;
  employee_count?: number;
  avg_score?: number;
}

const SCORE_COLOR = (score: number) => {
  if (score >= 80) return "text-emerald-400";
  if (score >= 60) return "text-amber-400";
  if (score >= 40) return "text-orange-400";
  return "text-red-400";
};

async function apiFetch<T>(path: string, params?: Record<string, string>): Promise<T> {
  const orgId = getStoredOrgId() || "default";
  const url = buildApiUrl(path, { ...params });
  const res = await fetch(url, {
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function extractArray<T>(data: unknown): T[] {
  if (Array.isArray(data)) return data as T[];
  if (data && typeof data === "object") {
    const obj = data as Record<string, unknown>;
    for (const k of ["scores", "employees", "departments", "items", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

export default function ScorePanel() {
  const [orgStats, setOrgStats] = useState<OrgStats | null>(null);
  const [scores, setScores] = useState<EmployeeScore[]>([]);
  const [depts, setDepts] = useState<DeptSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<"employees" | "depts">("employees");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const orgId = getStoredOrgId() || "default";
    try {
      const [rawStats, rawScores, rawDepts] = await Promise.all([
        apiFetch<OrgStats>(`/api/v1/awareness-score/orgs/${orgId}/stats`),
        apiFetch<unknown>(`/api/v1/awareness-score/orgs/${orgId}/scores`),
        apiFetch<unknown>(`/api/v1/awareness-score/orgs/${orgId}/department-summary`),
      ]);
      setOrgStats(rawStats);
      setScores(extractArray<EmployeeScore>(rawScores));
      setDepts(extractArray<DeptSummary>(rawDepts));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load awareness scores");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const kpis = [
    { label: "Employees", value: orgStats?.total_employees ?? 0, icon: Users, color: "text-indigo-400" },
    { label: "Avg Score", value: orgStats?.avg_score?.toFixed(1) ?? "—", icon: Star, color: "text-amber-400" },
    { label: "Top Score", value: orgStats?.top_score?.toFixed(1) ?? "—", icon: Trophy, color: "text-emerald-400" },
    { label: "Low Score", value: orgStats?.low_score?.toFixed(1) ?? "—", icon: TrendingUp, color: "text-red-400" },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="flex flex-col gap-5"
    >
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Trophy className="h-5 w-5 text-indigo-400" />
          <span className="font-semibold text-sm">Awareness Score</span>
        </div>
        <Button variant="outline" size="sm" onClick={load} className="gap-1.5">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </Button>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {kpis.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-lg bg-muted/40 border border-border px-4 py-3 flex flex-col gap-1">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Icon className={`h-3.5 w-3.5 ${color}`} />
              <span className="text-xs">{label}</span>
            </div>
            <span className={`text-2xl font-bold tabular-nums ${color}`}>{value}</span>
          </div>
        ))}
      </div>

      <div className="flex gap-2">
        {(["employees", "depts"] as const).map(v => (
          <button
            key={v}
            onClick={() => setView(v)}
            className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
              view === v ? "bg-indigo-600 text-white" : "bg-muted/40 text-muted-foreground hover:bg-muted"
            }`}
          >
            {v === "employees" ? `Employees (${scores.length})` : `By Department (${depts.length})`}
          </button>
        ))}
      </div>

      {view === "employees" && (
        scores.length === 0 ? (
          <EmptyState icon={Trophy} title="No scores yet" description="Employee awareness scores will appear once training and phishing tests are recorded." />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Employee", "Department", "Score", "Training", "Phishing Tests", "Updated"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {scores.slice(0, 200).map((s, i) => (
                  <tr key={s.employee_id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium">{s.name ?? s.employee_id}</td>
                    <td className="px-3 py-2 text-muted-foreground">{s.department ?? "—"}</td>
                    <td className="px-3 py-2">
                      <span className={`font-bold tabular-nums ${SCORE_COLOR(s.score ?? 0)}`}>
                        {s.score?.toFixed(1) ?? "—"}
                      </span>
                    </td>
                    <td className="px-3 py-2 tabular-nums text-muted-foreground">{s.training_completed ?? 0}</td>
                    <td className="px-3 py-2 tabular-nums text-muted-foreground">{s.phishing_tests ?? 0}</td>
                    <td className="px-3 py-2 text-muted-foreground">{s.last_updated ? new Date(s.last_updated).toLocaleDateString() : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}

      {view === "depts" && (
        depts.length === 0 ? (
          <EmptyState icon={Users} title="No department data" description="Department score summaries appear after employee scores are calculated." />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Department", "Employees", "Avg Score"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {depts.map((d, i) => (
                  <tr key={d.department ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium">{d.department ?? "—"}</td>
                    <td className="px-3 py-2 tabular-nums">{d.employee_count ?? 0}</td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-2">
                        <div className="flex-1 h-1.5 rounded-full bg-muted/40 overflow-hidden">
                          <div
                            className="h-full bg-indigo-500 rounded-full"
                            style={{ width: `${Math.min(d.avg_score ?? 0, 100)}%` }}
                          />
                        </div>
                        <span className={`tabular-nums font-semibold ${SCORE_COLOR(d.avg_score ?? 0)}`}>
                          {d.avg_score?.toFixed(1) ?? "—"}
                        </span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}
    </motion.div>
  );
}
