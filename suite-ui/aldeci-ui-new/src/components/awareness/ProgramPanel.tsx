/**
 * ProgramPanel — AwarenessHub "program" tab
 *
 * Wired to real backend:
 *   GET /api/v1/awareness-program/summary            → KPI bar
 *   GET /api/v1/awareness-program/                   → program list
 *   GET /api/v1/awareness-program/department-compliance → dept breakdown
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { GraduationCap, BookOpen, Users, TrendingUp, RefreshCw } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

interface ProgramSummary {
  total_programs?: number;
  total_enrollments?: number;
  completion_rate?: number;
  overdue_count?: number;
}

interface AwarenessProgram {
  program_id: string;
  name?: string;
  status?: string;
  enrollment_count?: number;
  completion_rate?: number;
  due_date?: string;
}

interface DeptCompliance {
  department?: string;
  total?: number;
  completed?: number;
  compliance_rate?: number;
}

async function apiFetch<T>(path: string, params?: Record<string, string>): Promise<T> {
  const orgId = getStoredOrgId() || "default";
  const url = buildApiUrl(path, { org_id: orgId, ...params });
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
    for (const k of ["programs", "departments", "items", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

const STATUS_CLASS: Record<string, string> = {
  active: "bg-emerald-700/80 text-emerald-100",
  completed: "bg-blue-700/80 text-blue-100",
  draft: "bg-slate-600/80 text-slate-100",
  archived: "bg-slate-700/80 text-slate-300",
};

export default function ProgramPanel() {
  const [summary, setSummary] = useState<ProgramSummary | null>(null);
  const [programs, setPrograms] = useState<AwarenessProgram[]>([]);
  const [depts, setDepts] = useState<DeptCompliance[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<"programs" | "depts">("programs");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rawSummary, rawPrograms, rawDepts] = await Promise.all([
        apiFetch<ProgramSummary>("/api/v1/awareness-program/summary"),
        apiFetch<unknown>("/api/v1/awareness-program/"),
        apiFetch<unknown>("/api/v1/awareness-program/department-compliance"),
      ]);
      setSummary(rawSummary);
      setPrograms(extractArray<AwarenessProgram>(rawPrograms));
      setDepts(extractArray<DeptCompliance>(rawDepts));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load program data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const kpis = [
    { label: "Programs", value: summary?.total_programs ?? 0, icon: BookOpen, color: "text-indigo-400" },
    { label: "Enrollments", value: summary?.total_enrollments ?? 0, icon: Users, color: "text-sky-400" },
    { label: "Completion", value: `${summary?.completion_rate ?? 0}%`, icon: TrendingUp, color: "text-emerald-400" },
    { label: "Overdue", value: summary?.overdue_count ?? 0, icon: GraduationCap, color: "text-red-400" },
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
          <GraduationCap className="h-5 w-5 text-indigo-400" />
          <span className="font-semibold text-sm">Awareness Program</span>
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
        {(["programs", "depts"] as const).map(v => (
          <button
            key={v}
            onClick={() => setView(v)}
            className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
              view === v ? "bg-indigo-600 text-white" : "bg-muted/40 text-muted-foreground hover:bg-muted"
            }`}
          >
            {v === "programs" ? `Programs (${programs.length})` : `By Department (${depts.length})`}
          </button>
        ))}
      </div>

      {view === "programs" && (
        programs.length === 0 ? (
          <EmptyState icon={GraduationCap} title="No programs" description="Create an awareness program to track employee training." />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Name", "Status", "Enrolled", "Completion", "Due Date"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {programs.slice(0, 200).map((p, i) => (
                  <tr key={p.program_id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium">{p.name ?? p.program_id}</td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${STATUS_CLASS[p.status?.toLowerCase() ?? ""] ?? "bg-muted/40 text-muted-foreground"}`}>
                        {p.status ?? "—"}
                      </span>
                    </td>
                    <td className="px-3 py-2 tabular-nums">{p.enrollment_count ?? 0}</td>
                    <td className="px-3 py-2 tabular-nums">{p.completion_rate != null ? `${p.completion_rate}%` : "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground">{p.due_date ? new Date(p.due_date).toLocaleDateString() : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}

      {view === "depts" && (
        depts.length === 0 ? (
          <EmptyState icon={Users} title="No department data" description="Department compliance data will populate as employees complete training." />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Department", "Total", "Completed", "Compliance Rate"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {depts.map((d, i) => (
                  <tr key={d.department ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium">{d.department ?? "—"}</td>
                    <td className="px-3 py-2 tabular-nums">{d.total ?? 0}</td>
                    <td className="px-3 py-2 tabular-nums">{d.completed ?? 0}</td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-2">
                        <div className="flex-1 h-1.5 rounded-full bg-muted/40 overflow-hidden">
                          <div
                            className="h-full bg-emerald-500 rounded-full"
                            style={{ width: `${d.compliance_rate ?? 0}%` }}
                          />
                        </div>
                        <span className="tabular-nums text-emerald-400 font-semibold">{d.compliance_rate ?? 0}%</span>
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
