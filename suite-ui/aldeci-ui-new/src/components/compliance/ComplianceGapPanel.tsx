/**
 * ComplianceGapPanel — ComplianceCoverageHub "gaps" tab
 *
 * Wired to real backend:
 *   GET /api/v1/compliance-gaps/stats        → KPI bar
 *   GET /api/v1/compliance-gaps/assessments  → assessments list
 *   GET /api/v1/compliance-gaps/gaps         → gaps table
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { ShieldAlert, RefreshCw, CheckCircle2, XCircle, AlertCircle } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// ── Types ─────────────────────────────────────────────────────────────────────

interface GapStats {
  total_gaps?: number;
  open_gaps?: number;
  closed_gaps?: number;
  in_progress_gaps?: number;
  total_assessments?: number;
  completed_assessments?: number;
  overall_compliance_pct?: number;
}

interface Assessment {
  assessment_id: string;
  framework?: string;
  status?: string;
  compliance_score?: number;
  created_at?: string;
  completed_at?: string;
  total_controls?: number;
  compliant_controls?: number;
}

interface Gap {
  gap_id: string;
  control_id?: string;
  control_name?: string;
  framework?: string;
  severity?: string;
  status?: string;
  description?: string;
  created_at?: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async function apiFetch<T>(path: string, params?: Record<string, string>): Promise<T> {
  const orgId = getStoredOrgId() || "default";
  const url = buildApiUrl(path, { org_id: orgId, ...params });
  const res = await fetch(url, {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": orgId,
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function extractArray<T>(data: unknown): T[] {
  if (Array.isArray(data)) return data as T[];
  if (data && typeof data === "object") {
    const obj = data as Record<string, unknown>;
    for (const k of ["items", "assessments", "gaps", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

const SEVERITY_CLASS: Record<string, string> = {
  critical: "bg-red-700/70 text-red-100",
  high: "bg-orange-600/70 text-orange-100",
  medium: "bg-amber-600/70 text-amber-100",
  low: "bg-slate-600/70 text-slate-100",
};

const STATUS_CLASS: Record<string, string> = {
  open: "bg-red-700/70 text-red-100",
  in_progress: "bg-amber-600/70 text-amber-100",
  closed: "bg-emerald-700/70 text-emerald-100",
  remediated: "bg-emerald-700/70 text-emerald-100",
  completed: "bg-emerald-700/70 text-emerald-100",
};

// ── Component ─────────────────────────────────────────────────────────────────

export default function ComplianceGapPanel() {
  const [stats, setStats] = useState<GapStats | null>(null);
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [gaps, setGaps] = useState<Gap[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [subtab, setSubtab] = useState<"gaps" | "assessments">("gaps");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsData, assessData, gapsData] = await Promise.all([
        apiFetch<GapStats>("/api/v1/compliance-gaps/stats"),
        apiFetch<unknown>("/api/v1/compliance-gaps/assessments"),
        apiFetch<unknown>("/api/v1/compliance-gaps/gaps"),
      ]);
      setStats(statsData);
      setAssessments(extractArray<Assessment>(assessData));
      setGaps(extractArray<Gap>(gapsData));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load compliance gap data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const kpis = [
    { label: "Total Gaps", value: stats?.total_gaps ?? 0, icon: ShieldAlert, color: "text-red-400" },
    { label: "Open", value: stats?.open_gaps ?? 0, icon: XCircle, color: "text-orange-400" },
    { label: "In Progress", value: stats?.in_progress_gaps ?? 0, icon: AlertCircle, color: "text-amber-400" },
    { label: "Closed", value: stats?.closed_gaps ?? 0, icon: CheckCircle2, color: "text-emerald-400" },
    { label: "Compliance %", value: `${stats?.overall_compliance_pct ?? 0}%`, icon: CheckCircle2, color: "text-indigo-400" },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="flex flex-col gap-4"
    >
      {/* KPI bar */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {kpis.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-lg border border-slate-700 bg-slate-800/60 p-3 flex flex-col gap-1">
            <div className="flex items-center gap-1.5">
              <Icon className={`h-3.5 w-3.5 ${color}`} />
              <span className="text-xs text-muted-foreground">{label}</span>
            </div>
            <span className={`text-xl font-semibold ${color}`}>{value}</span>
          </div>
        ))}
      </div>

      {/* Sub-tab switcher */}
      <div className="flex gap-2">
        {(["gaps", "assessments"] as const).map(k => (
          <button
            key={k}
            onClick={() => setSubtab(k)}
            className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
              subtab === k
                ? "bg-indigo-600 text-white"
                : "bg-slate-700/50 text-slate-300 hover:bg-slate-700"
            }`}
          >
            {k === "gaps" ? "Gaps" : "Assessments"}
          </button>
        ))}
        <Button size="sm" variant="ghost" className="ml-auto h-7 gap-1 text-xs" onClick={load}>
          <RefreshCw className="h-3 w-3" /> Refresh
        </Button>
      </div>

      {/* Gaps table */}
      {subtab === "gaps" && (
        gaps.length === 0
          ? <EmptyState title="No gaps found" description="Run a compliance assessment to identify control gaps." />
          : (
            <div className="overflow-x-auto rounded-lg border border-slate-700">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700 bg-slate-800/80">
                    {["Control", "Framework", "Severity", "Status", "Created"].map(h => (
                      <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {gaps.map((g, i) => (
                    <tr key={g.gap_id} className={`border-b border-slate-700/50 ${i % 2 === 0 ? "bg-slate-800/30" : ""} hover:bg-slate-700/30`}>
                      <td className="px-3 py-2 font-mono text-slate-300">{g.control_name ?? g.control_id}</td>
                      <td className="px-3 py-2 text-slate-400">{g.framework ?? "—"}</td>
                      <td className="px-3 py-2">
                        <Badge className={`text-[10px] ${SEVERITY_CLASS[g.severity?.toLowerCase() ?? ""] ?? "bg-slate-600/70 text-slate-100"}`}>
                          {g.severity ?? "—"}
                        </Badge>
                      </td>
                      <td className="px-3 py-2">
                        <Badge className={`text-[10px] ${STATUS_CLASS[g.status?.toLowerCase() ?? ""] ?? "bg-slate-600/70 text-slate-100"}`}>
                          {g.status ?? "—"}
                        </Badge>
                      </td>
                      <td className="px-3 py-2 text-slate-500">{g.created_at ? new Date(g.created_at).toLocaleDateString() : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
      )}

      {/* Assessments list */}
      {subtab === "assessments" && (
        assessments.length === 0
          ? <EmptyState title="No assessments" description="Start a compliance gap assessment to track framework coverage." />
          : (
            <div className="overflow-x-auto rounded-lg border border-slate-700">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700 bg-slate-800/80">
                    {["Framework", "Status", "Score", "Controls", "Created"].map(h => (
                      <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {assessments.map((a, i) => (
                    <tr key={a.assessment_id} className={`border-b border-slate-700/50 ${i % 2 === 0 ? "bg-slate-800/30" : ""} hover:bg-slate-700/30`}>
                      <td className="px-3 py-2 font-medium text-slate-200">{a.framework ?? "—"}</td>
                      <td className="px-3 py-2">
                        <Badge className={`text-[10px] ${STATUS_CLASS[a.status?.toLowerCase() ?? ""] ?? "bg-slate-600/70 text-slate-100"}`}>
                          {a.status ?? "—"}
                        </Badge>
                      </td>
                      <td className="px-3 py-2">
                        <span className={a.compliance_score != null
                          ? a.compliance_score >= 80 ? "text-emerald-400 font-semibold"
                          : a.compliance_score >= 60 ? "text-amber-400 font-semibold"
                          : "text-red-400 font-semibold"
                          : "text-slate-500"}>
                          {a.compliance_score != null ? `${a.compliance_score}%` : "—"}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-slate-400">
                        {a.compliant_controls != null && a.total_controls != null
                          ? `${a.compliant_controls}/${a.total_controls}`
                          : "—"}
                      </td>
                      <td className="px-3 py-2 text-slate-500">{a.created_at ? new Date(a.created_at).toLocaleDateString() : "—"}</td>
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
