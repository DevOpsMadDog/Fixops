/**
 * PrivacyImpactPanel — PrivacyComplianceHub "impact" tab
 *
 * Wired to real backend:
 *   GET /api/v1/privacy-impact/summary      → KPI bar
 *   GET /api/v1/privacy-impact/assessments  → assessment table
 *   GET /api/v1/privacy-impact/high-risk    → high-risk list
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { FileSearch, AlertTriangle, CheckCircle, RefreshCw, ClipboardList } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// ── Types ──────────────────────────────────────────────────────────────────────

interface PIASummary {
  total_assessments?: number;
  high_risk_count?: number;
  approved_count?: number;
  pending_approval_count?: number;
  average_risk_score?: number;
  by_type?: Record<string, number>;
}

interface PIAAssessment {
  assessment_id: string;
  project_name?: string;
  assessment_type?: string;
  status?: string;
  risk_level?: string;
  risk_score?: number;
  cross_border_transfer?: boolean;
  created_at?: string;
  data_controller?: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const RISK_CLASS: Record<string, string> = {
  critical: "bg-red-700/80 text-red-100",
  high: "bg-orange-600/80 text-orange-100",
  medium: "bg-amber-600/80 text-amber-100",
  low: "bg-blue-600/80 text-blue-100",
};

const STATUS_CLASS: Record<string, string> = {
  approved: "bg-emerald-700/70 text-emerald-100",
  pending_approval: "bg-amber-600/70 text-amber-100",
  in_progress: "bg-blue-600/70 text-blue-100",
  draft: "bg-slate-600/70 text-slate-100",
  rejected: "bg-red-700/70 text-red-100",
};

const RISK_COLOR = (score: number) => {
  if (score >= 75) return "text-red-400";
  if (score >= 50) return "text-orange-400";
  if (score >= 25) return "text-amber-400";
  return "text-emerald-400";
};

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
    for (const k of ["items", "assessments", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

// ── Component ──────────────────────────────────────────────────────────────────

export default function PrivacyImpactPanel() {
  const [summary, setSummary] = useState<PIASummary | null>(null);
  const [assessments, setAssessments] = useState<PIAAssessment[]>([]);
  const [highRisk, setHighRisk] = useState<PIAAssessment[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [subtab, setSubtab] = useState<"all" | "high-risk">("all");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rawSummary, rawAssessments, rawHighRisk] = await Promise.all([
        apiFetch<PIASummary>("/api/v1/privacy-impact/summary"),
        apiFetch<unknown>("/api/v1/privacy-impact/assessments"),
        apiFetch<unknown>("/api/v1/privacy-impact/high-risk"),
      ]);
      setSummary(rawSummary);
      setAssessments(extractArray<PIAAssessment>(rawAssessments));
      setHighRisk(extractArray<PIAAssessment>(rawHighRisk));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load PIA data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const kpis = [
    { label: "Total PIAs", value: summary?.total_assessments ?? 0, icon: ClipboardList, color: "text-slate-300" },
    { label: "High Risk", value: summary?.high_risk_count ?? 0, icon: AlertTriangle, color: "text-red-400" },
    { label: "Approved", value: summary?.approved_count ?? 0, icon: CheckCircle, color: "text-emerald-400" },
    { label: "Pending Approval", value: summary?.pending_approval_count ?? 0, icon: FileSearch, color: "text-amber-400" },
  ];

  const tableData = subtab === "all" ? assessments : highRisk;

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="flex flex-col gap-5"
    >
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <FileSearch className="h-5 w-5 text-indigo-400" />
          <span className="font-semibold text-sm">Privacy Impact Assessments (PIA/DPIA)</span>
        </div>
        <Button variant="outline" size="sm" onClick={load} className="gap-1.5">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </Button>
      </div>

      {/* KPI bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {kpis.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-lg bg-muted/40 border border-border px-4 py-3 flex flex-col gap-1">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Icon className={`h-3.5 w-3.5 ${color}`} />
              <span className="text-xs">{label}</span>
            </div>
            <span className={`text-2xl font-bold tabular-nums ${color}`}>
              {typeof value === "number" ? value.toLocaleString() : value}
            </span>
          </div>
        ))}
      </div>

      {/* Sub-tab switcher */}
      <div className="flex gap-2">
        {(["all", "high-risk"] as const).map(t => (
          <button
            key={t}
            onClick={() => setSubtab(t)}
            className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
              subtab === t ? "bg-indigo-600 text-white" : "bg-muted/40 text-muted-foreground hover:bg-muted"
            }`}
          >
            {t === "all" ? `All Assessments (${assessments.length})` : `High Risk (${highRisk.length})`}
          </button>
        ))}
      </div>

      {/* Assessment table */}
      {tableData.length === 0 ? (
        <EmptyState
          icon={FileSearch}
          title={subtab === "high-risk" ? "No high-risk assessments" : "No assessments yet"}
          description={
            subtab === "high-risk"
              ? "High-risk PIAs will appear when assessments have critical or high risk levels."
              : "Create a PIA via POST /api/v1/privacy-impact/assessments to begin tracking."
          }
        />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                {["Project", "Type", "Controller", "Risk Level", "Score", "Status", "Cross-Border", "Created"].map(h => (
                  <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {tableData.slice(0, 200).map((a, i) => (
                <tr key={a.assessment_id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                  <td className="px-3 py-2 font-medium max-w-[160px] truncate">{a.project_name ?? "—"}</td>
                  <td className="px-3 py-2 uppercase text-muted-foreground text-[10px]">{a.assessment_type ?? "—"}</td>
                  <td className="px-3 py-2 text-muted-foreground max-w-[120px] truncate">{a.data_controller || "—"}</td>
                  <td className="px-3 py-2">
                    {a.risk_level ? (
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${RISK_CLASS[a.risk_level.toLowerCase()] ?? "bg-muted/40 text-muted-foreground"}`}>
                        {a.risk_level}
                      </span>
                    ) : <span className="text-muted-foreground">—</span>}
                  </td>
                  <td className="px-3 py-2">
                    <span className={`font-bold tabular-nums ${RISK_COLOR(a.risk_score ?? 0)}`}>
                      {a.risk_score ?? "—"}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${STATUS_CLASS[a.status?.toLowerCase() ?? ""] ?? "bg-muted/40 text-muted-foreground"}`}>
                      {a.status ?? "—"}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    {a.cross_border_transfer ? (
                      <Badge variant="outline" className="text-[10px] border-orange-500 text-orange-400">Yes</Badge>
                    ) : (
                      <span className="text-muted-foreground">No</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-muted-foreground">
                    {a.created_at ? new Date(a.created_at).toLocaleDateString() : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </motion.div>
  );
}
