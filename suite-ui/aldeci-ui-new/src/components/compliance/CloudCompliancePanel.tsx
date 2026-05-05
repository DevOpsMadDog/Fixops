/**
 * CloudCompliancePanel — ComplianceCoverageHub "cloud" tab
 *
 * Wired to real backend:
 *   GET /api/v1/cloud-compliance/stats        → KPI bar
 *   GET /api/v1/cloud-compliance/controls     → controls table
 *   GET /api/v1/cloud-compliance/assessments  → assessments list
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { Cloud, RefreshCw, CheckCircle2, XCircle, AlertCircle, ShieldCheck } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// ── Types ─────────────────────────────────────────────────────────────────────

interface CloudStats {
  total_controls?: number;
  compliant_controls?: number;
  non_compliant_controls?: number;
  partial_controls?: number;
  overall_compliance_pct?: number;
  by_framework?: Record<string, number>;
}

interface CloudAssessment {
  assessment_id: string;
  framework?: string;
  status?: string;
  compliance_score?: number;
  created_at?: string;
  completed_at?: string;
}

interface CloudControl {
  result_id?: string;
  control_id?: string;
  control_name?: string;
  framework?: string;
  status?: string;
  cloud_provider?: string;
  resource_type?: string;
  checked_at?: string;
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
    for (const k of ["items", "controls", "assessments", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

const STATUS_CLASS: Record<string, string> = {
  compliant: "bg-emerald-700/70 text-emerald-100",
  non_compliant: "bg-red-700/70 text-red-100",
  partial: "bg-amber-600/70 text-amber-100",
  completed: "bg-emerald-700/70 text-emerald-100",
  in_progress: "bg-amber-600/70 text-amber-100",
  open: "bg-red-700/70 text-red-100",
};

// ── Component ─────────────────────────────────────────────────────────────────

export default function CloudCompliancePanel() {
  const [stats, setStats] = useState<CloudStats | null>(null);
  const [controls, setControls] = useState<CloudControl[]>([]);
  const [assessments, setAssessments] = useState<CloudAssessment[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [subtab, setSubtab] = useState<"controls" | "assessments">("controls");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsData, controlsData, assessData] = await Promise.all([
        apiFetch<CloudStats>("/api/v1/cloud-compliance/stats"),
        apiFetch<unknown>("/api/v1/cloud-compliance/controls"),
        apiFetch<unknown>("/api/v1/cloud-compliance/assessments"),
      ]);
      setStats(statsData);
      setControls(extractArray<CloudControl>(controlsData));
      setAssessments(extractArray<CloudAssessment>(assessData));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load cloud compliance data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const pct = stats?.overall_compliance_pct ?? 0;
  const kpis = [
    { label: "Total Controls", value: stats?.total_controls ?? 0, icon: ShieldCheck, color: "text-indigo-400" },
    { label: "Compliant", value: stats?.compliant_controls ?? 0, icon: CheckCircle2, color: "text-emerald-400" },
    { label: "Non-Compliant", value: stats?.non_compliant_controls ?? 0, icon: XCircle, color: "text-red-400" },
    { label: "Partial", value: stats?.partial_controls ?? 0, icon: AlertCircle, color: "text-amber-400" },
    { label: "Coverage", value: `${pct}%`, icon: Cloud, color: pct >= 80 ? "text-emerald-400" : pct >= 60 ? "text-amber-400" : "text-red-400" },
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

      {/* Framework breakdown */}
      {stats?.by_framework && Object.keys(stats.by_framework).length > 0 && (
        <div className="flex flex-wrap gap-2">
          {Object.entries(stats.by_framework).map(([fw, score]) => (
            <div key={fw} className="rounded border border-slate-700 bg-slate-800/40 px-2.5 py-1 text-xs flex items-center gap-1.5">
              <span className="text-slate-400">{fw}</span>
              <span className={`font-semibold ${(score as number) >= 80 ? "text-emerald-400" : (score as number) >= 60 ? "text-amber-400" : "text-red-400"}`}>
                {score}%
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Sub-tab switcher */}
      <div className="flex gap-2">
        {(["controls", "assessments"] as const).map(k => (
          <button
            key={k}
            onClick={() => setSubtab(k)}
            className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
              subtab === k
                ? "bg-indigo-600 text-white"
                : "bg-slate-700/50 text-slate-300 hover:bg-slate-700"
            }`}
          >
            {k === "controls" ? "Controls" : "Assessments"}
          </button>
        ))}
        <Button size="sm" variant="ghost" className="ml-auto h-7 gap-1 text-xs" onClick={load}>
          <RefreshCw className="h-3 w-3" /> Refresh
        </Button>
      </div>

      {/* Controls table */}
      {subtab === "controls" && (
        controls.length === 0
          ? <EmptyState title="No controls found" description="Create a cloud compliance assessment to start tracking controls." />
          : (
            <div className="overflow-x-auto rounded-lg border border-slate-700">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700 bg-slate-800/80">
                    {["Control", "Framework", "Provider", "Resource", "Status", "Checked"].map(h => (
                      <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {controls.map((c, i) => (
                    <tr key={c.result_id ?? c.control_id ?? i} className={`border-b border-slate-700/50 ${i % 2 === 0 ? "bg-slate-800/30" : ""} hover:bg-slate-700/30`}>
                      <td className="px-3 py-2 font-medium text-slate-200">{c.control_name ?? c.control_id ?? "—"}</td>
                      <td className="px-3 py-2 text-slate-400">{c.framework ?? "—"}</td>
                      <td className="px-3 py-2 text-slate-400">{c.cloud_provider ?? "—"}</td>
                      <td className="px-3 py-2 text-slate-400">{c.resource_type ?? "—"}</td>
                      <td className="px-3 py-2">
                        <Badge className={`text-[10px] ${STATUS_CLASS[c.status?.toLowerCase() ?? ""] ?? "bg-slate-600/70 text-slate-100"}`}>
                          {c.status ?? "—"}
                        </Badge>
                      </td>
                      <td className="px-3 py-2 text-slate-500">{c.checked_at ? new Date(c.checked_at).toLocaleDateString() : "—"}</td>
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
          ? <EmptyState title="No assessments" description="Start a cloud compliance assessment to track baseline coverage." />
          : (
            <div className="overflow-x-auto rounded-lg border border-slate-700">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700 bg-slate-800/80">
                    {["Framework", "Status", "Score", "Created", "Completed"].map(h => (
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
                      <td className="px-3 py-2 text-slate-500">{a.created_at ? new Date(a.created_at).toLocaleDateString() : "—"}</td>
                      <td className="px-3 py-2 text-slate-500">{a.completed_at ? new Date(a.completed_at).toLocaleDateString() : "—"}</td>
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
