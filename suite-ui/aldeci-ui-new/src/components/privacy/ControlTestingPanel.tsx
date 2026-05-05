/**
 * ControlTestingPanel — PrivacyComplianceHub "controls" tab
 *
 * Wired to real backend:
 *   GET /api/v1/control-testing/summary   → KPI bar
 *   GET /api/v1/control-testing/controls  → controls table
 *   GET /api/v1/control-testing/failing   → failing controls list
 *   GET /api/v1/control-testing/due       → due-tests list
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { ClipboardCheck, AlertTriangle, Calendar, RefreshCw, BarChart2 } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// ── Types ──────────────────────────────────────────────────────────────────────

interface ControlSummary {
  total_controls?: number;
  effective_count?: number;
  ineffective_count?: number;
  failing_count?: number;
  due_count?: number;
  average_score?: number;
  by_framework?: Record<string, number>;
  by_status?: Record<string, number>;
}

interface Control {
  control_id: string;
  control_name?: string;
  control_type?: string;
  framework?: string;
  status?: string;
  effectiveness_score?: number;
  owner?: string;
  last_tested?: string;
  next_due?: string;
  test_frequency_days?: number;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const STATUS_CLASS: Record<string, string> = {
  effective: "bg-emerald-700/70 text-emerald-100",
  partially_effective: "bg-amber-600/70 text-amber-100",
  ineffective: "bg-orange-600/70 text-orange-100",
  failing: "bg-red-700/70 text-red-100",
  untested: "bg-slate-600/70 text-slate-100",
  not_tested: "bg-slate-600/70 text-slate-100",
};

const SCORE_COLOR = (score: number) => {
  if (score >= 80) return "text-emerald-400";
  if (score >= 60) return "text-amber-400";
  if (score >= 40) return "text-orange-400";
  return "text-red-400";
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
    for (const k of ["items", "controls", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

// ── Component ──────────────────────────────────────────────────────────────────

export default function ControlTestingPanel() {
  const [summary, setSummary] = useState<ControlSummary | null>(null);
  const [controls, setControls] = useState<Control[]>([]);
  const [failing, setFailing] = useState<Control[]>([]);
  const [due, setDue] = useState<Control[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [subtab, setSubtab] = useState<"all" | "failing" | "due">("all");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rawSummary, rawControls, rawFailing, rawDue] = await Promise.all([
        apiFetch<ControlSummary>("/api/v1/control-testing/summary"),
        apiFetch<unknown>("/api/v1/control-testing/controls"),
        apiFetch<unknown>("/api/v1/control-testing/failing"),
        apiFetch<unknown>("/api/v1/control-testing/due"),
      ]);
      setSummary(rawSummary);
      setControls(extractArray<Control>(rawControls));
      setFailing(extractArray<Control>(rawFailing));
      setDue(extractArray<Control>(rawDue));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load control testing data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const avgScore = summary?.average_score ?? 0;

  const kpis = [
    { label: "Total Controls", value: summary?.total_controls ?? 0, icon: ClipboardCheck, color: "text-slate-300" },
    { label: "Failing", value: summary?.failing_count ?? (summary?.ineffective_count ?? 0), icon: AlertTriangle, color: "text-red-400" },
    { label: "Due for Testing", value: summary?.due_count ?? 0, icon: Calendar, color: "text-amber-400" },
    { label: "Avg Score", value: `${Math.round(avgScore)}%`, icon: BarChart2, color: SCORE_COLOR(avgScore) },
  ];

  const tableData = subtab === "all" ? controls : subtab === "failing" ? failing : due;

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
          <ClipboardCheck className="h-5 w-5 text-indigo-400" />
          <span className="font-semibold text-sm">Control Testing Lifecycle</span>
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

      {/* Framework breakdown (if present) */}
      {summary?.by_framework && Object.keys(summary.by_framework).length > 0 && (
        <div className="flex flex-wrap gap-2">
          {Object.entries(summary.by_framework).map(([fw, count]) => (
            <div key={fw} className="flex items-center gap-1.5 rounded-full bg-muted/40 border border-border px-3 py-1">
              <span className="text-xs font-medium text-indigo-300">{fw}</span>
              <Badge variant="secondary" className="text-[10px] h-4 px-1">{count}</Badge>
            </div>
          ))}
        </div>
      )}

      {/* Sub-tab switcher */}
      <div className="flex gap-2 flex-wrap">
        {(["all", "failing", "due"] as const).map(t => {
          const count = t === "all" ? controls.length : t === "failing" ? failing.length : due.length;
          const label = t === "all" ? "All Controls" : t === "failing" ? "Failing" : "Due for Testing";
          return (
            <button
              key={t}
              onClick={() => setSubtab(t)}
              className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                subtab === t ? "bg-indigo-600 text-white" : "bg-muted/40 text-muted-foreground hover:bg-muted"
              }`}
            >
              {label} ({count})
            </button>
          );
        })}
      </div>

      {/* Controls table */}
      {tableData.length === 0 ? (
        <EmptyState
          icon={ClipboardCheck}
          title={
            subtab === "failing" ? "No failing controls" :
            subtab === "due" ? "No controls due for testing" :
            "No controls registered"
          }
          description={
            subtab === "failing" ? "All controls are currently meeting effectiveness thresholds." :
            subtab === "due" ? "No controls are currently due for testing." :
            "Register controls via POST /api/v1/control-testing/controls to begin tracking."
          }
        />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                {["Control", "Type", "Framework", "Owner", "Score", "Status", "Last Tested", "Next Due"].map(h => (
                  <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {tableData.slice(0, 200).map((c, i) => (
                <tr key={c.control_id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                  <td className="px-3 py-2 font-medium max-w-[160px] truncate">{c.control_name ?? "—"}</td>
                  <td className="px-3 py-2 text-muted-foreground capitalize">{c.control_type ?? "—"}</td>
                  <td className="px-3 py-2 text-muted-foreground uppercase text-[10px]">{c.framework ?? "—"}</td>
                  <td className="px-3 py-2 text-muted-foreground max-w-[100px] truncate">{c.owner || "—"}</td>
                  <td className="px-3 py-2">
                    <span className={`font-bold tabular-nums ${SCORE_COLOR(c.effectiveness_score ?? 0)}`}>
                      {c.effectiveness_score !== undefined ? `${Math.round(c.effectiveness_score)}%` : "—"}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${STATUS_CLASS[c.status?.toLowerCase() ?? ""] ?? "bg-muted/40 text-muted-foreground"}`}>
                      {c.status ?? "—"}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-muted-foreground">
                    {c.last_tested ? new Date(c.last_tested).toLocaleDateString() : "—"}
                  </td>
                  <td className="px-3 py-2 text-muted-foreground">
                    {c.next_due ? new Date(c.next_due).toLocaleDateString() : "—"}
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
