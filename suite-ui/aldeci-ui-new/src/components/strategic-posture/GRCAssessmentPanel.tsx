/**
 * GRCAssessmentPanel — grc tab for StrategicPostureHub
 * Fetches /api/v1/grc/stats + /frameworks + /controls + /risks
 * Real data only — no mocks.
 */

import { useCallback, useEffect, useState } from "react";
import {
  ClipboardCheck,
  RefreshCw,
  AlertCircle,
  CheckCircle2,
  XCircle,
  MinusCircle,
} from "lucide-react";
import { grcApi, type GrcStats, type GrcFramework, type GrcControl, type GrcRisk } from "@/lib/api";

const CONTROL_STATUS_BADGE: Record<string, string> = {
  implemented:      "text-green-400 bg-green-500/10",
  partial:          "text-amber-400 bg-amber-500/10",
  not_implemented:  "text-red-400 bg-red-500/10",
  not_applicable:   "text-slate-400 bg-slate-400/10",
};

const CONTROL_STATUS_ICON: Record<string, React.ElementType> = {
  implemented:     CheckCircle2,
  partial:         MinusCircle,
  not_implemented: XCircle,
  not_applicable:  MinusCircle,
};

const RISK_TREATMENT_COLOR: Record<string, string> = {
  mitigate: "text-blue-400",
  accept:   "text-amber-400",
  transfer: "text-purple-400",
  avoid:    "text-green-400",
};

function ScoreBar({ score }: { score: number }) {
  const pct = Math.min(100, Math.max(0, score));
  const color = pct >= 80 ? "bg-green-500" : pct >= 60 ? "bg-amber-400" : "bg-red-500";
  return (
    <div className="h-1.5 w-full rounded-full bg-muted/40 overflow-hidden">
      <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

export function GRCAssessmentPanel() {
  const [grcStats, setGrcStats] = useState<GrcStats | null>(null);
  const [frameworks, setFrameworks] = useState<GrcFramework[]>([]);
  const [controls, setControls] = useState<GrcControl[]>([]);
  const [risks, setRisks] = useState<GrcRisk[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<"controls" | "risks">("controls");

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    Promise.all([
      grcApi.stats(),
      grcApi.frameworks(),
      grcApi.controls(),
      grcApi.risks(),
    ])
      .then(([statsRes, fwRes, ctrlRes, riskRes]) => {
        setGrcStats(statsRes.data ?? null);
        setFrameworks(Array.isArray(fwRes.data) ? fwRes.data : []);
        setControls(Array.isArray(ctrlRes.data) ? ctrlRes.data : []);
        setRisks(Array.isArray(riskRes.data) ? riskRes.data : []);
      })
      .catch((err: { response?: { data?: { detail?: string } }; message?: string }) => {
        setError(err?.response?.data?.detail ?? err?.message ?? "Failed to load GRC data");
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="flex flex-col gap-6">
      {/* Toolbar */}
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          GRC controls, frameworks, and risk register — source: /api/v1/grc
        </p>
        <button
          onClick={load}
          disabled={loading}
          className="flex items-center gap-1 rounded-md border border-border px-2.5 py-1 text-xs text-muted-foreground hover:text-foreground disabled:opacity-50"
          aria-label="Refresh GRC data"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {error && !loading && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          <AlertCircle className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}

      {loading && (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="h-20 animate-pulse rounded-xl bg-muted/40" />
            ))}
          </div>
          <div className="h-48 animate-pulse rounded-xl bg-muted/40" />
        </div>
      )}

      {!loading && !error && !grcStats && (
        <div className="flex flex-col items-center gap-3 rounded-xl border border-border/60 bg-card py-16 text-center">
          <ClipboardCheck className="h-10 w-10 text-muted-foreground/40" />
          <p className="text-sm font-medium text-muted-foreground">No GRC data yet</p>
          <p className="text-xs text-muted-foreground/60">
            Add frameworks and controls via the GRC API.
          </p>
        </div>
      )}

      {/* Stats row */}
      {!loading && grcStats && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[
            { label: "Frameworks",         value: grcStats.total_frameworks ?? 0 },
            { label: "Controls",           value: grcStats.total_controls ?? 0 },
            { label: "Implemented",        value: grcStats.implemented_controls ?? 0 },
            { label: "Open risks",         value: grcStats.open_risks ?? 0 },
          ].map(({ label, value }) => (
            <div key={label} className="rounded-xl border border-border/60 bg-card px-4 py-3 text-center">
              <p className="text-2xl font-bold tabular-nums text-foreground">{value}</p>
              <p className="text-xs text-muted-foreground mt-0.5">{label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Frameworks */}
      {!loading && frameworks.length > 0 && (
        <div className="flex flex-col gap-2">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            Frameworks
          </p>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {frameworks.map((fw) => (
              <div
                key={fw.id ?? fw.name}
                className="rounded-xl border border-border/60 bg-card px-4 py-3 flex flex-col gap-2"
              >
                <div className="flex items-center justify-between gap-2">
                  <p className="text-sm font-semibold text-foreground">{fw.name}</p>
                  <span className="text-[10px] text-muted-foreground">{fw.version}</span>
                </div>
                <ScoreBar score={fw.compliance_score ?? 0} />
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>{fw.implemented_controls ?? 0} / {fw.total_controls ?? 0} controls</span>
                  <span className="font-semibold text-foreground">
                    {Math.round(fw.compliance_score ?? 0)}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* View toggle: controls / risks */}
      {!loading && (controls.length > 0 || risks.length > 0) && (
        <div className="flex flex-col gap-3">
          <div className="flex items-center gap-2">
            {(["controls", "risks"] as const).map((v) => (
              <button
                key={v}
                onClick={() => setActiveView(v)}
                className={`rounded-md px-3 py-1 text-xs font-medium transition-colors capitalize ${
                  activeView === v
                    ? "bg-primary text-primary-foreground"
                    : "border border-border text-muted-foreground hover:text-foreground"
                }`}
                aria-pressed={activeView === v}
              >
                {v} ({v === "controls" ? controls.length : risks.length})
              </button>
            ))}
          </div>

          {activeView === "controls" && controls.length > 0 && (
            <div className="overflow-x-auto rounded-xl border border-border/60">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border/60 bg-muted/30 text-left text-muted-foreground">
                    <th className="px-3 py-2.5 font-medium">Ref</th>
                    <th className="px-3 py-2.5 font-medium">Title</th>
                    <th className="px-3 py-2.5 font-medium">Category</th>
                    <th className="px-3 py-2.5 font-medium">Status</th>
                    <th className="px-3 py-2.5 font-medium">Owner</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/40">
                  {controls.slice(0, 50).map((ctrl) => {
                    const StatusIcon = CONTROL_STATUS_ICON[ctrl.status] ?? MinusCircle;
                    const statusCls = CONTROL_STATUS_BADGE[ctrl.status] ?? "text-slate-400 bg-slate-400/10";
                    return (
                      <tr key={ctrl.id ?? ctrl.control_ref} className="bg-card hover:bg-muted/20 transition-colors">
                        <td className="px-3 py-2 font-mono text-muted-foreground">{ctrl.control_ref || "—"}</td>
                        <td className="max-w-[200px] truncate px-3 py-2 text-foreground" title={ctrl.title}>{ctrl.title || "—"}</td>
                        <td className="px-3 py-2 text-muted-foreground capitalize">{ctrl.category || "—"}</td>
                        <td className="px-3 py-2">
                          <span className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${statusCls}`}>
                            <StatusIcon className="h-2.5 w-2.5" />
                            {ctrl.status?.replace(/_/g, " ")}
                          </span>
                        </td>
                        <td className="px-3 py-2 text-muted-foreground">{ctrl.owner || "—"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {controls.length > 50 && (
                <p className="border-t border-border/40 bg-muted/20 px-3 py-2 text-[10px] text-muted-foreground">
                  Showing 50 of {controls.length} controls
                </p>
              )}
            </div>
          )}

          {activeView === "risks" && risks.length > 0 && (
            <div className="overflow-x-auto rounded-xl border border-border/60">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border/60 bg-muted/30 text-left text-muted-foreground">
                    <th className="px-3 py-2.5 font-medium">Risk</th>
                    <th className="px-3 py-2.5 font-medium">Category</th>
                    <th className="px-3 py-2.5 font-medium">Likelihood</th>
                    <th className="px-3 py-2.5 font-medium">Impact</th>
                    <th className="px-3 py-2.5 font-medium">Treatment</th>
                    <th className="px-3 py-2.5 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/40">
                  {risks.map((risk) => {
                    const treatCls = RISK_TREATMENT_COLOR[risk.treatment?.toLowerCase() ?? ""] ?? "text-muted-foreground";
                    return (
                      <tr key={risk.id ?? risk.title} className="bg-card hover:bg-muted/20 transition-colors">
                        <td className="max-w-[200px] truncate px-3 py-2 font-medium text-foreground" title={risk.title}>{risk.title}</td>
                        <td className="px-3 py-2 text-muted-foreground capitalize">{risk.category || "—"}</td>
                        <td className="px-3 py-2 tabular-nums text-center text-muted-foreground">{risk.likelihood ?? "—"}/5</td>
                        <td className="px-3 py-2 tabular-nums text-center text-muted-foreground">{risk.impact ?? "—"}/5</td>
                        <td className={`px-3 py-2 capitalize font-medium ${treatCls}`}>{risk.treatment || "—"}</td>
                        <td className="px-3 py-2 text-muted-foreground capitalize">{risk.status || "—"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
