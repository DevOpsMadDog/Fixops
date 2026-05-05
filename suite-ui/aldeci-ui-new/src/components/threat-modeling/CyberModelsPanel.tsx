/**
 * CyberModelsPanel — cyber threat model catalog from /api/v1/cyber-threat-models/
 * Shows summary stats, attack trees (unmitigated), and model aggregate view.
 */

import { useEffect, useState } from "react";
import { Network, RefreshCw, AlertTriangle, ShieldCheck } from "lucide-react";
import { cyberThreatModelsApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface CyberModelSummary {
  total_models: number;
  total_attack_trees: number;
  mitigated_trees: number;
  unmitigated_trees: number;
  threat_actors: number;
  model_types: Record<string, number>;
  by_status?: Record<string, number>;
}

interface UnmitigatedTree {
  tree_id: string;
  root_goal: string;
  attack_vector: string;
  likelihood: string;
  impact: string;
  model_name?: string;
  model_id?: string;
}

const LIKELIHOOD_COLORS: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-amber-400",
  low: "text-slate-400",
};

export function CyberModelsPanel() {
  const [summary, setSummary] = useState<CyberModelSummary | null>(null);
  const [unmitigated, setUnmitigated] = useState<UnmitigatedTree[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    setError(null);
    Promise.all([
      cyberThreatModelsApi.summary("default"),
      cyberThreatModelsApi.unmitigated("default"),
    ])
      .then(([summaryRes, unmitigatedRes]) => {
        setSummary(summaryRes.data as CyberModelSummary);
        const raw = unmitigatedRes.data;
        setUnmitigated(Array.isArray(raw) ? raw : raw?.items ?? []);
      })
      .catch((e: Error) => setError(e.message ?? "Failed to load cyber threat models"))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  if (loading) {
    return (
      <div className="space-y-3 mt-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="h-16 rounded-lg bg-muted/40 animate-pulse" />
        ))}
      </div>
    );
  }

  if (error) return <ErrorState message={error} onRetry={load} />;

  return (
    <div className="space-y-4 mt-2">
      {/* Summary stats */}
      {summary && (
        <div className="grid grid-cols-5 gap-3">
          {[
            { label: "Models", value: summary.total_models, color: "text-slate-300" },
            { label: "Attack Trees", value: summary.total_attack_trees, color: "text-indigo-400" },
            { label: "Mitigated", value: summary.mitigated_trees, color: "text-green-400" },
            { label: "Unmitigated", value: summary.unmitigated_trees, color: "text-red-400" },
            { label: "Threat Actors", value: summary.threat_actors, color: "text-amber-400" },
          ].map(s => (
            <div key={s.label} className="rounded-lg bg-muted/30 border border-border p-3 text-center">
              <div className={`text-2xl font-bold ${s.color}`}>{s.value ?? 0}</div>
              <div className="text-xs text-muted-foreground mt-0.5">{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Model types breakdown */}
      {summary?.model_types && Object.keys(summary.model_types).length > 0 && (
        <div className="rounded-lg border border-border bg-muted/10 p-4">
          <div className="text-xs font-semibold text-muted-foreground mb-2">By Model Type</div>
          <div className="flex flex-wrap gap-2">
            {Object.entries(summary.model_types).map(([type, count]) => (
              <span key={type} className="px-2 py-1 rounded bg-muted/40 text-xs">
                <span className="text-slate-300">{type}</span>
                <span className="ml-1 text-indigo-400 font-bold">{count}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Refresh */}
      <div className="flex justify-end">
        <button
          onClick={load}
          className="p-1.5 rounded-md hover:bg-muted/40 text-muted-foreground"
          aria-label="Refresh"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      {/* Unmitigated attack trees */}
      <div>
        <h3 className="text-sm font-semibold mb-2 flex items-center gap-1.5">
          <AlertTriangle className="h-4 w-4 text-red-400" />
          Unmitigated Attack Trees
        </h3>
        {unmitigated.length === 0 ? (
          <div className="rounded-lg border border-border bg-green-900/10 p-4 flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-green-400" />
            <span className="text-sm text-green-400">All attack trees are mitigated</span>
          </div>
        ) : (
          <div className="rounded-lg border border-border overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-muted/30">
                <tr>
                  <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Goal</th>
                  <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Vector</th>
                  <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Likelihood</th>
                  <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Impact</th>
                  <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Model</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {unmitigated.map(tree => (
                  <tr key={tree.tree_id} className="hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-3 font-medium text-sm">{tree.root_goal}</td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{tree.attack_vector}</td>
                    <td className={`px-4 py-3 text-xs font-medium ${LIKELIHOOD_COLORS[tree.likelihood?.toLowerCase()] ?? "text-slate-400"}`}>
                      {tree.likelihood}
                    </td>
                    <td className={`px-4 py-3 text-xs font-medium ${LIKELIHOOD_COLORS[tree.impact?.toLowerCase()] ?? "text-slate-400"}`}>
                      {tree.impact}
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{tree.model_name ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
