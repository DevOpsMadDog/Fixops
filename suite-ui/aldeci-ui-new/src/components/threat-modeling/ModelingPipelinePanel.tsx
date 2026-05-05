/**
 * ModelingPipelinePanel — continuous threat modeling pipeline
 * from /api/v1/threat-modeling-pipeline/models + /unmitigated
 * Shows active models with methodology, STRIDE coverage, and unmitigated threat queue.
 */

import { useEffect, useState } from "react";
import { ShieldOff, RefreshCw, AlertTriangle, ShieldCheck } from "lucide-react";
import { threatModelingPipelineApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface PipelineModel {
  model_id: string;
  model_name: string;
  system_description?: string;
  methodology: string;
  status: string;
  created_by?: string;
  org_id?: string;
  component_count?: number;
  threat_count?: number;
  mitigated_count?: number;
  created_at?: string;
}

interface UnmitigatedThreat {
  threat_id: string;
  threat_name: string;
  stride_category: string;
  description?: string;
  affected_component?: string;
  likelihood: string;
  impact: string;
  model_name?: string;
}

const METHODOLOGY_COLORS: Record<string, string> = {
  STRIDE: "bg-indigo-900/50 text-indigo-300",
  PASTA: "bg-purple-900/50 text-purple-300",
  VAST: "bg-blue-900/50 text-blue-300",
  "attack-tree": "bg-orange-900/50 text-orange-300",
  OCTAVE: "bg-teal-900/50 text-teal-300",
  custom: "bg-slate-700 text-slate-300",
};

const STATUS_COLORS: Record<string, string> = {
  active: "bg-green-800 text-green-200",
  draft: "bg-slate-700 text-slate-300",
  finalized: "bg-blue-800 text-blue-200",
  archived: "bg-slate-800 text-slate-400",
};

const IMPACT_COLORS: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-amber-400",
  low: "text-slate-400",
};

export function ModelingPipelinePanel() {
  const [models, setModels] = useState<PipelineModel[]>([]);
  const [unmitigated, setUnmitigated] = useState<UnmitigatedThreat[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>("all");

  const load = () => {
    setLoading(true);
    setError(null);
    Promise.all([
      threatModelingPipelineApi.models("default"),
      threatModelingPipelineApi.unmitigated("default"),
    ])
      .then(([modelsRes, unmitigatedRes]) => {
        const raw = modelsRes.data;
        setModels(Array.isArray(raw) ? raw : raw?.models ?? []);
        const rawU = unmitigatedRes.data;
        setUnmitigated(Array.isArray(rawU) ? rawU : rawU?.threats ?? []);
      })
      .catch((e: Error) => setError(e.message ?? "Failed to load modeling pipeline"))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  if (loading) {
    return (
      <div className="space-y-3 mt-4">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="h-20 rounded-lg bg-muted/40 animate-pulse" />
        ))}
      </div>
    );
  }

  if (error) return <ErrorState message={error} onRetry={load} />;

  const filteredModels = statusFilter === "all"
    ? models
    : models.filter(m => m.status === statusFilter);

  const totalThreats = models.reduce((a, m) => a + (m.threat_count ?? 0), 0);
  const totalMitigated = models.reduce((a, m) => a + (m.mitigated_count ?? 0), 0);

  return (
    <div className="space-y-4 mt-2">
      {/* Pipeline summary */}
      <div className="grid grid-cols-4 gap-3">
        <div className="rounded-lg bg-muted/30 border border-border p-3 text-center">
          <div className="text-2xl font-bold text-slate-300">{models.length}</div>
          <div className="text-xs text-muted-foreground mt-0.5">Pipeline Models</div>
        </div>
        <div className="rounded-lg bg-muted/30 border border-border p-3 text-center">
          <div className="text-2xl font-bold text-amber-400">{totalThreats}</div>
          <div className="text-xs text-muted-foreground mt-0.5">Total Threats</div>
        </div>
        <div className="rounded-lg bg-muted/30 border border-border p-3 text-center">
          <div className="text-2xl font-bold text-green-400">{totalMitigated}</div>
          <div className="text-xs text-muted-foreground mt-0.5">Mitigated</div>
        </div>
        <div className="rounded-lg bg-muted/30 border border-border p-3 text-center">
          <div className="text-2xl font-bold text-red-400">{unmitigated.length}</div>
          <div className="text-xs text-muted-foreground mt-0.5">Unmitigated</div>
        </div>
      </div>

      {/* Filter + refresh */}
      <div className="flex items-center gap-2">
        {["all", "active", "draft", "finalized"].map(f => (
          <button
            key={f}
            onClick={() => setStatusFilter(f)}
            className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
              statusFilter === f
                ? "bg-primary text-primary-foreground"
                : "bg-muted/40 text-muted-foreground hover:bg-muted/60"
            }`}
          >
            {f.charAt(0).toUpperCase() + f.slice(1)}
          </button>
        ))}
        <button
          onClick={load}
          className="ml-auto p-1.5 rounded-md hover:bg-muted/40 text-muted-foreground"
          aria-label="Refresh"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      {/* Models */}
      {filteredModels.length === 0 ? (
        <EmptyState
          icon={ShieldOff}
          title="No pipeline models"
          description="No threat modeling pipeline models found."
        />
      ) : (
        <div className="space-y-2">
          {filteredModels.map(m => (
            <div key={m.model_id} className="rounded-lg border border-border bg-muted/10 p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-medium text-sm">{m.model_name}</span>
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                      METHODOLOGY_COLORS[m.methodology] ?? METHODOLOGY_COLORS.custom
                    }`}>
                      {m.methodology}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                      STATUS_COLORS[m.status] ?? STATUS_COLORS.draft
                    }`}>
                      {m.status}
                    </span>
                  </div>
                  {m.system_description && (
                    <p className="text-xs text-muted-foreground truncate">{m.system_description}</p>
                  )}
                  {m.created_by && (
                    <p className="text-xs text-muted-foreground">By: {m.created_by}</p>
                  )}
                </div>
                <div className="flex-shrink-0 text-right text-xs space-y-0.5">
                  <div className="text-muted-foreground">{m.component_count ?? 0} components</div>
                  <div className="text-amber-400">{m.threat_count ?? 0} threats</div>
                  <div className="text-green-400">{m.mitigated_count ?? 0} mitigated</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Unmitigated threat queue */}
      {unmitigated.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold mb-2 flex items-center gap-1.5">
            <AlertTriangle className="h-4 w-4 text-red-400" />
            Unmitigated Threat Queue ({unmitigated.length})
          </h3>
          <div className="rounded-lg border border-border overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-muted/30">
                <tr>
                  <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Threat</th>
                  <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">STRIDE</th>
                  <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Component</th>
                  <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Likelihood</th>
                  <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Impact</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {unmitigated.map(t => (
                  <tr key={t.threat_id} className="hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-3 font-medium text-sm">{t.threat_name}</td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded bg-indigo-900/50 text-indigo-300 text-xs font-mono">
                        {t.stride_category}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{t.affected_component ?? "—"}</td>
                    <td className={`px-4 py-3 text-xs font-medium ${IMPACT_COLORS[t.likelihood?.toLowerCase()] ?? "text-slate-400"}`}>
                      {t.likelihood}
                    </td>
                    <td className={`px-4 py-3 text-xs font-medium ${IMPACT_COLORS[t.impact?.toLowerCase()] ?? "text-slate-400"}`}>
                      {t.impact}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {unmitigated.length === 0 && models.length > 0 && (
        <div className="rounded-lg border border-border bg-green-900/10 p-4 flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-green-400" />
          <span className="text-sm text-green-400">All modeled threats are mitigated</span>
        </div>
      )}
    </div>
  );
}
