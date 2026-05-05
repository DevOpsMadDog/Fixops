/**
 * StrideModelsPanel — STRIDE threat models from /api/v1/threat-modeling/models
 * Shows model catalog with component counts, threat counts, and STRIDE categories.
 */

import { useEffect, useState } from "react";
import { Layers, RefreshCw, ShieldAlert } from "lucide-react";
import { threatModelingApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface ThreatModel {
  model_id: string;
  name: string;
  description?: string;
  scope?: string;
  org_id?: string;
  status?: string;
  component_count?: number;
  threat_count?: number;
  mitigated_count?: number;
  residual_risk?: string;
  created_at?: string;
  updated_at?: string;
}

interface StrideCategory {
  description: string;
  mitigations: string[];
}

const STATUS_COLORS: Record<string, string> = {
  draft: "bg-slate-700 text-slate-300",
  active: "bg-green-800 text-green-200",
  review: "bg-amber-800 text-amber-200",
  archived: "bg-slate-800 text-slate-400",
};

function statusClass(s?: string) {
  return STATUS_COLORS[s?.toLowerCase() ?? ""] ?? STATUS_COLORS.draft;
}

export function StrideModelsPanel() {
  const [models, setModels] = useState<ThreatModel[]>([]);
  const [strideCategories, setStrideCategories] = useState<Record<string, StrideCategory>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    setError(null);
    Promise.all([
      threatModelingApi.models("default"),
      threatModelingApi.strideCategories(),
    ])
      .then(([modelsRes, strideRes]) => {
        const raw = modelsRes.data;
        setModels(Array.isArray(raw) ? raw : raw?.models ?? []);
        setStrideCategories((strideRes.data as Record<string, StrideCategory>) ?? {});
      })
      .catch((e: Error) => setError(e.message ?? "Failed to load STRIDE models"))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  if (loading) {
    return (
      <div className="space-y-3 mt-4">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="h-24 rounded-lg bg-muted/40 animate-pulse" />
        ))}
      </div>
    );
  }

  if (error) return <ErrorState message={error} onRetry={load} />;

  const strideKeys = Object.keys(strideCategories);

  return (
    <div className="space-y-4 mt-2">
      {/* STRIDE legend */}
      {strideKeys.length > 0 && (
        <div className="rounded-lg border border-border bg-muted/10 p-4">
          <div className="text-xs font-semibold text-muted-foreground mb-2">STRIDE Categories</div>
          <div className="flex flex-wrap gap-2">
            {strideKeys.map(key => (
              <span
                key={key}
                className="px-2 py-1 rounded bg-indigo-900/50 text-indigo-300 text-xs font-mono"
                title={strideCategories[key]?.description}
              >
                {key}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Summary counts */}
      <div className="grid grid-cols-3 gap-3">
        <div className="rounded-lg bg-muted/30 border border-border p-3 text-center">
          <div className="text-2xl font-bold text-slate-300">{models.length}</div>
          <div className="text-xs text-muted-foreground mt-0.5">Models</div>
        </div>
        <div className="rounded-lg bg-muted/30 border border-border p-3 text-center">
          <div className="text-2xl font-bold text-amber-400">
            {models.reduce((acc, m) => acc + (m.threat_count ?? 0), 0)}
          </div>
          <div className="text-xs text-muted-foreground mt-0.5">Total Threats</div>
        </div>
        <div className="rounded-lg bg-muted/30 border border-border p-3 text-center">
          <div className="text-2xl font-bold text-green-400">
            {models.reduce((acc, m) => acc + (m.mitigated_count ?? 0), 0)}
          </div>
          <div className="text-xs text-muted-foreground mt-0.5">Mitigated</div>
        </div>
      </div>

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

      {/* Models list */}
      {models.length === 0 ? (
        <EmptyState
          icon={Layers}
          title="No threat models"
          description="No STRIDE threat models have been created yet."
        />
      ) : (
        <div className="space-y-3">
          {models.map(m => (
            <div
              key={m.model_id}
              className="rounded-lg border border-border bg-muted/10 p-4"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <ShieldAlert className="h-4 w-4 text-indigo-400 flex-shrink-0" />
                    <span className="font-medium text-sm">{m.name}</span>
                    {m.status && (
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusClass(m.status)}`}>
                        {m.status}
                      </span>
                    )}
                  </div>
                  {m.description && (
                    <p className="text-xs text-muted-foreground truncate">{m.description}</p>
                  )}
                  {m.scope && (
                    <p className="text-xs text-muted-foreground">Scope: {m.scope}</p>
                  )}
                </div>
                <div className="flex-shrink-0 text-right text-xs text-muted-foreground space-y-0.5">
                  <div>{m.component_count ?? 0} components</div>
                  <div>{m.threat_count ?? 0} threats</div>
                  <div className="text-green-400">{m.mitigated_count ?? 0} mitigated</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
