/**
 * Architecture Layer Graph
 *
 * Module-level architectural layering — controllers / services / repos / data plane.
 * Route: /discover/arch-layers
 * API: GET /api/v1/graph/layers/{moduleId}
 * Multica id: 3d74cd0c-37e1-4628-b732-b7164104fff8
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Layers, RefreshCw, Search, AlertTriangle } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface LayerNode {
  id?: string;
  name?: string;
  layer?: string; // presentation | application | domain | infrastructure | data
  module?: string;
  fanout?: number;
  fanin?: number;
}
interface LayerViolation {
  from?: string;
  to?: string;
  rule?: string;
  severity?: string;
}
interface LayersResponse {
  module_id?: string;
  layers?: string[];
  nodes?: LayerNode[];
  violations?: LayerViolation[];
  comingSoon?: boolean;
}

async function apiFetch<T>(path: string): Promise<{ data: T; status: number }> {
  const orgId = getStoredOrgId();
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" },
  });
  if (res.status === 501) return { data: { comingSoon: true } as T, status: 501 };
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return { data: (await res.json()) as T, status: res.status };
}

const layerColor: Record<string, string> = {
  presentation: "border-purple-500/30 text-purple-400 bg-purple-500/10",
  application: "border-blue-500/30 text-blue-400 bg-blue-500/10",
  domain: "border-green-500/30 text-green-400 bg-green-500/10",
  infrastructure: "border-amber-500/30 text-amber-400 bg-amber-500/10",
  data: "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
};

export default function ArchitectureLayerGraph() {
  const [moduleId, setModuleId] = useState("");
  const [submitted, setSubmitted] = useState<string | null>(null);
  const [data, setData] = useState<LayersResponse | null>(null);
  const [comingSoon, setComingSoon] = useState(false);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async (id: string) => {
    setErr(null);
    setLoading(true);
    setComingSoon(false);
    try {
      const { data: payload } = await apiFetch<LayersResponse>(`/api/v1/graph/layers/${encodeURIComponent(id)}`);
      if (payload.comingSoon) {
        setComingSoon(true);
        setData(null);
      } else {
        setData(payload);
      }
    } catch (e) {
      setErr((e as Error).message);
      setData(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (submitted) load(submitted);
  }, [submitted]);

  const layers = data?.layers ?? Array.from(new Set((data?.nodes ?? []).map((n) => (n.layer ?? "unknown").toLowerCase())));
  const grouped = layers.map((l) => ({
    layer: l,
    nodes: (data?.nodes ?? []).filter((n) => (n.layer ?? "").toLowerCase() === l.toLowerCase()),
  }));
  const violations = data?.violations ?? [];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Architecture Layer Graph"
        description="Visualize layer boundaries and detect architectural violations"
        actions={
          <Button variant="outline" size="sm" onClick={() => submitted && load(submitted)} disabled={loading || !submitted}>
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
          </Button>
        }
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Search className="h-4 w-4" /> Module</CardTitle>
          <CardDescription className="text-xs">Enter a module / package id to load layered structure</CardDescription>
        </CardHeader>
        <CardContent className="flex items-center gap-2">
          <Input value={moduleId} onChange={(e) => setModuleId(e.target.value)} placeholder="module-id" className="h-9 text-xs" />
          <Button size="sm" onClick={() => moduleId.trim() && setSubmitted(moduleId.trim())} disabled={!moduleId.trim()}>
            Load
          </Button>
        </CardContent>
      </Card>

      {data && !comingSoon && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <KpiCard title="Layers" value={layers.length} icon={Layers} />
          <KpiCard title="Modules" value={data.nodes?.length ?? 0} icon={Layers} />
          <KpiCard title="Violations" value={violations.length} icon={AlertTriangle} trend={violations.length ? "up" : "flat"} />
          <KpiCard title="Module" value={data.module_id ?? submitted ?? "—"} icon={Layers} />
        </div>
      )}

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Layered Modules</CardTitle>
          <CardDescription className="text-xs">Architectural layers (presentation → data)</CardDescription>
        </CardHeader>
        <CardContent>
          {!submitted ? (
            <EmptyState icon={Search} title="No module selected" description="Enter a module id to view its layered structure." />
          ) : loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading layers…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={() => submitted && load(submitted)} />
          ) : comingSoon ? (
            <EmptyState icon={Layers} title="Coming soon" description="GET /api/v1/graph/layers/{id} is not enabled on this deployment." />
          ) : grouped.length === 0 ? (
            <EmptyState icon={Layers} title="No layers" description="No layered structure was returned for this module." />
          ) : (
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              {grouped.map((g) => (
                <div key={g.layer} className="border border-border rounded-lg p-3">
                  <div className="flex items-center justify-between mb-2">
                    <Badge className={cn("text-[10px] border capitalize", layerColor[g.layer.toLowerCase()] ?? "border-border")}>{g.layer}</Badge>
                    <span className="text-[10px] text-muted-foreground">{g.nodes.length} modules</span>
                  </div>
                  <div className="space-y-1 max-h-40 overflow-y-auto">
                    {g.nodes.length === 0 ? <p className="text-[10px] text-muted-foreground">empty</p> : g.nodes.map((n, i) => (
                      <div key={n.id ?? i} className="text-[11px] font-mono text-muted-foreground truncate">{n.name ?? n.module ?? "—"}</div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {violations.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400"><AlertTriangle className="h-4 w-4" /> Layer Violations</CardTitle>
            <CardDescription className="text-xs">Forbidden inter-layer dependencies</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="divide-y divide-border">
              {violations.map((v, i) => (
                <div key={i} className="py-2 flex items-center justify-between text-[11px]">
                  <div className="font-mono">{v.from} → {v.to}</div>
                  <div className="text-muted-foreground">{v.rule}</div>
                  <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">{v.severity ?? "violation"}</Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </motion.div>
  );
}
