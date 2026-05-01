// FOLDED 2026-05-02 into FinanceHub.tsx — tab "bu-heatmap" at /mission-control/finance?tab=bu-heatmap
// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * BU Dollar Risk Heatmap — cross-BU dollar exposure heatmap (Wave 3)
 * Route: /bu-dollar-heatmap (now redirects to /mission-control/finance?tab=bu-heatmap)
 * API:   GET /api/v1/risk/heatmap (with fallback to /api/v1/risk/brs/bu list)
 */

import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { DollarSign, RefreshCw, Grid3x3, Building2 } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface HeatmapCell {
  bu_id?: string;
  bu_name?: string;
  category?: string;
  dollar_exposure?: number;
  brs_score?: number;
  finding_count?: number;
}

interface HeatmapResponse {
  cells?: HeatmapCell[];
  business_units?: HeatmapCell[];
  items?: HeatmapCell[];
  total_exposure?: number;
}

async function apiFetch<T>(path: string): Promise<T | null> {
  const res = await fetch(buildApiUrl(path), {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
  });
  if (res.status === 404 || res.status === 501) return null;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

function fmtMoney(n?: number) {
  if (n === undefined || n === null) return "—";
  if (n >= 1e9) return `$${(n / 1e9).toFixed(1)}B`;
  if (n >= 1e6) return `$${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `$${(n / 1e3).toFixed(0)}K`;
  return `$${n.toFixed(0)}`;
}

function cellColor(score?: number) {
  if (score === undefined) return "bg-muted/40";
  if (score >= 80) return "bg-red-500/40 hover:bg-red-500/60";
  if (score >= 60) return "bg-orange-500/40 hover:bg-orange-500/60";
  if (score >= 40) return "bg-yellow-500/40 hover:bg-yellow-500/60";
  if (score >= 20) return "bg-green-500/30 hover:bg-green-500/50";
  return "bg-emerald-500/20 hover:bg-emerald-500/40";
}

export default function BUDollarRiskHeatmap() {
  const [cells, setCells] = useState<HeatmapCell[]>([]);
  const [totalExposure, setTotalExposure] = useState<number | undefined>();
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [usedFallback, setUsedFallback] = useState(false);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    setUsedFallback(false);
    try {
      const primary = await apiFetch<HeatmapResponse>("/api/v1/risk/heatmap");
      if (primary) {
        const list = primary.cells ?? primary.business_units ?? primary.items ?? [];
        setCells(list);
        setTotalExposure(primary.total_exposure ?? list.reduce((s, c) => s + (c.dollar_exposure ?? 0), 0));
      } else {
        // fallback to BRS BU list
        setUsedFallback(true);
        const fallback = await apiFetch<{ business_units?: HeatmapCell[] }>("/api/v1/risk/brs/bu");
        const list = fallback?.business_units ?? [];
        setCells(list);
        setTotalExposure(list.reduce((s, c) => s + (c.dollar_exposure ?? 0), 0));
      }
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const sortedCells = useMemo(() => [...cells].sort((a, b) => (b.dollar_exposure ?? 0) - (a.dollar_exposure ?? 0)), [cells]);
  const avgScore = useMemo(() => {
    if (cells.length === 0) return undefined;
    const ss = cells.filter((c) => typeof c.brs_score === "number").map((c) => c.brs_score!);
    if (ss.length === 0) return undefined;
    return ss.reduce((a, b) => a + b, 0) / ss.length;
  }, [cells]);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="BU Dollar-Risk Heatmap"
        description="Color-graded grid of business-unit risk score weighted by dollar exposure"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Business Units" value={cells.length} icon={Building2} />
        <KpiCard title="Total Exposure" value={fmtMoney(totalExposure)} icon={DollarSign} />
        <KpiCard title="Avg BRS" value={avgScore !== undefined ? avgScore.toFixed(0) : "—"} icon={Grid3x3} />
        <KpiCard title="High-Risk BUs" value={cells.filter((c) => (c.brs_score ?? 0) >= 60).length} icon={Building2} trend="down" />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Grid3x3 className="h-4 w-4" /> Heatmap Grid
          </CardTitle>
          <CardDescription className="text-xs">
            Cell size ∝ dollar exposure · Color ∝ BRS score
            {usedFallback && <Badge className="ml-2 text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">fallback</Badge>}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : sortedCells.length === 0 ? (
            <EmptyState icon={Grid3x3} title="No BUs registered" description="Create business units and run BRS scoring to populate this heatmap." />
          ) : (
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6">
              {sortedCells.map((c, i) => (
                <div
                  key={(c.bu_id ?? c.bu_name ?? "cell") + i}
                  className={cn("rounded-md p-3 transition-colors border border-border/50", cellColor(c.brs_score))}
                  title={`${c.bu_name ?? c.bu_id ?? "BU"} — score ${c.brs_score ?? "?"} — exposure ${fmtMoney(c.dollar_exposure)}`}
                >
                  <div className="text-xs font-semibold truncate">{c.bu_name ?? c.bu_id ?? "BU"}</div>
                  <div className="mt-1 text-[10px] text-foreground/80 font-mono">{fmtMoney(c.dollar_exposure)}</div>
                  <div className="mt-1 flex items-center justify-between">
                    <span className="text-[10px] uppercase tracking-wider opacity-70">BRS</span>
                    <span className="text-xs font-mono">{c.brs_score?.toFixed(0) ?? "—"}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Top Exposures</CardTitle>
          <CardDescription className="text-xs">Highest-dollar BUs sorted descending</CardDescription>
        </CardHeader>
        <CardContent>
          {sortedCells.slice(0, 8).length === 0 ? (
            <EmptyState icon={DollarSign} title="No exposure data" />
          ) : (
            <div className="space-y-1">
              {sortedCells.slice(0, 8).map((c, i) => (
                <div key={(c.bu_id ?? "row") + i} className="flex items-center justify-between text-xs py-1 border-b border-border/30 last:border-0">
                  <span>{c.bu_name ?? c.bu_id}</span>
                  <span className="font-mono">{fmtMoney(c.dollar_exposure)}</span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
