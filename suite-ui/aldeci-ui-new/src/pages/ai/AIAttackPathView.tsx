/**
 * AI Attack Path View
 *
 * Choke-point analysis on AI/agent attack paths — which nodes appear in the most paths.
 * Route: /ai/attack-paths
 * API: GET /api/v1/attack-paths/choke-points
 * Multica id: 36dd3ab6-6664-4a9f-b04a-fb8522e4e621
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Crosshair, RefreshCw, AlertTriangle, Network } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface ChokePoint {
  id?: string;
  asset?: string;
  asset_type?: string;
  paths_through?: number;
  blast_radius?: number;
  criticality?: string;
  recommended_action?: string;
  cve_count?: number;
}
interface ChokeResponse {
  choke_points?: ChokePoint[];
  items?: ChokePoint[];
  total_paths?: number;
  comingSoon?: boolean;
}

async function apiFetch<T>(path: string): Promise<{ data: T; status: number }> {
  const orgId = getStoredOrgId();
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" } });
  if (res.status === 501) return { data: { comingSoon: true } as T, status: 501 };
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return { data: (await res.json()) as T, status: res.status };
}

const critColor: Record<string, string> = {
  critical: "border-red-500/30 text-red-400 bg-red-500/10",
  high: "border-orange-500/30 text-orange-400 bg-orange-500/10",
  medium: "border-amber-500/30 text-amber-400 bg-amber-500/10",
  low: "border-blue-500/30 text-blue-400 bg-blue-500/10",
};

export default function AIAttackPathView() {
  const [points, setPoints] = useState<ChokePoint[]>([]);
  const [meta, setMeta] = useState<ChokeResponse | null>(null);
  const [comingSoon, setComingSoon] = useState(false);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    setErr(null);
    setLoading(true);
    setComingSoon(false);
    try {
      const { data } = await apiFetch<ChokeResponse>("/api/v1/attack-paths/choke-points");
      if (data.comingSoon) {
        setComingSoon(true);
        setPoints([]);
      } else {
        const list = Array.isArray(data) ? (data as ChokePoint[]) : (data.choke_points ?? data.items ?? []);
        setPoints(list);
        setMeta(data);
      }
    } catch (e) {
      setErr((e as Error).message);
      setPoints([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const totalPoints = points.length;
  const totalPaths = meta?.total_paths ?? points.reduce((s, p) => s + (p.paths_through ?? 0), 0);
  const criticalCount = points.filter((p) => (p.criticality ?? "").toLowerCase() === "critical").length;
  const maxBlast = points.reduce((m, p) => Math.max(m, p.blast_radius ?? 0), 0);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="AI Attack Path View"
        description="Choke-point analysis — pinpoint the assets that appear in the most attack paths"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
          </Button>
        }
      />

      {!comingSoon && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <KpiCard title="Choke Points" value={totalPoints} icon={Crosshair} />
          <KpiCard title="Total Paths" value={totalPaths} icon={Network} />
          <KpiCard title="Critical" value={criticalCount} icon={AlertTriangle} trend={criticalCount ? "up" : "flat"} />
          <KpiCard title="Max Blast Radius" value={maxBlast} icon={Network} />
        </div>
      )}

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Top Choke Points</CardTitle>
          <CardDescription className="text-xs">Patch these to break the most attack paths</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Computing choke points…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : comingSoon ? (
            <EmptyState icon={Crosshair} title="Coming soon" description="GET /api/v1/attack-paths/choke-points is not enabled on this deployment." />
          ) : points.length === 0 ? (
            <EmptyState icon={Crosshair} title="No choke points" description="No high-blast-radius nodes found in current attack paths." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Asset</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Paths Through</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Blast Radius</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">CVEs</TableHead>
                    <TableHead className="text-[11px] h-8">Criticality</TableHead>
                    <TableHead className="text-[11px] h-8">Recommendation</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {points.slice(0, 200).map((p, i) => (
                    <TableRow key={p.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">{p.asset ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{p.asset_type ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-right text-orange-400">{p.paths_through ?? 0}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-right">{p.blast_radius ?? 0}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-right">{p.cve_count ?? 0}</TableCell>
                      <TableCell className="py-2"><Badge className={cn("text-[10px] border capitalize", critColor[(p.criticality ?? "").toLowerCase()] ?? "border-border")}>{p.criticality ?? "—"}</Badge></TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground truncate max-w-xs">{p.recommended_action ?? "—"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
