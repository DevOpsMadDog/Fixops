// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Choke Point Dashboard — high-leverage attack-path bottlenecks (Wave 3)
 * Route: /choke-points
 * API:   GET /api/v1/attack-paths/choke-points
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Crosshair, RefreshCw, Network, AlertTriangle, Wrench } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
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
  asset_id?: string;
  asset_name?: string;
  asset_type?: string;
  paths_through?: number;
  blast_radius?: number;
  fix_complexity?: "low" | "medium" | "high";
  recommended_action?: string;
  affected_assets?: number;
  severity?: string;
}

interface Response {
  choke_points?: ChokePoint[];
  items?: ChokePoint[];
  total?: number;
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

function complexityBadge(c?: string) {
  switch ((c ?? "").toLowerCase()) {
    case "low": return "border-green-500/30 text-green-400 bg-green-500/10";
    case "medium": return "border-yellow-500/30 text-yellow-400 bg-yellow-500/10";
    case "high": return "border-red-500/30 text-red-400 bg-red-500/10";
    default: return "border-border";
  }
}

export default function ChokePointDashboard() {
  const [points, setPoints] = useState<ChokePoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [comingSoon, setComingSoon] = useState(false);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    setComingSoon(false);
    try {
      const r = await apiFetch<Response>("/api/v1/attack-paths/choke-points");
      if (!r) {
        setComingSoon(true);
        setPoints([]);
      } else {
        setPoints(r.choke_points ?? r.items ?? []);
      }
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const totalBlast = points.reduce((s, p) => s + (p.blast_radius ?? 0), 0);
  const fixableNow = points.filter((p) => p.fix_complexity === "low").length;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Attack-Path Choke Points"
        description="Single-point assets that disproportionately enable attack chains — fix one, neutralize many"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Choke Points" value={points.length} icon={Crosshair} />
        <KpiCard title="Total Blast" value={totalBlast} icon={Network} />
        <KpiCard title="Quick Wins" value={fixableNow} icon={Wrench} trend="up" />
        <KpiCard title="Critical" value={points.filter((p) => (p.severity ?? "").toLowerCase() === "critical").length} icon={AlertTriangle} trend="down" />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Crosshair className="h-4 w-4" /> Ranked Choke Points
          </CardTitle>
          <CardDescription className="text-xs">Sorted by blast-radius × paths-through</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : comingSoon ? (
            <EmptyState
              icon={Crosshair}
              title="Coming soon"
              description="The choke-point analyzer endpoint is not yet enabled in this build."
            />
          ) : points.length === 0 ? (
            <EmptyState icon={Crosshair} title="No choke points detected" description="Run an attack-path analysis to identify high-leverage assets." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Asset</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8">Paths Through</TableHead>
                    <TableHead className="text-[11px] h-8">Blast Radius</TableHead>
                    <TableHead className="text-[11px] h-8">Fix Effort</TableHead>
                    <TableHead className="text-[11px] h-8">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {points.map((p, i) => (
                    <TableRow key={p.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">{p.asset_name ?? p.asset_id ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground capitalize">{p.asset_type ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">{p.paths_through ?? 0}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">{p.blast_radius ?? 0}</TableCell>
                      <TableCell className="py-2">
                        <Badge className={cn("text-[10px] border capitalize", complexityBadge(p.fix_complexity))}>
                          {p.fix_complexity ?? "—"}
                        </Badge>
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground max-w-[280px] truncate">
                        {p.recommended_action ?? "—"}
                      </TableCell>
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
