/**
 * SBOM Continuous Monitoring — re-evaluation history for an SBOM (Wave 3)
 * Route: /sbom-continuous-monitoring
 * API:   GET /api/v1/sbom/{id}/re-eval-history
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Package, RefreshCw, Search, Clock, ShieldAlert } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface ReEval {
  id?: string;
  evaluated_at?: string;
  total_components?: number;
  vulns_total?: number;
  vulns_critical?: number;
  vulns_high?: number;
  new_vulns?: number;
  fixed_vulns?: number;
  trigger?: string;
  duration_ms?: number;
}
interface Response {
  sbom_id?: string;
  history?: ReEval[];
  items?: ReEval[];
  total_evaluations?: number;
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

export default function SBOMContinuousMonitoring() {
  const [sbomId, setSbomId] = useState("");
  const [data, setData] = useState<Response | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [comingSoon, setComingSoon] = useState(false);

  const load = async (id: string) => {
    if (!id.trim()) return;
    setErr(null);
    setLoading(true);
    setComingSoon(false);
    try {
      const r = await apiFetch<Response>(`/api/v1/sbom/${encodeURIComponent(id.trim())}/re-eval-history`);
      if (!r) {
        setComingSoon(true);
        setData(null);
      } else {
        setData(r);
      }
    } catch (e) {
      setErr((e as Error).message);
      setData(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const hash = window.location.hash.match(/sbom=([^&]+)/);
    if (hash) {
      setSbomId(hash[1]);
      load(hash[1]);
    }
  }, []);

  const items = data?.history ?? data?.items ?? [];
  const latest = items[0];
  const totalNew = items.reduce((s, h) => s + (h.new_vulns ?? 0), 0);
  const totalFixed = items.reduce((s, h) => s + (h.fixed_vulns ?? 0), 0);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="SBOM Continuous Monitoring"
        description="Watch how an SBOM's vulnerability profile evolves with each NVD/OSV/GHSA re-evaluation"
        actions={
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-muted-foreground" />
              <Input
                value={sbomId}
                onChange={(e) => setSbomId(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && load(sbomId)}
                placeholder="SBOM ID…"
                className="h-8 w-[260px] pl-7 text-xs font-mono"
              />
            </div>
            <Button variant="outline" size="sm" onClick={() => load(sbomId)} disabled={loading || !sbomId.trim()}>
              <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
            </Button>
          </div>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Re-evaluations" value={items.length} icon={RefreshCw} />
        <KpiCard title="Latest Vulns" value={latest?.vulns_total ?? 0} icon={ShieldAlert} />
        <KpiCard title="Net New Vulns" value={totalNew} icon={ShieldAlert} trend="down" />
        <KpiCard title="Net Fixed" value={totalFixed} icon={Package} trend="up" />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Clock className="h-4 w-4" /> Evaluation Timeline
          </CardTitle>
          <CardDescription className="text-xs">SBOM: <span className="font-mono">{data?.sbom_id ?? sbomId ?? "—"}</span></CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={() => load(sbomId)} />
          ) : comingSoon ? (
            <EmptyState icon={Package} title="Coming soon" description="The SBOM re-eval history endpoint is not yet enabled." />
          ) : !data ? (
            <EmptyState icon={Package} title="Pick an SBOM" description="Enter an SBOM ID above to inspect its evaluation history." />
          ) : items.length === 0 ? (
            <EmptyState icon={Package} title="No evaluations yet" description="This SBOM has not been re-evaluated since ingestion." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Evaluated</TableHead>
                    <TableHead className="text-[11px] h-8">Components</TableHead>
                    <TableHead className="text-[11px] h-8">Vulns Total</TableHead>
                    <TableHead className="text-[11px] h-8">Critical</TableHead>
                    <TableHead className="text-[11px] h-8">High</TableHead>
                    <TableHead className="text-[11px] h-8">Δ New / Fixed</TableHead>
                    <TableHead className="text-[11px] h-8">Trigger</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Duration</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((h, i) => (
                    <TableRow key={(h.id ?? "h") + i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">{h.evaluated_at?.replace("T", " ").slice(0, 16) ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">{h.total_components ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">{h.vulns_total ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-red-400">{h.vulns_critical ?? 0}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-orange-400">{h.vulns_high ?? 0}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">
                        <span className="text-red-400">+{h.new_vulns ?? 0}</span> / <span className="text-green-400">−{h.fixed_vulns ?? 0}</span>
                      </TableCell>
                      <TableCell className="py-2"><Badge className="text-[10px] border border-border">{h.trigger ?? "—"}</Badge></TableCell>
                      <TableCell className="py-2 text-[11px] text-right text-muted-foreground">{h.duration_ms ? `${h.duration_ms}ms` : "—"}</TableCell>
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
