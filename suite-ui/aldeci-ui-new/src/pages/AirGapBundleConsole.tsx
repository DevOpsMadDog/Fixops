// FOLDED into AirGapHub at /connect/mcp/air-gap?tab=feed-status (2026-05-02) — preserve for git history; lazy-imported by hub
/**
 * Air-Gap Bundle Console — feed-status of offline bundles
 * Route: /air-gap/feed-status
 * API: GET /api/v1/air-gap/feed-status
 * Multica id: ca5c00d5
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Package, RefreshCw, ShieldCheck, Database } from "lucide-react";

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

interface FeedStatus {
  feed_id?: string;
  name?: string;
  source?: string;
  last_synced?: string;
  records?: number;
  signature_verified?: boolean;
  status?: string;
}

interface FeedPayload {
  feeds?: FeedStatus[];
  items?: FeedStatus[];
  total?: number;
  signed?: number;
  last_update?: string;
  detail?: string;
}

async function apiFetch<T>(path: string): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
  });
  if (res.status === 501) return { detail: "Coming soon", feeds: [] } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function AirGapBundleConsole() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [payload, setPayload] = useState<FeedPayload | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const data = await apiFetch<FeedPayload>("/api/v1/air-gap/feed-status");
      setPayload(data);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const feeds = payload?.feeds ?? payload?.items ?? [];
  const totalFeeds = payload?.total ?? feeds.length;
  const signed = payload?.signed ?? feeds.filter(f => f.signature_verified).length;
  const lastUpdate = payload?.last_update ?? feeds[0]?.last_synced ?? "—";
  const isComingSoon = !!payload?.detail;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Air-Gap Bundle Console"
        description="Feed-status view of offline bundles delivered to air-gapped deployments"
        badge={isComingSoon ? "Coming Soon" : undefined}
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
        <KpiCard title="Total Feeds" value={totalFeeds} icon={Database} />
        <KpiCard title="Signed Feeds" value={signed} icon={ShieldCheck} trend={signed > 0 ? "up" : "flat"} />
        <KpiCard title="Last Update" value={lastUpdate.toString().slice(0, 19) || "—"} icon={Package} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Feed Inventory</CardTitle>
          <CardDescription className="text-xs">
            Endpoint: <code className="text-[10px]">GET /api/v1/air-gap/feed-status</code>
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading feed status…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : isComingSoon ? (
            <EmptyState icon={Package} title="Coming soon" description={`Endpoint /api/v1/air-gap/feed-status is registered but not yet implemented (HTTP 501).`} />
          ) : feeds.length === 0 ? (
            <EmptyState icon={Package} title="No feeds registered" description="Bundle feeds will appear once distributed to air-gapped sites." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Feed</TableHead>
                    <TableHead className="text-[11px] h-8">Source</TableHead>
                    <TableHead className="text-[11px] h-8">Records</TableHead>
                    <TableHead className="text-[11px] h-8">Signed</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Last Synced</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {feeds.map((f, i) => (
                    <TableRow key={f.feed_id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">{f.name ?? f.feed_id ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{f.source ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] tabular-nums">{f.records ?? 0}</TableCell>
                      <TableCell className="py-2">
                        {f.signature_verified ? (
                          <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Verified</Badge>
                        ) : (
                          <Badge className="text-[10px] border border-orange-500/30 text-orange-400 bg-orange-500/10">Unsigned</Badge>
                        )}
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground text-right">{f.last_synced ?? "—"}</TableCell>
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
