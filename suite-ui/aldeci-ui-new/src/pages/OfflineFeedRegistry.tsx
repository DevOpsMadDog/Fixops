/**
 * Offline Feed Registry — list of all air-gap feeds available
 * Route: /air-gap/feeds
 * API: GET /api/v1/air-gap/feeds
 * Multica id: f6ebc551
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Database, RefreshCw, ShieldCheck } from "lucide-react";

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

interface Feed {
  feed_id?: string;
  id?: string;
  name?: string;
  description?: string;
  format?: string;
  size_bytes?: number;
  signature?: string;
  updated_at?: string;
}

interface FeedListResp {
  feeds?: Feed[];
  items?: Feed[];
  total?: number;
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

function formatBytes(n?: number) {
  if (!n) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export default function OfflineFeedRegistry() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [data, setData] = useState<FeedListResp | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const resp = await apiFetch<FeedListResp>("/api/v1/air-gap/feeds");
      setData(resp);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const feeds = data?.feeds ?? data?.items ?? [];
  const total = data?.total ?? feeds.length;
  const signed = feeds.filter(f => !!f.signature).length;
  const isComingSoon = !!data?.detail;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Offline Feed Registry"
        description="All feeds prepared for air-gapped deployments — signatures, sizes, formats"
        badge={isComingSoon ? "Coming Soon" : undefined}
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
        <KpiCard title="Registered Feeds" value={total} icon={Database} />
        <KpiCard title="Signed Feeds" value={signed} icon={ShieldCheck} trend={signed === total ? "up" : "flat"} />
        <KpiCard title="Coverage" value={total > 0 ? `${Math.round((signed / total) * 100)}%` : "—"} icon={ShieldCheck} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Feeds</CardTitle>
          <CardDescription className="text-xs">
            Endpoint: <code className="text-[10px]">GET /api/v1/air-gap/feeds</code>
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading feeds…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : isComingSoon ? (
            <EmptyState icon={Database} title="Coming soon" description="Endpoint /api/v1/air-gap/feeds returns 501 — implementation pending." />
          ) : feeds.length === 0 ? (
            <EmptyState icon={Database} title="No feeds registered" />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Feed</TableHead>
                    <TableHead className="text-[11px] h-8">Format</TableHead>
                    <TableHead className="text-[11px] h-8">Size</TableHead>
                    <TableHead className="text-[11px] h-8">Signature</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Updated</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {feeds.map((f, i) => (
                    <TableRow key={f.id ?? f.feed_id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">{f.name ?? f.feed_id ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{f.format ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">{formatBytes(f.size_bytes)}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-muted-foreground">{(f.signature ?? "").slice(0, 12) || "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground text-right">{f.updated_at ?? "—"}</TableCell>
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
