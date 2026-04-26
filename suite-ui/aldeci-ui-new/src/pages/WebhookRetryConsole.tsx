/**
 * Webhook Retry Console
 * Route: /webhooks/retry-queue
 * API: GET /api/v1/webhooks/retry-queue (501 ok)
 * Multica id: 5c721621
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { RotateCcw, RefreshCw, AlertTriangle } from "lucide-react";

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

interface RetryItem {
  id?: string;
  event?: string;
  endpoint_url?: string;
  attempts?: number;
  last_status?: number;
  last_error?: string;
  next_retry?: string;
}

interface Resp {
  queue?: RetryItem[];
  items?: RetryItem[];
  total?: number;
  oldest?: string;
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
  if (res.status === 501) return { detail: "Coming soon", queue: [] } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function WebhookRetryConsole() {
  const [data, setData] = useState<Resp | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const r = await apiFetch<Resp>("/api/v1/webhooks/retry-queue");
      setData(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const items = data?.queue ?? data?.items ?? [];
  const isComingSoon = !!data?.detail;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Webhook Retry Queue"
        description="Failed webhook deliveries pending retry — investigate, force retry, drop"
        badge={isComingSoon ? "Coming Soon" : undefined}
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
        <KpiCard title="Pending" value={data?.total ?? items.length} icon={RotateCcw} />
        <KpiCard title="Errors" value={items.filter(i => i.last_error).length} icon={AlertTriangle} trend={items.filter(i => i.last_error).length > 0 ? "down" : "flat"} />
        <KpiCard title="Oldest" value={data?.oldest ?? items[0]?.next_retry ?? "—"} icon={RotateCcw} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Retry Queue</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">GET /api/v1/webhooks/retry-queue</code></CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? <div className="p-6 text-sm text-muted-foreground">Loading…</div>
          : err ? <ErrorState message={err} onRetry={load} />
          : isComingSoon ? <EmptyState icon={RotateCcw} title="Coming soon" description="Endpoint returns 501." />
          : items.length === 0 ? <EmptyState icon={RotateCcw} title="Queue is clear" description="No retries pending. Webhooks delivering normally." />
          : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">ID</TableHead>
                    <TableHead className="text-[11px] h-8">Event</TableHead>
                    <TableHead className="text-[11px] h-8">Endpoint</TableHead>
                    <TableHead className="text-[11px] h-8">Attempts</TableHead>
                    <TableHead className="text-[11px] h-8">Last</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Next Retry</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((it, i) => (
                    <TableRow key={it.id ?? i}>
                      <TableCell className="py-2 text-[11px] font-mono">{(it.id ?? "").slice(0, 12) || "—"}</TableCell>
                      <TableCell className="py-2"><Badge className="text-[10px]">{it.event ?? "—"}</Badge></TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-muted-foreground truncate max-w-xs">{it.endpoint_url ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] tabular-nums">{it.attempts ?? 0}</TableCell>
                      <TableCell className="py-2">
                        {it.last_status ? <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">{it.last_status}</Badge> : <Badge className="text-[10px]">—</Badge>}
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground text-right">{it.next_retry ?? "—"}</TableCell>
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
