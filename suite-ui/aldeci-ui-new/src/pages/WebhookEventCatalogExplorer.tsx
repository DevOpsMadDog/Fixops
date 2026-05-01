// FOLDED into WebhookIngestionHub at /connect/webhook-ingestion?tab=catalogue — preserve for git history
/**
 * Webhook Event Catalog Explorer
 * Route: /webhooks/event-catalogue
 * API: GET /api/v1/webhooks/event-catalogue
 * Multica id: cd12e22b
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Webhook, RefreshCw, BookOpen } from "lucide-react";

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

interface EventDef {
  event?: string;
  name?: string;
  category?: string;
  description?: string;
  version?: string;
  schema_url?: string;
}

interface Resp {
  events?: EventDef[];
  items?: EventDef[];
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
  if (res.status === 501) return { detail: "Coming soon", events: [] } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function WebhookEventCatalogExplorer() {
  const [data, setData] = useState<Resp | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [filter, setFilter] = useState("");

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const r = await apiFetch<Resp>("/api/v1/webhooks/event-catalogue");
      setData(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const all = data?.events ?? data?.items ?? [];
  const events = filter ? all.filter(e => (e.event ?? e.name ?? "").toLowerCase().includes(filter.toLowerCase())) : all;
  const isComingSoon = !!data?.detail;
  const categories = new Set(all.map(e => e.category ?? "").filter(Boolean));

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Webhook Event Catalogue"
        description="Browse all webhook event types ALdeci emits — schemas, versions, payload examples"
        badge={isComingSoon ? "Coming Soon" : undefined}
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
        <KpiCard title="Events" value={data?.total ?? all.length} icon={Webhook} />
        <KpiCard title="Categories" value={categories.size} icon={BookOpen} />
        <KpiCard title="Filter Match" value={events.length} icon={BookOpen} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Events</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">GET /api/v1/webhooks/event-catalogue</code></CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter by event name…" className="text-sm" />
          {loading ? <div className="text-sm text-muted-foreground">Loading…</div>
          : err ? <ErrorState message={err} onRetry={load} />
          : isComingSoon ? <EmptyState icon={Webhook} title="Coming soon" description="Endpoint returns 501." />
          : events.length === 0 ? <EmptyState icon={Webhook} title="No events match" />
          : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Event</TableHead>
                    <TableHead className="text-[11px] h-8">Category</TableHead>
                    <TableHead className="text-[11px] h-8">Version</TableHead>
                    <TableHead className="text-[11px] h-8">Description</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {events.map((e, i) => (
                    <TableRow key={i}>
                      <TableCell className="py-2 text-[11px] font-mono">{e.event ?? e.name ?? "—"}</TableCell>
                      <TableCell className="py-2"><Badge className="text-[10px]">{e.category ?? "—"}</Badge></TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-muted-foreground">{e.version ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{e.description ?? "—"}</TableCell>
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
