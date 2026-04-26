/**
 * Hooks Status Panel
 * Route: /hooks/status
 * API: GET /api/v1/hooks/status (501 ok)
 * Multica id: b5842e05
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Activity, RefreshCw, Webhook } from "lucide-react";

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

interface HookStatus {
  name?: string;
  stage?: string;
  enabled?: boolean;
  invocations?: number;
  failures?: number;
  last_run?: string;
}

interface Resp {
  hooks?: HookStatus[];
  total?: number;
  enabled?: number;
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
  if (res.status === 501) return { detail: "Coming soon", hooks: [] } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function HooksStatusPanel() {
  const [data, setData] = useState<Resp | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const r = await apiFetch<Resp>("/api/v1/hooks/status");
      setData(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const hooks = data?.hooks ?? [];
  const isComingSoon = !!data?.detail;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Hooks Status"
        description="Live status of registered pipeline hooks — invocations, failures, last run"
        badge={isComingSoon ? "Coming Soon" : undefined}
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
        <KpiCard title="Hooks" value={data?.total ?? hooks.length} icon={Webhook} />
        <KpiCard title="Enabled" value={data?.enabled ?? hooks.filter(h => h.enabled).length} icon={Activity} trend="up" />
        <KpiCard title="Failures (1h)" value={hooks.reduce((s, h) => s + (h.failures ?? 0), 0)} icon={Webhook} trend={hooks.reduce((s, h) => s + (h.failures ?? 0), 0) > 0 ? "down" : "flat"} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Registered Hooks</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">GET /api/v1/hooks/status</code></CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? <div className="p-6 text-sm text-muted-foreground">Loading…</div>
          : err ? <ErrorState message={err} onRetry={load} />
          : isComingSoon ? <EmptyState icon={Webhook} title="Coming soon" description="Endpoint returns 501." />
          : hooks.length === 0 ? <EmptyState icon={Webhook} title="No hooks registered" />
          : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Hook</TableHead>
                    <TableHead className="text-[11px] h-8">Stage</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                    <TableHead className="text-[11px] h-8">Invocations</TableHead>
                    <TableHead className="text-[11px] h-8">Failures</TableHead>
                    <TableHead className="text-[11px] h-8">Last Run</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {hooks.map((h, i) => (
                    <TableRow key={i}>
                      <TableCell className="py-2 text-[11px] font-mono">{h.name ?? "—"}</TableCell>
                      <TableCell className="py-2"><Badge className="text-[10px]">{h.stage ?? "—"}</Badge></TableCell>
                      <TableCell className="py-2">
                        {h.enabled ? <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Enabled</Badge>
                          : <Badge className="text-[10px] border border-muted text-muted-foreground">Disabled</Badge>}
                      </TableCell>
                      <TableCell className="py-2 text-[11px] tabular-nums">{h.invocations ?? 0}</TableCell>
                      <TableCell className="py-2 text-[11px] tabular-nums text-red-400">{h.failures ?? 0}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{h.last_run ?? "—"}</TableCell>
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
