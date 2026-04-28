// FOLDED into Admin hero 2026-04-27 — preserve for git history
// Tab path: /admin?tab=scopes
/**
 * Scope Manager — list/manage org/repo/asset scopes
 * Route: /scopes
 * API: GET /api/v1/scopes
 * Multica id: e51905df
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Layers, RefreshCw, Plus } from "lucide-react";

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

interface Scope {
  id?: string;
  name?: string;
  kind?: string;
  parent?: string;
  member_count?: number;
  policy_count?: number;
}

interface Resp {
  scopes?: Scope[];
  items?: Scope[];
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
  if (res.status === 501) return { detail: "Coming soon", scopes: [] } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function ScopeManager() {
  const [data, setData] = useState<Resp | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const r = await apiFetch<Resp>("/api/v1/scopes");
      setData(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const scopes = data?.scopes ?? data?.items ?? [];
  const isComingSoon = !!data?.detail;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Scope Manager"
        description="Define and manage organizational, repo, and asset scopes for policies and reporting"
        badge={isComingSoon ? "Coming Soon" : undefined}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
              <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
            </Button>
            <Button size="sm"><Plus className="h-4 w-4 mr-2" /> New Scope</Button>
          </div>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
        <KpiCard title="Scopes" value={scopes.length} icon={Layers} />
        <KpiCard title="Members" value={scopes.reduce((s, x) => s + (x.member_count ?? 0), 0)} icon={Layers} />
        <KpiCard title="Policies Bound" value={scopes.reduce((s, x) => s + (x.policy_count ?? 0), 0)} icon={Layers} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Scopes</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">GET /api/v1/scopes</code></CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? <div className="p-6 text-sm text-muted-foreground">Loading…</div>
          : err ? <ErrorState message={err} onRetry={load} />
          : isComingSoon ? <EmptyState icon={Layers} title="Coming soon" description="Endpoint returns 501." />
          : scopes.length === 0 ? <EmptyState icon={Layers} title="No scopes defined" description="Create your first scope to group assets and apply policies." />
          : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Name</TableHead>
                    <TableHead className="text-[11px] h-8">Kind</TableHead>
                    <TableHead className="text-[11px] h-8">Parent</TableHead>
                    <TableHead className="text-[11px] h-8">Members</TableHead>
                    <TableHead className="text-[11px] h-8">Policies</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {scopes.map((s, i) => (
                    <TableRow key={s.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">{s.name ?? "—"}</TableCell>
                      <TableCell className="py-2"><Badge className="text-[10px]">{s.kind ?? "scope"}</Badge></TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{s.parent ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] tabular-nums">{s.member_count ?? 0}</TableCell>
                      <TableCell className="py-2 text-[11px] tabular-nums">{s.policy_count ?? 0}</TableCell>
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
