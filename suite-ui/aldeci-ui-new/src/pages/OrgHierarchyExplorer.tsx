/**
 * Org Hierarchy Explorer
 * Route: /organizations
 * API: GET /api/v1/organizations
 * Multica id: 0c157c34
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Building2, RefreshCw, Users, Layers } from "lucide-react";

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

interface Org {
  id?: string;
  name?: string;
  parent?: string;
  type?: string;
  member_count?: number;
  asset_count?: number;
  depth?: number;
}

interface Resp {
  organizations?: Org[];
  items?: Org[];
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
  if (res.status === 501) return { detail: "Coming soon", organizations: [] } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function OrgHierarchyExplorer() {
  const [data, setData] = useState<Resp | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const r = await apiFetch<Resp>("/api/v1/organizations");
      setData(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const orgs = data?.organizations ?? data?.items ?? [];
  const isComingSoon = !!data?.detail;
  const totalAssets = orgs.reduce((s, o) => s + (o.asset_count ?? 0), 0);
  const totalMembers = orgs.reduce((s, o) => s + (o.member_count ?? 0), 0);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Organization Hierarchy"
        description="Browse the multi-org tree — parents, children, members, and asset counts"
        badge={isComingSoon ? "Coming Soon" : undefined}
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
        <KpiCard title="Organizations" value={data?.total ?? orgs.length} icon={Building2} />
        <KpiCard title="Total Members" value={totalMembers} icon={Users} />
        <KpiCard title="Total Assets" value={totalAssets} icon={Layers} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Organizations</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">GET /api/v1/organizations</code></CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? <div className="p-6 text-sm text-muted-foreground">Loading…</div>
          : err ? <ErrorState message={err} onRetry={load} />
          : isComingSoon ? <EmptyState icon={Building2} title="Coming soon" description="Endpoint returns 501." />
          : orgs.length === 0 ? <EmptyState icon={Building2} title="No organizations" />
          : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Org</TableHead>
                    <TableHead className="text-[11px] h-8">Parent</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8">Depth</TableHead>
                    <TableHead className="text-[11px] h-8">Members</TableHead>
                    <TableHead className="text-[11px] h-8">Assets</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {orgs.map((o, i) => (
                    <TableRow key={o.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono" style={{ paddingLeft: `${0.5 + (o.depth ?? 0) * 1}rem` }}>{o.name ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{o.parent ?? "—"}</TableCell>
                      <TableCell className="py-2"><Badge className="text-[10px]">{o.type ?? "org"}</Badge></TableCell>
                      <TableCell className="py-2 text-[11px] tabular-nums">{o.depth ?? 0}</TableCell>
                      <TableCell className="py-2 text-[11px] tabular-nums">{o.member_count ?? 0}</TableCell>
                      <TableCell className="py-2 text-[11px] tabular-nums">{o.asset_count ?? 0}</TableCell>
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
