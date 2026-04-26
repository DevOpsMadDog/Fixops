/**
 * Component Version Graph — safe-upgrade chart for a purl
 * Route: /components/version-graph
 * API: GET /api/v1/components/{purl}/safe-upgrade
 * Multica id: 93e2e8dc
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { GitBranch, Search, ArrowUpRight, ShieldCheck } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

interface SafeUpgrade {
  current?: string;
  candidate?: string;
  is_breaking?: boolean;
  cves_resolved?: string[];
  effort?: string;
  notes?: string;
}

interface UpgradeResp {
  purl?: string;
  current_version?: string;
  recommended?: string;
  upgrades?: SafeUpgrade[];
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
  if (res.status === 501) return { detail: "Coming soon", upgrades: [] } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function ComponentVersionGraph() {
  const [purl, setPurl] = useState("pkg:npm/lodash@4.17.20");
  const [data, setData] = useState<UpgradeResp | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    if (!purl.trim()) return;
    setLoading(true);
    setErr(null);
    try {
      const r = await apiFetch<UpgradeResp>(`/api/v1/components/${encodeURIComponent(purl)}/safe-upgrade`);
      setData(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const isComingSoon = !!data?.detail;
  const upgrades = data?.upgrades ?? [];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Component Version Graph"
        description="Safe upgrade paths for a Package URL — CVEs resolved, breaking changes, effort"
        badge={isComingSoon ? "Coming Soon" : undefined}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><GitBranch className="h-4 w-4" /> Resolve PURL</CardTitle>
          <CardDescription className="text-xs">
            Endpoint: <code className="text-[10px]">GET /api/v1/components/{`{purl}`}/safe-upgrade</code>
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2 items-end">
            <div className="flex-1">
              <Label className="text-xs">Package URL (purl)</Label>
              <Input value={purl} onChange={e => setPurl(e.target.value)} placeholder="pkg:npm/lodash@4.17.20" className="text-sm font-mono" />
            </div>
            <Button onClick={load} disabled={loading} size="sm">
              <Search className="h-4 w-4 mr-2" /> Resolve
            </Button>
          </div>

          {err && <ErrorState message={err} onRetry={load} />}
          {isComingSoon && <EmptyState icon={GitBranch} title="Coming soon" description="Endpoint returns 501 — safe-upgrade graph implementation pending." />}

          {!err && !isComingSoon && data && (
            <div className="space-y-4">
              <div className="grid grid-cols-3 gap-3">
                <div className="rounded-md border p-3"><div className="text-[10px] uppercase text-muted-foreground">Current</div><div className="font-mono text-sm">{data.current_version ?? "—"}</div></div>
                <div className="rounded-md border p-3"><div className="text-[10px] uppercase text-muted-foreground">Recommended</div><div className="font-mono text-sm text-green-400">{data.recommended ?? "—"}</div></div>
                <div className="rounded-md border p-3"><div className="text-[10px] uppercase text-muted-foreground">Candidates</div><div className="font-mono text-sm">{upgrades.length}</div></div>
              </div>
              {upgrades.length === 0 ? (
                <EmptyState icon={ShieldCheck} title="No upgrades available" description="Component is already on the latest safe version." />
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow className="hover:bg-transparent">
                        <TableHead className="text-[11px] h-8">From</TableHead>
                        <TableHead className="text-[11px] h-8">To</TableHead>
                        <TableHead className="text-[11px] h-8">Breaking</TableHead>
                        <TableHead className="text-[11px] h-8">CVEs Resolved</TableHead>
                        <TableHead className="text-[11px] h-8">Effort</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {upgrades.map((u, i) => (
                        <TableRow key={i}>
                          <TableCell className="py-2 text-[11px] font-mono">{u.current ?? "—"}</TableCell>
                          <TableCell className="py-2 text-[11px] font-mono"><ArrowUpRight className="h-3 w-3 inline mr-1 text-green-400" />{u.candidate ?? "—"}</TableCell>
                          <TableCell className="py-2">
                            {u.is_breaking ? (
                              <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">Breaking</Badge>
                            ) : (
                              <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Safe</Badge>
                            )}
                          </TableCell>
                          <TableCell className="py-2 text-[11px] font-mono">{(u.cves_resolved ?? []).length}</TableCell>
                          <TableCell className="py-2 text-[11px] text-muted-foreground">{u.effort ?? "—"}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
