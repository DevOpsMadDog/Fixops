/**
 * Subsidiary Attribution Graph — list discovered subsidiaries for an org
 * Route: /easm/subsidiaries
 * API: GET /api/v1/easm/subsidiaries/{org}
 * Multica id: 7467742d
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Building2, Search, Network } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

interface Subsidiary {
  id?: string;
  name?: string;
  domain?: string;
  country?: string;
  attribution_confidence?: number;
  asset_count?: number;
  source?: string;
}

interface Resp {
  org?: string;
  subsidiaries?: Subsidiary[];
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
  if (res.status === 501) return { detail: "Coming soon", subsidiaries: [] } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function SubsidiaryAttributionGraph() {
  const [org, setOrg] = useState("");
  const [data, setData] = useState<Resp | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    if (!org.trim()) return;
    setLoading(true);
    setErr(null);
    try {
      const r = await apiFetch<Resp>(`/api/v1/easm/subsidiaries/${encodeURIComponent(org)}`);
      setData(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const isComingSoon = !!data?.detail;
  const subs = data?.subsidiaries ?? [];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Subsidiary Attribution"
        description="Map subsidiaries, divisions, M&A acquisitions discovered for an organization"
        badge={isComingSoon ? "Coming Soon" : undefined}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Building2 className="h-4 w-4" /> Lookup</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">GET /api/v1/easm/subsidiaries/{`{org}`}</code></CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2 items-end">
            <div className="flex-1">
              <Label className="text-xs">Parent Organization</Label>
              <Input value={org} onChange={e => setOrg(e.target.value)} placeholder="acme-corp" className="text-sm font-mono" />
            </div>
            <Button onClick={load} disabled={loading || !org.trim()} size="sm"><Search className="h-4 w-4 mr-2" /> Resolve</Button>
          </div>

          {err && <ErrorState message={err} onRetry={load} />}
          {isComingSoon && <EmptyState icon={Building2} title="Coming soon" description="Endpoint returns 501." />}

          {!err && !isComingSoon && data && (
            <>
              <div className="grid grid-cols-3 gap-3">
                <KpiCard title="Subsidiaries" value={subs.length} icon={Building2} />
                <KpiCard title="Total Assets" value={subs.reduce((s, x) => s + (x.asset_count ?? 0), 0)} icon={Network} />
                <KpiCard title="High Confidence" value={subs.filter(s => (s.attribution_confidence ?? 0) > 0.8).length} icon={Building2} trend="up" />
              </div>

              {subs.length === 0 ? (
                <EmptyState icon={Building2} title="No subsidiaries discovered" />
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow className="hover:bg-transparent">
                        <TableHead className="text-[11px] h-8">Subsidiary</TableHead>
                        <TableHead className="text-[11px] h-8">Domain</TableHead>
                        <TableHead className="text-[11px] h-8">Country</TableHead>
                        <TableHead className="text-[11px] h-8">Confidence</TableHead>
                        <TableHead className="text-[11px] h-8">Assets</TableHead>
                        <TableHead className="text-[11px] h-8">Source</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {subs.map((s, i) => (
                        <TableRow key={s.id ?? i}>
                          <TableCell className="py-2 text-[11px] font-mono">{s.name ?? "—"}</TableCell>
                          <TableCell className="py-2 text-[11px] font-mono text-muted-foreground">{s.domain ?? "—"}</TableCell>
                          <TableCell className="py-2 text-[11px]">{s.country ?? "—"}</TableCell>
                          <TableCell className="py-2"><Badge className="text-[10px]">{((s.attribution_confidence ?? 0) * 100).toFixed(0)}%</Badge></TableCell>
                          <TableCell className="py-2 text-[11px] tabular-nums">{s.asset_count ?? 0}</TableCell>
                          <TableCell className="py-2 text-[11px] text-muted-foreground">{s.source ?? "—"}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
