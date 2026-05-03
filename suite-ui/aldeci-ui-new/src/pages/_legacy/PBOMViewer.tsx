/**
 * PBOM Viewer — pipeline BOM propagation
 * Route: /pbom/propagation
 * API: GET /api/v1/pbom/artifact/{digest}/propagation
 * Multica id: 146607ec
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Boxes, Search, GitBranch } from "lucide-react";

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

interface Stop {
  stage?: string;
  artifact?: string;
  attestation?: string;
  ts?: string;
}

interface Resp {
  digest?: string;
  pipeline?: Stop[];
  envs_deployed?: string[];
  total_consumers?: number;
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
  if (res.status === 501) return { detail: "Coming soon" } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function PBOMViewer() {
  const [digest, setDigest] = useState("");
  const [data, setData] = useState<Resp | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    if (!digest.trim()) return;
    setLoading(true);
    setErr(null);
    try {
      const r = await apiFetch<Resp>(`/api/v1/pbom/artifact/${encodeURIComponent(digest)}/propagation`);
      setData(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const isComingSoon = !!data?.detail;
  const stops = data?.pipeline ?? [];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="PBOM Viewer"
        description="Pipeline-BOM propagation — where an artifact has flowed through CI/CD"
        badge={isComingSoon ? "Coming Soon" : undefined}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Boxes className="h-4 w-4" /> Artifact Lookup</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">GET /api/v1/pbom/artifact/{`{digest}`}/propagation</code></CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2 items-end">
            <div className="flex-1">
              <Label className="text-xs">Artifact Digest</Label>
              <Input value={digest} onChange={e => setDigest(e.target.value)} placeholder="sha256:abc…" className="text-sm font-mono" />
            </div>
            <Button onClick={load} disabled={loading || !digest.trim()} size="sm"><Search className="h-4 w-4 mr-2" /> Trace</Button>
          </div>

          {err && <ErrorState message={err} onRetry={load} />}
          {isComingSoon && <EmptyState icon={Boxes} title="Coming soon" description="Endpoint returns 501." />}

          {!err && !isComingSoon && data && (
            <>
              <div className="grid grid-cols-3 gap-3">
                <KpiCard title="Stages" value={stops.length} icon={GitBranch} />
                <KpiCard title="Envs Deployed" value={(data.envs_deployed ?? []).length} icon={Boxes} />
                <KpiCard title="Consumers" value={data.total_consumers ?? 0} icon={Boxes} />
              </div>

              {stops.length === 0 ? <EmptyState icon={Boxes} title="No propagation found" />
              : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow className="hover:bg-transparent">
                        <TableHead className="text-[11px] h-8">Stage</TableHead>
                        <TableHead className="text-[11px] h-8">Artifact</TableHead>
                        <TableHead className="text-[11px] h-8">Attestation</TableHead>
                        <TableHead className="text-[11px] h-8 text-right">Timestamp</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {stops.map((s, i) => (
                        <TableRow key={i}>
                          <TableCell className="py-2"><Badge className="text-[10px]">{s.stage ?? "—"}</Badge></TableCell>
                          <TableCell className="py-2 text-[11px] font-mono text-muted-foreground">{(s.artifact ?? "").slice(0, 16) || "—"}…</TableCell>
                          <TableCell className="py-2 text-[11px] font-mono">{s.attestation ?? "—"}</TableCell>
                          <TableCell className="py-2 text-[11px] text-muted-foreground text-right">{s.ts ?? "—"}</TableCell>
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
