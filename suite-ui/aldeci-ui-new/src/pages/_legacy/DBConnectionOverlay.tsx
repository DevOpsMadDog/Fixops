/**
 * DB Connection Overlay — graph overlay showing DB connections in a repo
 * Route: /graph/databases
 * API: GET /api/v1/graph/databases/{repoId}
 * Multica id: cc7301fc
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Database, Search } from "lucide-react";

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

interface DbConn {
  service?: string;
  driver?: string;
  url?: string;
  schema?: string;
  used_by?: string[];
  pii?: boolean;
}

interface DbResp {
  repo_id?: string;
  connections?: DbConn[];
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
  if (res.status === 501) return { detail: "Coming soon", connections: [] } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function DBConnectionOverlay() {
  const [repoId, setRepoId] = useState("");
  const [data, setData] = useState<DbResp | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    if (!repoId.trim()) return;
    setLoading(true);
    setErr(null);
    try {
      const r = await apiFetch<DbResp>(`/api/v1/graph/databases/${encodeURIComponent(repoId)}`);
      setData(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const isComingSoon = !!data?.detail;
  const conns = data?.connections ?? [];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="DB Connection Overlay"
        description="Discovered database connections inside a repo — drivers, URLs, PII flag"
        badge={isComingSoon ? "Coming Soon" : undefined}
      />
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Database className="h-4 w-4" /> Connections</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">GET /api/v1/graph/databases/{`{repoId}`}</code></CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2 items-end">
            <div className="flex-1">
              <Label className="text-xs">Repo ID</Label>
              <Input value={repoId} onChange={e => setRepoId(e.target.value)} placeholder="acme/payments-api" className="text-sm font-mono" />
            </div>
            <Button onClick={load} disabled={loading || !repoId.trim()} size="sm"><Search className="h-4 w-4 mr-2" /> Inspect</Button>
          </div>

          {err && <ErrorState message={err} onRetry={load} />}
          {isComingSoon && <EmptyState icon={Database} title="Coming soon" description="Endpoint returns 501." />}
          {!err && !isComingSoon && data && (
            conns.length === 0 ? (
              <EmptyState icon={Database} title="No DB connections discovered" />
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="text-[11px] h-8">Service</TableHead>
                      <TableHead className="text-[11px] h-8">Driver</TableHead>
                      <TableHead className="text-[11px] h-8">URL</TableHead>
                      <TableHead className="text-[11px] h-8">Schema</TableHead>
                      <TableHead className="text-[11px] h-8">PII</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {conns.map((c, i) => (
                      <TableRow key={i}>
                        <TableCell className="py-2 text-[11px] font-mono">{c.service ?? "—"}</TableCell>
                        <TableCell className="py-2 text-[11px]">{c.driver ?? "—"}</TableCell>
                        <TableCell className="py-2 text-[11px] font-mono text-muted-foreground truncate max-w-xs">{c.url ?? "—"}</TableCell>
                        <TableCell className="py-2 text-[11px]">{c.schema ?? "—"}</TableCell>
                        <TableCell className="py-2">
                          {c.pii ? <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">PII</Badge> : <Badge className="text-[10px]">no</Badge>}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
