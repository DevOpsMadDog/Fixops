/**
 * RQL Query Builder — investigate via Risk Query Language
 * Route: /investigate/rql
 * API: POST /api/v1/investigate/rql
 * Multica id: 5231fdec
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Terminal, Play, Save } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

interface QueryResult {
  rows?: Record<string, unknown>[];
  columns?: string[];
  total?: number;
  query_id?: string;
  detail?: string;
}

async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    method: "POST",
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (res.status === 501) return { detail: "Coming soon", rows: [] } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function RQLQueryBuilder() {
  const [rql, setRql] = useState("FIND assets WHERE severity == 'critical' AND exposure == 'public'");
  const [result, setResult] = useState<QueryResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const run = async () => {
    if (!rql.trim()) return;
    setLoading(true);
    setErr(null);
    try {
      const r = await apiPost<QueryResult>("/api/v1/investigate/rql", { rql, org_id: getStoredOrgId() });
      setResult(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const isComingSoon = !!result?.detail;
  const rows = result?.rows ?? [];
  const cols = result?.columns ?? (rows[0] ? Object.keys(rows[0]) : []);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="RQL Query Builder"
        description="Risk Query Language — investigate findings, assets, exposures via SQL-like DSL"
        badge={isComingSoon ? "Coming Soon" : undefined}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Terminal className="h-4 w-4" /> Editor</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">POST /api/v1/investigate/rql</code></CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label className="text-xs">RQL Statement</Label>
            <Textarea rows={5} value={rql} onChange={e => setRql(e.target.value)} className="font-mono text-xs" />
          </div>
          <div className="flex gap-2">
            <Button onClick={run} disabled={loading} size="sm"><Play className="h-4 w-4 mr-2" /> {loading ? "Running…" : "Run"}</Button>
            <Button variant="outline" size="sm" disabled={!rql.trim()}><Save className="h-4 w-4 mr-2" /> Save</Button>
            {result?.query_id && <Badge variant="secondary" className="ml-auto self-center text-[10px]">Query {result.query_id}</Badge>}
          </div>

          {err && <ErrorState message={err} onRetry={run} />}
          {isComingSoon && <EmptyState icon={Terminal} title="Coming soon" description="RQL endpoint returns 501." />}
          {!err && !isComingSoon && result && (
            rows.length === 0 ? (
              <EmptyState icon={Terminal} title="No rows" description="Query returned 0 results." />
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      {cols.map(c => <TableHead key={c} className="text-[11px] h-8">{c}</TableHead>)}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rows.map((r, i) => (
                      <TableRow key={i}>
                        {cols.map(c => <TableCell key={c} className="py-2 text-[11px] font-mono">{String(r[c] ?? "—")}</TableCell>)}
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
