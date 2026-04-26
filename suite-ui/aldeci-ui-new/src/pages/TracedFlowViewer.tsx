/**
 * Traced Flow Viewer — copilot query traversal trace
 * Route: /copilot/traversal-trace
 * API: GET /api/v1/copilot/{q_id}/traversal-trace
 * Multica id: 967d4b4d
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { GitMerge, Search, Eye } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

interface Step {
  step?: number;
  node?: string;
  edge?: string;
  decision?: string;
  ts_ms?: number;
}

interface Resp {
  q_id?: string;
  steps?: Step[];
  total_ms?: number;
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
  if (res.status === 501) return { detail: "Coming soon", steps: [] } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function TracedFlowViewer() {
  const [qId, setQId] = useState("");
  const [data, setData] = useState<Resp | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    if (!qId.trim()) return;
    setLoading(true);
    setErr(null);
    try {
      const r = await apiFetch<Resp>(`/api/v1/copilot/${encodeURIComponent(qId)}/traversal-trace`);
      setData(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const isComingSoon = !!data?.detail;
  const steps = data?.steps ?? [];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Traced Flow Viewer"
        description="Step-by-step trace of how Copilot traversed the graph to answer a query"
        badge={isComingSoon ? "Coming Soon" : undefined}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><GitMerge className="h-4 w-4" /> Trace</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">GET /api/v1/copilot/{`{q_id}`}/traversal-trace</code></CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2 items-end">
            <div className="flex-1">
              <Label className="text-xs">Query ID</Label>
              <Input value={qId} onChange={e => setQId(e.target.value)} placeholder="q-1234" className="text-sm font-mono" />
            </div>
            <Button onClick={load} disabled={loading || !qId.trim()} size="sm"><Search className="h-4 w-4 mr-2" /> Trace</Button>
          </div>

          {err && <ErrorState message={err} onRetry={load} />}
          {isComingSoon && <EmptyState icon={GitMerge} title="Coming soon" description="Endpoint returns 501." />}

          {!err && !isComingSoon && data && (
            <>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Eye className="h-3 w-3" /> {steps.length} step(s) — total {data.total_ms ?? 0}ms
              </div>
              {steps.length === 0 ? <EmptyState icon={GitMerge} title="No trace recorded for this query" />
              : (
                <div className="space-y-2">
                  {steps.map((s, i) => (
                    <div key={i} className="rounded-md border p-3 text-xs">
                      <div className="flex items-center gap-2">
                        <Badge className="text-[10px]">step {s.step ?? i + 1}</Badge>
                        <span className="font-mono">{s.node ?? "node"}</span>
                        <Badge variant="secondary" className="text-[9px] ml-auto">{s.ts_ms ?? 0}ms</Badge>
                      </div>
                      {s.edge && <div className="text-[10px] text-muted-foreground mt-1">edge: <span className="font-mono">{s.edge}</span></div>}
                      {s.decision && <div className="text-[10px] text-muted-foreground mt-1">decision: {s.decision}</div>}
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
