/**
 * Traversal Explanation Panel
 *
 * Step-by-step explanation of how a copilot answer was derived from graph traversals.
 * Route: /ai/copilot-trace
 * API: GET /api/v1/copilot/{q_id}/traversal-trace
 * Multica id: 9827cdc3-add5-467a-99fe-f44a424fc13a
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { GitBranch, RefreshCw, Search, ArrowRight } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface TraversalStep {
  step?: number;
  op?: string;
  detail?: string;
  edges_traversed?: number;
  nodes_visited?: number;
  duration_ms?: number;
  cypher?: string;
}

interface TraceResponse {
  q_id?: string;
  query?: string;
  total_nodes?: number;
  total_edges?: number;
  total_duration_ms?: number;
  steps?: TraversalStep[];
  comingSoon?: boolean;
}

async function apiFetch<T>(path: string): Promise<{ data: T; status: number }> {
  const orgId = getStoredOrgId();
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" } });
  if (res.status === 501 || res.status === 404) return { data: { comingSoon: true } as T, status: res.status };
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return { data: (await res.json()) as T, status: res.status };
}

export default function TraversalExplanationPanel() {
  const [qId, setQId] = useState("");
  const [submitted, setSubmitted] = useState<string | null>(null);
  const [trace, setTrace] = useState<TraceResponse | null>(null);
  const [comingSoon, setComingSoon] = useState(false);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async (id: string) => {
    setErr(null);
    setLoading(true);
    setComingSoon(false);
    try {
      const { data } = await apiFetch<TraceResponse>(`/api/v1/copilot/${encodeURIComponent(id)}/traversal-trace`);
      if (data.comingSoon) {
        setComingSoon(true);
        setTrace(null);
      } else {
        setTrace(data);
      }
    } catch (e) {
      setErr((e as Error).message);
      setTrace(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { if (submitted) load(submitted); }, [submitted]);

  const steps = trace?.steps ?? [];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Traversal Explanation"
        description="Step-by-step trace of how a copilot answer was derived"
        actions={
          <Button variant="outline" size="sm" onClick={() => submitted && load(submitted)} disabled={loading || !submitted}>
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
          </Button>
        }
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Search className="h-4 w-4" /> Query Id</CardTitle>
          <CardDescription className="text-xs">Enter a copilot q_id to fetch its traversal trace</CardDescription>
        </CardHeader>
        <CardContent className="flex items-center gap-2">
          <Input value={qId} onChange={(e) => setQId(e.target.value)} placeholder="q-id" className="h-9 text-xs" />
          <Button size="sm" onClick={() => qId.trim() && setSubmitted(qId.trim())} disabled={!qId.trim()}>
            Trace
          </Button>
        </CardContent>
      </Card>

      {trace && !comingSoon && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <KpiCard title="Steps" value={steps.length} icon={GitBranch} />
          <KpiCard title="Nodes Visited" value={trace.total_nodes ?? 0} icon={GitBranch} />
          <KpiCard title="Edges Traversed" value={trace.total_edges ?? 0} icon={ArrowRight} />
          <KpiCard title="Duration (ms)" value={trace.total_duration_ms ?? 0} icon={GitBranch} />
        </div>
      )}

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Trace</CardTitle>
          <CardDescription className="text-xs">{trace?.query ? `Query: ${trace.query}` : "Per-step breakdown"}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {!submitted ? (
            <EmptyState icon={Search} title="No q_id selected" description="Submit a copilot query id to view the trace." />
          ) : loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading trace…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={() => submitted && load(submitted)} />
          ) : comingSoon ? (
            <EmptyState icon={GitBranch} title="Coming soon" description="GET /api/v1/copilot/{q_id}/traversal-trace is not enabled on this deployment." />
          ) : steps.length === 0 ? (
            <EmptyState icon={GitBranch} title="No trace" description="No traversal steps were recorded for this query." />
          ) : (
            <div className="divide-y divide-border">
              {steps.map((s, i) => (
                <div key={i} className="px-4 py-3 hover:bg-muted/30">
                  <div className="flex items-center gap-3 text-[11px]">
                    <span className="font-mono text-muted-foreground w-6">{s.step ?? i + 1}.</span>
                    <Badge className="text-[10px] border border-border">{s.op ?? "step"}</Badge>
                    <span className="font-mono">{s.detail ?? ""}</span>
                    <span className="ml-auto text-[10px] text-muted-foreground">
                      {s.nodes_visited ?? 0}n · {s.edges_traversed ?? 0}e · {s.duration_ms ?? 0}ms
                    </span>
                  </div>
                  {s.cypher && (
                    <pre className="mt-2 ml-9 text-[10px] font-mono bg-muted/30 rounded p-2 overflow-x-auto">{s.cypher}</pre>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
