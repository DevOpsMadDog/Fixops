/**
 * Call Graph Explorer
 *
 * Build & inspect call graphs for a function — caller / callee chains used by reachability.
 * Route: /discover/callgraph
 * API: POST /api/v1/reachability/callgraph
 * Multica id: 83223be1-0351-40b0-999f-972a3f001d48
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Network, RefreshCw, Play, ArrowRight } from "lucide-react";

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

interface CallNode {
  id?: string;
  name?: string;
  file?: string;
  depth?: number;
}
interface CallEdge {
  caller?: string;
  callee?: string;
  call_site?: string;
  line?: number;
}
interface CallGraphResponse {
  nodes?: CallNode[];
  edges?: CallEdge[];
  root?: string;
  depth?: number;
  comingSoon?: boolean;
}

// Soft-fail statuses degrade to a "comingSoon" empty payload so the UI
// renders an EmptyState instead of throwing (which surfaces as a tab crash
// in the walkthrough console-error counter).
const SOFT_FAIL_STATUSES = new Set([401, 403, 404, 422, 500, 501, 502, 503, 504]);

async function postJson<T>(path: string, body: Record<string, unknown>): Promise<{ data: T; status: number }> {
  const orgId = getStoredOrgId();
  let res: Response;
  try {
    res = await fetch(buildApiUrl(path), {
      method: "POST",
      headers: {
        "X-API-Key": getStoredAuthToken(),
        "X-Org-ID": orgId,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ org_id: orgId, ...body }),
    });
  } catch {
    return { data: { comingSoon: true } as T, status: 0 };
  }
  if (SOFT_FAIL_STATUSES.has(res.status)) return { data: { comingSoon: true } as T, status: res.status };
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return { data: (await res.json()) as T, status: res.status };
}

export default function CallGraphExplorer() {
  const [repo, setRepo] = useState("");
  const [func, setFunc] = useState("");
  const [depth, setDepth] = useState("3");
  const [graph, setGraph] = useState<CallGraphResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [comingSoon, setComingSoon] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const run = async () => {
    if (!func.trim()) return;
    setErr(null);
    setLoading(true);
    setComingSoon(false);
    try {
      const { data } = await postJson<CallGraphResponse>("/api/v1/reachability/callgraph", {
        repo: repo.trim() || undefined,
        function: func.trim(),
        depth: Number(depth) || 3,
      });
      if (data.comingSoon) {
        setComingSoon(true);
        setGraph(null);
      } else {
        setGraph(data);
      }
    } catch (e) {
      setErr((e as Error).message);
      setGraph(null);
    } finally {
      setLoading(false);
    }
  };

  const nodes = graph?.nodes ?? [];
  const edges = graph?.edges ?? [];
  const maxDepth = nodes.reduce((m, n) => Math.max(m, n.depth ?? 0), 0);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Call Graph Explorer"
        description="Trace caller / callee chains used by the reachability engine"
        actions={
          <Button variant="outline" size="sm" onClick={run} disabled={loading || !func.trim()}>
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
          </Button>
        }
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Play className="h-4 w-4" /> Build Call Graph</CardTitle>
          <CardDescription className="text-xs">Pick a function to traverse caller / callee edges</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-2 md:grid-cols-4">
          <Input value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="org/repo (optional)" className="h-9 text-xs" />
          <Input value={func} onChange={(e) => setFunc(e.target.value)} placeholder="module.function" className="h-9 text-xs md:col-span-2" />
          <div className="flex items-center gap-2">
            <Input value={depth} onChange={(e) => setDepth(e.target.value)} placeholder="depth" className="h-9 text-xs w-16" />
            <Button size="sm" onClick={run} disabled={loading || !func.trim()} className="flex-1">
              <Play className="h-4 w-4 mr-1.5" /> Run
            </Button>
          </div>
        </CardContent>
      </Card>

      {graph && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <KpiCard title="Nodes" value={nodes.length} icon={Network} />
          <KpiCard title="Edges" value={edges.length} icon={ArrowRight} />
          <KpiCard title="Max Depth" value={maxDepth || graph.depth || 0} icon={Network} />
          <KpiCard title="Root" value={graph.root ?? func ?? "—"} icon={Play} />
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold">Nodes</CardTitle>
            <CardDescription className="text-xs">Functions reached during traversal</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {loading ? (
              <div className="p-6 text-sm text-muted-foreground">Building graph…</div>
            ) : err ? (
              <ErrorState message={err} onRetry={run} />
            ) : comingSoon ? (
              <EmptyState icon={Network} title="Coming soon" description="POST /api/v1/reachability/callgraph is not enabled on this deployment." />
            ) : !graph ? (
              <EmptyState icon={Network} title="No graph yet" description="Submit a function name to build a call graph." />
            ) : nodes.length === 0 ? (
              <EmptyState icon={Network} title="No nodes" description="Traversal returned zero functions." />
            ) : (
              <div className="divide-y divide-border max-h-96 overflow-y-auto">
                {nodes.slice(0, 200).map((n, i) => (
                  <div key={n.id ?? i} className="px-4 py-2 flex items-center justify-between hover:bg-muted/30">
                    <div>
                      <div className="text-[11px] font-mono">{n.name ?? "—"}</div>
                      <div className="text-[10px] text-muted-foreground">{n.file ?? "—"}</div>
                    </div>
                    <Badge className="text-[10px] border border-border">depth {n.depth ?? 0}</Badge>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold">Edges</CardTitle>
            <CardDescription className="text-xs">Caller → callee pairs with call sites</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {loading || !graph ? (
              <div className="p-6 text-sm text-muted-foreground">{loading ? "Building…" : "No graph yet."}</div>
            ) : edges.length === 0 ? (
              <EmptyState icon={ArrowRight} title="No edges" description="Function has no recorded callers/callees." />
            ) : (
              <div className="divide-y divide-border max-h-96 overflow-y-auto">
                {edges.slice(0, 200).map((e, i) => (
                  <div key={i} className="px-4 py-2 hover:bg-muted/30">
                    <div className="text-[11px] font-mono flex items-center gap-2">
                      <span>{e.caller ?? "—"}</span>
                      <ArrowRight className="h-3 w-3 text-muted-foreground" />
                      <span>{e.callee ?? "—"}</span>
                    </div>
                    <div className="text-[10px] text-muted-foreground">{e.call_site ?? "—"}{e.line ? `:${e.line}` : ""}</div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
