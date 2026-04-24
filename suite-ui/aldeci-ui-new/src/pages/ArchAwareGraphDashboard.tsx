/**
 * Architecture-Aware Graph Dashboard
 *
 * Component classifications + flow tracing across architectural boundaries.
 * Route: /arch-graph
 * API: GET /api/v1/arch-graph/classifications; POST /api/v1/arch-graph/trace-flow
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Workflow, RefreshCw, ArrowRightCircle, Layers, GitMerge, Shield } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Classification {
  id?: string;
  component?: string;
  tier?: string;
  kind?: string;
  risk?: string;
  tags?: string[];
}

interface FlowHop {
  from?: string;
  to?: string;
  protocol?: string;
  trust_boundary?: boolean;
  risk?: string;
}

interface FlowResult {
  source?: string;
  sink?: string;
  hops?: FlowHop[];
  crosses_boundaries?: number;
  flagged?: boolean;
}

async function apiFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    ...opts,
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
      ...(opts.headers ?? {}),
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function tierColor(t?: string) {
  const key = (t ?? "").toLowerCase();
  if (key.includes("edge") || key.includes("public")) return "bg-red-500/20 text-red-300 border-red-500/30";
  if (key.includes("app") || key.includes("service")) return "bg-blue-500/20 text-blue-300 border-blue-500/30";
  if (key.includes("data") || key.includes("db"))     return "bg-violet-500/20 text-violet-300 border-violet-500/30";
  if (key.includes("infra") || key.includes("net"))   return "bg-amber-500/20 text-amber-300 border-amber-500/30";
  return "bg-muted/60 text-muted-foreground border-border";
}

function riskColor(r?: string) {
  const k = (r ?? "").toLowerCase();
  if (k === "critical") return "text-red-400";
  if (k === "high")     return "text-orange-400";
  if (k === "medium")   return "text-yellow-400";
  return "text-green-400";
}

export default function ArchAwareGraphDashboard() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [tracing, setTracing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [classifications, setClassifications] = useState<Classification[]>([]);
  const [source, setSource] = useState("");
  const [sink, setSink] = useState("");
  const [flow, setFlow] = useState<FlowResult | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const c = await apiFetch<Classification[] | { classifications?: Classification[] }>("/api/v1/arch-graph/classifications");
      setClassifications(Array.isArray(c) ? c : c.classifications ?? []);
    } catch (e) { setErr((e as Error).message); }
    finally { setLoading(false); setRefreshing(false); }
  };

  useEffect(() => { load(); }, []);

  const handleTrace = async () => {
    if (!source.trim() || !sink.trim()) return;
    setTracing(true);
    setFlow(null);
    try {
      const r = await apiFetch<FlowResult>("/api/v1/arch-graph/trace-flow", {
        method: "POST",
        body: JSON.stringify({ source: source.trim(), sink: sink.trim() }),
      });
      setFlow(r);
    } catch (e) { setErr((e as Error).message); }
    finally { setTracing(false); }
  };

  const tiers = Array.from(new Set(classifications.map(c => c.tier).filter(Boolean)));
  const totalComp = classifications.length;
  const highRiskComp = classifications.filter(c => ["critical", "high"].includes((c.risk ?? "").toLowerCase())).length;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Architecture-Aware Graph"
        description="Component classification and data-flow tracing across architectural trust boundaries"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
        <KpiCard title="Components" value={totalComp} icon={Layers} />
        <KpiCard title="Architectural Tiers" value={tiers.length} icon={Workflow} />
        <KpiCard title="High-Risk Components" value={highRiskComp} icon={Shield} trend="down" />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><GitMerge className="h-4 w-4" /> Flow Tracer</CardTitle>
          <CardDescription className="text-xs">Trace a data flow from a source component to a sink — see trust-boundary crossings</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <Input value={source} onChange={e => setSource(e.target.value)} placeholder="source component" className="h-9 text-xs" />
            <ArrowRightCircle className="h-4 w-4 text-muted-foreground hidden sm:block" />
            <Input value={sink} onChange={e => setSink(e.target.value)} placeholder="sink component" className="h-9 text-xs" />
            <Button size="sm" onClick={handleTrace} disabled={tracing || !source.trim() || !sink.trim()}>
              <ArrowRightCircle className={cn("h-4 w-4 mr-2", tracing && "animate-pulse")} />
              Trace
            </Button>
          </div>

          {flow && (flow.hops ?? []).length > 0 && (
            <div className="rounded border border-border/50 bg-muted/20 p-3">
              <div className="flex items-center justify-between text-xs mb-2">
                <span className="font-mono">{flow.source} → {flow.sink}</span>
                <Badge className={cn("text-[10px] border", (flow.crosses_boundaries ?? 0) > 0 ? "border-orange-500/30 text-orange-400 bg-orange-500/10" : "border-green-500/30 text-green-400 bg-green-500/10")}>
                  {flow.crosses_boundaries ?? 0} boundary crossings
                </Badge>
              </div>
              <div className="space-y-1 text-[11px]">
                {(flow.hops ?? []).map((h, i) => (
                  <div key={i} className="flex items-center justify-between rounded bg-muted/30 px-2 py-1">
                    <div className="flex items-center gap-2 font-mono">
                      <span>{h.from}</span>
                      <ArrowRightCircle className="h-3 w-3" />
                      <span>{h.to}</span>
                      <span className="text-muted-foreground">[{h.protocol ?? "tcp"}]</span>
                    </div>
                    {h.trust_boundary && <Badge className="text-[10px] border border-orange-500/30 text-orange-400 bg-orange-500/10">Boundary</Badge>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Layers className="h-4 w-4" /> Component Classifications</CardTitle>
          <CardDescription className="text-xs">Components classified by architectural tier, kind, and risk</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : classifications.length === 0 ? (
            <EmptyState icon={Layers} title="No classifications" description="Components will be classified as the arch-graph builds." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Component</TableHead>
                    <TableHead className="text-[11px] h-8">Tier</TableHead>
                    <TableHead className="text-[11px] h-8">Kind</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Risk</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {classifications.map((c, i) => (
                    <TableRow key={c.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">{c.component ?? "—"}</TableCell>
                      <TableCell className="py-2"><Badge className={cn("text-[10px] border capitalize", tierColor(c.tier))}>{c.tier ?? "—"}</Badge></TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground capitalize">{c.kind ?? "—"}</TableCell>
                      <TableCell className={cn("py-2 text-[11px] font-mono text-right capitalize", riskColor(c.risk))}>{c.risk ?? "low"}</TableCell>
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
