/**
 * Graph Perf Dashboard
 *
 * Performance / data flow metrics for service-level graph traversals.
 * Route: /discover/graph-perf
 * API: GET /api/v1/graph/flows/{serviceId}
 * Multica id: 04decda1-b551-4e08-9e1f-84c70e8cd405
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Activity, RefreshCw, Search, Gauge, ArrowRight } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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

interface GraphFlow {
  id?: string;
  source?: string;
  target?: string;
  flow_type?: string;
  latency_ms?: number;
  throughput?: number;
  error_rate?: number;
  protocol?: string;
}

interface FlowsResponse {
  service_id?: string;
  flows?: GraphFlow[];
  items?: GraphFlow[];
  total_flows?: number;
  total_latency_ms?: number;
  hot_path?: string;
  comingSoon?: boolean;
}

async function apiFetch<T>(path: string): Promise<{ data: T; status: number }> {
  const orgId = getStoredOrgId();
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" },
  });
  if (res.status === 501) return { data: { comingSoon: true } as T, status: 501 };
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return { data: (await res.json()) as T, status: res.status };
}

export default function GraphPerfDashboard() {
  const [serviceId, setServiceId] = useState("");
  const [submitted, setSubmitted] = useState<string | null>(null);
  const [flows, setFlows] = useState<GraphFlow[]>([]);
  const [meta, setMeta] = useState<FlowsResponse | null>(null);
  const [comingSoon, setComingSoon] = useState(false);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async (id: string) => {
    setErr(null);
    setLoading(true);
    setComingSoon(false);
    try {
      const { data } = await apiFetch<FlowsResponse>(`/api/v1/graph/flows/${encodeURIComponent(id)}`);
      if (data.comingSoon) {
        setComingSoon(true);
        setFlows([]);
      } else {
        const list = Array.isArray(data) ? (data as GraphFlow[]) : (data.flows ?? data.items ?? []);
        setFlows(list);
        setMeta(data);
      }
    } catch (e) {
      setErr((e as Error).message);
      setFlows([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (submitted) load(submitted);
  }, [submitted]);

  const totalFlows = flows.length;
  const avgLatency = flows.length ? Math.round(flows.reduce((s, f) => s + (f.latency_ms ?? 0), 0) / flows.length) : 0;
  const avgThroughput = flows.length ? Math.round(flows.reduce((s, f) => s + (f.throughput ?? 0), 0) / flows.length) : 0;
  const errFlows = flows.filter((f) => (f.error_rate ?? 0) > 0.01).length;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Graph Perf Dashboard"
        description="Service-level data flow performance from the security knowledge graph"
        actions={
          <Button variant="outline" size="sm" onClick={() => submitted && load(submitted)} disabled={loading || !submitted}>
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
          </Button>
        }
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Search className="h-4 w-4" /> Service</CardTitle>
          <CardDescription className="text-xs">Pick a service / asset id to load flow performance</CardDescription>
        </CardHeader>
        <CardContent className="flex items-center gap-2">
          <Input value={serviceId} onChange={(e) => setServiceId(e.target.value)} placeholder="service-id" className="h-9 text-xs" />
          <Button size="sm" onClick={() => serviceId.trim() && setSubmitted(serviceId.trim())} disabled={!serviceId.trim()}>
            Load
          </Button>
        </CardContent>
      </Card>

      {submitted && !comingSoon && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <KpiCard title="Total Flows" value={meta?.total_flows ?? totalFlows} icon={Activity} />
          <KpiCard title="Avg Latency (ms)" value={avgLatency} icon={Gauge} />
          <KpiCard title="Avg Throughput" value={avgThroughput} icon={ArrowRight} />
          <KpiCard title="Flows w/ Errors" value={errFlows} icon={Activity} trend={errFlows ? "up" : "flat"} />
        </div>
      )}

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Flows</CardTitle>
          <CardDescription className="text-xs">{meta?.hot_path ? `Hot path: ${meta.hot_path}` : "Source → target flow profile"}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {!submitted ? (
            <EmptyState icon={Search} title="No service selected" description="Enter a service id to view flow performance." />
          ) : loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading flows…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={() => submitted && load(submitted)} />
          ) : comingSoon ? (
            <EmptyState icon={Activity} title="Coming soon" description="GET /api/v1/graph/flows/{id} is not enabled on this deployment." />
          ) : flows.length === 0 ? (
            <EmptyState icon={Activity} title="No flows" description="The graph contains no flows for this service." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Source</TableHead>
                    <TableHead className="text-[11px] h-8">Target</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8">Protocol</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Latency (ms)</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Throughput</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Err Rate</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {flows.slice(0, 200).map((f, i) => (
                    <TableRow key={f.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">{f.source ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">{f.target ?? "—"}</TableCell>
                      <TableCell className="py-2"><Badge className="text-[10px] border border-border">{f.flow_type ?? "flow"}</Badge></TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{f.protocol ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-right">{f.latency_ms ?? 0}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-right">{f.throughput ?? 0}</TableCell>
                      <TableCell className={cn("py-2 text-[11px] font-mono text-right", (f.error_rate ?? 0) > 0.01 && "text-red-400")}>{((f.error_rate ?? 0) * 100).toFixed(2)}%</TableCell>
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
