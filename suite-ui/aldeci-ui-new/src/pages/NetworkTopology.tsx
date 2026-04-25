/**
 * Network Topology
 *
 * Asset map, segment isolation, and exposure detection.
 *   1. KPIs: Total Nodes, Network Segments, Exposed Assets, Topology Edges
 *   2. Node inventory table (12 rows)
 *   3. Segment cards (6 segments in 2-col grid)
 *   4. Exposure alerts (7 alert cards)
 *   5. Path finder input with mock result
 *
 * API stubs: GET /api/v1/network/nodes, /api/v1/network/segments, /api/v1/network/exposure
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Network, Server, Shield, AlertTriangle, RefreshCw,
  Search, ChevronRight, Layers, Globe, Lock,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

async function apiFetch<T = any>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

// ── Helpers ────────────────────────────────────────────────────

function TypeBadge({ type }: { type: string }) {
  const cls =
    type === "server"      ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
    type === "workstation" ? "border-indigo-500/30 text-indigo-400 bg-indigo-500/10" :
    type === "router"      ? "border-purple-500/30 text-purple-400 bg-purple-500/10" :
    type === "firewall"    ? "border-green-500/30 text-green-400 bg-green-500/10" :
                             "border-orange-500/30 text-orange-400 bg-orange-500/10";
  return <Badge className={cn("text-[10px] border", cls)}>{type}</Badge>;
}

function CritBadge({ crit }: { crit: string }) {
  const cls =
    crit === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    crit === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    crit === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                          "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{crit}</Badge>;
}

function ZoneBadge({ zone }: { zone: string }) {
  const cls =
    zone === "DMZ"        ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    zone === "Restricted" ? "border-red-500/30 text-red-400 bg-red-500/10" :
                            "border-blue-500/30 text-blue-400 bg-blue-500/10";
  return <Badge className={cn("text-[10px] border", cls)}>{zone}</Badge>;
}

function StatusDot({ status }: { status: string }) {
  const cls =
    status === "online"   ? "bg-green-500" :
    status === "degraded" ? "bg-amber-500" :
                            "bg-muted-foreground";
  return <span className={cn("inline-block w-2 h-2 rounded-full", cls)} title={status} />;
}

// ── Component ──────────────────────────────────────────────────

export default function NetworkTopology() {
  const [refreshing, setRefreshing]   = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [srcNode, setSrcNode]         = useState("");
  const [dstNode, setDstNode]         = useState("");
  const [pathResult, setPathResult]   = useState<string[] | null>(null);
  const [pathError, setPathError]     = useState<string | null>(null);
  const [nodes, setNodes] = useState<any[]>([]);
  const [edges, setEdges] = useState<any[]>([]);
  const [segments, setSegments] = useState<any[]>([]);

  const fetchAll = async () => {
    setRefreshing(true);
    setError(null);
    try {
      const [nodesRes, edgesRes, segRes] = await Promise.allSettled([
        apiFetch<any>("/api/v1/network-topology/nodes"),
        apiFetch<any>("/api/v1/network-topology/edges"),
        apiFetch<any>("/api/v1/network-topology/segments"),
      ]);
      if (nodesRes.status === "fulfilled") {
        const v = nodesRes.value;
        setNodes(Array.isArray(v) ? v : (v?.nodes ?? v?.items ?? []));
      } else {
        setError((nodesRes.reason as Error).message);
      }
      if (edgesRes.status === "fulfilled") {
        const v = edgesRes.value;
        setEdges(Array.isArray(v) ? v : (v?.edges ?? v?.items ?? []));
      }
      if (segRes.status === "fulfilled") {
        const v = segRes.value;
        setSegments(Array.isArray(v) ? v : (v?.segments ?? v?.items ?? []));
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { fetchAll(); }, []);

  const handleRefresh = () => { fetchAll(); };

  const handleFindPath = async () => {
    if (!srcNode.trim() || !dstNode.trim()) return;
    setPathError(null);
    setPathResult(null);
    try {
      const startNode = nodes.find((n) => (n.hostname ?? n.name ?? n.id) === srcNode.trim());
      if (!startNode?.id) {
        setPathError("Source node not found in topology");
        return;
      }
      const v = await apiFetch<any>(`/api/v1/network-topology/nodes/${encodeURIComponent(startNode.id)}/neighbors`);
      const list = Array.isArray(v) ? v : (v?.neighbors ?? v?.path ?? []);
      setPathResult(list.map((n: any) => `${n.hostname ?? n.name ?? n.id} (${n.ip ?? "—"})`));
    } catch (e) {
      setPathError((e as Error).message);
    }
  };

  if (loading) return <PageSkeleton />;

  const exposedAssets = nodes.filter((n: any) => (n.criticality === "Critical" || n.exposed === true)).length;


  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Network Topology"
        description="Asset map, segment isolation, and exposure detection"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {error && <ErrorState message={error} onRetry={fetchAll} />}

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Nodes"       value={nodes.length}         icon={Server}  />
        <KpiCard title="Network Segments"  value={segments.length}      icon={Layers}  />
        <KpiCard title="Exposed Assets"    value={exposedAssets}        icon={Globe}   trend="up" className="border-red-500/20" />
        <KpiCard title="Topology Edges"    value={edges.length}         icon={Network} />
      </div>

      {/* Node inventory table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Server className="h-4 w-4 text-blue-400" />
            Node Inventory
          </CardTitle>
          <CardDescription className="text-xs">All network-connected assets with classification and segment assignment</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {nodes.length === 0 && !error ? <EmptyState icon={Server} title="No nodes" description="Register network nodes via /api/v1/network-topology/nodes." /> : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Hostname</TableHead>
                  <TableHead className="text-[11px] h-8">IP</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">OS</TableHead>
                  <TableHead className="text-[11px] h-8">Location</TableHead>
                  <TableHead className="text-[11px] h-8">Criticality</TableHead>
                  <TableHead className="text-[11px] h-8">Segment</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {nodes.map((n: any) => (
                  <TableRow key={n.id ?? n.hostname} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5">{n.hostname ?? n.name ?? n.id}</TableCell>
                    <TableCell className="text-xs font-mono py-2.5 text-muted-foreground">{n.ip ?? "—"}</TableCell>
                    <TableCell className="py-2.5"><TypeBadge type={n.type ?? "server"} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{n.os ?? "—"}</TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{n.location ?? "—"}</TableCell>
                    <TableCell className="py-2.5"><CritBadge crit={n.criticality ?? "Medium"} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{n.segment ?? "—"}</TableCell>
                    <TableCell className="py-2.5"><StatusDot status={n.status ?? "online"} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          )}
        </CardContent>
      </Card>

      {/* Segments grid */}
      <div>
        <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <Layers className="h-4 w-4 text-purple-400" />
          Network Segments
        </h3>
        {segments.length === 0 ? <EmptyState icon={Layers} title="No segments" description="Add network segments to populate this view." /> : (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {segments.map((seg: any) => (
            <Card key={seg.id ?? seg.name} className="hover:border-border/80 transition-colors">
              <CardContent className="p-4 space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <span className="text-sm font-semibold truncate">{seg.name}</span>
                  <ZoneBadge zone={seg.zone ?? "Internal"} />
                </div>
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-muted-foreground">
                  <span className="text-[10px] uppercase tracking-wide text-muted-foreground/60">VLAN</span>
                  <span className="text-[10px] uppercase tracking-wide text-muted-foreground/60">Subnet</span>
                  <span className="font-mono">{seg.vlan ?? "—"}</span>
                  <span className="font-mono">{seg.subnet ?? seg.cidr ?? "—"}</span>
                </div>
                <div className="flex items-center justify-between pt-1 border-t border-border/40">
                  <span className="text-xs text-muted-foreground">Nodes</span>
                  <span className="text-sm font-bold tabular-nums">{seg.nodes ?? seg.node_count ?? 0}</span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
        )}
      </div>

      {/* Path finder */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Search className="h-4 w-4 text-indigo-400" />
            Path Finder
          </CardTitle>
          <CardDescription className="text-xs">Trace the network path between any two nodes</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-2 flex-wrap">
            <Input
              placeholder="Source node (e.g. workstation-42)"
              value={srcNode}
              onChange={(e) => setSrcNode(e.target.value)}
              className="h-8 text-xs flex-1 min-w-[180px]"
            />
            <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />
            <Input
              placeholder="Destination node (e.g. db-primary)"
              value={dstNode}
              onChange={(e) => setDstNode(e.target.value)}
              className="h-8 text-xs flex-1 min-w-[180px]"
            />
            <Button size="sm" className="h-8 text-xs" onClick={handleFindPath}>
              Find Path
            </Button>
          </div>

          {pathError && <p className="text-[11px] text-red-400">{pathError}</p>}

          {pathResult && (
            <motion.div
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              className="rounded-md border border-indigo-500/30 bg-indigo-500/5 p-3"
            >
              <p className="text-[10px] uppercase tracking-wide text-indigo-400 mb-2">Neighbors discovered — {pathResult.length} nodes</p>
              <div className="flex items-center gap-1 flex-wrap">
                {pathResult.map((node, i) => (
                  <span key={i} className="flex items-center gap-1">
                    <span className="rounded bg-muted px-2 py-0.5 text-xs font-mono">{node}</span>
                    {i < pathResult.length - 1 && <ChevronRight className="h-3 w-3 text-muted-foreground" />}
                  </span>
                ))}
              </div>
            </motion.div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
