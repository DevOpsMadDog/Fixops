/**
 * Attack-Path Interactive Graph (Wave 3)
 * Route: /attack-paths/graph
 * API:   GET /api/v1/attack-paths/graph
 *
 * Renders the attack-path graph as a force-laid SVG. No external graph lib —
 * uses a simple, deterministic radial layout so we don't pull in d3-force.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { motion } from "framer-motion";
import { Network, RefreshCw, Maximize2, Search } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface GraphNode {
  id: string;
  label?: string;
  type?: string;
  severity?: string;
  is_entry?: boolean;
  is_target?: boolean;
}
interface GraphEdge {
  source: string;
  target: string;
  technique?: string;
  weight?: number;
}
interface GraphResponse {
  nodes?: GraphNode[];
  edges?: GraphEdge[];
  paths_count?: number;
}

async function apiFetch<T>(path: string): Promise<T | null> {
  const res = await fetch(buildApiUrl(path), {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
  });
  if (res.status === 404 || res.status === 501) return null;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

function severityColor(s?: string) {
  switch ((s ?? "").toLowerCase()) {
    case "critical": return "#f87171";
    case "high": return "#fb923c";
    case "medium": return "#facc15";
    case "low": return "#4ade80";
    default: return "#94a3b8";
  }
}

export default function AttackPathInteractiveGraph() {
  const [data, setData] = useState<GraphResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [hovered, setHovered] = useState<string | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const r = await apiFetch<GraphResponse>("/api/v1/attack-paths/graph");
      setData(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const positions = useMemo(() => {
    const out = new Map<string, { x: number; y: number }>();
    const nodes = data?.nodes ?? [];
    if (nodes.length === 0) return out;
    const cx = 400, cy = 300;
    const entries = nodes.filter((n) => n.is_entry);
    const targets = nodes.filter((n) => n.is_target);
    const middle = nodes.filter((n) => !n.is_entry && !n.is_target);

    entries.forEach((n, i) => {
      out.set(n.id, { x: 60, y: 80 + i * (520 / Math.max(1, entries.length)) });
    });
    targets.forEach((n, i) => {
      out.set(n.id, { x: 740, y: 80 + i * (520 / Math.max(1, targets.length)) });
    });
    middle.forEach((n, i) => {
      const angle = (i / Math.max(1, middle.length)) * Math.PI * 2;
      const r = 200 + (i % 3) * 30;
      out.set(n.id, { x: cx + Math.cos(angle) * r, y: cy + Math.sin(angle) * r });
    });
    return out;
  }, [data]);

  const visibleNodes = useMemo(() => {
    const ns = data?.nodes ?? [];
    if (!filter.trim()) return ns;
    const q = filter.toLowerCase();
    return ns.filter((n) => (n.label ?? n.id).toLowerCase().includes(q) || (n.type ?? "").toLowerCase().includes(q));
  }, [data, filter]);

  const visibleIds = useMemo(() => new Set(visibleNodes.map((n) => n.id)), [visibleNodes]);
  const visibleEdges = (data?.edges ?? []).filter((e) => visibleIds.has(e.source) && visibleIds.has(e.target));

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Attack-Path Interactive Graph"
        description="Visualize entry → pivot → target chains across the asset graph"
        actions={
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-muted-foreground" />
              <Input
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="Filter nodes…"
                className="h-8 w-[180px] pl-7 text-xs"
              />
            </div>
            <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
              <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
            </Button>
          </div>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Nodes" value={data?.nodes?.length ?? 0} icon={Network} />
        <KpiCard title="Edges" value={data?.edges?.length ?? 0} icon={Maximize2} />
        <KpiCard title="Entry Points" value={(data?.nodes ?? []).filter((n) => n.is_entry).length} icon={Network} />
        <KpiCard title="Paths" value={data?.paths_count ?? 0} icon={Network} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Network className="h-4 w-4" /> Graph
          </CardTitle>
          <CardDescription className="text-xs">
            Hover a node for details · entries on left · targets on right
            {hovered && <Badge className="ml-2 text-[10px] border border-border font-mono">{hovered}</Badge>}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading graph…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : !data || (data.nodes ?? []).length === 0 ? (
            <EmptyState icon={Network} title="No attack paths" description="Run a path-discovery scan to populate the graph." />
          ) : (
            <div className="w-full overflow-x-auto bg-muted/10 rounded-md">
              <svg ref={svgRef} viewBox="0 0 800 600" className="w-full h-[600px]">
                {visibleEdges.map((e, i) => {
                  const a = positions.get(e.source);
                  const b = positions.get(e.target);
                  if (!a || !b) return null;
                  return (
                    <line
                      key={i}
                      x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                      stroke="rgba(148,163,184,0.4)"
                      strokeWidth={Math.max(0.5, Math.min(3, e.weight ?? 1))}
                    />
                  );
                })}
                {visibleNodes.map((n) => {
                  const p = positions.get(n.id);
                  if (!p) return null;
                  const r = n.is_entry || n.is_target ? 10 : 6;
                  return (
                    <g key={n.id} onMouseEnter={() => setHovered(n.label ?? n.id)} onMouseLeave={() => setHovered(null)}>
                      <circle cx={p.x} cy={p.y} r={r} fill={severityColor(n.severity)} stroke="rgba(15,23,42,0.6)" strokeWidth={1} />
                      <text x={p.x + 12} y={p.y + 4} fontSize={9} fill="currentColor" className="text-foreground/80">
                        {(n.label ?? n.id).slice(0, 22)}
                      </text>
                    </g>
                  );
                })}
              </svg>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
