/**
 * Asset Graph HERO — "second brain made visible" (Apiiro / Wiz pattern).
 *
 * Phase 3 P0, S8 in UX_CONSOLIDATION_PLAN_2026-04-26.md.
 *
 * Folds in: ArchitectureLayerGraph, GraphPerfDashboard,
 * AttackPathInteractiveGraph, SubsidiaryAttributionGraph,
 * ChokePointDashboard, ComponentVersionGraph, DiffModeGraphCanvas,
 * KnowledgeGraph, SecurityGraph, DBConnectionOverlay.
 *
 * Force-directed canvas (deterministic radial layout — no extra deps; same
 * pattern Wave 1 SecurityGraph uses). Side panel for clicked-node detail
 * (criticality, crown-jewel tag, attack paths through this node, related
 * findings). Right rail: top 5 chokepoints by betweenness centrality.
 *
 * Real apiFetch only. NO MOCKS. EmptyState when endpoint returns 404/501.
 *
 * Route: /assets
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  Box,
  Crown,
  Database,
  GitBranch,
  Globe,
  Layers,
  Network,
  RefreshCw,
  Search,
  Server,
  Shield,
  Target,
  X,
  Zap,
} from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";

import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface GraphNode {
  id: string;
  label?: string;
  name?: string;
  type?: string;        // service / database / api / cloud / external / repo / module
  criticality?: string; // critical / high / medium / low
  crown_jewel?: boolean;
  centrality?: number;  // 0..1 betweenness centrality (chokepoint signal)
  finding_count?: number;
  attack_paths?: number;
  // visual derived
  x?: number;
  y?: number;
}

interface GraphEdge {
  id?: string;
  source: string;
  target: string;
  kind?: string;
  weight?: number;
}

interface GraphResponse {
  nodes?: GraphNode[];
  edges?: GraphEdge[];
  links?: GraphEdge[]; // some endpoints use links
  total_nodes?: number;
  total_edges?: number;
}

type TabKey = "architecture" | "flows" | "layers" | "databases" | "subsidiaries" | "diff" | "chokepoints";

interface TabSpec {
  key: TabKey;
  label: string;
  icon: typeof Network;
  endpoint: string;
  description: string;
}

const TABS: TabSpec[] = [
  { key: "architecture", label: "Architecture", icon: Box, endpoint: "/api/v1/graph/architecture-detect", description: "Service-to-service architecture inferred from repos + traces" },
  { key: "flows",        label: "Flows",        icon: GitBranch, endpoint: "/api/v1/graph/flows", description: "Data + request flows between services" },
  { key: "layers",       label: "Layers",       icon: Layers, endpoint: "/api/v1/graph/layers", description: "N-tier architecture layers (presentation / app / data)" },
  { key: "databases",    label: "Databases",    icon: Database, endpoint: "/api/v1/graph/databases", description: "Database connections + schema lineage per repo" },
  { key: "subsidiaries", label: "Subsidiaries", icon: Globe, endpoint: "/api/v1/easm/subsidiaries", description: "External attack surface — subsidiary + domain attribution" },
  { key: "diff",         label: "Diff (PR)",    icon: Zap, endpoint: "/api/v1/graph/diff", description: "Graph delta between PR HEAD and main branch" },
  { key: "chokepoints",  label: "Choke Points", icon: Target, endpoint: "/api/v1/attack-paths/choke-points", description: "Top nodes by betweenness centrality — bottlenecks in attack paths" },
];

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

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

function nodesFromResponse(r: unknown): GraphNode[] {
  if (Array.isArray(r)) return r as GraphNode[];
  if (!r || typeof r !== "object") return [];
  const obj = r as GraphResponse & { items?: GraphNode[]; assets?: GraphNode[] };
  return obj.nodes ?? obj.items ?? obj.assets ?? [];
}

function edgesFromResponse(r: unknown): GraphEdge[] {
  if (!r || typeof r !== "object") return [];
  if (Array.isArray(r)) return [];
  const obj = r as GraphResponse;
  return obj.edges ?? obj.links ?? [];
}

function critTone(c?: string) {
  switch ((c ?? "").toLowerCase()) {
    case "critical": return "border-red-500/40 text-red-400 bg-red-500/10";
    case "high": return "border-orange-500/40 text-orange-400 bg-orange-500/10";
    case "medium": return "border-yellow-500/40 text-yellow-400 bg-yellow-500/10";
    case "low": return "border-emerald-500/40 text-emerald-400 bg-emerald-500/10";
    default: return "border-border text-muted-foreground";
  }
}

const TYPE_COLORS: Record<string, string> = {
  service: "#60a5fa",
  database: "#34d399",
  api: "#a78bfa",
  cloud: "#fbbf24",
  external: "#f87171",
  repo: "#94a3b8",
  module: "#22d3ee",
  unknown: "#64748b",
};

function nodeColor(n: GraphNode) {
  return TYPE_COLORS[(n.type ?? "unknown").toLowerCase()] ?? TYPE_COLORS.unknown;
}

/**
 * Deterministic radial layout — group by type into concentric rings.
 * No d3-force, no extra deps. Visualization scales to ~500 nodes; beyond that
 * we virtualize by capping renderable nodes (see VIEWPORT_CAP).
 */
const VIEWPORT_CAP = 500;

function layoutNodes(nodes: GraphNode[], cx: number, cy: number): GraphNode[] {
  const capped = nodes.slice(0, VIEWPORT_CAP);
  const groups: Record<string, GraphNode[]> = {};
  for (const n of capped) {
    const k = (n.type ?? "unknown").toLowerCase();
    (groups[k] ||= []).push(n);
  }
  const groupKeys = Object.keys(groups);
  const ringStep = 110;
  const positioned: GraphNode[] = [];
  groupKeys.forEach((k, ringIdx) => {
    const ring = groups[k];
    const radius = 90 + ringIdx * ringStep;
    ring.forEach((n, i) => {
      const angle = (i / ring.length) * Math.PI * 2;
      positioned.push({
        ...n,
        x: cx + Math.cos(angle) * radius,
        y: cy + Math.sin(angle) * radius,
      });
    });
  });
  return positioned;
}

// ─────────────────────────────────────────────────────────────────────────────
// Component
// ─────────────────────────────────────────────────────────────────────────────

export default function AssetGraph() {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialTab = (searchParams.get("tab") as TabKey | null) ?? "architecture";

  const [tab, setTab] = useState<TabKey>(initialTab);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState<GraphNode | null>(null);

  // Persist tab to ?tab= for deep links + redirects
  useEffect(() => {
    const next = new URLSearchParams(searchParams);
    if (tab === "architecture") next.delete("tab");
    else next.set("tab", tab);
    if (next.toString() !== searchParams.toString()) {
      setSearchParams(next, { replace: true });
    }
  }, [tab, searchParams, setSearchParams]);

  const activeSpec = useMemo(() => TABS.find((t) => t.key === tab) ?? TABS[0], [tab]);

  const load = useCallback(async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const r = await apiFetch<GraphResponse | GraphNode[]>(activeSpec.endpoint);
      if (r === null) {
        setUnavailable(true);
        setNodes([]);
        setEdges([]);
      } else {
        setUnavailable(false);
        setNodes(nodesFromResponse(r));
        setEdges(edgesFromResponse(r));
      }
    } catch (e) {
      setErr((e as Error).message);
      setNodes([]);
      setEdges([]);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [activeSpec.endpoint]);

  useEffect(() => {
    setLoading(true);
    setSelected(null);
    load();
  }, [load]);

  const filteredNodes = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return nodes;
    return nodes.filter((n) => {
      const hay = [n.id, n.label ?? n.name, n.type, n.criticality].filter(Boolean).join(" ").toLowerCase();
      return hay.includes(q);
    });
  }, [nodes, filter]);

  const chokepoints = useMemo(
    () =>
      [...nodes]
        .filter((n) => n.centrality != null)
        .sort((a, b) => (b.centrality ?? 0) - (a.centrality ?? 0))
        .slice(0, 5),
    [nodes],
  );

  const crownJewels = useMemo(() => nodes.filter((n) => n.crown_jewel).length, [nodes]);
  const totalFindings = useMemo(() => nodes.reduce((s, n) => s + (n.finding_count ?? 0), 0), [nodes]);
  const totalAttackPaths = useMemo(() => nodes.reduce((s, n) => s + (n.attack_paths ?? 0), 0), [nodes]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6 p-6"
    >
      <PageHeader
        title="Asset Graph"
        description="The second brain — every service, repo, database, API, and external surface in one force-directed canvas. Apiiro/Wiz pattern. Click any node for criticality, crown-jewel status, attack paths, and related findings."
        badge="HERO"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("mr-2 h-4 w-4", refreshing && "animate-spin")} />
            Refresh
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <KpiCard title="Nodes" value={nodes.length.toLocaleString()} icon={Server} />
        <KpiCard title="Edges" value={edges.length.toLocaleString()} icon={Network} />
        <KpiCard title="Crown Jewels" value={crownJewels} icon={Crown} trend={crownJewels > 0 ? "up" : "flat"} />
        <KpiCard title="Findings" value={totalFindings.toLocaleString()} icon={AlertTriangle} />
        <KpiCard title="Attack Paths" value={totalAttackPaths.toLocaleString()} icon={Target} />
      </div>

      <Tabs value={tab} onValueChange={(v) => setTab(v as TabKey)} className="space-y-4">
        <TabsList className="flex flex-wrap gap-1 h-auto justify-start">
          {TABS.map((t) => {
            const Icon = t.icon;
            return (
              <TabsTrigger key={t.key} value={t.key} className="flex items-center gap-1.5">
                <Icon className="h-3.5 w-3.5" />
                {t.label}
              </TabsTrigger>
            );
          })}
        </TabsList>

        {TABS.map((t) => (
          <TabsContent key={t.key} value={t.key} className="space-y-4">
            <p className="text-sm text-muted-foreground">{t.description}</p>

            <div className="flex items-center gap-2">
              <div className="relative flex-1 max-w-md">
                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Filter by id, name, type, criticality…"
                  className="pl-8"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                />
              </div>
              <Badge variant="outline" className="gap-1">
                {filteredNodes.length} of {nodes.length}
              </Badge>
              {nodes.length > VIEWPORT_CAP && (
                <Badge variant="outline" className="gap-1 border-amber-500/40 text-amber-400">
                  Rendering capped at {VIEWPORT_CAP} (virtualized)
                </Badge>
              )}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {/* Center pane: graph canvas */}
              <Card className="lg:col-span-2">
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">{t.label} Graph</CardTitle>
                  <CardDescription>
                    Concentric ring layout grouped by node type. Click a node to inspect.
                  </CardDescription>
                </CardHeader>
                <CardContent className="p-0">
                  {loading ? (
                    <div className="p-6"><Skeleton className="h-[520px] w-full" /></div>
                  ) : err ? (
                    <ErrorState title="Failed to load graph" message={err} onRetry={load} />
                  ) : unavailable ? (
                    <EmptyState
                      icon={Network}
                      title={`${t.label} graph endpoint not available`}
                      description={`\`${t.endpoint}\` returned 404 or 501. The graph engine may not be running yet, or this view is "Coming soon".`}
                    />
                  ) : filteredNodes.length === 0 ? (
                    <EmptyState
                      icon={Box}
                      title="No nodes for this view"
                      description="Adjust the filter, or run a discovery scan from /discover to populate the graph."
                    />
                  ) : (
                    <div className="border-t border-border">
                      <GraphCanvas
                        nodes={filteredNodes}
                        edges={edges}
                        selectedId={selected?.id}
                        onSelect={setSelected}
                      />
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Right rail: chokepoints + selection detail */}
              <div className="space-y-4">
                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base flex items-center gap-2">
                      <Target className="h-4 w-4 text-primary" />
                      Top Chokepoints
                    </CardTitle>
                    <CardDescription>By betweenness centrality — fix these to break the most attack paths.</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {loading ? (
                      <div className="space-y-2">
                        {Array.from({ length: 5 }).map((_, i) => (
                          <Skeleton key={i} className="h-10 w-full" />
                        ))}
                      </div>
                    ) : chokepoints.length === 0 ? (
                      <EmptyState
                        icon={Target}
                        title="No centrality data yet"
                        description="Centrality computes once the graph engine has finished its first traversal pass."
                      />
                    ) : (
                      <div className="space-y-2">
                        {chokepoints.map((n) => (
                          <button
                            key={n.id}
                            type="button"
                            onClick={() => setSelected(n)}
                            className={cn(
                              "w-full rounded-md border border-border bg-muted/30 p-2.5 text-left space-y-1.5",
                              "hover:border-primary/60 hover:bg-muted/40 transition-colors",
                              selected?.id === n.id && "border-primary/80 bg-primary/10",
                            )}
                          >
                            <div className="flex items-center justify-between">
                              <span className="text-xs font-medium truncate">{n.label ?? n.name ?? n.id}</span>
                              <Badge variant="outline" className={cn("text-[9px]", critTone(n.criticality))}>
                                {(n.criticality ?? "—").toUpperCase()}
                              </Badge>
                            </div>
                            <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                              <span>{n.type ?? "—"}</span>
                              <span className="tabular-nums">
                                centrality {((n.centrality ?? 0) * 100).toFixed(1)}%
                              </span>
                            </div>
                            <Progress value={Math.round((n.centrality ?? 0) * 100)} className="h-1" />
                          </button>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base flex items-center gap-2">
                      <Activity className="h-4 w-4" />
                      Type Distribution
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <TypeDistribution nodes={nodes} />
                  </CardContent>
                </Card>
              </div>
            </div>
          </TabsContent>
        ))}
      </Tabs>

      {/* Side panel: clicked-node details */}
      {selected && (
        <motion.aside
          key={selected.id}
          initial={{ x: 480, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: 480, opacity: 0 }}
          transition={{ duration: 0.25 }}
          className="fixed right-0 top-0 z-40 h-screen w-full max-w-[460px] border-l border-border bg-background shadow-2xl flex flex-col"
        >
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <div className="min-w-0 flex items-center gap-2">
              <div
                className="h-3 w-3 rounded-full shrink-0"
                style={{ backgroundColor: nodeColor(selected) }}
              />
              <div className="min-w-0">
                <h3 className="font-semibold truncate">
                  {selected.label ?? selected.name ?? selected.id}
                  {selected.crown_jewel && (
                    <Crown className="inline h-3.5 w-3.5 ml-1.5 text-amber-400" />
                  )}
                </h3>
                <p className="text-xs text-muted-foreground truncate font-mono">{selected.id}</p>
              </div>
            </div>
            <Button variant="ghost" size="icon" onClick={() => setSelected(null)} aria-label="Close">
              <X className="h-4 w-4" />
            </Button>
          </div>
          <ScrollArea className="flex-1">
            <div className="p-4 space-y-3 text-sm">
              <Card>
                <CardHeader className="pb-2"><CardTitle className="text-sm">Asset Profile</CardTitle></CardHeader>
                <CardContent className="text-xs space-y-2">
                  <div className="flex justify-between"><span className="text-muted-foreground">Type</span><span className="font-medium capitalize">{selected.type ?? "—"}</span></div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Criticality</span>
                    <Badge variant="outline" className={critTone(selected.criticality)}>
                      {(selected.criticality ?? "—").toUpperCase()}
                    </Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Crown jewel</span>
                    <span className="font-medium">{selected.crown_jewel ? "Yes" : "No"}</span>
                  </div>
                  {selected.centrality != null && (
                    <div className="space-y-1">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Betweenness centrality</span>
                        <span className="font-medium tabular-nums">{(selected.centrality * 100).toFixed(1)}%</span>
                      </div>
                      <Progress value={Math.round(selected.centrality * 100)} className="h-1.5" />
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-2"><CardTitle className="text-sm flex items-center gap-2"><AlertTriangle className="h-3.5 w-3.5" />Risk Posture</CardTitle></CardHeader>
                <CardContent className="text-xs space-y-2">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Findings on this node</span>
                    <span className="font-medium tabular-nums">{selected.finding_count ?? 0}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Attack paths through</span>
                    <span className="font-medium tabular-nums">{selected.attack_paths ?? 0}</span>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-2"><CardTitle className="text-sm flex items-center gap-2"><Shield className="h-3.5 w-3.5" />Drill-In</CardTitle></CardHeader>
                <CardContent className="text-xs space-y-2">
                  <a href={`/issues?asset=${encodeURIComponent(selected.id)}`} className="block underline text-primary">
                    View related findings →
                  </a>
                  <a href={`/assets?tab=chokepoints`} className="block underline text-primary">
                    See in chokepoints view →
                  </a>
                  <code className="block rounded bg-muted p-2 font-mono mt-1 text-[10px] truncate">
                    GET /api/v1/dca/entities/{selected.id}
                  </code>
                </CardContent>
              </Card>
            </div>
          </ScrollArea>
        </motion.aside>
      )}
    </motion.div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Graph canvas — SVG, deterministic radial layout, no extra deps.
// ─────────────────────────────────────────────────────────────────────────────

interface GraphCanvasProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  selectedId?: string;
  onSelect: (n: GraphNode) => void;
}

function GraphCanvas({ nodes, edges, selectedId, onSelect }: GraphCanvasProps) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const cx = 460;
  const cy = 280;
  const positioned = useMemo(() => layoutNodes(nodes, cx, cy), [nodes]);

  const nodeIndex = useMemo(() => {
    const m = new Map<string, GraphNode>();
    for (const n of positioned) m.set(n.id, n);
    return m;
  }, [positioned]);

  const visibleEdges = useMemo(
    () =>
      edges.filter((e) => nodeIndex.has(e.source) && nodeIndex.has(e.target)).slice(0, 1500),
    [edges, nodeIndex],
  );

  return (
    <div className="relative h-[520px] w-full overflow-hidden bg-background">
      <svg
        ref={svgRef}
        viewBox="0 0 920 560"
        className="h-full w-full"
        role="img"
        aria-label="Asset graph"
      >
        {/* edges */}
        <g stroke="rgba(148, 163, 184, 0.22)" strokeWidth={0.6} fill="none">
          {visibleEdges.map((e, i) => {
            const a = nodeIndex.get(e.source);
            const b = nodeIndex.get(e.target);
            if (!a || !b) return null;
            return (
              <line
                key={(e.id ?? `${e.source}-${e.target}-${i}`)}
                x1={a.x}
                y1={a.y}
                x2={b.x}
                y2={b.y}
              />
            );
          })}
        </g>

        {/* nodes */}
        <g>
          {positioned.map((n) => {
            const r = n.crown_jewel ? 7 : (n.centrality ?? 0) > 0.4 ? 6 : 4.5;
            const isSel = selectedId === n.id;
            return (
              <g
                key={n.id}
                onClick={() => onSelect(n)}
                style={{ cursor: "pointer" }}
              >
                <circle
                  cx={n.x}
                  cy={n.y}
                  r={r + (isSel ? 3 : 0)}
                  fill={nodeColor(n)}
                  stroke={isSel ? "#f8fafc" : "rgba(0,0,0,0.4)"}
                  strokeWidth={isSel ? 1.5 : 0.5}
                  opacity={isSel ? 1 : 0.92}
                />
                {n.crown_jewel && (
                  <circle
                    cx={n.x}
                    cy={n.y}
                    r={r + 4}
                    fill="none"
                    stroke="#fbbf24"
                    strokeWidth={1}
                    opacity={0.7}
                  />
                )}
                {(isSel || (n.centrality ?? 0) > 0.5) && (
                  <text
                    x={(n.x ?? 0) + r + 5}
                    y={(n.y ?? 0) + 3}
                    fontSize={9}
                    fill="rgba(248, 250, 252, 0.85)"
                    pointerEvents="none"
                  >
                    {(n.label ?? n.name ?? n.id).slice(0, 28)}
                  </text>
                )}
              </g>
            );
          })}
        </g>
      </svg>

      {/* legend */}
      <div className="absolute bottom-2 left-2 flex flex-wrap gap-1.5 rounded border border-border/60 bg-background/80 backdrop-blur p-1.5 text-[10px]">
        {Object.entries(TYPE_COLORS).map(([k, c]) => (
          <span key={k} className="inline-flex items-center gap-1 px-1.5">
            <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: c }} />
            <span className="capitalize text-muted-foreground">{k}</span>
          </span>
        ))}
        <span className="inline-flex items-center gap-1 px-1.5">
          <Crown className="h-2.5 w-2.5 text-amber-400" />
          <span className="text-muted-foreground">crown jewel</span>
        </span>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Type distribution mini-chart
// ─────────────────────────────────────────────────────────────────────────────

function TypeDistribution({ nodes }: { nodes: GraphNode[] }) {
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const n of nodes) {
      const k = (n.type ?? "unknown").toLowerCase();
      c[k] = (c[k] ?? 0) + 1;
    }
    return Object.entries(c).sort(([, a], [, b]) => b - a);
  }, [nodes]);

  if (counts.length === 0) {
    return (
      <p className="text-xs text-muted-foreground italic">
        No nodes — load a tab to populate distribution.
      </p>
    );
  }

  const max = counts[0][1];
  return (
    <div className="space-y-2">
      {counts.map(([k, n]) => (
        <div key={k} className="space-y-1">
          <div className="flex items-center justify-between text-[11px]">
            <span className="capitalize flex items-center gap-1.5">
              <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: TYPE_COLORS[k] ?? TYPE_COLORS.unknown }} />
              {k}
            </span>
            <span className="tabular-nums text-muted-foreground">{n}</span>
          </div>
          <Progress value={(n / max) * 100} className="h-1" />
        </div>
      ))}
    </div>
  );
}
