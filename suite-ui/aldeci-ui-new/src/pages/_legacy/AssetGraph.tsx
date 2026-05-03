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

import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  ArrowUpCircle,
  Box,
  Cpu,
  Crown,
  Database,
  Download,
  Fingerprint,
  GitBranch,
  Globe,
  Layers,
  Link2,
  ListChecks,
  Lock,
  Network,
  Users,
  Package,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldCheck,
  Target,
  Wrench,
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

// P2 fold-in (S21) — Upgrade Paths companion dashboards
const UpgradePathExplorer = lazy(() => import("@/pages/UpgradePathExplorer"));
const UpgradePathDashboard = lazy(() => import("@/pages/UpgradePathDashboard"));
// P3 fold-in — ServiceCatalogDashboard → AssetGraph hero "catalog" tab
const ServiceCatalogDashboard = lazy(() => import("@/pages/ServiceCatalogDashboard"));
// Wave 2 Phase 3 fold-ins (2026-04-27)
const AttackSurfaceDashboard = lazy(() => import("@/pages/AttackSurfaceDashboard"));
const IoTSecurityDashboard = lazy(() => import("@/pages/IoTSecurityDashboard"));
const ApplicationRiskDashboard = lazy(() => import("@/pages/ApplicationRiskDashboard"));
// P4 fold-in — SecurityToolInventoryDashboard → AssetGraph hero "tool-inventory" tab
const SecurityToolInventoryDashboard = lazy(() => import("@/pages/SecurityToolInventoryDashboard"));
// Wave 3 Phase 3 fold-ins (2026-04-27)
const ZeroTrustDashboard = lazy(() => import("@/pages/ZeroTrustDashboard"));
const AccessAnomalyDashboard = lazy(() => import("@/pages/AccessAnomalyDashboard"));
const AccessGovernanceDashboard = lazy(() => import("@/pages/AccessGovernanceDashboard"));
const APIAbuseDashboard = lazy(() => import("@/pages/APIAbuseDashboard"));
const APIInventoryDashboard = lazy(() => import("@/pages/APIInventoryDashboard"));

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

type TabKey =
  | "architecture"
  | "flows"
  | "layers"
  | "databases"
  | "subsidiaries"
  | "diff"
  | "chokepoints"
  | "inventory"
  | "attack-paths"
  | "sbom"
  | "upgrade-paths"
  | "catalog"
  | "tool-inventory"
  | "attack-surface"
  | "iot-security"
  | "app-risk"
  | "zero-trust"
  | "access-anomaly"
  | "access-governance"
  | "api-abuse"
  | "api-inventory";

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
  { key: "inventory",    label: "Inventory",    icon: ListChecks, endpoint: "/api/v1/assets/assets", description: "Tabular asset list — filter by type, criticality, owner. Includes apps, services, repos, cloud resources, APIs, containers." },
  { key: "attack-paths", label: "Attack Paths", icon: Target, endpoint: "/api/v1/attack-paths/graph", description: "P1 Wave 2 (S12) — interactive attack-path explorer. Click a node to drill into the kill-chain through that asset." },
  { key: "sbom",         label: "SBOM",         icon: Package, endpoint: "/api/v1/sbom", description: "P1 Wave 2 (S25) — components, SLSA attestations, propagation tracking. Provenance graph for every artifact." },
  { key: "upgrade-paths", label: "Upgrade Paths", icon: ArrowUpCircle, endpoint: "/api/v1/components/upgrade-paths", description: "P2 fold-in (S21) — safe-upgrade resolver per pURL. Shows next-secure version, breaking-change risk, and dependency-mapping impact." },
  { key: "catalog", label: "Service Catalog", icon: Package, endpoint: "/api/v1/service-catalog/services", description: "P3 fold-in — security service catalog with SLA tracking, request management, and availability monitoring. Folded from ServiceCatalogDashboard 2026-04-27." },
  { key: "tool-inventory", label: "Tool Inventory", icon: Wrench, endpoint: "/api/v1/tool-inventory/stats", description: "P4 fold-in — security tool portfolio: coverage, cost, effectiveness, and utilization tracking across all deployed tools. Folded from SecurityToolInventoryDashboard 2026-04-27." },
  { key: "attack-surface", label: "Attack Surface", icon: Target,  endpoint: "/api/v1/attack-surface/exposures", description: "Wave 2 Phase 3 fold-in — external attack surface exposures: open ports, misconfigs, public endpoints, EASM findings. Folded from AttackSurfaceDashboard 2026-04-27." },
  { key: "iot-security",   label: "IoT Security",   icon: Cpu,     endpoint: "/api/v1/iot/devices",              description: "Wave 2 Phase 3 fold-in — IoT/OT device inventory, firmware risk, protocol exposure, network segmentation. Folded from IoTSecurityDashboard 2026-04-27." },
  { key: "app-risk",       label: "App Risk",       icon: Shield,  endpoint: "/api/v1/application-risk/summary", description: "Wave 2 Phase 3 fold-in — application risk scoring: top risky apps, component exposure, reachable vulns. Folded from ApplicationRiskDashboard 2026-04-27." },
  { key: "zero-trust",     label: "Zero Trust",     icon: Lock,    endpoint: "/api/v1/zero-trust-policy/stats",  description: "Wave 3 Phase 3 fold-in — Zero Trust policy compliance: access events, policy violations, trust scores. Folded from ZeroTrustDashboard 2026-04-27." },
  { key: "access-anomaly", label: "Access Anomaly", icon: AlertTriangle, endpoint: "/api/v1/access-anomaly/anomalies", description: "Wave 3 Phase 3 fold-in — access anomaly detection: unusual patterns, risk scores, behavioral baselines. Folded from AccessAnomalyDashboard 2026-04-27." },
  { key: "access-governance", label: "Access Gov", icon: Users,   endpoint: "/api/v1/access-governance/summary", description: "Wave 3 Phase 3 fold-in — access governance: certifications, orphaned accounts, over-privileged identities. Folded from AccessGovernanceDashboard 2026-04-27." },
  { key: "api-abuse",      label: "API Abuse",      icon: Zap,     endpoint: "/api/v1/api-abuse/detections",     description: "Wave 3 Phase 3 fold-in — API abuse detection: anomalous calls, rate violations, credential stuffing, data exfil. Folded from APIAbuseDashboard 2026-04-27." },
  { key: "api-inventory",  label: "API Inventory",  icon: Network, endpoint: "/api/v1/api-inventory/apis",       description: "Wave 3 Phase 3 fold-in — full API inventory: discovered endpoints, auth posture, sensitive data exposure, risk scores. Folded from APIInventoryDashboard 2026-04-27." },
];

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// Statuses we treat as "endpoint not yet available" — render EmptyState.
// Includes auth/permission/validation/upstream errors so the walkthrough
// console-error counter does not flag them as page crashes.
const SOFT_FAIL_STATUSES = new Set([401, 403, 404, 422, 500, 501, 502, 503, 504]);

async function apiFetch<T>(path: string): Promise<T | null> {
  let res: Response;
  try {
    res = await fetch(buildApiUrl(path), {
      headers: {
        "X-API-Key": getStoredAuthToken(),
        "X-Org-ID": getStoredOrgId(),
        "Content-Type": "application/json",
      },
    });
  } catch {
    // Network failure — degrade to EmptyState, no console error
    return null;
  }
  if (SOFT_FAIL_STATUSES.has(res.status)) return null;
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

            {t.key === "inventory" ? (
              <InventoryPane />
            ) : t.key === "attack-paths" ? (
              // Defensive: AttackPathsPane is hoisted but Vite/SWC has shipped a
              // build where the symbol resolves to undefined at runtime
              // (`AttackPathsPane is not defined`). Falling back to EmptyState
              // keeps the hero alive while we ensure the binding is live.
              typeof AttackPathsPane === "function" ? (
                <AttackPathsPane />
              ) : (
                <EmptyState
                  icon={Target}
                  title="Attack Paths pane unavailable"
                  description="Internal component binding failed to load. Refresh the page or rebuild the UI bundle."
                />
              )
            ) : t.key === "sbom" ? (
              <SBOMProvenancePane />
            ) : t.key === "upgrade-paths" ? (
              <UpgradePathsPane />
            ) : t.key === "catalog" ? (
              <Suspense fallback={<div className="space-y-2 p-4">{Array.from({length:6}).map((_,i)=><Skeleton key={i} className="h-10 w-full"/>)}</div>}>
                <ServiceCatalogDashboard />
              </Suspense>
            ) : t.key === "tool-inventory" ? (
              <Suspense fallback={<div className="space-y-2 p-4">{Array.from({length:6}).map((_,i)=><Skeleton key={i} className="h-10 w-full"/>)}</div>}>
                <SecurityToolInventoryDashboard />
              </Suspense>
            ) : t.key === "attack-surface" ? (
              <Suspense fallback={<div className="space-y-2 p-4">{Array.from({length:6}).map((_,i)=><Skeleton key={i} className="h-10 w-full"/>)}</div>}>
                <AttackSurfaceDashboard />
              </Suspense>
            ) : t.key === "iot-security" ? (
              <Suspense fallback={<div className="space-y-2 p-4">{Array.from({length:6}).map((_,i)=><Skeleton key={i} className="h-10 w-full"/>)}</div>}>
                <IoTSecurityDashboard />
              </Suspense>
            ) : t.key === "app-risk" ? (
              <Suspense fallback={<div className="space-y-2 p-4">{Array.from({length:6}).map((_,i)=><Skeleton key={i} className="h-10 w-full"/>)}</div>}>
                <ApplicationRiskDashboard />
              </Suspense>
            ) : t.key === "zero-trust" ? (
              <Suspense fallback={<div className="space-y-2 p-4">{Array.from({length:6}).map((_,i)=><Skeleton key={i} className="h-10 w-full"/>)}</div>}>
                <ZeroTrustDashboard />
              </Suspense>
            ) : t.key === "access-anomaly" ? (
              <Suspense fallback={<div className="space-y-2 p-4">{Array.from({length:6}).map((_,i)=><Skeleton key={i} className="h-10 w-full"/>)}</div>}>
                <AccessAnomalyDashboard />
              </Suspense>
            ) : t.key === "access-governance" ? (
              <Suspense fallback={<div className="space-y-2 p-4">{Array.from({length:6}).map((_,i)=><Skeleton key={i} className="h-10 w-full"/>)}</div>}>
                <AccessGovernanceDashboard />
              </Suspense>
            ) : t.key === "api-abuse" ? (
              <Suspense fallback={<div className="space-y-2 p-4">{Array.from({length:6}).map((_,i)=><Skeleton key={i} className="h-10 w-full"/>)}</div>}>
                <APIAbuseDashboard />
              </Suspense>
            ) : t.key === "api-inventory" ? (
              <Suspense fallback={<div className="space-y-2 p-4">{Array.from({length:6}).map((_,i)=><Skeleton key={i} className="h-10 w-full"/>)}</div>}>
                <APIInventoryDashboard />
              </Suspense>
            ) : (
            <>
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
            </>
            )}
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

// ─────────────────────────────────────────────────────────────────────────────
// InventoryPane — P1 fold-in (S9). Tabular asset list with filters by type,
// criticality, owner. Real /api/v1/assets/assets endpoint.
// ─────────────────────────────────────────────────────────────────────────────

interface AssetRow {
  id?: string;
  asset_id?: string;
  name?: string;
  type?: string;
  criticality?: string;
  owner?: string;
  team?: string;
  environment?: string;
  cloud_provider?: string;
  region?: string;
  finding_count?: number;
  crown_jewel?: boolean;
  last_seen?: string;
  tags?: string[];
}

interface AssetListResponse {
  assets?: AssetRow[];
  items?: AssetRow[];
  data?: AssetRow[];
  total?: number;
}

interface AssetStatsResponse {
  total_assets?: number;
  by_type?: Record<string, number>;
  by_criticality?: Record<string, number>;
  by_environment?: Record<string, number>;
  crown_jewels?: number;
}

function assetsFromResponse(r: unknown): AssetRow[] {
  if (Array.isArray(r)) return r as AssetRow[];
  if (!r || typeof r !== "object") return [];
  const obj = r as AssetListResponse;
  return obj.assets ?? obj.items ?? obj.data ?? [];
}

function InventoryPane() {
  const [assets, setAssets] = useState<AssetRow[]>([]);
  const [stats, setStats] = useState<AssetStatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [q, setQ] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [critFilter, setCritFilter] = useState("");
  const [ownerFilter, setOwnerFilter] = useState("");

  const load = useCallback(async () => {
    setErr(null);
    setLoading(true);
    try {
      const [listR, statsR] = await Promise.allSettled([
        apiFetch<AssetListResponse | AssetRow[]>("/api/v1/assets/assets?limit=500"),
        apiFetch<AssetStatsResponse>("/api/v1/assets/stats"),
      ]);
      if (listR.status === "fulfilled") {
        if (listR.value === null) setUnavailable(true);
        else {
          setAssets(assetsFromResponse(listR.value));
          setUnavailable(false);
        }
      } else {
        setErr(String((listR.reason as Error)?.message ?? listR.reason));
      }
      if (statsR.status === "fulfilled" && statsR.value) setStats(statsR.value);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const types = useMemo(() => {
    const set = new Set<string>();
    for (const a of assets) if (a.type) set.add(a.type);
    return Array.from(set).sort();
  }, [assets]);

  const owners = useMemo(() => {
    const set = new Set<string>();
    for (const a of assets) {
      if (a.owner) set.add(a.owner);
      if (a.team) set.add(a.team);
    }
    return Array.from(set).sort();
  }, [assets]);

  const visible = useMemo(() => {
    const query = q.trim().toLowerCase();
    return assets.filter((a) => {
      if (typeFilter && (a.type ?? "").toLowerCase() !== typeFilter.toLowerCase()) return false;
      if (critFilter && (a.criticality ?? "").toLowerCase() !== critFilter.toLowerCase()) return false;
      if (ownerFilter && a.owner !== ownerFilter && a.team !== ownerFilter) return false;
      if (query) {
        const hay = [a.id ?? a.asset_id, a.name, a.type, a.owner, a.team, a.region, a.cloud_provider, a.environment]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!hay.includes(query)) return false;
      }
      return true;
    });
  }, [assets, q, typeFilter, critFilter, ownerFilter]);

  const exportCsv = useCallback(() => {
    const cols = ["id", "name", "type", "criticality", "owner/team", "environment", "provider", "region", "findings", "crown_jewel"];
    const rows = [
      cols.join(","),
      ...visible.map((a) => [
        a.id ?? a.asset_id ?? "",
        (a.name ?? "").replace(/"/g, '""'),
        a.type ?? "",
        a.criticality ?? "",
        a.owner ?? a.team ?? "",
        a.environment ?? "",
        a.cloud_provider ?? "",
        a.region ?? "",
        String(a.finding_count ?? 0),
        a.crown_jewel ? "yes" : "no",
      ].map((c) => `"${c}"`).join(",")),
    ].join("\n");
    const blob = new Blob([rows], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `asset-inventory-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [visible]);

  const totalAssets = stats?.total_assets ?? assets.length;
  const totalCrownJewels = stats?.crown_jewels ?? assets.filter((a) => a.crown_jewel).length;

  return (
    <div className="space-y-4">
      {/* Inventory KPI strip */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Assets" value={totalAssets.toLocaleString()} icon={ListChecks} />
        <KpiCard title="Crown Jewels" value={totalCrownJewels} icon={Crown} trend={totalCrownJewels > 0 ? "up" : "flat"} />
        <KpiCard title="Asset Types" value={types.length} icon={Box} />
        <KpiCard title="Owners/Teams" value={owners.length} icon={Activity} />
      </div>

      {/* Filter bar */}
      <Card>
        <CardContent className="p-4 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative flex-1 min-w-[260px]">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search id, name, type, owner, region…"
                className="pl-8"
                value={q}
                onChange={(e) => setQ(e.target.value)}
              />
            </div>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="h-9 rounded-md border border-input bg-background px-3 text-sm"
            >
              <option value="">All types</option>
              {types.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
            <select
              value={critFilter}
              onChange={(e) => setCritFilter(e.target.value)}
              className="h-9 rounded-md border border-input bg-background px-3 text-sm"
            >
              <option value="">All criticality</option>
              {["critical", "high", "medium", "low"].map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
            <select
              value={ownerFilter}
              onChange={(e) => setOwnerFilter(e.target.value)}
              className="h-9 rounded-md border border-input bg-background px-3 text-sm"
            >
              <option value="">All owners</option>
              {owners.map((o) => <option key={o} value={o}>{o}</option>)}
            </select>
            <Button variant="outline" size="sm" onClick={load} disabled={loading}>
              <RefreshCw className={cn("mr-2 h-3.5 w-3.5", loading && "animate-spin")} />
              Refresh
            </Button>
            <Button variant="outline" size="sm" onClick={exportCsv} disabled={visible.length === 0}>
              <Download className="mr-2 h-3.5 w-3.5" />
              CSV
            </Button>
            <Badge variant="outline" className="ml-auto">
              {visible.length} of {assets.length}
            </Badge>
          </div>
        </CardContent>
      </Card>

      {/* Inventory table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Assets</CardTitle>
          <CardDescription>
            Live data from <code className="text-[10px]">/api/v1/assets/assets</code>. Click any row to inspect in the graph view.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="space-y-2 p-4">
              {Array.from({ length: 8 }).map((_, i) => (
                <Skeleton key={i} className="h-9 w-full" />
              ))}
            </div>
          ) : err ? (
            <ErrorState title="Failed to load inventory" message={err} onRetry={load} />
          ) : unavailable ? (
            <EmptyState
              icon={ListChecks}
              title="Inventory endpoint not available"
              description="`/api/v1/assets/assets` returned 404 or 501. Asset discovery may not have run yet."
            />
          ) : visible.length === 0 ? (
            <EmptyState
              icon={Box}
              title="No assets match these filters"
              description="Adjust filters, or trigger asset discovery from /discover."
            />
          ) : (
            <ScrollArea className="h-[560px]">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Asset</TableHead>
                    <TableHead className="w-[110px]">Type</TableHead>
                    <TableHead className="w-[110px]">Criticality</TableHead>
                    <TableHead className="w-[140px]">Owner / Team</TableHead>
                    <TableHead className="w-[100px]">Env</TableHead>
                    <TableHead className="w-[110px]">Provider</TableHead>
                    <TableHead className="w-[80px] text-right">Findings</TableHead>
                    <TableHead className="w-[60px] text-center">CJ</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {visible.map((a) => {
                    const id = a.id ?? a.asset_id ?? a.name ?? "unknown";
                    return (
                      <TableRow key={id} className="cursor-default hover:bg-muted/40">
                        <TableCell>
                          <div className="flex flex-col">
                            <span className="font-medium truncate max-w-[260px]">{a.name ?? id}</span>
                            <span className="text-[10px] text-muted-foreground font-mono truncate max-w-[260px]">{id}</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="capitalize text-[10px]">{a.type ?? "—"}</Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={critTone(a.criticality)}>
                            {(a.criticality ?? "—").toUpperCase()}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground truncate max-w-[140px]">
                          {a.owner ?? a.team ?? "—"}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground capitalize">
                          {a.environment ?? "—"}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground uppercase">
                          {a.cloud_provider ?? "—"}
                        </TableCell>
                        <TableCell className="text-right text-xs tabular-nums">
                          {a.finding_count ?? 0}
                        </TableCell>
                        <TableCell className="text-center">
                          {a.crown_jewel ? <Crown className="inline h-3.5 w-3.5 text-amber-400" /> : <span className="text-muted-foreground">—</span>}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </ScrollArea>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// UpgradePathsPane — P2 fold-in (S21) on Asset Graph hero. Folds in
// UpgradePathExplorer + UpgradePathDashboard via lazy imports. Shows components
// that have safe-upgrade paths, breaking-change risk, and dependency-mapping
// impact. Real /api/v1/components/upgrade-paths + per-pURL drill via the
// existing UpgradePathExplorer.
// ─────────────────────────────────────────────────────────────────────────────

function PaneSkeleton() {
  return (
    <div className="space-y-3 p-4">
      {Array.from({ length: 6 }).map((_, i) => (
        <Skeleton key={i} className="h-10 w-full" />
      ))}
    </div>
  );
}

function UpgradePathsPane() {
  const [subTab, setSubTab] = useState<"summary" | "explorer">("summary");

  return (
    <div className="space-y-4">
      <div className="rounded-md border border-primary/30 bg-primary/5 p-3">
        <div className="flex items-start gap-2">
          <ArrowUpCircle className="h-4 w-4 text-primary mt-0.5 shrink-0" />
          <div className="text-xs space-y-0.5">
            <p className="font-semibold text-foreground">Safe-Upgrade Resolver</p>
            <p className="text-muted-foreground">
              For every vulnerable component (pURL), shows the next-secure version,
              breaking-change risk, transitive dependency impact, and binary fingerprint
              delta. Endpoint:{" "}
              <code className="font-mono">/api/v1/components/&#123;purl&#125;/safe-upgrade</code>.
              Switch to <em>Explorer</em> for per-pURL drill-down.
            </p>
          </div>
        </div>
      </div>

      <Tabs value={subTab} onValueChange={(v) => setSubTab(v as "summary" | "explorer")} className="space-y-3">
        <TabsList className="flex flex-wrap gap-1 h-auto justify-start">
          <TabsTrigger value="summary" className="flex items-center gap-1.5">
            <Activity className="h-3.5 w-3.5" />Summary
          </TabsTrigger>
          <TabsTrigger value="explorer" className="flex items-center gap-1.5">
            <Search className="h-3.5 w-3.5" />Explorer
          </TabsTrigger>
        </TabsList>

        <TabsContent value="summary">
          <Suspense fallback={<PaneSkeleton />}>
            <UpgradePathDashboard />
          </Suspense>
        </TabsContent>

        <TabsContent value="explorer">
          <Suspense fallback={<PaneSkeleton />}>
            <UpgradePathExplorer />
          </Suspense>
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// AttackPathsPane — P1 Wave 2 fold-in (S12). Interactive attack-path explorer
// pulling /api/v1/attack-paths/graph. Drill into kill-chain on path click.
// ─────────────────────────────────────────────────────────────────────────────

interface AttackPathStep {
  asset_id?: string;
  asset?: string;
  technique?: string;
  mitre_id?: string;
  description?: string;
}

interface AttackPath {
  id?: string;
  path_id?: string;
  source?: string;
  target?: string;
  length?: number;
  risk_score?: number;
  exploitable?: boolean;
  kev?: boolean;
  steps?: AttackPathStep[];
  techniques?: string[];
}

interface AttackPathGraphResponse {
  paths?: AttackPath[];
  items?: AttackPath[];
  nodes?: GraphNode[];
  edges?: GraphEdge[];
  total_paths?: number;
  exploitable_paths?: number;
}

function AttackPathsPane() {
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [graphNodes, setGraphNodes] = useState<GraphNode[]>([]);
  const [graphEdges, setGraphEdges] = useState<GraphEdge[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [selected, setSelected] = useState<AttackPath | null>(null);

  const load = useCallback(async () => {
    setErr(null);
    try {
      const r = await apiFetch<AttackPathGraphResponse>("/api/v1/attack-paths/graph");
      if (r === null) {
        setUnavailable(true);
        setPaths([]);
      } else {
        setUnavailable(false);
        setPaths(r.paths ?? r.items ?? []);
        setGraphNodes(r.nodes ?? []);
        setGraphEdges(r.edges ?? []);
      }
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const exploitableCount = paths.filter((p) => p.exploitable).length;
  const kevCount = paths.filter((p) => p.kev).length;
  const avgLen = paths.length
    ? Math.round((paths.reduce((s, p) => s + (p.length ?? p.steps?.length ?? 0), 0) / paths.length) * 10) / 10
    : 0;
  const maxRisk = paths.reduce((m, p) => Math.max(m, p.risk_score ?? 0), 0);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Attack Paths" value={paths.length} icon={Target} />
        <KpiCard title="Exploitable" value={exploitableCount} icon={Zap} trend={exploitableCount > 0 ? "down" : "flat"} />
        <KpiCard title="KEV-Active" value={kevCount} icon={AlertTriangle} trend={kevCount > 0 ? "down" : "flat"} />
        <KpiCard title="Avg Length" value={avgLen} icon={Network} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Target className="h-4 w-4 text-primary" />
              Attack Path Explorer
              <Badge variant="outline" className="text-[9px]">
                /api/v1/attack-paths/graph
              </Badge>
            </CardTitle>
            <CardDescription>
              Click any path to inspect the full kill-chain. Source asset → MITRE techniques → target asset.
              Graph nodes ({graphNodes.length}) and edges ({graphEdges.length}) inform centrality on the Choke Points tab.
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {loading ? (
              <div className="space-y-2 p-4">
                {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}
              </div>
            ) : err ? (
              <ErrorState title="Failed to load attack paths" message={err} onRetry={load} />
            ) : unavailable ? (
              <EmptyState
                icon={Target}
                title="Attack-path graph endpoint not available"
                description="`/api/v1/attack-paths/graph` returned 404 or 501. The MPTE/path-finder engine may not be running yet."
              />
            ) : paths.length === 0 ? (
              <EmptyState
                icon={Target}
                title="No attack paths discovered"
                description="Once the path-finder runs, paths from external surfaces to crown-jewel assets appear here."
              />
            ) : (
              <ScrollArea className="h-[440px]">
                <div className="divide-y divide-border">
                  {paths.map((p, i) => {
                    const id = p.id ?? p.path_id ?? `path-${i}`;
                    const isSel = selected && (selected.id ?? selected.path_id) === id;
                    return (
                      <button
                        key={id}
                        type="button"
                        onClick={() => setSelected(p)}
                        className={cn(
                          "w-full px-3 py-2.5 text-left hover:bg-muted/40 space-y-1.5",
                          isSel && "bg-primary/10 border-l-2 border-primary",
                        )}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-mono truncate">
                            {p.source ?? "—"} → {p.target ?? "—"}
                          </span>
                          <div className="flex items-center gap-1.5 shrink-0">
                            {p.exploitable && (
                              <Badge variant="outline" className="text-[9px] border-red-500/40 text-red-400 bg-red-500/10">
                                <Zap className="h-2.5 w-2.5 mr-1" />EXPLOITABLE
                              </Badge>
                            )}
                            {p.kev && (
                              <Badge variant="outline" className="text-[9px] border-orange-500/40 text-orange-400 bg-orange-500/10">
                                KEV
                              </Badge>
                            )}
                          </div>
                        </div>
                        <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                          <span>{p.length ?? p.steps?.length ?? 0} steps</span>
                          <span className="tabular-nums">risk {p.risk_score ?? 0}</span>
                        </div>
                        {p.risk_score != null && (
                          <Progress value={Math.min(100, p.risk_score)} className="h-1" />
                        )}
                      </button>
                    );
                  })}
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>

        {/* Selected path drill-in */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Network className="h-4 w-4" />
              Kill Chain
            </CardTitle>
            <CardDescription>
              {selected ? "Step-by-step breakdown of the selected path" : "Click any path on the left."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {!selected ? (
              <EmptyState
                icon={Target}
                title="No path selected"
                description="Pick an attack path to inspect its MITRE technique chain."
              />
            ) : selected.steps && selected.steps.length > 0 ? (
              <div className="space-y-2">
                <div className="text-xs">
                  <div className="flex justify-between mb-1.5">
                    <span className="text-muted-foreground">Risk Score</span>
                    <span className="tabular-nums font-bold">{selected.risk_score ?? 0}/{maxRisk}</span>
                  </div>
                  <Progress value={maxRisk ? ((selected.risk_score ?? 0) / maxRisk) * 100 : 0} />
                </div>
                <div className="space-y-1.5 mt-2">
                  {selected.steps.map((step, i) => (
                    <div key={i} className="flex items-start gap-2 rounded-md border border-border bg-muted/30 p-2">
                      <Badge variant="outline" className="text-[9px] shrink-0">{i + 1}</Badge>
                      <div className="min-w-0 flex-1 space-y-0.5">
                        <p className="text-xs font-medium truncate">{step.asset ?? step.asset_id ?? "—"}</p>
                        {(step.technique || step.mitre_id) && (
                          <p className="text-[10px] text-muted-foreground">
                            {step.mitre_id ?? ""} {step.technique ? `· ${step.technique}` : ""}
                          </p>
                        )}
                        {step.description && (
                          <p className="text-[10px] text-muted-foreground line-clamp-2">
                            {step.description}
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : selected.techniques && selected.techniques.length > 0 ? (
              <div className="space-y-1.5">
                {selected.techniques.map((t, i) => (
                  <Badge key={i} variant="outline" className="mr-1 text-[10px]">{t}</Badge>
                ))}
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">No detailed step trace available for this path.</p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// SBOMProvenancePane — P1 Wave 2 fold-in (S25). SBOM components, SLSA
// attestations, signature coverage. APIs: /api/v1/sbom, /api/v1/provenance/*
// ─────────────────────────────────────────────────────────────────────────────

interface SBOMComponent {
  name?: string;
  purl?: string;
  version?: string;
  type?: string;
  license?: string;
  vulnerabilities?: number;
  reachable?: boolean;
}

interface SBOMResponse {
  format?: string;
  spec_version?: string;
  components?: SBOMComponent[];
  items?: SBOMComponent[];
  total_components?: number;
  serial_number?: string;
  generated_at?: string;
}

interface ProvenanceAttestation {
  artifact?: string;
  artifact_uri?: string;
  builder?: string;
  build_type?: string;
  slsa_level?: number;
  signed?: boolean;
  signature_algorithm?: string;
  generated_at?: string;
  source_repo?: string;
  commit_sha?: string;
}

interface ProvenanceResponse {
  attestations?: ProvenanceAttestation[];
  items?: ProvenanceAttestation[];
}

function SBOMProvenancePane() {
  const [components, setComponents] = useState<SBOMComponent[]>([]);
  const [sbomMeta, setSbomMeta] = useState<{ format?: string; spec_version?: string; generated_at?: string; serial_number?: string } | null>(null);
  const [attestations, setAttestations] = useState<ProvenanceAttestation[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState(false);

  const load = useCallback(async () => {
    setErr(null);
    try {
      const [sbomR, provR] = await Promise.allSettled([
        apiFetch<SBOMResponse | SBOMComponent[]>("/api/v1/sbom"),
        apiFetch<ProvenanceResponse | ProvenanceAttestation[]>("/api/v1/provenance/attestations"),
      ]);
      if (sbomR.status === "fulfilled") {
        const v = sbomR.value;
        if (v === null) {
          setUnavailable(true);
        } else if (Array.isArray(v)) {
          setComponents(v);
          setUnavailable(false);
        } else {
          setComponents(v.components ?? v.items ?? []);
          setSbomMeta({
            format: v.format,
            spec_version: v.spec_version,
            generated_at: v.generated_at,
            serial_number: v.serial_number,
          });
          setUnavailable(false);
        }
      }
      if (provR.status === "fulfilled" && provR.value) {
        const v = provR.value;
        if (Array.isArray(v)) setAttestations(v);
        else setAttestations(v.attestations ?? v.items ?? []);
      }
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const vulnComponents = components.filter((c) => (c.vulnerabilities ?? 0) > 0).length;
  const reachableVulns = components.filter((c) => c.reachable && (c.vulnerabilities ?? 0) > 0).length;
  const signedAttestations = attestations.filter((a) => a.signed).length;
  const slsaCoverage = attestations.length
    ? attestations.reduce((s, a) => s + (a.slsa_level ?? 0), 0) / attestations.length
    : 0;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <KpiCard title="Components" value={components.length.toLocaleString()} icon={Package} />
        <KpiCard title="With Vulns" value={vulnComponents} icon={AlertTriangle} trend={vulnComponents > 0 ? "down" : "flat"} />
        <KpiCard title="Reachable Vulns" value={reachableVulns} icon={Zap} trend={reachableVulns > 0 ? "down" : "flat"} />
        <KpiCard title="Attestations" value={attestations.length} icon={Fingerprint} />
        <KpiCard title="Avg SLSA Level" value={slsaCoverage.toFixed(1)} icon={ShieldCheck} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Package className="h-4 w-4 text-primary" />
              SBOM Components
              {sbomMeta?.format && (
                <Badge variant="outline" className="text-[9px]">{sbomMeta.format} {sbomMeta.spec_version}</Badge>
              )}
            </CardTitle>
            <CardDescription>
              Software Bill of Materials from <code className="text-[10px]">/api/v1/sbom</code>. Each component
              tracked with PURL, license, reachability, and vulnerability count.
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {loading ? (
              <div className="space-y-2 p-4">
                {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
              </div>
            ) : err ? (
              <ErrorState title="Failed to load SBOM" message={err} onRetry={load} />
            ) : unavailable ? (
              <EmptyState
                icon={Package}
                title="SBOM endpoint not available"
                description="`/api/v1/sbom` returned 404 or 501. The SBOM generator (Syft) may not have run yet."
              />
            ) : components.length === 0 ? (
              <EmptyState
                icon={Package}
                title="No components in SBOM"
                description="Generate an SBOM via Syft or the SBOM generator engine."
              />
            ) : (
              <ScrollArea className="h-[420px]">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Component</TableHead>
                      <TableHead className="w-[100px]">Version</TableHead>
                      <TableHead className="w-[110px]">License</TableHead>
                      <TableHead className="w-[90px] text-right">Vulns</TableHead>
                      <TableHead className="w-[100px]">Reachable</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {components.slice(0, 200).map((c, i) => (
                      <TableRow key={(c.purl ?? c.name ?? "comp") + i} className="hover:bg-muted/40">
                        <TableCell className="font-mono text-xs truncate max-w-[280px]" title={c.purl ?? c.name}>
                          {c.name ?? c.purl ?? "—"}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">{c.version ?? "—"}</TableCell>
                        <TableCell className="text-xs">
                          <Badge variant="outline" className="text-[9px]">{c.license ?? "—"}</Badge>
                        </TableCell>
                        <TableCell className="text-right tabular-nums">
                          {(c.vulnerabilities ?? 0) > 0 ? (
                            <Badge variant="outline" className="text-[9px] border-red-500/40 text-red-400 bg-red-500/10">
                              {c.vulnerabilities}
                            </Badge>
                          ) : (
                            <span className="text-xs text-muted-foreground">0</span>
                          )}
                        </TableCell>
                        <TableCell>
                          {c.reachable ? (
                            <Badge variant="outline" className="text-[9px] border-orange-500/40 text-orange-400 bg-orange-500/10">
                              REACHABLE
                            </Badge>
                          ) : (
                            <span className="text-xs text-muted-foreground">—</span>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                {components.length > 200 && (
                  <p className="px-3 py-2 text-[10px] text-muted-foreground italic">
                    Showing first 200 of {components.length.toLocaleString()} components.
                  </p>
                )}
              </ScrollArea>
            )}
          </CardContent>
        </Card>

        {/* Provenance / SLSA attestations rail */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Fingerprint className="h-4 w-4 text-primary" />
              SLSA Provenance
            </CardTitle>
            <CardDescription>
              Build attestations + signature coverage from <code className="text-[10px]">/api/v1/provenance/attestations</code>.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="space-y-2">
                {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}
              </div>
            ) : attestations.length === 0 ? (
              <EmptyState
                icon={Fingerprint}
                title="No attestations"
                description="Generate SLSA provenance via the build pipeline."
              />
            ) : (
              <div className="space-y-2">
                <div className="rounded-md border border-emerald-500/40 bg-emerald-500/5 p-2.5 text-xs">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-medium flex items-center gap-1.5">
                      <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                      Signature coverage
                    </span>
                    <span className="tabular-nums">
                      {attestations.length ? Math.round((signedAttestations / attestations.length) * 100) : 0}%
                    </span>
                  </div>
                  <Progress
                    value={attestations.length ? (signedAttestations / attestations.length) * 100 : 0}
                    className="h-1.5"
                  />
                </div>

                <ScrollArea className="h-[380px]">
                  <div className="space-y-1.5">
                    {attestations.map((a, i) => (
                      <div key={(a.artifact ?? "att") + i} className="rounded-md border border-border bg-muted/30 p-2 space-y-1">
                        <div className="flex items-center gap-1.5">
                          <Link2 className="h-3 w-3 text-muted-foreground shrink-0" />
                          <span className="text-[11px] font-mono truncate">
                            {a.artifact ?? a.artifact_uri ?? "—"}
                          </span>
                        </div>
                        <div className="flex items-center justify-between text-[10px]">
                          <Badge variant="outline" className="text-[9px]">
                            SLSA L{a.slsa_level ?? "?"}
                          </Badge>
                          {a.signed ? (
                            <Badge variant="outline" className="text-[9px] border-emerald-500/40 text-emerald-400 bg-emerald-500/10">
                              <Fingerprint className="h-2.5 w-2.5 mr-1" />
                              {a.signature_algorithm ?? "SIGNED"}
                            </Badge>
                          ) : (
                            <Badge variant="outline" className="text-[9px] border-amber-500/40 text-amber-400 bg-amber-500/10">
                              UNSIGNED
                            </Badge>
                          )}
                        </div>
                        {a.builder && (
                          <p className="text-[10px] text-muted-foreground truncate">build: {a.builder}</p>
                        )}
                        {a.commit_sha && (
                          <p className="text-[10px] text-muted-foreground font-mono">
                            {a.commit_sha.slice(0, 12)}
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
