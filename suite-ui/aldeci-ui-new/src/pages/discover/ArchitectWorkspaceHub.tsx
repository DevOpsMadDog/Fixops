// ArchitectWorkspaceHub — P29 Software Architect persona
// 4 tabs: threat-models | code-to-runtime | api-deps | arch-graph
// All data from real API endpoints — zero mocks.

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Network,
  Layers,
  Code2,
  GitBranch,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Activity,
  Server,
  Globe,
  Shield,
  Box,
} from "lucide-react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { threatModelingApi, networkTopologyApi } from "@/lib/api";
import { toArray } from "@/lib/api-utils";

// ── types ──────────────────────────────────────────────────────────────────

type TabKey = "threat-models" | "code-to-runtime" | "api-deps" | "arch-graph";

interface ThreatModel {
  id: string;
  name: string;
  status?: string;
  created_at?: string;
  components?: unknown[];
  threats?: unknown[];
}

interface StrideCategory {
  id: string;
  name: string;
  description?: string;
  examples?: string[];
}

interface RuntimeEvent {
  event_id?: string;
  id?: string;
  service?: string;
  type?: string;
  matched?: boolean;
  timestamp?: string;
  severity?: string;
}

interface RuntimeStats {
  total_events?: number;
  matched_events?: number;
  unmatched_events?: number;
  services?: number;
}

interface TopoNode {
  node_id?: string;
  id?: string;
  label?: string;
  type?: string;
  segment?: string;
  exposed?: boolean;
}

interface TopoStats {
  total_nodes?: number;
  total_edges?: number;
  segments?: number;
  exposed_nodes?: number;
}

interface ExposureResult {
  exposed_paths?: unknown[];
  critical_nodes?: string[];
  risk_level?: string;
}

// ── shared helpers ─────────────────────────────────────────────────────────

function TabSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-12 w-full rounded-lg" />
      ))}
    </div>
  );
}

function SeverityBadge({ value }: { value?: string }) {
  const v = (value ?? "").toLowerCase();
  const cls =
    v === "critical"
      ? "bg-red-500/20 text-red-400 border-red-500/30"
      : v === "high"
      ? "bg-orange-500/20 text-orange-400 border-orange-500/30"
      : v === "medium"
      ? "bg-amber-500/20 text-amber-400 border-amber-500/30"
      : "bg-slate-500/20 text-slate-400 border-slate-500/30";
  return (
    <Badge variant="outline" className={cls}>
      {value ?? "unknown"}
    </Badge>
  );
}

// ── tab: threat-models ─────────────────────────────────────────────────────

function ThreatModelsTab() {
  const {
    data: modelsRaw,
    isLoading: loadingModels,
    isError: errModels,
    refetch: refetchModels,
  } = useQuery({
    queryKey: ["threat-modeling", "models"],
    queryFn: () => threatModelingApi.listModels(),
    retry: 1,
  });

  const {
    data: strideRaw,
    isLoading: loadingStride,
  } = useQuery({
    queryKey: ["threat-modeling", "stride-categories"],
    queryFn: () => threatModelingApi.getStrideCategories(),
    retry: 1,
  });

  const models = toArray<ThreatModel>(modelsRaw);
  const strideMap = (strideRaw as Record<string, StrideCategory[]> | null)?.categories ?? [];
  const strideCategories = toArray<StrideCategory>(strideMap);

  if (errModels) return <ErrorState message="Failed to load threat models" onRetry={refetchModels} />;

  const loading = loadingModels || loadingStride;

  return (
    <div className="space-y-6">
      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard
          title="Total Models"
          value={loading ? "—" : String(models.length)}
          icon={<Layers className="w-4 h-4" />}
          trend={undefined}
        />
        <KpiCard
          title="STRIDE Categories"
          value={loading ? "—" : String(strideCategories.length)}
          icon={<Shield className="w-4 h-4" />}
          trend={undefined}
        />
        <KpiCard
          title="Analyzed"
          value={loading ? "—" : String(models.filter((m) => m.status === "analyzed").length)}
          icon={<CheckCircle2 className="w-4 h-4" />}
          trend={undefined}
        />
        <KpiCard
          title="Pending"
          value={loading ? "—" : String(models.filter((m) => m.status !== "analyzed").length)}
          icon={<AlertTriangle className="w-4 h-4" />}
          trend={undefined}
        />
      </div>

      {/* Models table */}
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-sm font-medium text-slate-300">Threat Models</CardTitle>
          <CardDescription className="text-slate-500">
            STRIDE-based models from /api/v1/threat-modeling/models
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <TabSkeleton rows={5} />
          ) : models.length === 0 ? (
            <EmptyState
              title="No threat models"
              description="Create a threat model to start STRIDE analysis."
              icon={<Layers className="w-8 h-8 text-slate-500" />}
            />
          ) : (
            <ScrollArea className="h-64">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-slate-500 border-b border-slate-700">
                    <th className="pb-2 pr-4 font-medium">Name</th>
                    <th className="pb-2 pr-4 font-medium">Status</th>
                    <th className="pb-2 pr-4 font-medium">Components</th>
                    <th className="pb-2 font-medium">Threats</th>
                  </tr>
                </thead>
                <tbody>
                  {models.map((m) => (
                    <tr key={m.id} className="border-b border-slate-700/50 hover:bg-slate-700/30">
                      <td className="py-2 pr-4 text-slate-200 font-mono text-xs">{m.name}</td>
                      <td className="py-2 pr-4">
                        <Badge
                          variant="outline"
                          className={
                            m.status === "analyzed"
                              ? "bg-green-500/20 text-green-400 border-green-500/30"
                              : "bg-amber-500/20 text-amber-400 border-amber-500/30"
                          }
                        >
                          {m.status ?? "draft"}
                        </Badge>
                      </td>
                      <td className="py-2 pr-4 text-slate-400">
                        {toArray(m.components).length}
                      </td>
                      <td className="py-2 text-slate-400">{toArray(m.threats).length}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </ScrollArea>
          )}
        </CardContent>
      </Card>

      {/* STRIDE categories */}
      {!loading && strideCategories.length > 0 && (
        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader>
            <CardTitle className="text-sm font-medium text-slate-300">STRIDE Categories</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              {strideCategories.map((cat) => (
                <div
                  key={cat.id ?? cat.name}
                  className="p-3 rounded-lg bg-slate-700/40 border border-slate-600/50"
                >
                  <p className="text-xs font-semibold text-indigo-400">{cat.name}</p>
                  {cat.description && (
                    <p className="text-xs text-slate-500 mt-1 line-clamp-2">{cat.description}</p>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ── tab: code-to-runtime ───────────────────────────────────────────────────

function CodeToRuntimeTab() {
  const {
    data: statsRaw,
    isLoading: loadingStats,
    isError: errStats,
    refetch,
  } = useQuery<RuntimeStats>({
    queryKey: ["code-to-runtime", "stats"],
    queryFn: () =>
      fetch("/api/v1/code-to-runtime/stats")
        .then((r) => (r.ok ? r.json() : Promise.reject(r)))
        .catch(() => null),
    retry: 1,
  });

  const {
    data: eventsRaw,
    isLoading: loadingEvents,
  } = useQuery({
    queryKey: ["code-to-runtime", "events"],
    queryFn: () =>
      fetch("/api/v1/code-to-runtime/events?limit=50")
        .then((r) => (r.ok ? r.json() : Promise.reject(r)))
        .catch(() => null),
    retry: 1,
  });

  const stats: RuntimeStats = statsRaw ?? {};
  const events = toArray<RuntimeEvent>(eventsRaw);
  const loading = loadingStats || loadingEvents;

  if (errStats && !loadingStats) return <ErrorState message="Failed to load code-to-runtime data" onRetry={refetch} />;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard
          title="Total Events"
          value={loading ? "—" : String(stats.total_events ?? events.length)}
          icon={<Activity className="w-4 h-4" />}
          trend={undefined}
        />
        <KpiCard
          title="Matched"
          value={loading ? "—" : String(stats.matched_events ?? events.filter((e) => e.matched).length)}
          icon={<CheckCircle2 className="w-4 h-4" />}
          trend={undefined}
        />
        <KpiCard
          title="Unmatched"
          value={loading ? "—" : String(stats.unmatched_events ?? events.filter((e) => !e.matched).length)}
          icon={<AlertTriangle className="w-4 h-4" />}
          trend={undefined}
        />
        <KpiCard
          title="Services"
          value={loading ? "—" : String(stats.services ?? new Set(events.map((e) => e.service)).size)}
          icon={<Server className="w-4 h-4" />}
          trend={undefined}
        />
      </div>

      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-sm font-medium text-slate-300">Runtime Events</CardTitle>
          <CardDescription className="text-slate-500">
            Code-to-runtime mappings from /api/v1/code-to-runtime/events
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <TabSkeleton rows={5} />
          ) : events.length === 0 ? (
            <EmptyState
              title="No runtime events"
              description="Ingest runtime events to see code-to-runtime mappings."
              icon={<Code2 className="w-8 h-8 text-slate-500" />}
            />
          ) : (
            <ScrollArea className="h-72">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-slate-500 border-b border-slate-700">
                    <th className="pb-2 pr-4 font-medium">Service</th>
                    <th className="pb-2 pr-4 font-medium">Type</th>
                    <th className="pb-2 pr-4 font-medium">Severity</th>
                    <th className="pb-2 font-medium">Matched</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e, i) => (
                    <tr key={e.event_id ?? e.id ?? i} className="border-b border-slate-700/50 hover:bg-slate-700/30">
                      <td className="py-2 pr-4 text-slate-200 font-mono text-xs">{e.service ?? "—"}</td>
                      <td className="py-2 pr-4 text-slate-400 text-xs">{e.type ?? "—"}</td>
                      <td className="py-2 pr-4"><SeverityBadge value={e.severity} /></td>
                      <td className="py-2">
                        {e.matched ? (
                          <CheckCircle2 className="w-4 h-4 text-green-400" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-amber-400" />
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </ScrollArea>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ── tab: api-deps ──────────────────────────────────────────────────────────

function ApiDepsTab() {
  const {
    data: statsRaw,
    isLoading: loadingStats,
    refetch,
  } = useQuery<TopoStats>({
    queryKey: ["network-topology", "stats"],
    queryFn: () => networkTopologyApi.stats(),
    retry: 1,
  });

  const {
    data: nodesRaw,
    isLoading: loadingNodes,
    isError: errNodes,
  } = useQuery({
    queryKey: ["network-topology", "nodes"],
    queryFn: () => networkTopologyApi.listNodes(),
    retry: 1,
  });

  const {
    data: exposureRaw,
    isLoading: loadingExposure,
  } = useQuery<ExposureResult>({
    queryKey: ["network-topology", "exposure"],
    queryFn: () => networkTopologyApi.detectExposure(),
    retry: 1,
  });

  const stats: TopoStats = statsRaw ?? {};
  const nodes = toArray<TopoNode>(nodesRaw);
  const exposure: ExposureResult = exposureRaw ?? {};
  const loading = loadingStats || loadingNodes || loadingExposure;

  if (errNodes && !loadingNodes) return <ErrorState message="Failed to load API dependency data" onRetry={refetch} />;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard
          title="Nodes"
          value={loading ? "—" : String(stats.total_nodes ?? nodes.length)}
          icon={<Box className="w-4 h-4" />}
          trend={undefined}
        />
        <KpiCard
          title="Edges"
          value={loading ? "—" : String(stats.total_edges ?? "—")}
          icon={<GitBranch className="w-4 h-4" />}
          trend={undefined}
        />
        <KpiCard
          title="Segments"
          value={loading ? "—" : String(stats.segments ?? "—")}
          icon={<Network className="w-4 h-4" />}
          trend={undefined}
        />
        <KpiCard
          title="Exposed"
          value={loading ? "—" : String(stats.exposed_nodes ?? toArray(exposure.critical_nodes).length)}
          icon={<Globe className="w-4 h-4" />}
          trend={undefined}
        />
      </div>

      {/* Exposure risk */}
      {!loadingExposure && exposure.risk_level && (
        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader>
            <CardTitle className="text-sm font-medium text-slate-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              Exposure Risk
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-3">
              <SeverityBadge value={exposure.risk_level} />
              <span className="text-slate-400 text-sm">
                {toArray(exposure.critical_nodes).length} critical node(s) externally reachable
              </span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Nodes table */}
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-sm font-medium text-slate-300">Network Nodes</CardTitle>
          <CardDescription className="text-slate-500">
            API dependency map from /api/v1/network-topology/nodes
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <TabSkeleton rows={5} />
          ) : nodes.length === 0 ? (
            <EmptyState
              title="No nodes discovered"
              description="Connect network topology sources to populate the dependency map."
              icon={<Network className="w-8 h-8 text-slate-500" />}
            />
          ) : (
            <ScrollArea className="h-64">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-slate-500 border-b border-slate-700">
                    <th className="pb-2 pr-4 font-medium">Node</th>
                    <th className="pb-2 pr-4 font-medium">Type</th>
                    <th className="pb-2 pr-4 font-medium">Segment</th>
                    <th className="pb-2 font-medium">Exposed</th>
                  </tr>
                </thead>
                <tbody>
                  {nodes.map((n, i) => (
                    <tr key={n.node_id ?? n.id ?? i} className="border-b border-slate-700/50 hover:bg-slate-700/30">
                      <td className="py-2 pr-4 text-slate-200 font-mono text-xs">{n.label ?? n.node_id ?? n.id ?? "—"}</td>
                      <td className="py-2 pr-4 text-slate-400 text-xs">{n.type ?? "—"}</td>
                      <td className="py-2 pr-4 text-slate-400 text-xs">{n.segment ?? "—"}</td>
                      <td className="py-2">
                        {n.exposed ? (
                          <Badge variant="outline" className="bg-red-500/20 text-red-400 border-red-500/30 text-xs">
                            Yes
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="bg-green-500/20 text-green-400 border-green-500/30 text-xs">
                            No
                          </Badge>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </ScrollArea>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ── tab: arch-graph ────────────────────────────────────────────────────────

interface KgNode {
  id?: string;
  label?: string;
  type?: string;
  community?: string | number;
  degree?: number;
}

interface KgStats {
  total_nodes?: number;
  total_edges?: number;
  communities?: number;
}

function ArchGraphTab() {
  const {
    data: kgRaw,
    isLoading,
    isError,
    refetch,
  } = useQuery({
    queryKey: ["knowledge-graph"],
    queryFn: () =>
      fetch("/api/v1/knowledge-graph/")
        .then((r) => (r.ok ? r.json() : Promise.reject(r)))
        .catch(() => null),
    retry: 1,
  });

  // Normalise: backend may return {nodes,edges,stats} or an array directly
  const nodes: KgNode[] = kgRaw
    ? toArray<KgNode>(
        Array.isArray(kgRaw) ? kgRaw : (kgRaw as Record<string, unknown>).nodes
      )
    : [];

  const stats: KgStats = kgRaw && !Array.isArray(kgRaw)
    ? ((kgRaw as Record<string, unknown>).stats as KgStats) ?? {}
    : {};

  if (isError) return <ErrorState message="Failed to load architecture graph" onRetry={refetch} />;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
        <KpiCard
          title="Graph Nodes"
          value={isLoading ? "—" : String(stats.total_nodes ?? nodes.length)}
          icon={<Box className="w-4 h-4" />}
          trend={undefined}
        />
        <KpiCard
          title="Graph Edges"
          value={isLoading ? "—" : String(stats.total_edges ?? "—")}
          icon={<GitBranch className="w-4 h-4" />}
          trend={undefined}
        />
        <KpiCard
          title="Communities"
          value={isLoading ? "—" : String(stats.communities ?? "—")}
          icon={<Network className="w-4 h-4" />}
          trend={undefined}
        />
      </div>

      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-sm font-medium text-slate-300">Architecture Nodes</CardTitle>
          <CardDescription className="text-slate-500">
            Top 100 nodes from /api/v1/knowledge-graph/ — force-directed visualization coming in Sprint 3
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <TabSkeleton rows={5} />
          ) : nodes.length === 0 ? (
            <EmptyState
              title="Graph not populated"
              description="Run Brain Pipeline ingestion to build the architecture knowledge graph."
              icon={<Network className="w-8 h-8 text-slate-500" />}
            />
          ) : (
            <ScrollArea className="h-80">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-slate-500 border-b border-slate-700">
                    <th className="pb-2 pr-4 font-medium">Label</th>
                    <th className="pb-2 pr-4 font-medium">Type</th>
                    <th className="pb-2 pr-4 font-medium">Community</th>
                    <th className="pb-2 font-medium">Degree</th>
                  </tr>
                </thead>
                <tbody>
                  {nodes.slice(0, 100).map((n, i) => (
                    <tr key={n.id ?? i} className="border-b border-slate-700/50 hover:bg-slate-700/30">
                      <td className="py-2 pr-4 text-slate-200 font-mono text-xs truncate max-w-[180px]">
                        {n.label ?? n.id ?? "—"}
                      </td>
                      <td className="py-2 pr-4 text-slate-400 text-xs">{n.type ?? "—"}</td>
                      <td className="py-2 pr-4 text-slate-400 text-xs">{n.community ?? "—"}</td>
                      <td className="py-2 text-slate-400 text-xs">{n.degree ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </ScrollArea>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ── main hub ───────────────────────────────────────────────────────────────

const TABS: { key: TabKey; label: string; icon: typeof Network }[] = [
  { key: "threat-models", label: "Threat Models", icon: Layers },
  { key: "code-to-runtime", label: "Code to Runtime", icon: Code2 },
  { key: "api-deps", label: "API Dependencies", icon: Network },
  { key: "arch-graph", label: "Architecture Graph", icon: GitBranch },
];

export default function ArchitectWorkspaceHub() {
  const [activeTab, setActiveTab] = useState<TabKey>("threat-models");

  return (
    <div className="flex flex-col h-full bg-slate-900 text-slate-100 overflow-hidden">
      <PageHeader
        title="Architect Workspace"
        description="Threat models, code-to-runtime mappings, API dependency graph, and architecture knowledge graph for P29 Software Architect"
        icon={<Network className="w-5 h-5 text-indigo-400" />}
        actions={
          <Button
            variant="outline"
            size="sm"
            className="border-slate-700 text-slate-300 hover:bg-slate-700"
            onClick={() => window.location.reload()}
          >
            <RefreshCw className="w-3.5 h-3.5 mr-1.5" />
            Refresh
          </Button>
        }
      />

      <div className="flex-1 overflow-y-auto p-6">
        <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as TabKey)}>
          <TabsList className="bg-slate-800 border border-slate-700 mb-6">
            {TABS.map(({ key, label, icon: Icon }) => (
              <TabsTrigger
                key={key}
                value={key}
                className="data-[state=active]:bg-indigo-600 data-[state=active]:text-white text-slate-400 gap-1.5"
              >
                <Icon className="w-3.5 h-3.5" />
                {label}
              </TabsTrigger>
            ))}
          </TabsList>

          <TabsContent value="threat-models">
            <ThreatModelsTab />
          </TabsContent>
          <TabsContent value="code-to-runtime">
            <CodeToRuntimeTab />
          </TabsContent>
          <TabsContent value="api-deps">
            <ApiDepsTab />
          </TabsContent>
          <TabsContent value="arch-graph">
            <ArchGraphTab />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
