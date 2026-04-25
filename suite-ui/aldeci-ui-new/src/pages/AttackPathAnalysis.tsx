/**
 * Attack Path Analysis Dashboard
 *
 * Lateral movement path discovery with node graph visualization.
 * Entry points, attack paths, and crown jewels at risk.
 * Route: /attack-paths
 *
 * API: GET /api/v1/attack-paths/stats  GET /api/v1/attack-paths/crown-jewels-at-risk
 * Falls back to mock data on failure.
 */

import { useState, useEffect, useMemo } from "react";
import { motion } from "framer-motion";
import {
  AlertTriangle,
  Network,
  Target,
  Shield,
  TrendingUp,
  Zap,
  RefreshCw,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "juice-shop-corp";

async function apiFetch(path: string) {
  const res = await fetch(`${API}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

interface GraphNode {
  id: string;
  name: string;
  type: "entry_point" | "compromised" | "normal" | "crown_jewel";
  risk_score: number;
}

interface GraphEdge {
  from: string;
  to: string;
}

interface AttackPath {
  id: string;
  length: number;
  start_node: string;
  end_node: string;
  cves_required: string[];
  blast_radius: number;
}

interface CrownJewel {
  asset: string;
  exposure_paths: number;
  highest_risk_cve: string;
  risk_level: "critical" | "high" | "medium" | "low";
}

interface AttackPathsStats {
  total_paths: number;
  critical_paths: number;
  avg_path_length: number;
  nodes_at_risk: number;
  graph: {
    nodes: GraphNode[];
    edges: GraphEdge[];
  };
  paths: AttackPath[];
}

// ═══════════════════════════════════════════════════════════
// Mock data
// ═══════════════════════════════════════════════════════════

const MOCK_GRAPH_NODES: GraphNode[] = [
  { id: "entry-1", name: "Web Server (exposed)", type: "entry_point", risk_score: 92 },
  { id: "app-1", name: "App Server", type: "compromised", risk_score: 78 },
  { id: "db-1", name: "Database", type: "crown_jewel", risk_score: 95 },
  { id: "cache-1", name: "Cache Layer", type: "normal", risk_score: 35 },
  { id: "admin-1", name: "Admin Panel", type: "compromised", risk_score: 88 },
  { id: "backup-1", name: "Backup Server", type: "crown_jewel", risk_score: 85 },
];

const MOCK_GRAPH_EDGES: GraphEdge[] = [
  { from: "entry-1", to: "app-1" },
  { from: "app-1", to: "db-1" },
  { from: "app-1", to: "cache-1" },
  { from: "admin-1", to: "db-1" },
  { from: "cache-1", to: "backup-1" },
];

const MOCK_PATHS: AttackPath[] = [
  {
    id: "path-1",
    length: 3,
    start_node: "entry-1",
    end_node: "db-1",
    cves_required: ["CVE-2024-1234", "CVE-2024-5678"],
    blast_radius: 8,
  },
  {
    id: "path-2",
    length: 2,
    start_node: "entry-1",
    end_node: "admin-1",
    cves_required: ["CVE-2024-9999"],
    blast_radius: 5,
  },
];

const MOCK_CROWN_JEWELS: CrownJewel[] = [
  {
    asset: "Production Database",
    exposure_paths: 3,
    highest_risk_cve: "CVE-2024-1234",
    risk_level: "critical",
  },
  {
    asset: "Backup Server",
    exposure_paths: 2,
    highest_risk_cve: "CVE-2024-5678",
    risk_level: "high",
  },
  {
    asset: "API Key Store",
    exposure_paths: 1,
    highest_risk_cve: "CVE-2024-3456",
    risk_level: "critical",
  },
];

// ═══════════════════════════════════════════════════════════
// Node Visualization Component
// ═══════════════════════════════════════════════════════════

function NodeGraph({ nodes, edges }: { nodes: GraphNode[]; edges: GraphEdge[] }) {
  // Calculate positions in a circle layout
  const width = 500;
  const height = 400;
  const radius = 120;
  const centerX = width / 2;
  const centerY = height / 2;

  const positions: Record<string, { x: number; y: number }> = {};
  nodes.forEach((node, idx) => {
    const angle = (idx / nodes.length) * Math.PI * 2;
    positions[node.id] = {
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle),
    };
  });

  const getNodeColor = (node: GraphNode) => {
    switch (node.type) {
      case "entry_point":
        return "#ef4444"; // red
      case "crown_jewel":
        return "#eab308"; // yellow
      case "compromised":
        return "#f97316"; // orange
      default:
        return "#6b7280"; // gray
    }
  };

  const getNodeLabel = (type: GraphNode["type"]) => {
    switch (type) {
      case "entry_point":
        return "Entry";
      case "crown_jewel":
        return "Jewel";
      case "compromised":
        return "Comp";
      default:
        return "Normal";
    }
  };

  return (
    <svg width="100%" height="100%" viewBox={`0 0 ${width} ${height}`} className="max-w-full">
      {/* Edges */}
      {edges.map((edge, idx) => {
        const from = positions[edge.from];
        const to = positions[edge.to];
        if (!from || !to) return null;
        return (
          <line
            key={idx}
            x1={from.x}
            y1={from.y}
            x2={to.x}
            y2={to.y}
            stroke="oklch(0.35 0.01 250)"
            strokeWidth="1.5"
            markerEnd="url(#arrowhead)"
          />
        );
      })}

      {/* Arrow marker */}
      <defs>
        <marker
          id="arrowhead"
          markerWidth="10"
          markerHeight="10"
          refX="9"
          refY="3"
          orient="auto"
        >
          <polygon points="0 0, 10 3, 0 6" fill="oklch(0.35 0.01 250)" />
        </marker>
      </defs>

      {/* Nodes */}
      {nodes.map((node) => {
        const pos = positions[node.id];
        if (!pos) return null;
        const color = getNodeColor(node);
        return (
          <g key={node.id}>
            {/* Circle */}
            <circle
              cx={pos.x}
              cy={pos.y}
              r="24"
              fill={color}
              opacity="0.9"
              className="transition-all duration-200 hover:opacity-100"
            />
            {/* Label text */}
            <text
              x={pos.x}
              y={pos.y + 4}
              textAnchor="middle"
              fontSize="10"
              fontWeight="bold"
              fill="white"
              className="pointer-events-none"
            >
              {getNodeLabel(node.type)}
            </text>
            {/* Risk score below node */}
            <text
              x={pos.x}
              y={pos.y + 40}
              textAnchor="middle"
              fontSize="9"
              fill="oklch(0.60 0.01 250)"
              className="pointer-events-none"
            >
              {node.risk_score}%
            </text>
          </g>
        );
      })}
    </svg>
  );
}

// ═══════════════════════════════════════════════════════════
// Entry Point Card
// ═══════════════════════════════════════════════════════════

function EntryPointCard({ node, index }: { node: GraphNode; index: number }) {
  const getRiskColor = (score: number) => {
    if (score >= 80) return "bg-red-500/20 text-red-400 border-red-400/30";
    if (score >= 60) return "bg-orange-500/20 text-orange-400 border-orange-400/30";
    if (score >= 40) return "bg-yellow-500/20 text-yellow-400 border-yellow-400/30";
    return "bg-blue-500/20 text-blue-400 border-blue-400/30";
  };

  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.05, duration: 0.3 }}
    >
      <Card className="hover:border-primary/30 transition-colors duration-200">
        <CardContent className="p-3 space-y-2">
          <div className="flex items-start justify-between gap-2">
            <span className="text-xs font-medium truncate flex-1">{node.name}</span>
            <Badge className={cn("text-xs flex-shrink-0", getRiskColor(node.risk_score))}>
              {node.risk_score}%
            </Badge>
          </div>
          <p className="text-[11px] text-muted-foreground">
            {node.type === "entry_point" && "Exposed entry point"}
            {node.type === "compromised" && "Likely compromised"}
            {node.type === "crown_jewel" && "Critical asset"}
            {node.type === "normal" && "Standard asset"}
          </p>
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ═══════════════════════════════════════════════════════════
// Attack Path Row
// ═══════════════════════════════════════════════════════════

function AttackPathRow({
  path,
  nodeMap,
  index,
}: {
  path: AttackPath;
  nodeMap: Record<string, GraphNode>;
  index: number;
}) {
  const startNode = nodeMap[path.start_node];
  const endNode = nodeMap[path.end_node];

  return (
    <motion.tr
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.03, duration: 0.25 }}
      className="border-b border-border/50 hover:bg-accent/30 transition-colors"
    >
      <td className="py-2.5 px-3 text-xs font-mono text-muted-foreground">{path.id}</td>
      <td className="py-2.5 px-3 text-xs">
        <span className="bg-blue-500/10 text-blue-400 px-2 py-0.5 rounded text-[10px]">
          {path.length} hops
        </span>
      </td>
      <td className="py-2.5 px-3 text-xs">
        {startNode?.name || "Unknown"} → {endNode?.name || "Unknown"}
      </td>
      <td className="py-2.5 px-3 text-xs text-muted-foreground">{path.cves_required.length} CVEs</td>
      <td className="py-2.5 px-3 text-xs text-right">
        <Badge variant="outline" className="text-[10px]">
          {path.blast_radius} assets
        </Badge>
      </td>
    </motion.tr>
  );
}

// ═══════════════════════════════════════════════════════════
// Crown Jewel Row
// ═══════════════════════════════════════════════════════════

function CrownJewelRow({ jewel, index }: { jewel: CrownJewel; index: number }) {
  const riskColor =
    jewel.risk_level === "critical"
      ? "bg-red-500/10 text-red-400"
      : jewel.risk_level === "high"
        ? "bg-orange-500/10 text-orange-400"
        : jewel.risk_level === "medium"
          ? "bg-yellow-500/10 text-yellow-400"
          : "bg-blue-500/10 text-blue-400";

  return (
    <motion.tr
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.03, duration: 0.25 }}
      className="border-b border-border/50 hover:bg-accent/30 transition-colors"
    >
      <td className="py-2.5 px-3 text-xs font-medium">{jewel.asset}</td>
      <td className="py-2.5 px-3 text-xs">
        <Badge variant="outline" className="text-[10px]">
          {jewel.exposure_paths} paths
        </Badge>
      </td>
      <td className="py-2.5 px-3 text-xs font-mono text-muted-foreground">
        {jewel.highest_risk_cve}
      </td>
      <td className="py-2.5 px-3 text-xs">
        <Badge
          className={cn(
            "text-[10px] uppercase tracking-wide border-0",
            riskColor,
          )}
        >
          {jewel.risk_level}
        </Badge>
      </td>
    </motion.tr>
  );
}

// ═══════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════

export default function AttackPathAnalysis() {
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  const loadData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/attack-paths/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/attack-paths/nodes?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/attack-paths/crown-jewels-at-risk?org_id=${ORG_ID}`),
    ]).then(([statsResult, nodesResult, crownResult]) => {
      const statsRaw    = statsResult.status    === "fulfilled" ? statsResult.value    : null;
      const nodesRaw    = nodesResult.status    === "fulfilled" ? nodesResult.value    : null;
      const crownRaw    = crownResult.status    === "fulfilled" ? crownResult.value    : null;
      if (statsRaw || nodesRaw || crownRaw) {
        setLiveData({ stats: statsRaw, nodes: nodesRaw, crown: crownRaw });
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { loadData(); }, []);

  // Build stats shape from live data or fall back to mock
  const stats: AttackPathsStats = liveData?.stats
    ? {
        total_paths:    liveData.stats.total_paths    ?? liveData.stats.path_count   ?? ([] as any).length,
        critical_paths: liveData.stats.critical_paths ?? liveData.stats.crown_jewels ?? ([] as any).length,
        avg_path_length: liveData.stats.avg_hops      ?? 2.5,
        nodes_at_risk:  liveData.stats.total_nodes    ?? ([] as any).length,
        graph: { nodes: liveData.nodes ?? ([] as any), edges: MOCK_GRAPH_EDGES },
        paths: MOCK_PATHS,
      }
    : {
        total_paths: MOCK_PATHS.length,
        critical_paths: MOCK_PATHS.length,
        avg_path_length: 2.5,
        nodes_at_risk: MOCK_GRAPH_NODES.length,
        graph: { nodes: MOCK_GRAPH_NODES, edges: MOCK_GRAPH_EDGES },
        paths: MOCK_PATHS,
      };

  const crownJewels: CrownJewel[] = liveData?.crown ?? ([] as any);

  const nodeMap = useMemo(() => {
    const map: Record<string, GraphNode> = {};
    stats?.graph.nodes.forEach((node) => {
      map[node.id] = node;
    });
    return map;
  }, [stats]);

  const entryPoints = useMemo(() => {
    return stats?.graph.nodes.filter((n) => n.type === "entry_point") || [];
  }, [stats]);

  const criticalPaths = useMemo(() => {
    return stats?.paths.filter((p) => p.blast_radius >= 5) || [];
  }, [stats]);

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      {/* Header */}
      <PageHeader
        title="Attack Path Analysis"
        description="Lateral movement path discovery across your infrastructure"
        badge="AI"
        actions={
          <Button
            size="sm"
            variant="outline"
            onClick={() => loadData()}
            disabled={dataLoading}
            className="gap-2"
          >
            <RefreshCw className={cn("w-3.5 h-3.5", dataLoading && "animate-spin")} />
            Refresh
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard
          title="Attack Paths"
          value={stats?.total_paths ?? 0}
          icon={Network}
          trend="up"
          trendLabel="Active"
        />
        <KpiCard
          title="Critical Paths"
          value={stats?.critical_paths ?? 0}
          icon={AlertTriangle}
          trend="up"
          trendLabel="High priority"
        />
        <KpiCard
          title="Nodes at Risk"
          value={stats?.nodes_at_risk ?? 0}
          icon={Target}
          trend="down"
          trendLabel="Require hardening"
        />
        <KpiCard
          title="Avg Path Length"
          value={`${stats?.avg_path_length.toFixed(1) ?? 0} hops`}
          icon={TrendingUp}
          trend="flat"
          trendLabel="Attack complexity"
        />
      </div>

      {/* Main grid: Graph + Entry Points + Paths + Crown Jewels */}
      <div className="grid grid-cols-1 xl:grid-cols-4 gap-6 min-h-0">
        {/* Left: Graph + Entry Points (2 columns) */}
        <div className="xl:col-span-2 space-y-6 min-h-0">
          {/* Graph Visualization */}
          <Card className="flex flex-col">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold">Node Graph</CardTitle>
            </CardHeader>
            <Separator />
            <CardContent className="pt-4 flex-1 flex items-center justify-center min-h-[320px]">
              {stats?.graph ? (
                <NodeGraph nodes={stats.graph.nodes} edges={stats.graph.edges} />
              ) : (
                <div className="text-center text-muted-foreground text-xs">
                  Loading graph visualization...
                </div>
              )}
            </CardContent>
          </Card>

          {/* Entry Points */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-sm font-semibold">
                <Zap className="w-4 h-4" />
                Entry Points
              </CardTitle>
            </CardHeader>
            <Separator />
            <ScrollArea className="h-[180px]">
              <div className="p-3 space-y-2">
                {entryPoints.length > 0 ? (
                  entryPoints.map((node, i) => (
                    <EntryPointCard key={node.id} node={node} index={i} />
                  ))
                ) : (
                  <div className="text-xs text-muted-foreground text-center py-8">
                    No entry points detected
                  </div>
                )}
              </div>
            </ScrollArea>
          </Card>
        </div>

        {/* Right: Paths + Crown Jewels (2 columns) */}
        <div className="xl:col-span-2 space-y-6 min-h-0">
          {/* Attack Paths */}
          <Card className="flex flex-col min-h-0">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold">Attack Paths Found</CardTitle>
            </CardHeader>
            <Separator />
            <div className="flex-1 overflow-hidden">
              <ScrollArea className="h-[220px]">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border text-xs text-muted-foreground sticky top-0 bg-background">
                      <th className="py-2 px-3 text-left font-medium text-xs">ID</th>
                      <th className="py-2 px-3 text-left font-medium text-xs">Hops</th>
                      <th className="py-2 px-3 text-left font-medium text-xs">Path</th>
                      <th className="py-2 px-3 text-left font-medium text-xs">CVEs</th>
                      <th className="py-2 px-3 text-left font-medium text-xs">Radius</th>
                    </tr>
                  </thead>
                  <tbody>
                    {criticalPaths.length > 0 ? (
                      criticalPaths.map((path, i) => (
                        <AttackPathRow
                          key={path.id}
                          path={path}
                          nodeMap={nodeMap}
                          index={i}
                        />
                      ))
                    ) : (
                      <tr>
                        <td colSpan={5} className="py-8 text-center text-xs text-muted-foreground">
                          No attack paths found
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </ScrollArea>
            </div>
          </Card>

          {/* Crown Jewels at Risk */}
          <Card className="flex flex-col min-h-0">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-sm font-semibold">
                <Shield className="w-4 h-4" />
                Crown Jewels at Risk
              </CardTitle>
            </CardHeader>
            <Separator />
            <div className="flex-1 overflow-hidden">
              <ScrollArea className="h-[220px]">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border text-xs text-muted-foreground sticky top-0 bg-background">
                      <th className="py-2 px-3 text-left font-medium text-xs">Asset</th>
                      <th className="py-2 px-3 text-left font-medium text-xs">Paths</th>
                      <th className="py-2 px-3 text-left font-medium text-xs">Top CVE</th>
                      <th className="py-2 px-3 text-left font-medium text-xs">Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {crownJewels && crownJewels.length > 0 ? (
                      crownJewels.map((jewel, i) => (
                        <CrownJewelRow key={jewel.asset} jewel={jewel} index={i} />
                      ))
                    ) : (
                      <tr>
                        <td colSpan={4} className="py-8 text-center text-xs text-muted-foreground">
                          No crown jewels identified
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </ScrollArea>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
