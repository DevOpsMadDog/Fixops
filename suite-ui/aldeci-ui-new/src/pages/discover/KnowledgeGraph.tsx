import { useState, useCallback, useMemo } from "react";
import { motion } from "framer-motion";
import {
  Network, Search, RefreshCw, Send, Clock, Filter,
  Boxes, GitFork, Bug, Package, Cpu, Shield,
  ChevronRight, Zap, Eye,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { ErrorState } from "@/components/shared/ErrorState";
import { useKnowledgeGraph } from "@/hooks/use-api";
import { useMutation } from "@tanstack/react-query";
import { knowledgeGraphApi } from "@/lib/api";
import { cn } from "@/lib/utils";

interface GraphStats {
  node_count?: number;
  edge_count?: number;
  component_count?: number;
  attack_path_count?: number;
  nodes?: number;
  edges?: number;
  components?: number;
  attack_paths?: number;
}

interface QueryResult {
  id?: string;
  type?: string;
  label?: string;
  severity?: string;
  properties?: Record<string, unknown>;
}

interface RecentQuery {
  query: string;
  timestamp: Date;
  resultCount: number;
}

const NODE_TYPES = [
  { key: "app", label: "Application", icon: Boxes, color: "text-blue-400" },
  { key: "component", label: "Component", icon: Cpu, color: "text-purple-400" },
  { key: "finding", label: "Finding", icon: Bug, color: "text-red-400" },
  { key: "cve", label: "CVE", icon: Shield, color: "text-orange-400" },
  { key: "package", label: "Package", icon: Package, color: "text-green-400" },
];

const SUGGESTED_QUERIES = [
  "Show all critical findings with known attack paths",
  "Find packages with CVE dependencies",
  "List applications with exposed secrets",
  "Show components connected to internet-facing services",
  "Identify lateral movement paths from compromised component",
];

export default function KnowledgeGraph() {
  const [queryInput, setQueryInput] = useState("");
  const [activeNodeTypes, setActiveNodeTypes] = useState<Set<string>>(
    new Set(NODE_TYPES.map((n) => n.key))
  );
  const [recentQueries, setRecentQueries] = useState<RecentQuery[]>([]);
  const [queryResults, setQueryResults] = useState<QueryResult[] | null>(null);
  const [lastQuery, setLastQuery] = useState<string>("");

  const graphParams = useMemo(() => {
    const nodeTypes = Array.from(activeNodeTypes).join(",");
    return nodeTypes ? { node_types: nodeTypes } : undefined;
  }, [activeNodeTypes]);

  const graphQuery = useKnowledgeGraph(graphParams);
  const refetch = useCallback(() => graphQuery.refetch(), [graphQuery]);

  const graphData = useMemo(() => {
    const d = graphQuery.data;
    if (!d) return null;
    return d;
  }, [graphQuery.data]);

  const stats: GraphStats = useMemo(() => {
    if (!graphData) return {};
    const s = graphData.stats ?? {};
    return {
      node_count: s.total_nodes ?? graphData.node_count ?? (Array.isArray(graphData.nodes) ? graphData.nodes.length : graphData.nodes) ?? 0,
      edge_count: s.total_edges ?? graphData.edge_count ?? (Array.isArray(graphData.edges) ? graphData.edges.length : graphData.edges) ?? 0,
      component_count: s.components ?? graphData.component_count ?? graphData.components ?? 0,
      attack_path_count: s.attack_paths ?? graphData.attack_path_count ?? graphData.attack_paths ?? 0,
    };
  }, [graphData]);

  const nlQueryMutation = useMutation({
    mutationFn: async (query: string) => {
      const { data } = await knowledgeGraphApi.nlQuery({ query });
      return data;
    },
    onSuccess: (data, query) => {
      const results = data?.results || data?.nodes || (Array.isArray(data) ? data : []);
      setQueryResults(results);
      setLastQuery(query);
      setRecentQueries((prev) => [
        { query, timestamp: new Date(), resultCount: results.length },
        ...prev.slice(0, 9),
      ]);
    },
  });

  function handleQuery() {
    if (!queryInput.trim()) return;
    nlQueryMutation.mutate(queryInput.trim());
    setQueryInput("");
  }

  function handleSuggestedQuery(q: string) {
    setQueryInput(q);
    nlQueryMutation.mutate(q);
  }

  function toggleNodeType(key: string) {
    setActiveNodeTypes((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  if (graphQuery.isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-10 w-64" />
        <div className="grid grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
        <Skeleton className="h-[500px]" />
      </div>
    );
  }

  if (graphQuery.isError) {
    return <ErrorState message="Failed to load knowledge graph data." onRetry={refetch} />;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader title="Knowledge Graph" description="Security relationship graph with natural language query">
        <Button variant="outline" size="sm" onClick={refetch} className="gap-2">
          <RefreshCw className="h-4 w-4" /> Refresh
        </Button>
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Nodes" value={stats.node_count || 0} icon={Boxes} />
        <KpiCard title="Edges" value={stats.edge_count || 0} icon={GitFork} />
        <KpiCard title="Components" value={stats.component_count || 0} icon={Network} />
        <KpiCard title="Attack Paths" value={stats.attack_path_count || 0} icon={Zap} className="border-red-500/20" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Left sidebar: Node filters + Recent queries */}
        <div className="space-y-4">
          {/* Node Type Filters */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Filter className="h-4 w-4" /> Node Types
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {NODE_TYPES.map((nodeType) => {
                const Icon = nodeType.icon;
                const isActive = activeNodeTypes.has(nodeType.key);
                return (
                  <div key={nodeType.key} className="flex items-center gap-2.5">
                    <Checkbox
                      id={nodeType.key}
                      checked={isActive}
                      onCheckedChange={() => toggleNodeType(nodeType.key)}
                    />
                    <Label htmlFor={nodeType.key} className="flex items-center gap-2 cursor-pointer">
                      <Icon className={cn("h-3.5 w-3.5", isActive ? nodeType.color : "text-muted-foreground")} />
                      <span className={cn("text-xs", isActive ? "text-foreground" : "text-muted-foreground")}>
                        {nodeType.label}
                      </span>
                    </Label>
                  </div>
                );
              })}
              <Separator />
              <Button
                variant="ghost"
                size="sm"
                className="w-full text-xs h-7"
                onClick={() => setActiveNodeTypes(new Set(NODE_TYPES.map((n) => n.key))}
              >
                Select All
              </Button>
            </CardContent>
          </Card>

          {/* Recent Queries */}
          {recentQueries.length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Clock className="h-4 w-4" /> Recent Queries
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="max-h-48">
                  <div className="space-y-2">
                    {recentQueries.map((rq, i) => (
                      <button
                        key={i}
                        className="w-full text-left p-2 rounded-md hover:bg-muted/50 transition-colors"
                        onClick={() => handleSuggestedQuery(rq.query)}
                      >
                        <p className="text-xs truncate">{rq.query}</p>
                        <div className="flex justify-between mt-1">
                          <span className="text-xs text-muted-foreground">
                            {rq.timestamp.toLocaleTimeString()}
                          </span>
                          <Badge variant="outline" className="text-xs h-4">{rq.resultCount} results</Badge>
                        </div>
                      </button>
                    ))}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Main graph + query area */}
        <div className="lg:col-span-3 space-y-4">
          {/* NL Query */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Search className="h-4 w-4 text-primary" />
                Natural Language Query
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex gap-2">
                <Textarea
                  placeholder="Ask a security question... e.g. 'Show all critical findings with attack paths' or 'Which packages have known CVEs?'"
                  value={queryInput}
                  onChange={(e) => setQueryInput(e.target.value)}
                  className="resize-none h-20 text-sm"
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) handleQuery();
                  }}
                />
                <Button
                  className="shrink-0 gap-2 self-end"
                  onClick={handleQuery}
                  disabled={!queryInput.trim() || nlQueryMutation.isPending}
                >
                  <Send className="h-4 w-4" />
                  {nlQueryMutation.isPending ? "Querying..." : "Query"}
                </Button>
              </div>

              {/* Suggested queries */}
              <div>
                <p className="text-xs text-muted-foreground mb-2">Suggested queries:</p>
                <div className="flex flex-wrap gap-2">
                  {SUGGESTED_QUERIES.slice(0, 3).map((q) => (
                    <Button
                      key={q}
                      variant="outline"
                      size="sm"
                      className="text-xs h-7 gap-1"
                      onClick={() => handleSuggestedQuery(q)}
                    >
                      <ChevronRight className="h-3 w-3" />
                      {q}
                    </Button>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Graph Visualization Placeholder */}
          <Card className="overflow-hidden">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <Network className="h-4 w-4 text-primary" />
                  Graph Visualization
                </span>
                <Badge variant="outline" className="text-xs">
                  {Array.from(activeNodeTypes).join(", ")} nodes active
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="relative h-[380px] bg-gradient-to-br from-slate-900/80 via-slate-800/50 to-slate-900/80 border-t overflow-hidden">
                {/* Decorative grid */}
                <svg className="absolute inset-0 w-full h-full opacity-10" xmlns="http://www.w3.org/2000/svg">
                  <defs>
                    <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                      <path d="M 40 0 L 0 0 0 40" fill="none" stroke="currentColor" strokeWidth="0.5" />
                    </pattern>
                  </defs>
                  <rect width="100%" height="100%" fill="url(#grid)" />
                </svg>

                {/* Animated nodes */}
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="relative w-72 h-72">
                    {/* Center node */}
                    <motion.div
                      className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-14 h-14 rounded-full bg-primary/20 border-2 border-primary/50 flex items-center justify-center z-10"
                      animate={{ scale: [1, 1.05, 1] }}
                      transition={{ repeat: Infinity, duration: 3 }}
                    >
                      <Network className="h-6 w-6 text-primary" />
                    </motion.div>

                    {/* Orbiting nodes */}
                    {NODE_TYPES.filter((n) => activeNodeTypes.has(n.key)).map((nodeType, i, arr) => {
                      const angle = (i / arr.length) * Math.PI * 2 - Math.PI / 2;
                      const radius = 110;
                      const x = Math.cos(angle) * radius + 144 - 20;
                      const y = Math.sin(angle) * radius + 144 - 20;
                      const Icon = nodeType.icon;
                      return (
                        <motion.div
                          key={nodeType.key}
                          className="absolute w-10 h-10 rounded-full bg-background/80 border border-border/50 flex items-center justify-center backdrop-blur-sm"
                          style={{ left: x, top: y }}
                          initial={{ opacity: 0, scale: 0 }}
                          animate={{ opacity: 1, scale: 1 }}
                          transition={{ delay: i * 0.1 }}
                          whileHover={{ scale: 1.2 }}
                        >
                          <Icon className={cn("h-4 w-4", nodeType.color)} />
                        </motion.div>
                      );
                    })}

                    {/* Connection lines */}
                    <svg className="absolute inset-0 w-full h-full" style={{ zIndex: 0 }}>
                      {NODE_TYPES.filter((n) => activeNodeTypes.has(n.key)).map((nodeType, i, arr) => {
                        const angle = (i / arr.length) * Math.PI * 2 - Math.PI / 2;
                        const radius = 110;
                        const x = Math.cos(angle) * radius + 144;
                        const y = Math.sin(angle) * radius + 144;
                        return (
                          <line
                            key={nodeType.key}
                            x1={144}
                            y1={144}
                            x2={x}
                            y2={y}
                            stroke="currentColor"
                            strokeWidth="1"
                            strokeOpacity="0.2"
                            strokeDasharray="4 4"
                          />
                        );
                      })}
                    </svg>
                  </div>
                </div>

                {/* Canvas hint */}
                <div className="absolute bottom-3 right-3">
                  <Badge variant="outline" className="text-xs bg-background/60 backdrop-blur-sm">
                    Interactive canvas (canvas-based renderer in production)
                  </Badge>
                </div>

                {/* Stats overlay */}
                <div className="absolute top-3 left-3 flex gap-2 flex-wrap">
                  {[
                    { label: "Nodes", value: stats.node_count || 0 },
                    { label: "Edges", value: stats.edge_count || 0 },
                  ].map(({ label, value }) => (
                    <div key={label} className="bg-background/60 backdrop-blur-sm border border-border/50 rounded-md px-2 py-1">
                      <span className="text-xs text-muted-foreground">{label}: </span>
                      <span className="text-xs font-mono font-bold">{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Query Results */}
          {queryResults !== null && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <Eye className="h-4 w-4 text-primary" />
                    Query Results
                    {lastQuery && (
                      <span className="text-xs text-muted-foreground font-normal truncate max-w-xs">
                        "{lastQuery}"
                      </span>
                    )}
                  </span>
                  <Badge variant="outline" className="text-xs">{queryResults.length} results</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {queryResults.length === 0 ? (
                  <div className="text-center py-6 text-muted-foreground">
                    <Search className="h-8 w-8 opacity-30 mx-auto mb-2" />
                    <p className="text-sm">No results found for this query</p>
                  </div>
                ) : (
                  <ScrollArea className="max-h-64">
                    <div className="space-y-2">
                      {queryResults.map((result, i) => {
                        const nodeType = NODE_TYPES.find((n) => n.key === result.type);
                        const Icon = nodeType?.icon || Network;
                        return (
                          <div
                            key={result.id || String(i)}
                            className="flex items-center gap-3 p-2 bg-muted/30 rounded-md hover:bg-muted/50 transition-colors cursor-pointer"
                          >
                            <div className={cn("p-1.5 rounded-md bg-background", nodeType?.color || "text-muted-foreground")}>
                              <Icon className="h-3.5 w-3.5" />
                            </div>
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-medium truncate">{result.label || result.id || `Result ${i + 1}`}</p>
                              {result.type && (
                                <p className="text-xs text-muted-foreground capitalize">{result.type}</p>
                              )}
                            </div>
                            {result.severity && (
                              <Badge className={cn("border text-xs shrink-0",
                                result.severity === "critical" ? "bg-red-500/15 text-red-400 border-red-500/30" :
                                  result.severity === "high" ? "bg-orange-500/15 text-orange-400 border-orange-500/30" :
                                    "bg-slate-500/15 text-slate-400 border-slate-500/30"
                              )}>{result.severity}</Badge>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </ScrollArea>
                )}
              </CardContent>
            </Card>
          )}

          {/* Query failed state */}
          {nlQueryMutation.isError && (
            <Card className="border-red-500/20">
              <CardContent className="pt-4">
                <div className="flex items-center gap-2 text-red-400">
                  <Shield className="h-4 w-4" />
                  <p className="text-sm">Query failed. Please check your connection and try again.</p>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </motion.div>
  );
}
