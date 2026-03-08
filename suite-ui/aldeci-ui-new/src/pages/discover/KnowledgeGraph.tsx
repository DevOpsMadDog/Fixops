import { useState, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Network, Search, ZoomIn, ZoomOut, RefreshCw, Download,
  Server, Shield, User, Database, Cloud, Bug, ChevronRight, X
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { knowledgeGraphApi } from "@/lib/api";
import { toast } from "sonner";

// ── Mock Graph Data ────────────────────────────────────────────────────────────
interface GraphNode {
  id: string;
  label: string;
  type: "service" | "database" | "user" | "cloud" | "finding" | "internet";
  severity?: "critical" | "high" | "medium" | "low";
  x: number;
  y: number;
  r: number;
  description: string;
  riskScore: number;
}

interface GraphEdge {
  source: string;
  target: string;
  label: string;
  type: "attack" | "network" | "auth" | "data";
}

const GRAPH_NODES: GraphNode[] = [
  { id: "internet", label: "Internet", type: "internet", x: 80, y: 200, r: 28, description: "External internet access point", riskScore: 100 },
  { id: "alb", label: "ALB", type: "cloud", x: 200, y: 200, r: 24, description: "AWS Application Load Balancer", riskScore: 62 },
  { id: "api-gw", label: "API Gateway", type: "service", severity: "high", x: 330, y: 200, r: 26, description: "Internal API Gateway service", riskScore: 78 },
  { id: "auth-svc", label: "AuthService", type: "service", x: 330, y: 100, r: 24, description: "Authentication microservice", riskScore: 45 },
  { id: "payment-svc", label: "PaymentSvc", type: "service", severity: "critical", x: 460, y: 140, r: 26, description: "Payment processing service", riskScore: 92 },
  { id: "user-db", label: "UserDB", type: "database", severity: "high", x: 460, y: 260, r: 26, description: "PostgreSQL user database", riskScore: 81 },
  { id: "redis", label: "Redis Cache", type: "database", severity: "critical", x: 330, y: 300, r: 24, description: "Redis cache instance - exposed", riskScore: 95 },
  { id: "s3-bucket", label: "S3 Bucket", type: "cloud", severity: "critical", x: 580, y: 200, r: 26, description: "S3 data lake - public access", riskScore: 88 },
  { id: "lambda", label: "Lambda", type: "service", x: 580, y: 100, r: 22, description: "Serverless function", riskScore: 42 },
  { id: "admin-user", label: "admin@corp", type: "user", x: 200, y: 320, r: 22, description: "Administrative user account", riskScore: 55 },
  { id: "vuln-sqli", label: "SQL Injection", type: "finding", severity: "critical", x: 460, y: 340, r: 20, description: "CVE in user search endpoint", riskScore: 95 },
  { id: "vuln-ssrf", label: "SSRF", type: "finding", severity: "high", x: 410, y: 90, r: 18, description: "Server-side request forgery", riskScore: 72 },
];

const GRAPH_EDGES: GraphEdge[] = [
  { source: "internet", target: "alb", label: "HTTPS", type: "network" },
  { source: "alb", target: "api-gw", label: "routes", type: "network" },
  { source: "api-gw", target: "auth-svc", label: "validates", type: "auth" },
  { source: "api-gw", target: "payment-svc", label: "calls", type: "network" },
  { source: "api-gw", target: "user-db", label: "queries", type: "data" },
  { source: "api-gw", target: "redis", label: "reads", type: "data" },
  { source: "payment-svc", target: "s3-bucket", label: "stores", type: "data" },
  { source: "payment-svc", target: "lambda", label: "triggers", type: "network" },
  { source: "admin-user", target: "alb", label: "authenticates", type: "auth" },
  { source: "vuln-sqli", target: "user-db", label: "exploits", type: "attack" },
  { source: "vuln-ssrf", target: "lambda", label: "exploits", type: "attack" },
  { source: "internet", target: "redis", label: "exposed!", type: "attack" },
];

const NL_QUERY_EXAMPLES = [
  "Show attack paths from internet to database",
  "Which services can be reached from the Redis vulnerability?",
  "What is the blast radius of CVE-2023-44487?",
  "Find all unauthenticated access paths",
];

const NODE_COLORS: Record<GraphNode["type"], string> = {
  internet:  "#6b7280",
  cloud:     "#3b82f6",
  service:   "#8b5cf6",
  database:  "#f97316",
  user:      "#10b981",
  finding:   "#ef4444",
};

const SEVERITY_STROKE: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
};

const EDGE_COLORS: Record<GraphEdge["type"], string> = {
  attack: "#ef4444",
  network: "#6b7280",
  auth: "#10b981",
  data: "#3b82f6",
};

const NODE_ICONS: Record<GraphNode["type"], React.ComponentType<{ className?: string }>> = {
  internet: Cloud,
  cloud: Cloud,
  service: Server,
  database: Database,
  user: User,
  finding: Bug,
};

export default function KnowledgeGraph() {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [nlQuery, setNlQuery] = useState("");
  const [queryResult, setQueryResult] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const svgRef = useRef<SVGSVGElement>(null);

  const { data } = useQuery({
    queryKey: ["knowledge-graph", "visualize"],
    queryFn: () => knowledgeGraphApi.visualize({ limit: "50" }),
  });

  void data;

  const handleNlQuery = () => {
    if (!nlQuery.trim()) return;
    toast.success("Query submitted to AI engine");
    setQueryResult(`Found 3 attack paths matching "${nlQuery}". Highest risk path: Internet → Redis Cache (exposed) → API Gateway → UserDB with combined risk score 94/100.`);
  };

  const getNodeIcon = (node: GraphNode) => {
    const Icon = NODE_ICONS[node.type];
    return <Icon className="h-3 w-3" />;
  };

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Knowledge Graph"
        description="AI-powered security graph showing relationships between assets, vulnerabilities, and attack paths"
        badge="AI"
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => toast.success("Graph exported as JSON")}><Download className="h-4 w-4 mr-1.5" />Export</Button>
            <Button size="sm" onClick={() => toast.success("Graph refreshed from live data")}><RefreshCw className="h-4 w-4 mr-1.5" />Refresh</Button>
          </>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Nodes" value={GRAPH_NODES.length} icon={Network} />
        <KpiCard title="Attack Paths" value={3} change={1} trend="up" icon={Shield} />
        <KpiCard title="Critical Nodes" value={GRAPH_NODES.filter((n) => n.severity === "critical").length} icon={Bug} />
        <KpiCard title="Avg Risk Score" value="76/100" icon={ChevronRight} />
      </div>

      {/* NL Query bar */}
      <Card className="border-primary/30">
        <CardContent className="p-4">
          <p className="text-xs text-muted-foreground uppercase tracking-wider mb-3">Natural Language Query</p>
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Ask the graph anything... e.g. 'Show attack paths from internet to user data'"
                value={nlQuery}
                onChange={(e) => setNlQuery(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleNlQuery()}
                className="pl-9"
              />
            </div>
            <Button onClick={handleNlQuery}>Query</Button>
          </div>
          <div className="flex flex-wrap gap-2 mt-3">
            {NL_QUERY_EXAMPLES.map((ex) => (
              <button
                key={ex}
                onClick={() => { setNlQuery(ex); toast.success("Example query loaded"); }}
                className="text-xs text-muted-foreground bg-muted/30 hover:bg-muted/50 px-2.5 py-1 rounded-full transition-colors"
              >
                {ex}
              </button>
            ))}
          </div>
          {queryResult && (
            <motion.div initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} className="mt-3 rounded-md bg-primary/10 border border-primary/20 p-3">
              <p className="text-sm text-primary">{queryResult}</p>
              <button onClick={() => setQueryResult(null)} className="absolute top-2 right-2"><X className="h-3 w-3" /></button>
            </motion.div>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Graph canvas */}
        <div className="lg:col-span-3">
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-base flex items-center gap-2">
                  <Network className="h-4 w-4 text-primary" />
                  Security Knowledge Graph
                </CardTitle>
                <div className="flex items-center gap-2">
                  <div className="flex items-center gap-1 rounded-md border border-border/50 p-0.5">
                    <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={() => setZoom(Math.min(zoom + 0.2, 2))}><ZoomIn className="h-3.5 w-3.5" /></Button>
                    <span className="text-xs text-muted-foreground px-1">{Math.round(zoom * 100)}%</span>
                    <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={() => setZoom(Math.max(zoom - 0.2, 0.5))}><ZoomOut className="h-3.5 w-3.5" /></Button>
                  </div>
                </div>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <div className="relative overflow-hidden rounded-b-lg bg-[#0a0a12] h-[420px]">
                <svg
                  ref={svgRef}
                  width="100%"
                  height="100%"
                  viewBox="0 0 700 420"
                  style={{ transform: `scale(${zoom})`, transformOrigin: "center" }}
                >
                  {/* Background grid */}
                  <defs>
                    <pattern id="grid" width="30" height="30" patternUnits="userSpaceOnUse">
                      <path d="M 30 0 L 0 0 0 30" fill="none" stroke="#1a1a2e" strokeWidth="1" />
                    </pattern>
                  </defs>
                  <rect width="100%" height="100%" fill="url(#grid)" />

                  {/* Edges */}
                  {GRAPH_EDGES.map((edge, i) => {
                    const src = GRAPH_NODES.find((n) => n.id === edge.source);
                    const tgt = GRAPH_NODES.find((n) => n.id === edge.target);
                    if (!src || !tgt) return null;
                    const mx = (src.x + tgt.x) / 2;
                    const my = (src.y + tgt.y) / 2;
                    return (
                      <g key={i}>
                        <line
                          x1={src.x} y1={src.y} x2={tgt.x} y2={tgt.y}
                          stroke={EDGE_COLORS[edge.type]}
                          strokeWidth={edge.type === "attack" ? 2.5 : 1.5}
                          strokeOpacity={edge.type === "attack" ? 0.9 : 0.4}
                          strokeDasharray={edge.type === "attack" ? "6,3" : "none"}
                        />
                        <text x={mx} y={my - 4} fontSize={9} fill={EDGE_COLORS[edge.type]} fillOpacity={0.8} textAnchor="middle">{edge.label}</text>
                      </g>
                    );
                  })}

                  {/* Nodes */}
                  {GRAPH_NODES.map((node) => (
                    <g
                      key={node.id}
                      transform={`translate(${node.x}, ${node.y})`}
                      onClick={() => setSelectedNode(selectedNode?.id === node.id ? null : node)}
                      className="cursor-pointer"
                    >
                      {/* Glow for high-risk nodes */}
                      {node.severity === "critical" && (
                        <circle r={node.r + 6} fill="none" stroke="#ef4444" strokeWidth={1.5} strokeOpacity={0.3} />
                      )}
                      <circle
                        r={node.r}
                        fill={NODE_COLORS[node.type]}
                        fillOpacity={selectedNode?.id === node.id ? 1 : 0.85}
                        stroke={node.severity ? SEVERITY_STROKE[node.severity] : "transparent"}
                        strokeWidth={node.severity ? 2.5 : 0}
                      />
                      <text y={4} fontSize={9} fill="white" textAnchor="middle" fontWeight="600">{node.label.slice(0, 8)}</text>
                      {node.riskScore >= 80 && (
                        <circle r={5} cx={node.r - 4} cy={-node.r + 4} fill="#ef4444" />
                      )}
                    </g>
                  ))}
                </svg>

                {/* Legend */}
                <div className="absolute bottom-3 left-3 flex flex-wrap gap-3">
                  {Object.entries(NODE_COLORS).map(([type, color]) => (
                    <div key={type} className="flex items-center gap-1.5">
                      <div className="h-2.5 w-2.5 rounded-full" style={{ background: color }} />
                      <span className="text-xs text-gray-400 capitalize">{type}</span>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Entity detail panel */}
        <div>
          {selectedNode ? (
            <Card>
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between">
                  <CardTitle className="text-sm">{selectedNode.label}</CardTitle>
                  <button onClick={() => setSelectedNode(null)}><X className="h-4 w-4 text-muted-foreground" /></button>
                </div>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-xs text-muted-foreground capitalize">{selectedNode.type}</span>
                  {selectedNode.severity && (
                    <Badge variant={selectedNode.severity === "critical" ? "destructive" : "warning"}>{selectedNode.severity}</Badge>
                  )}
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <p className="text-xs text-muted-foreground">Description</p>
                  <p className="text-sm mt-1">{selectedNode.description}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Risk Score</p>
                  <div className="flex items-center gap-2 mt-1">
                    <div className="flex-1 h-2 rounded-full bg-muted/30 overflow-hidden">
                      <div
                        className={`h-full rounded-full ${selectedNode.riskScore >= 80 ? "bg-red-500" : selectedNode.riskScore >= 60 ? "bg-orange-500" : "bg-green-500"}`}
                        style={{ width: `${selectedNode.riskScore}%` }}
                      />
                    </div>
                    <span className={`text-sm font-bold ${selectedNode.riskScore >= 80 ? "text-red-400" : selectedNode.riskScore >= 60 ? "text-orange-400" : "text-green-400"}`}>
                      {selectedNode.riskScore}/100
                    </span>
                  </div>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-2">Connections</p>
                  {GRAPH_EDGES.filter((e) => e.source === selectedNode.id || e.target === selectedNode.id).map((edge, i) => (
                    <div key={i} className="flex items-center gap-2 py-1">
                      <div className="h-1.5 w-1.5 rounded-full" style={{ background: EDGE_COLORS[edge.type] }} />
                      <span className="text-xs text-muted-foreground">
                        {edge.source === selectedNode.id ? `→ ${edge.target}` : `← ${edge.source}`} ({edge.label})
                      </span>
                    </div>
                  ))}
                </div>
                <Button size="sm" className="w-full" onClick={() => toast.success("Attack paths calculated")}>
                  Show Attack Paths
                </Button>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm">Graph Summary</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {[
                  { label: "Total Nodes", value: GRAPH_NODES.length, icon: Network },
                  { label: "Total Edges", value: GRAPH_EDGES.length, icon: ChevronRight },
                  { label: "Attack Edges", value: GRAPH_EDGES.filter((e) => e.type === "attack").length, icon: Shield },
                  { label: "Critical Nodes", value: GRAPH_NODES.filter((n) => n.severity === "critical").length, icon: Bug },
                ].map(({ label, value, icon: Icon }) => (
                  <div key={label} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Icon className="h-4 w-4 text-muted-foreground" />
                      <span className="text-sm text-muted-foreground">{label}</span>
                    </div>
                    <span className="font-semibold">{value}</span>
                  </div>
                ))}
                <div className="pt-2 space-y-2">
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">High-Risk Nodes</p>
                  {GRAPH_NODES.filter((n) => n.riskScore >= 80).sort((a, b) => b.riskScore - a.riskScore).map((n) => (
                    <div key={n.id} className="flex items-center justify-between cursor-pointer hover:bg-muted/20 rounded p-1.5" onClick={() => setSelectedNode(n)}>
                      <div className="flex items-center gap-2">
                        <div className="h-2 w-2 rounded-full bg-red-500" />
                        <span className="text-xs">{n.label}</span>
                      </div>
                      <span className="text-xs font-semibold text-red-400">{n.riskScore}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </motion.div>
  );
}
