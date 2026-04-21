/**
 * Security Graph — Interactive force-directed security relationship visualization
 *
 * The "Wiz killer" feature: cloud resources → vulnerabilities → attack paths → crown jewels.
 * Assets ↔ findings ↔ CVEs ↔ threat actors, all in one explorable canvas.
 *
 * Route: /security-graph
 * API:
 *   GET /api/v1/graph/query/top_risks
 *   GET /api/v1/graph/query/attack_surface
 *
 * Falls back to rich demo data on API failure.
 */

import {
  useState,
  useEffect,
  useRef,
  useCallback,
  useMemo,
} from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Search,
  X,
  RefreshCw,
  Filter,
  ChevronRight,
  Server,
  Bug,
  Shield,
  User,
  AlertTriangle,
  Database,
  Globe,
  Lock,
  ZoomIn,
  ZoomOut,
  Maximize2,
  ExternalLink,
  Network,
  Eye,
  Activity,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ─── Config ───────────────────────────────────────────────
const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_";
const ORG_ID = "default";

async function apiFetch(path: string) {
  const sep = path.includes("?") ? "&" : "?";
  const res = await fetch(`${API}${path}${sep}org_id=${ORG_ID}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

// ─── Types ────────────────────────────────────────────────

type NodeType = "asset" | "finding" | "cve" | "actor" | "cloud" | "crown_jewel";
type Severity = "critical" | "high" | "medium" | "low" | "info";

interface GraphNode {
  id: string;
  label: string;
  type: NodeType;
  severity: Severity;
  risk_score: number;
  meta: Record<string, string | number | boolean>;
  // physics state (mutable, not React state)
  x: number;
  y: number;
  vx: number;
  vy: number;
}

interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
}

interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

// ─── Constants ────────────────────────────────────────────

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22c55e",
  info:     "#64748b",
};

const SEVERITY_GLOW: Record<Severity, string> = {
  critical: "rgba(239,68,68,0.4)",
  high:     "rgba(249,115,22,0.35)",
  medium:   "rgba(234,179,8,0.3)",
  low:      "rgba(34,197,94,0.25)",
  info:     "rgba(100,116,139,0.2)",
};

const NODE_TYPE_ICON: Record<NodeType, typeof Server> = {
  asset:       Server,
  finding:     Bug,
  cve:         AlertTriangle,
  actor:       User,
  cloud:       Globe,
  crown_jewel: Shield,
};

const NODE_TYPE_LABEL: Record<NodeType, string> = {
  asset:       "Asset",
  finding:     "Finding",
  cve:         "CVE",
  actor:       "Threat Actor",
  cloud:       "Cloud Resource",
  crown_jewel: "Crown Jewel",
};

const NODE_TYPE_COLOR: Record<NodeType, string> = {
  asset:       "#38bdf8",
  finding:     "#f97316",
  cve:         "#ef4444",
  actor:       "#a78bfa",
  cloud:       "#34d399",
  crown_jewel: "#fbbf24",
};

const NODE_RADIUS: Record<NodeType, number> = {
  crown_jewel: 22,
  cve:         18,
  actor:       18,
  finding:     16,
  cloud:       16,
  asset:       14,
};

const ALL_TYPES: NodeType[] = ["asset", "cloud", "finding", "cve", "actor", "crown_jewel"];
const ALL_SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

// ─── Mock data ────────────────────────────────────────────

function buildMockData(): GraphData {
  const nodes: GraphNode[] = [
    // Crown jewels
    { id: "cj-1", label: "Customer DB", type: "crown_jewel", severity: "critical", risk_score: 98, meta: { host: "db.prod.internal", owner: "Platform" }, x: 0, y: 0, vx: 0, vy: 0 },
    { id: "cj-2", label: "Auth Service", type: "crown_jewel", severity: "critical", risk_score: 94, meta: { host: "auth.prod.internal", owner: "Identity" }, x: 0, y: 0, vx: 0, vy: 0 },
    // Cloud resources
    { id: "cl-1", label: "S3 Bucket (public)", type: "cloud", severity: "critical", risk_score: 91, meta: { provider: "AWS", region: "us-east-1", misconfigured: true }, x: 0, y: 0, vx: 0, vy: 0 },
    { id: "cl-2", label: "EC2 Web Server", type: "cloud", severity: "high", risk_score: 78, meta: { provider: "AWS", region: "us-east-1", exposed_port: 22 }, x: 0, y: 0, vx: 0, vy: 0 },
    { id: "cl-3", label: "RDS Instance", type: "cloud", severity: "high", risk_score: 82, meta: { provider: "AWS", region: "us-west-2", publicly_accessible: true }, x: 0, y: 0, vx: 0, vy: 0 },
    { id: "cl-4", label: "Lambda Function", type: "cloud", severity: "medium", risk_score: 55, meta: { provider: "AWS", region: "eu-west-1" }, x: 0, y: 0, vx: 0, vy: 0 },
    { id: "cl-5", label: "GKE Cluster", type: "cloud", severity: "high", risk_score: 74, meta: { provider: "GCP", region: "us-central1", privileged_pods: 3 }, x: 0, y: 0, vx: 0, vy: 0 },
    // Assets
    { id: "a-1", label: "api-gateway-01", type: "asset", severity: "high", risk_score: 76, meta: { ip: "10.0.1.10", os: "Ubuntu 22.04" }, x: 0, y: 0, vx: 0, vy: 0 },
    { id: "a-2", label: "worker-node-12", type: "asset", severity: "medium", risk_score: 48, meta: { ip: "10.0.2.12", os: "Amazon Linux 2" }, x: 0, y: 0, vx: 0, vy: 0 },
    { id: "a-3", label: "bastion-host", type: "asset", severity: "critical", risk_score: 89, meta: { ip: "52.12.34.56", os: "CentOS 7", internet_facing: true }, x: 0, y: 0, vx: 0, vy: 0 },
    { id: "a-4", label: "jenkins-ci-01", type: "asset", severity: "high", risk_score: 71, meta: { ip: "10.0.3.5", os: "Debian 11" }, x: 0, y: 0, vx: 0, vy: 0 },
    // Findings
    { id: "f-1", label: "Log4Shell Active", type: "finding", severity: "critical", risk_score: 99, meta: { cve: "CVE-2021-44228", status: "open", sla_breach: true }, x: 0, y: 0, vx: 0, vy: 0 },
    { id: "f-2", label: "Public S3 Exposure", type: "finding", severity: "critical", risk_score: 95, meta: { cve: "N/A", status: "open", data_at_risk: "PII" }, x: 0, y: 0, vx: 0, vy: 0 },
    { id: "f-3", label: "SSH Brute Force", type: "finding", severity: "high", risk_score: 80, meta: { cve: "N/A", status: "in_progress" }, x: 0, y: 0, vx: 0, vy: 0 },
    { id: "f-4", label: "Outdated TLS 1.0", type: "finding", severity: "medium", risk_score: 52, meta: { cve: "CVE-2011-3389", status: "open" }, x: 0, y: 0, vx: 0, vy: 0 },
    { id: "f-5", label: "K8s Priv Escalation", type: "finding", severity: "high", risk_score: 84, meta: { cve: "CVE-2023-2878", status: "open" }, x: 0, y: 0, vx: 0, vy: 0 },
    { id: "f-6", label: "Exposed Jenkins API", type: "finding", severity: "high", risk_score: 77, meta: { cve: "CVE-2024-23897", status: "open" }, x: 0, y: 0, vx: 0, vy: 0 },
    // CVEs
    { id: "cve-1", label: "CVE-2021-44228", type: "cve", severity: "critical", risk_score: 100, meta: { cvss: 10.0, epss: 0.974, kev: true, vendor: "Apache" }, x: 0, y: 0, vx: 0, vy: 0 },
    { id: "cve-2", label: "CVE-2023-2878", type: "cve", severity: "high", risk_score: 83, meta: { cvss: 8.3, epss: 0.41, kev: false, vendor: "Kubernetes" }, x: 0, y: 0, vx: 0, vy: 0 },
    { id: "cve-3", label: "CVE-2024-23897", type: "cve", severity: "critical", risk_score: 92, meta: { cvss: 9.8, epss: 0.88, kev: true, vendor: "Jenkins" }, x: 0, y: 0, vx: 0, vy: 0 },
    { id: "cve-4", label: "CVE-2011-3389", type: "cve", severity: "medium", risk_score: 50, meta: { cvss: 5.9, epss: 0.12, kev: false, vendor: "Various" }, x: 0, y: 0, vx: 0, vy: 0 },
    // Threat actors
    { id: "ta-1", label: "APT-29 (Cozy Bear)", type: "actor", severity: "critical", risk_score: 96, meta: { origin: "Russia", ttps: "T1566, T1078", active: true }, x: 0, y: 0, vx: 0, vy: 0 },
    { id: "ta-2", label: "FIN7", type: "actor", severity: "high", risk_score: 85, meta: { origin: "Unknown", ttps: "T1190, T1133", active: true }, x: 0, y: 0, vx: 0, vy: 0 },
  ];

  const edges: GraphEdge[] = [
    // Attack surface chain
    { id: "e-1",  source: "a-3",   target: "cl-2",  label: "lateral move" },
    { id: "e-2",  source: "cl-2",  target: "f-3",   label: "exposed" },
    { id: "e-3",  source: "cl-2",  target: "a-1",   label: "connects" },
    { id: "e-4",  source: "a-1",   target: "f-1",   label: "vulnerable" },
    { id: "e-5",  source: "f-1",   target: "cve-1", label: "maps to" },
    { id: "e-6",  source: "cve-1", target: "cj-1",  label: "threatens" },
    { id: "e-7",  source: "cve-1", target: "cj-2",  label: "threatens" },
    // S3 path
    { id: "e-8",  source: "cl-1",  target: "f-2",   label: "misconfig" },
    { id: "e-9",  source: "f-2",   target: "cj-1",  label: "data leak" },
    // K8s path
    { id: "e-10", source: "cl-5",  target: "f-5",   label: "vulnerable" },
    { id: "e-11", source: "f-5",   target: "cve-2", label: "maps to" },
    { id: "e-12", source: "cve-2", target: "cj-2",  label: "threatens" },
    // Jenkins path
    { id: "e-13", source: "a-4",   target: "f-6",   label: "vulnerable" },
    { id: "e-14", source: "f-6",   target: "cve-3", label: "maps to" },
    { id: "e-15", source: "cl-4",  target: "a-2",   label: "invokes" },
    { id: "e-16", source: "a-2",   target: "cl-3",  label: "connects" },
    { id: "e-17", source: "cl-3",  target: "cj-1",  label: "hosts" },
    // TLS finding
    { id: "e-18", source: "a-1",   target: "f-4",   label: "exposes" },
    { id: "e-19", source: "f-4",   target: "cve-4", label: "maps to" },
    // Actor attributions
    { id: "e-20", source: "ta-1",  target: "cve-1", label: "exploits" },
    { id: "e-21", source: "ta-1",  target: "f-3",   label: "executing" },
    { id: "e-22", source: "ta-2",  target: "cve-3", label: "exploits" },
    { id: "e-23", source: "ta-2",  target: "f-6",   label: "targeting" },
    // Asset to RDS
    { id: "e-24", source: "a-3",   target: "cl-3",  label: "path" },
    { id: "e-25", source: "a-4",   target: "cj-2",  label: "pipeline access" },
  ];

  return { nodes, edges };
}

// ─── Force simulation (simple Euler integration) ──────────

const REPULSION = 12000;
const ATTRACTION = 0.04;
const GRAVITY = 0.015;
const DAMPING = 0.82;
const ITERATIONS = 1; // per frame

function simulateStep(nodes: GraphNode[], edges: GraphEdge[], cx: number, cy: number) {
  // Gravity toward center
  for (const n of nodes) {
    n.vx += (cx - n.x) * GRAVITY;
    n.vy += (cy - n.y) * GRAVITY;
  }

  // Repulsion between all node pairs
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i], b = nodes[j];
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const dist2 = dx * dx + dy * dy + 1;
      const dist = Math.sqrt(dist2);
      const force = REPULSION / dist2;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      a.vx -= fx; a.vy -= fy;
      b.vx += fx; b.vy += fy;
    }
  }

  // Attraction along edges
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));
  for (const e of edges) {
    const a = nodeMap.get(e.source);
    const b = nodeMap.get(e.target);
    if (!a || !b) continue;
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    const dist = Math.sqrt(dx * dx + dy * dy) || 1;
    const ideal = 120;
    const force = (dist - ideal) * ATTRACTION;
    const fx = (dx / dist) * force;
    const fy = (dy / dist) * force;
    a.vx += fx; a.vy += fy;
    b.vx -= fx; b.vy -= fy;
  }

  // Integrate
  for (const n of nodes) {
    n.vx *= DAMPING;
    n.vy *= DAMPING;
    n.x += n.vx;
    n.y += n.vy;
  }
}

function initPositions(nodes: GraphNode[], cx: number, cy: number) {
  const r = 180;
  nodes.forEach((n, i) => {
    const angle = (i / nodes.length) * Math.PI * 2;
    n.x = cx + Math.cos(angle) * r * (0.5 + Math.random() * 0.5);
    n.y = cy + Math.sin(angle) * r * (0.5 + Math.random() * 0.5);
    n.vx = (Math.random() - 0.5) * 2;
    n.vy = (Math.random() - 0.5) * 2;
  });
}

// ─── Subcomponents ────────────────────────────────────────

function SeverityDot({ severity }: { severity: Severity }) {
  return (
    <span
      className="inline-block w-2 h-2 rounded-full flex-shrink-0"
      style={{ backgroundColor: SEVERITY_COLOR[severity] }}
    />
  );
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider"
      style={{
        backgroundColor: SEVERITY_COLOR[severity] + "22",
        color: SEVERITY_COLOR[severity],
        border: `1px solid ${SEVERITY_COLOR[severity]}44`,
      }}
    >
      {severity}
    </span>
  );
}

function TypeFilterChip({
  type,
  active,
  onClick,
}: {
  type: NodeType;
  active: boolean;
  onClick: () => void;
}) {
  const color = NODE_TYPE_COLOR[type];
  const Icon = NODE_TYPE_ICON[type];
  return (
    <button
      onClick={onClick}
      className={cn(
        "flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium transition-all border",
        active ? "opacity-100" : "opacity-40",
      )}
      style={{
        backgroundColor: active ? color + "18" : "transparent",
        borderColor: active ? color + "55" : "transparent",
        color: active ? color : "var(--color-muted-foreground)",
      }}
    >
      <Icon className="w-3 h-3" />
      {NODE_TYPE_LABEL[type]}
    </button>
  );
}

interface DetailPanelProps {
  node: GraphNode;
  connected: GraphNode[];
  onClose: () => void;
  onNavigate: (id: string) => void;
}

function DetailPanel({ node, connected, onClose, onNavigate }: DetailPanelProps) {
  const Icon = NODE_TYPE_ICON[node.type];
  const color = NODE_TYPE_COLOR[node.type];

  return (
    <motion.div
      key={node.id}
      initial={{ opacity: 0, x: 24 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 24 }}
      transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
      className="flex flex-col h-full"
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-2 p-4 border-b border-border/60">
        <div className="flex items-center gap-2.5 min-w-0">
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ backgroundColor: color + "22", border: `1px solid ${color}44` }}
          >
            <Icon className="w-4 h-4" style={{ color }} />
          </div>
          <div className="min-w-0">
            <p className="text-xs text-muted-foreground mb-0.5">{NODE_TYPE_LABEL[node.type]}</p>
            <p className="text-sm font-semibold font-mono leading-tight truncate">{node.label}</p>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded hover:bg-accent/50 transition-colors flex-shrink-0"
        >
          <X className="w-3.5 h-3.5 text-muted-foreground" />
        </button>
      </div>

      <ScrollArea className="flex-1">
        <div className="p-4 space-y-4">
          {/* Risk score */}
          <div>
            <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Risk Score</p>
            <div className="flex items-center gap-3">
              <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                <motion.div
                  className="h-full rounded-full"
                  style={{ backgroundColor: SEVERITY_COLOR[node.severity] }}
                  initial={{ width: 0 }}
                  animate={{ width: `${node.risk_score}%` }}
                  transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
                />
              </div>
              <span className="text-sm font-bold tabular-nums" style={{ color: SEVERITY_COLOR[node.severity] }}>
                {node.risk_score}
              </span>
            </div>
            <div className="flex items-center gap-2 mt-2">
              <SeverityBadge severity={node.severity} />
            </div>
          </div>

          <Separator className="opacity-40" />

          {/* Properties */}
          <div>
            <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Properties</p>
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">ID</span>
                <span className="text-xs font-mono text-foreground/80">{node.id}</span>
              </div>
              {Object.entries(node.meta).map(([k, v]) => (
                <div key={k} className="flex items-center justify-between gap-2">
                  <span className="text-xs text-muted-foreground capitalize">{k.replace(/_/g, " ")}</span>
                  <span className={cn(
                    "text-xs font-mono truncate max-w-[140px]",
                    v === true ? "text-red-400" : v === false ? "text-green-400" : "text-foreground/80"
                  )}>
                    {String(v)}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Connected nodes */}
          {connected.length > 0 && (
            <>
              <Separator className="opacity-40" />
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">
                  Connected Entities ({connected.length})
                </p>
                <div className="space-y-1">
                  {connected.map((cn_node) => {
                    const CIcon = NODE_TYPE_ICON[cn_node.type];
                    const cColor = NODE_TYPE_COLOR[cn_node.type];
                    return (
                      <button
                        key={cn_node.id}
                        onClick={() => onNavigate(cn_node.id)}
                        className="w-full flex items-center gap-2 px-2 py-1.5 rounded hover:bg-accent/40 transition-colors text-left group"
                      >
                        <CIcon className="w-3 h-3 flex-shrink-0" style={{ color: cColor }} />
                        <span className="text-xs font-mono flex-1 truncate">{cn_node.label}</span>
                        <SeverityDot severity={cn_node.severity} />
                        <ChevronRight className="w-3 h-3 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0" />
                      </button>
                    );
                  })}
                </div>
              </div>
            </>
          )}

          {/* Investigate button */}
          <Separator className="opacity-40" />
          <Button size="sm" className="w-full gap-2" variant="outline">
            <ExternalLink className="w-3.5 h-3.5" />
            Investigate Entity
          </Button>
        </div>
      </ScrollArea>
    </motion.div>
  );
}

// ─── Canvas renderer ──────────────────────────────────────

interface CanvasProps {
  data: GraphData;
  selectedId: string | null;
  hoveredId: string | null;
  filterTypes: Set<NodeType>;
  filterSeverities: Set<Severity>;
  searchQuery: string;
  zoom: number;
  panX: number;
  panY: number;
  onSelectNode: (id: string | null) => void;
  onHoverNode: (id: string | null) => void;
  onPanChange: (dx: number, dy: number) => void;
  animating: boolean;
}

function GraphCanvas({
  data,
  selectedId,
  hoveredId,
  filterTypes,
  filterSeverities,
  searchQuery,
  zoom,
  panX,
  panY,
  onSelectNode,
  onHoverNode,
  onPanChange,
  animating,
}: CanvasProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const isDraggingCanvas = useRef(false);
  const lastPointer = useRef({ x: 0, y: 0 });

  const visibleNodes = useMemo(() => {
    return data.nodes.filter((n) => {
      if (!filterTypes.has(n.type)) return false;
      if (!filterSeverities.has(n.severity)) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        return n.label.toLowerCase().includes(q) || n.id.toLowerCase().includes(q);
      }
      return true;
    });
  }, [data.nodes, filterTypes, filterSeverities, searchQuery]);

  const visibleIds = useMemo(() => new Set(visibleNodes.map((n) => n.id)), [visibleNodes]);

  const visibleEdges = useMemo(() => {
    return data.edges.filter((e) => visibleIds.has(e.source) && visibleIds.has(e.target));
  }, [data.edges, visibleIds]);

  const nodeMap = useMemo(() => {
    return new Map(data.nodes.map((n) => [n.id, n]));
  }, [data.nodes]);

  function svgCoords(e: React.MouseEvent<SVGSVGElement>) {
    const rect = svgRef.current!.getBoundingClientRect();
    return {
      x: (e.clientX - rect.left - panX) / zoom,
      y: (e.clientY - rect.top - panY) / zoom,
    };
  }

  function handleSvgMouseDown(e: React.MouseEvent<SVGSVGElement>) {
    if ((e.target as Element).closest(".sg-node")) return;
    isDraggingCanvas.current = true;
    lastPointer.current = { x: e.clientX, y: e.clientY };
    e.preventDefault();
  }

  function handleSvgMouseMove(e: React.MouseEvent<SVGSVGElement>) {
    if (!isDraggingCanvas.current) return;
    const dx = e.clientX - lastPointer.current.x;
    const dy = e.clientY - lastPointer.current.y;
    lastPointer.current = { x: e.clientX, y: e.clientY };
    onPanChange(dx, dy);
  }

  function handleSvgMouseUp() {
    isDraggingCanvas.current = false;
  }

  function handleNodeClick(e: React.MouseEvent, id: string) {
    e.stopPropagation();
    onSelectNode(id === selectedId ? null : id);
  }

  function handleSvgClick() {
    onSelectNode(null);
  }

  // Dim nodes unrelated to selection
  function getNodeOpacity(node: GraphNode) {
    if (!selectedId) return 1;
    if (node.id === selectedId) return 1;
    const edge = data.edges.find(
      (e) => (e.source === selectedId && e.target === node.id) ||
             (e.target === selectedId && e.source === node.id)
    );
    return edge ? 0.85 : 0.18;
  }

  function getEdgeOpacity(edge: GraphEdge) {
    if (!selectedId) return 0.45;
    return edge.source === selectedId || edge.target === selectedId ? 0.9 : 0.06;
  }

  // Build arrowhead id by severity/type for edge coloring
  function edgeColor(edge: GraphEdge) {
    const src = nodeMap.get(edge.source);
    if (!src) return "#64748b";
    return SEVERITY_COLOR[src.severity] + "88";
  }

  const tick = animating; // just to trigger re-render reference

  return (
    <svg
      ref={svgRef}
      className="w-full h-full cursor-grab active:cursor-grabbing select-none"
      onMouseDown={handleSvgMouseDown}
      onMouseMove={handleSvgMouseMove}
      onMouseUp={handleSvgMouseUp}
      onMouseLeave={handleSvgMouseUp}
      onClick={handleSvgClick}
    >
      <defs>
        <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
          <path d="M 0 0 L 6 3 L 0 6 z" fill="#475569" fillOpacity="0.6" />
        </marker>
        <filter id="glow-critical">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
        <filter id="glow-high">
          <feGaussianBlur stdDeviation="2.5" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
        <filter id="glow-select">
          <feGaussianBlur stdDeviation="5" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
        {/* Grid pattern */}
        <pattern id="sg-grid" width="40" height="40" patternUnits="userSpaceOnUse">
          <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="0.5" />
        </pattern>
      </defs>

      {/* Background grid */}
      <rect width="100%" height="100%" fill="url(#sg-grid)" />

      <g transform={`translate(${panX},${panY}) scale(${zoom})`}>
        {/* Edges */}
        <g>
          {visibleEdges.map((edge) => {
            const src = nodeMap.get(edge.source);
            const tgt = nodeMap.get(edge.target);
            if (!src || !tgt) return null;
            const opacity = getEdgeOpacity(edge);
            const color = edgeColor(edge);
            // Offset line ends to node edge (not center)
            const dx = tgt.x - src.x;
            const dy = tgt.y - src.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;
            const srcR = NODE_RADIUS[src.type] + 2;
            const tgtR = NODE_RADIUS[tgt.type] + 8;
            const x1 = src.x + (dx / dist) * srcR;
            const y1 = src.y + (dy / dist) * srcR;
            const x2 = tgt.x - (dx / dist) * tgtR;
            const y2 = tgt.y - (dy / dist) * tgtR;
            const mx = (x1 + x2) / 2;
            const my = (y1 + y2) / 2;
            return (
              <g key={edge.id} opacity={opacity}>
                <line
                  x1={x1} y1={y1} x2={x2} y2={y2}
                  stroke={color}
                  strokeWidth={edge.source === selectedId || edge.target === selectedId ? 1.5 : 1}
                  markerEnd="url(#arrow)"
                  strokeDasharray={edge.source === selectedId || edge.target === selectedId ? "none" : "4 3"}
                />
                {edge.label && (dist > 80) && (
                  <text
                    x={mx} y={my - 4}
                    textAnchor="middle"
                    fontSize="9"
                    fill="rgba(148,163,184,0.7)"
                    fontFamily="'JetBrains Mono', monospace"
                  >
                    {edge.label}
                  </text>
                )}
              </g>
            );
          })}
        </g>

        {/* Nodes */}
        <g>
          {visibleNodes.map((node) => {
            const r = NODE_RADIUS[node.type];
            const color = NODE_TYPE_COLOR[node.type];
            const sColor = SEVERITY_COLOR[node.severity];
            const isSelected = node.id === selectedId;
            const isHovered = node.id === hoveredId;
            const opacity = getNodeOpacity(node);
            const isCritical = node.severity === "critical";
            const filter = isSelected ? "url(#glow-select)" : isCritical ? "url(#glow-critical)" : undefined;

            return (
              <g
                key={node.id}
                transform={`translate(${node.x},${node.y})`}
                opacity={opacity}
                className="sg-node"
                style={{ cursor: "pointer" }}
                onClick={(e) => handleNodeClick(e, node.id)}
                onMouseEnter={() => onHoverNode(node.id)}
                onMouseLeave={() => onHoverNode(null)}
              >
                {/* Outer glow ring for selected/critical */}
                {(isSelected || isCritical) && (
                  <circle
                    r={r + 6}
                    fill="none"
                    stroke={isSelected ? "#38bdf8" : sColor}
                    strokeWidth={isSelected ? 2 : 1}
                    strokeOpacity={isSelected ? 0.8 : 0.3}
                    filter={filter}
                  />
                )}

                {/* Hover ring */}
                {isHovered && !isSelected && (
                  <circle
                    r={r + 4}
                    fill="none"
                    stroke={color}
                    strokeWidth="1.5"
                    strokeOpacity="0.5"
                  />
                )}

                {/* Node background */}
                <circle
                  r={r}
                  fill={`${color}18`}
                  stroke={isSelected ? "#38bdf8" : sColor}
                  strokeWidth={isSelected ? 2.5 : node.severity === "critical" ? 2 : 1.5}
                  strokeOpacity={isSelected ? 1 : 0.75}
                  filter={filter}
                />

                {/* Severity arc (outer ring showing severity) */}
                <circle
                  r={r - 3}
                  fill={`${sColor}12`}
                />

                {/* Icon (text-based fallback, rendered as circle indicator) */}
                <circle r={4} fill={sColor} opacity={0.9} />

                {/* Risk score dot for high severity */}
                {node.risk_score >= 80 && (
                  <circle r={2.5} cy={-r + 4} cx={r - 4} fill={sColor} opacity={0.95} />
                )}

                {/* Label */}
                <text
                  y={r + 14}
                  textAnchor="middle"
                  fontSize={isSelected || isHovered ? "11" : "10"}
                  fontWeight={isSelected ? "700" : "500"}
                  fill={isSelected ? "#f1f5f9" : "rgba(203,213,225,0.85)"}
                  fontFamily="'JetBrains Mono', 'SF Mono', monospace"
                  style={{ pointerEvents: "none" }}
                >
                  {node.label.length > 18 ? node.label.slice(0, 16) + "…" : node.label}
                </text>

                {/* Type badge under label */}
                <text
                  y={r + 24}
                  textAnchor="middle"
                  fontSize="8"
                  fill={color}
                  fontFamily="'JetBrains Mono', monospace"
                  opacity="0.7"
                  style={{ pointerEvents: "none" }}
                >
                  {NODE_TYPE_LABEL[node.type].toUpperCase()}
                </text>
              </g>
            );
          })}
        </g>
      </g>

      {/* Suppress unused variable warning */}
      {tick && null}
    </svg>
  );
}

// ─── Main Page ────────────────────────────────────────────

export default function SecurityGraph() {
  const svgContainerRef = useRef<HTMLDivElement>(null);
  const nodesRef = useRef<GraphNode[]>([]);
  const edgesRef = useRef<GraphEdge[]>([]);
  const animFrameRef = useRef<number>(0);
  const stableRef = useRef(0); // frames with low velocity
  const [tick, setTick] = useState(0);

  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [filterTypes, setFilterTypes] = useState<Set<NodeType>>(new Set(ALL_TYPES));
  const [filterSeverities, setFilterSeverities] = useState<Set<Severity>>(new Set(ALL_SEVERITIES));
  const [zoom, setZoom] = useState(1);
  const [panX, setPanX] = useState(0);
  const [panY, setPanY] = useState(0);
  const [showFilters, setShowFilters] = useState(false);
  const [isSimulating, setIsSimulating] = useState(true);

  // Derived graph data for render (snapshot of refs)
  const [graphData, setGraphData] = useState<GraphData>({ nodes: [], edges: [] });

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [topRisks, attackSurface] = await Promise.allSettled([
        apiFetch("/api/v1/graph/query/top_risks"),
        apiFetch("/api/v1/graph/query/attack_surface"),
      ]);

      let merged: GraphData | null = null;

      if (topRisks.status === "fulfilled" && topRisks.value) {
        const d = topRisks.value;
        if (Array.isArray(d.nodes) && d.nodes.length > 0) {
          merged = { nodes: d.nodes, edges: d.edges || [] };
        }
      }

      if (attackSurface.status === "fulfilled" && attackSurface.value && merged) {
        const d = attackSurface.value;
        if (Array.isArray(d.nodes)) {
          const existingIds = new Set(merged.nodes.map((n: GraphNode) => n.id));
          const newNodes = d.nodes.filter((n: GraphNode) => !existingIds.has(n.id));
          merged.nodes = [...merged.nodes, ...newNodes];
          merged.edges = [...merged.edges, ...(d.edges || [])];
        }
      }

      initGraph(merged ?? buildMockData());
    } catch {
      initGraph(buildMockData());
    } finally {
      setLoading(false);
    }
  }, []);

  function initGraph(data: GraphData) {
    const w = svgContainerRef.current?.clientWidth ?? 800;
    const h = svgContainerRef.current?.clientHeight ?? 600;
    const cx = w / 2;
    const cy = h / 2;

    // Deep clone so physics state is mutable
    const nodes: GraphNode[] = data.nodes.map((n) => ({ ...n, x: 0, y: 0, vx: 0, vy: 0 }));
    const edges: GraphEdge[] = data.edges.map((e, i) => ({ ...e, id: e.id || `e-${i}` }));

    initPositions(nodes, cx, cy);
    nodesRef.current = nodes;
    edgesRef.current = edges;
    stableRef.current = 0;
    setIsSimulating(true);
    setGraphData({ nodes: [...nodes], edges: [...edges] });
  }

  // Physics loop
  useEffect(() => {
    if (nodesRef.current.length === 0) return;

    const w = svgContainerRef.current?.clientWidth ?? 800;
    const h = svgContainerRef.current?.clientHeight ?? 600;

    let running = true;

    function loop() {
      if (!running) return;

      if (isSimulating) {
        for (let i = 0; i < ITERATIONS; i++) {
          simulateStep(nodesRef.current, edgesRef.current, w / 2, h / 2);
        }

        // Check stability
        const maxV = nodesRef.current.reduce((m, n) => Math.max(m, Math.abs(n.vx), Math.abs(n.vy)), 0);
        if (maxV < 0.3) {
          stableRef.current++;
          if (stableRef.current > 60) {
            setIsSimulating(false);
          }
        } else {
          stableRef.current = 0;
        }

        setTick((t) => t + 1);
      }

      animFrameRef.current = requestAnimationFrame(loop);
    }

    animFrameRef.current = requestAnimationFrame(loop);
    return () => {
      running = false;
      cancelAnimationFrame(animFrameRef.current);
    };
  }, [isSimulating, graphData.nodes.length]);

  // Sync ref state to render state every frame while simulating
  useEffect(() => {
    if (isSimulating && nodesRef.current.length > 0) {
      setGraphData((prev) => ({
        edges: prev.edges,
        nodes: nodesRef.current.map((n) => ({ ...n })),
      }));
    }
  }, [tick, isSimulating]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Zoom handlers
  function handleZoomIn() { setZoom((z) => Math.min(z * 1.3, 3)); }
  function handleZoomOut() { setZoom((z) => Math.max(z / 1.3, 0.25)); }
  function handleZoomReset() { setZoom(1); setPanX(0); setPanY(0); }

  function handlePanChange(dx: number, dy: number) {
    setPanX((x) => x + dx);
    setPanY((y) => y + dy);
  }

  function handleWheelZoom(e: React.WheelEvent) {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setZoom((z) => Math.min(Math.max(z * delta, 0.25), 3));
  }

  // Node selection navigation (from detail panel)
  function navigateToNode(id: string) {
    setSelectedId(id);
  }

  // Toggle filter helpers
  function toggleType(t: NodeType) {
    setFilterTypes((prev) => {
      const next = new Set(prev);
      if (next.has(t)) { if (next.size > 1) next.delete(t); }
      else next.add(t);
      return next;
    });
  }

  function toggleSeverity(s: Severity) {
    setFilterSeverities((prev) => {
      const next = new Set(prev);
      if (next.has(s)) { if (next.size > 1) next.delete(s); }
      else next.add(s);
      return next;
    });
  }

  // Derived stats
  const stats = useMemo(() => {
    const nodes = graphData.nodes;
    return {
      total: nodes.length,
      critical: nodes.filter((n) => n.severity === "critical").length,
      crown_jewels: nodes.filter((n) => n.type === "crown_jewel").length,
      actors: nodes.filter((n) => n.type === "actor").length,
    };
  }, [graphData.nodes]);

  // Selected node detail
  const selectedNode = useMemo(() => {
    return graphData.nodes.find((n) => n.id === selectedId) ?? null;
  }, [graphData.nodes, selectedId]);

  const connectedNodes = useMemo(() => {
    if (!selectedId) return [];
    const edgeNodeIds = graphData.edges
      .filter((e) => e.source === selectedId || e.target === selectedId)
      .map((e) => e.source === selectedId ? e.target : e.source);
    return graphData.nodes.filter((n) => edgeNodeIds.includes(n.id));
  }, [selectedId, graphData]);

  if (loading) {
    return (
      <div className="flex flex-col gap-6 p-6">
        <div className="h-8 w-64 bg-muted/40 rounded animate-pulse" />
        <div className="grid grid-cols-4 gap-4">
          {[1,2,3,4].map((i) => <div key={i} className="h-28 bg-muted/40 rounded-lg animate-pulse" />)}
        </div>
        <div className="h-[560px] bg-muted/40 rounded-lg animate-pulse" />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4 p-6 min-h-0 h-full">
      {/* Header */}
      <PageHeader
        title="Security Graph"
        description="Interactive relationship map — cloud resources, vulnerabilities, attack paths, and crown jewels"
        badge="LIVE"
        actions={
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => { stableRef.current = 0; setIsSimulating(true); }}
              className="gap-1.5 text-xs"
            >
              <Activity className="w-3.5 h-3.5" />
              Relayout
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={loadData}
              className="gap-1.5 text-xs"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Refresh
            </Button>
          </div>
        }
      />

      {/* KPIs */}
      <motion.div
        className="grid grid-cols-2 md:grid-cols-4 gap-3"
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        <KpiCard title="Total Entities" value={stats.total} icon={Network} trendLabel="In graph" />
        <KpiCard title="Critical Nodes" value={stats.critical} icon={AlertTriangle} trend="up" trendLabel="Require action" />
        <KpiCard title="Crown Jewels" value={stats.crown_jewels} icon={Shield} trendLabel="At risk" />
        <KpiCard title="Threat Actors" value={stats.actors} icon={Eye} trendLabel="Active" />
      </motion.div>

      {/* Search + Filter bar */}
      <motion.div
        className="flex items-center gap-2 flex-wrap"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.1 }}
      >
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input
            placeholder="Search entity name or ID…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8 h-8 text-xs font-mono bg-card border-border/60"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery("")}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        <Button
          size="sm"
          variant="outline"
          className={cn("gap-1.5 text-xs h-8", showFilters && "border-primary/50 text-primary")}
          onClick={() => setShowFilters((v) => !v)}
        >
          <Filter className="w-3.5 h-3.5" />
          Filters
          {(filterTypes.size < ALL_TYPES.length || filterSeverities.size < ALL_SEVERITIES.length) && (
            <Badge variant="secondary" className="ml-0.5 text-[9px] px-1 py-0">
              {(ALL_TYPES.length - filterTypes.size) + (ALL_SEVERITIES.length - filterSeverities.size)} off
            </Badge>
          )}
        </Button>

        {/* Quick type chips */}
        <div className="flex items-center gap-1 flex-wrap">
          {ALL_TYPES.map((t) => (
            <TypeFilterChip key={t} type={t} active={filterTypes.has(t)} onClick={() => toggleType(t)} />
          ))}
        </div>
      </motion.div>

      {/* Expanded filter panel */}
      <AnimatePresence>
        {showFilters && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <Card className="p-3">
              <div className="flex items-center gap-4 flex-wrap">
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1.5">Severity</p>
                  <div className="flex items-center gap-1.5">
                    {ALL_SEVERITIES.map((s) => (
                      <button
                        key={s}
                        onClick={() => toggleSeverity(s)}
                        className={cn(
                          "px-2.5 py-1 rounded-full text-xs font-medium border transition-all",
                          filterSeverities.has(s) ? "opacity-100" : "opacity-30"
                        )}
                        style={{
                          backgroundColor: filterSeverities.has(s) ? SEVERITY_COLOR[s] + "18" : "transparent",
                          borderColor: filterSeverities.has(s) ? SEVERITY_COLOR[s] + "55" : "transparent",
                          color: SEVERITY_COLOR[s],
                        }}
                      >
                        {s}
                      </button>
                    ))}
                  </div>
                </div>
                <Separator orientation="vertical" className="h-10 opacity-40" />
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="ghost"
                    className="text-xs h-7"
                    onClick={() => { setFilterTypes(new Set(ALL_TYPES)); setFilterSeverities(new Set(ALL_SEVERITIES)); }}
                  >
                    Reset all
                  </Button>
                </div>
              </div>
            </Card>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Main canvas area */}
      <motion.div
        className="flex gap-4 flex-1 min-h-0"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.15 }}
      >
        {/* Graph canvas */}
        <Card
          className={cn(
            "flex-1 overflow-hidden relative transition-all duration-300",
            selectedNode ? "xl:flex-[3]" : "flex-1"
          )}
        >
          {/* Toolbar overlay */}
          <div className="absolute top-3 right-3 z-10 flex flex-col gap-1.5">
            <Button size="icon" variant="outline" className="w-7 h-7" onClick={handleZoomIn}>
              <ZoomIn className="w-3.5 h-3.5" />
            </Button>
            <Button size="icon" variant="outline" className="w-7 h-7" onClick={handleZoomOut}>
              <ZoomOut className="w-3.5 h-3.5" />
            </Button>
            <Button size="icon" variant="outline" className="w-7 h-7" onClick={handleZoomReset}>
              <Maximize2 className="w-3.5 h-3.5" />
            </Button>
          </div>

          {/* Sim indicator */}
          {isSimulating && (
            <div className="absolute top-3 left-3 z-10 flex items-center gap-1.5 px-2 py-1 rounded bg-card/80 backdrop-blur-sm border border-border/50">
              <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
              <span className="text-[10px] text-muted-foreground font-mono">Simulating…</span>
            </div>
          )}

          {/* Legend */}
          <div className="absolute bottom-3 left-3 z-10 flex flex-col gap-1 p-2 rounded bg-card/80 backdrop-blur-sm border border-border/50">
            {[
              { color: SEVERITY_COLOR.critical, label: "Critical" },
              { color: SEVERITY_COLOR.high,     label: "High" },
              { color: SEVERITY_COLOR.medium,   label: "Medium" },
              { color: SEVERITY_COLOR.low,      label: "Low" },
            ].map(({ color, label }) => (
              <div key={label} className="flex items-center gap-1.5">
                <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                <span className="text-[9px] text-muted-foreground font-mono">{label}</span>
              </div>
            ))}
          </div>

          {/* SVG */}
          <div
            ref={svgContainerRef}
            className="w-full h-full"
            style={{ minHeight: 480 }}
            onWheel={handleWheelZoom}
          >
            <GraphCanvas
              data={graphData}
              selectedId={selectedId}
              hoveredId={hoveredId}
              filterTypes={filterTypes}
              filterSeverities={filterSeverities}
              searchQuery={searchQuery}
              zoom={zoom}
              panX={panX}
              panY={panY}
              onSelectNode={setSelectedId}
              onHoverNode={setHoveredId}
              onPanChange={handlePanChange}
              animating={isSimulating}
            />
          </div>
        </Card>

        {/* Detail panel */}
        <AnimatePresence>
          {selectedNode && (
            <motion.div
              initial={{ opacity: 0, width: 0 }}
              animate={{ opacity: 1, width: 280 }}
              exit={{ opacity: 0, width: 0 }}
              transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
              className="overflow-hidden flex-shrink-0"
            >
              <Card className="w-[280px] h-full flex flex-col overflow-hidden">
                <AnimatePresence mode="wait">
                  <DetailPanel
                    key={selectedNode.id}
                    node={selectedNode}
                    connected={connectedNodes}
                    onClose={() => setSelectedId(null)}
                    onNavigate={navigateToNode}
                  />
                </AnimatePresence>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      {/* Footer stats bar */}
      <motion.div
        className="flex items-center gap-4 text-xs text-muted-foreground font-mono"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.2 }}
      >
        <span>{graphData.nodes.length} nodes</span>
        <span className="text-border">·</span>
        <span>{graphData.edges.length} edges</span>
        <span className="text-border">·</span>
        <span>{Math.round(zoom * 100)}% zoom</span>
        {selectedNode && (
          <>
            <span className="text-border">·</span>
            <span className="text-primary">
              Selected: <span className="font-semibold">{selectedNode.label}</span>
            </span>
          </>
        )}
        {isSimulating && (
          <>
            <span className="text-border">·</span>
            <span className="flex items-center gap-1">
              <Lock className="w-3 h-3" />
              Physics active
            </span>
          </>
        )}
        <span className="ml-auto">Scroll to zoom · Drag canvas to pan · Click node for details</span>
      </motion.div>
    </div>
  );
}
