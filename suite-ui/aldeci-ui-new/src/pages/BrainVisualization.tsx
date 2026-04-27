/**
 * BrainVisualization — ALDECI Neural Brain Map
 *
 * Renders all brain nodes as a living, force-directed neural network on a
 * dark-space canvas. Pure React + Canvas API + framer-motion. No D3.
 *
 * Visual language:
 *   • Bioluminescent nodes that breathe (radius oscillates on a sine wave)
 *   • Color-coded by type: finding=red, asset=cyan, component=emerald,
 *     cve=violet, actor=amber, alert=orange, default=slate
 *   • Connections rendered as translucent arcs that pulse with a travelling
 *     highlight ("energy packet") to simulate synapse firing
 *   • Dark-void (#080c14) background with a subtle radial gradient vignette
 *   • HUD panel: live stats, type legend, selected-node detail
 *
 * Route: /brain
 * APIs:  GET /api/v1/brain/stats
 *        GET /api/v1/brain/nodes?limit=200
 */

import {
  useEffect,
  useRef,
  useState,
  useCallback,
  useMemo,
} from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Brain,
  Activity,
  Cpu,
  Shield,
  AlertTriangle,
  RefreshCw,
  X,
  Maximize2,
  Minimize2,
  ChevronRight,
  Layers,
  Network,
  Zap,
} from "lucide-react";
import { usePageTitle } from "@/hooks/use-page-title";

// ── API ──────────────────────────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" &&
    window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`API ${res.status}: ${path}`);
  return res.json();
}

// ── Types ────────────────────────────────────────────────────────────────────
interface BrainStats {
  total_nodes: number;
  total_edges: number;
  density: number;
  node_types: Record<string, number>;
  edge_types: Record<string, number>;
  organizations: Record<string, number>;
}

interface RawNode {
  node_id: string;
  node_type: string;
  org_id: string;
  properties: Record<string, unknown>;
  created_at: string;
}

interface SimNode {
  id: string;
  type: string;
  org: string;
  props: Record<string, unknown>;
  // physics
  x: number;
  y: number;
  vx: number;
  vy: number;
  // visual
  radius: number;
  baseRadius: number;
  phase: number; // breathing offset
  color: string;
  glowColor: string;
}

interface SimEdge {
  source: string;
  target: string;
  pulseOffset: number; // 0-1 staggered start
}

// ── Color palette by node type ───────────────────────────────────────────────
const TYPE_COLORS: Record<string, { fill: string; glow: string; label: string }> = {
  finding:   { fill: "#ff4d4d", glow: "#ff000088", label: "Findings" },
  Finding:   { fill: "#ff4d4d", glow: "#ff000088", label: "Findings" },
  alert:     { fill: "#ff8c42", glow: "#ff6a0088", label: "Alerts" },
  asset:     { fill: "#00d4ff", glow: "#00d4ff66", label: "Assets" },
  Asset:     { fill: "#00d4ff", glow: "#00d4ff66", label: "Assets" },
  component: { fill: "#00e676", glow: "#00e67666", label: "Components" },
  Component: { fill: "#00e676", glow: "#00e67666", label: "Components" },
  cve:       { fill: "#b47cff", glow: "#8c00ff66", label: "CVEs" },
  CVE:       { fill: "#b47cff", glow: "#8c00ff66", label: "CVEs" },
  actor:     { fill: "#ffd600", glow: "#ffd60066", label: "Actors" },
  Actor:     { fill: "#ffd600", glow: "#ffd60066", label: "Actors" },
};

const DEFAULT_COLOR = { fill: "#7c8fa6", glow: "#7c8fa633", label: "Other" };

function nodeColor(type: string) {
  return TYPE_COLORS[type] ?? DEFAULT_COLOR;
}

// ── Force-directed simulation (vanilla, no D3) ───────────────────────────────
const REPULSION   = 4800;
const ATTRACTION  = 0.006;
const DAMPING     = 0.82;
const CENTER_PULL = 0.003;
const MIN_DIST    = 18;

function tick(nodes: SimNode[], edges: SimEdge[], W: number, H: number) {
  const cx = W / 2;
  const cy = H / 2;
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));

  // Repulsion: O(n²) — capped at 300 nodes for performance
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i];
      const b = nodes[j];
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || MIN_DIST;
      const force = REPULSION / (dist * dist);
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      a.vx -= fx;
      a.vy -= fy;
      b.vx += fx;
      b.vy += fy;
    }
  }

  // Attraction along edges
  for (const edge of edges) {
    const src = nodeMap.get(edge.source);
    const tgt = nodeMap.get(edge.target);
    if (!src || !tgt) continue;
    const dx = tgt.x - src.x;
    const dy = tgt.y - src.y;
    const dist = Math.sqrt(dx * dx + dy * dy) || 1;
    const fx = dx * ATTRACTION;
    const fy = dy * ATTRACTION;
    src.vx += fx;
    src.vy += fy;
    tgt.vx -= fx;
    tgt.vy -= fy;
  }

  // Centre gravity + update positions
  for (const n of nodes) {
    n.vx += (cx - n.x) * CENTER_PULL;
    n.vy += (cy - n.y) * CENTER_PULL;
    n.vx *= DAMPING;
    n.vy *= DAMPING;
    n.x += n.vx;
    n.y += n.vy;
    // clamp to canvas
    n.x = Math.max(n.baseRadius + 4, Math.min(W - n.baseRadius - 4, n.x));
    n.y = Math.max(n.baseRadius + 4, Math.min(H - n.baseRadius - 4, n.y));
  }
}

// ── Canvas renderer ──────────────────────────────────────────────────────────
function drawFrame(
  ctx: CanvasRenderingContext2D,
  W: number,
  H: number,
  nodes: SimNode[],
  edges: SimEdge[],
  t: number,                     // seconds elapsed
  hoveredId: string | null,
  selectedId: string | null,
) {
  ctx.clearRect(0, 0, W, H);

  // Background vignette
  const vignette = ctx.createRadialGradient(W / 2, H / 2, 0, W / 2, H / 2, Math.max(W, H) * 0.72);
  vignette.addColorStop(0, "#0d1320");
  vignette.addColorStop(1, "#050810");
  ctx.fillStyle = vignette;
  ctx.fillRect(0, 0, W, H);

  const nodeMap = new Map(nodes.map((n) => [n.id, n]));

  // Breathing: update radii
  for (const n of nodes) {
    n.radius = n.baseRadius + Math.sin(t * 1.4 + n.phase) * (n.baseRadius * 0.18);
  }

  // Draw edges
  for (const edge of edges) {
    const src = nodeMap.get(edge.source);
    const tgt = nodeMap.get(edge.target);
    if (!src || !tgt) continue;

    const dx = tgt.x - src.x;
    const dy = tgt.y - src.y;

    // Base line
    ctx.beginPath();
    ctx.moveTo(src.x, src.y);
    ctx.lineTo(tgt.x, tgt.y);
    ctx.strokeStyle = "rgba(100,180,255,0.07)";
    ctx.lineWidth = 0.8;
    ctx.stroke();

    // Travelling energy pulse (a bright dot moving along the edge)
    const pulseT = ((t * 0.5 + edge.pulseOffset) % 1);
    const px = src.x + dx * pulseT;
    const py = src.y + dy * pulseT;
    const pg = ctx.createRadialGradient(px, py, 0, px, py, 5);
    pg.addColorStop(0, "rgba(100,220,255,0.7)");
    pg.addColorStop(1, "rgba(100,220,255,0)");
    ctx.beginPath();
    ctx.arc(px, py, 5, 0, Math.PI * 2);
    ctx.fillStyle = pg;
    ctx.fill();
  }

  // Draw nodes
  for (const n of nodes) {
    const isHovered  = n.id === hoveredId;
    const isSelected = n.id === selectedId;
    const r = n.radius;
    const glowR = r * (isHovered || isSelected ? 5.5 : 3.2);

    // Outer glow
    const glow = ctx.createRadialGradient(n.x, n.y, r * 0.2, n.x, n.y, glowR);
    glow.addColorStop(0, n.glowColor.replace("66", isHovered ? "cc" : "88"));
    glow.addColorStop(1, "rgba(0,0,0,0)");
    ctx.beginPath();
    ctx.arc(n.x, n.y, glowR, 0, Math.PI * 2);
    ctx.fillStyle = glow;
    ctx.fill();

    // Core circle
    ctx.beginPath();
    ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
    ctx.fillStyle = n.color;
    ctx.shadowColor = n.glowColor;
    ctx.shadowBlur  = isHovered || isSelected ? 18 : 8;
    ctx.fill();
    ctx.shadowBlur = 0;

    // Selection ring
    if (isSelected) {
      ctx.beginPath();
      ctx.arc(n.x, n.y, r + 4 + Math.sin(t * 3) * 2, 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(255,255,255,0.6)";
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }

    // Label for hovered / selected
    if (isHovered || isSelected) {
      const label = String(
        n.props.title ?? n.props.name ?? n.props.finding_id ?? n.id.split(":")[1] ?? n.id
      ).slice(0, 28);
      ctx.font = "bold 11px 'JetBrains Mono', monospace";
      ctx.textAlign = "center";
      ctx.fillStyle = "#e2e8f0";
      ctx.shadowColor = "#000";
      ctx.shadowBlur = 6;
      ctx.fillText(label, n.x, n.y - r - 6);
      ctx.shadowBlur = 0;
    }
  }
}

// ── Tooltip / detail panel ────────────────────────────────────────────────────
function NodeDetailPanel({
  node,
  onClose,
}: {
  node: SimNode | null;
  onClose: () => void;
}) {
  if (!node) return null;
  const col = nodeColor(node.type);
  const sev = String(node.props.severity ?? "");
  const sevColor =
    sev === "critical" ? "#ff4d4d"
    : sev === "high"   ? "#ff8c42"
    : sev === "medium" ? "#ffd600"
    : sev === "low"    ? "#00e676"
    : "#7c8fa6";

  return (
    <AnimatePresence>
      <motion.div
        key={node.id}
        initial={{ opacity: 0, x: 24 }}
        animate={{ opacity: 1, x: 0 }}
        exit={{ opacity: 0, x: 24 }}
        transition={{ type: "spring", stiffness: 300, damping: 28 }}
        className="absolute top-4 right-4 w-72 rounded-xl border backdrop-blur-md z-20"
        style={{
          background: "rgba(8,12,20,0.92)",
          borderColor: col.fill + "44",
          boxShadow: `0 0 32px ${col.glow}`,
        }}
      >
        {/* Header */}
        <div
          className="flex items-center justify-between px-4 py-3 rounded-t-xl"
          style={{ background: col.fill + "18", borderBottom: `1px solid ${col.fill}22` }}
        >
          <div className="flex items-center gap-2">
            <div
              className="w-2.5 h-2.5 rounded-full animate-pulse"
              style={{ background: col.fill, boxShadow: `0 0 8px ${col.fill}` }}
            />
            <span className="text-xs font-semibold tracking-widest uppercase" style={{ color: col.fill }}>
              {node.type}
            </span>
          </div>
          <button
            onClick={onClose}
            className="text-slate-500 hover:text-slate-200 transition-colors"
          >
            <X size={14} />
          </button>
        </div>

        {/* Body */}
        <div className="px-4 py-3 space-y-2.5">
          <p className="text-sm font-medium text-slate-100 leading-snug">
            {String(node.props.title ?? node.props.name ?? node.id.split(":").slice(1).join(":") ?? node.id)}
          </p>

          <div className="grid grid-cols-2 gap-2 text-xs">
            <Detail label="Org" value={node.org} />
            <Detail label="Node ID" value={node.id.split(":")[1] ?? node.id} />
            {sev && (
              <div className="col-span-2 flex items-center gap-2">
                <span className="text-slate-500">Severity</span>
                <span
                  className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider"
                  style={{ background: sevColor + "22", color: sevColor, border: `1px solid ${sevColor}44` }}
                >
                  {sev}
                </span>
              </div>
            )}
            {Boolean(node.props.source) && (
              <Detail label="Source" value={String(node.props.source)} />
            )}
            {Boolean(node.props.cvss_score) && (
              <Detail label="CVSS" value={String(node.props.cvss_score)} />
            )}
          </div>

          <div
            className="text-[10px] text-slate-600 pt-1 border-t"
            style={{ borderColor: col.fill + "20" }}
          >
            Click canvas to deselect
          </div>
        </div>
      </motion.div>
    </AnimatePresence>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="text-slate-600 block">{label}</span>
      <span className="text-slate-300 truncate block">{value}</span>
    </div>
  );
}

// ── Legend ────────────────────────────────────────────────────────────────────
function LegendDot({ color, label, count }: { color: string; label: string; count: number }) {
  return (
    <div className="flex items-center gap-2 text-xs">
      <div
        className="w-2.5 h-2.5 rounded-full flex-shrink-0"
        style={{ background: color, boxShadow: `0 0 6px ${color}` }}
      />
      <span className="text-slate-400">{label}</span>
      <span className="ml-auto text-slate-600 tabular-nums">{count.toLocaleString()}</span>
    </div>
  );
}

// ── Tooltip hover card (tiny, follows cursor) ─────────────────────────────────
function HoverTooltip({
  node,
  mouseX,
  mouseY,
}: {
  node: SimNode | null;
  mouseX: number;
  mouseY: number;
}) {
  if (!node) return null;
  const col = nodeColor(node.type);
  const title = String(
    node.props.title ?? node.props.name ?? node.id.split(":")[1] ?? node.id
  ).slice(0, 36);
  return (
    <div
      className="pointer-events-none fixed z-30 text-xs rounded-lg px-3 py-2 border backdrop-blur-sm"
      style={{
        left: mouseX + 16,
        top: mouseY - 10,
        background: "rgba(8,12,20,0.95)",
        borderColor: col.fill + "55",
        color: col.fill,
        boxShadow: `0 0 12px ${col.glow}`,
      }}
    >
      <div className="font-semibold">{title}</div>
      <div className="text-slate-500 mt-0.5">{node.type} · {node.org}</div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function BrainVisualization() {
  usePageTitle("Neural Brain Map");

  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const rafRef = useRef<number>(0);
  const simNodesRef = useRef<SimNode[]>([]);
  const simEdgesRef = useRef<SimEdge[]>([]);
  const startTimeRef = useRef<number>(performance.now());

  const [stats, setStats] = useState<BrainStats | null>(null);
  const [rawNodes, setRawNodes] = useState<RawNode[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<SimNode | null>(null);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });
  const [fullscreen, setFullscreen] = useState(false);
  const [simReady, setSimReady] = useState(false);

  // ── Fetch data ──────────────────────────────────────────────────────────────
  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsData, nodesData] = await Promise.all([
        apiFetch("/api/v1/brain/stats"),
        apiFetch("/api/v1/brain/nodes?limit=200"),
      ]);
      setStats(statsData);
      setRawNodes(nodesData.nodes ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load brain data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  // ── Build simulation nodes from raw API data ────────────────────────────────
  const canvasSize = useCallback(() => {
    const el = containerRef.current;
    if (!el) return { W: 900, H: 600 };
    return { W: el.clientWidth, H: el.clientHeight };
  }, []);

  useEffect(() => {
    if (rawNodes.length === 0) return;
    const { W, H } = canvasSize();

    // Clamp to 300 nodes max for performance
    const capped = rawNodes.slice(0, 300);

    const newNodes: SimNode[] = capped.map((raw, i) => {
      const col = nodeColor(raw.node_type);
      const angle = (i / capped.length) * Math.PI * 2;
      const r = Math.min(W, H) * 0.35;
      return {
        id: raw.node_id,
        type: raw.node_type,
        org: raw.org_id,
        props: raw.properties,
        x: W / 2 + Math.cos(angle) * r * (0.5 + Math.random() * 0.5),
        y: H / 2 + Math.sin(angle) * r * (0.5 + Math.random() * 0.5),
        vx: (Math.random() - 0.5) * 2,
        vy: (Math.random() - 0.5) * 2,
        baseRadius: raw.node_type.toLowerCase().includes("cve")    ? 6
                  : raw.node_type.toLowerCase().includes("finding") ? 7
                  : raw.node_type.toLowerCase().includes("asset")   ? 9
                  : 5,
        radius: 6,
        phase: Math.random() * Math.PI * 2,
        color: col.fill,
        glowColor: col.glow,
      };
    });

    // Build edges: connect same-org nodes with probability, max 3 per node
    const edges: SimEdge[] = [];
    const edgeCount = new Map<string, number>();
    for (let i = 0; i < newNodes.length; i++) {
      for (let j = i + 1; j < newNodes.length; j++) {
        const a = newNodes[i];
        const b = newNodes[j];
        if ((edgeCount.get(a.id) ?? 0) >= 3) continue;
        if ((edgeCount.get(b.id) ?? 0) >= 3) continue;
        const sameOrg = a.org === b.org;
        const prob = sameOrg ? 0.04 : 0.005;
        if (Math.random() < prob) {
          edges.push({ source: a.id, target: b.id, pulseOffset: Math.random() });
          edgeCount.set(a.id, (edgeCount.get(a.id) ?? 0) + 1);
          edgeCount.set(b.id, (edgeCount.get(b.id) ?? 0) + 1);
        }
      }
    }

    simNodesRef.current = newNodes;
    simEdgesRef.current = edges;
    setSimReady(true);
  }, [rawNodes, canvasSize]);

  // ── Animation loop ──────────────────────────────────────────────────────────
  useEffect(() => {
    if (!simReady) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let frameCount = 0;

    function loop() {
      const { W, H } = canvasSize();
      if (canvas!.width !== W || canvas!.height !== H) {
        canvas!.width  = W;
        canvas!.height = H;
      }

      const t = (performance.now() - startTimeRef.current) / 1000;

      // Run physics for first 300 frames to settle, then slow-tick for breathing
      if (frameCount < 300 || frameCount % 3 === 0) {
        tick(simNodesRef.current, simEdgesRef.current, W, H);
      }
      frameCount++;

      drawFrame(ctx!, W, H, simNodesRef.current, simEdgesRef.current, t, hoveredId, selectedNode?.id ?? null);
      rafRef.current = requestAnimationFrame(loop);
    }

    rafRef.current = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(rafRef.current);
  }, [simReady, hoveredId, selectedNode, canvasSize]);

  // ── Mouse interaction ───────────────────────────────────────────────────────
  const hitTest = useCallback((clientX: number, clientY: number): SimNode | null => {
    const canvas = canvasRef.current;
    if (!canvas) return null;
    const rect = canvas.getBoundingClientRect();
    const mx = clientX - rect.left;
    const my = clientY - rect.top;
    for (const n of simNodesRef.current) {
      const dx = n.x - mx;
      const dy = n.y - my;
      if (dx * dx + dy * dy <= (n.radius + 8) * (n.radius + 8)) return n;
    }
    return null;
  }, []);

  const handleMouseMove = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      setMousePos({ x: e.clientX, y: e.clientY });
      const hit = hitTest(e.clientX, e.clientY);
      setHoveredId(hit?.id ?? null);
      if (canvasRef.current) {
        canvasRef.current.style.cursor = hit ? "pointer" : "default";
      }
    },
    [hitTest],
  );

  const handleClick = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      const hit = hitTest(e.clientX, e.clientY);
      setSelectedNode((prev) => (prev?.id === hit?.id ? null : hit));
    },
    [hitTest],
  );

  // ── Derived stats for HUD ───────────────────────────────────────────────────
  const legendItems = useMemo(() => {
    if (!stats) return [];
    return Object.entries(stats.node_types).map(([type, count]) => ({
      type,
      count,
      ...nodeColor(type),
    }));
  }, [stats]);

  const orgItems = useMemo(() => {
    if (!stats) return [];
    return Object.entries(stats.organizations);
  }, [stats]);

  // ── Render ──────────────────────────────────────────────────────────────────
  return (
    <div
      className="flex flex-col"
      style={{
        height: fullscreen ? "100vh" : "calc(100vh - 64px)",
        background: "#050810",
        fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
      }}
    >
      {/* Top bar */}
      <div
        className="flex items-center justify-between px-6 py-3 border-b flex-shrink-0"
        style={{ background: "rgba(8,12,20,0.97)", borderColor: "#1a2540" }}
      >
        <div className="flex items-center gap-3">
          <div className="relative">
            <Brain size={22} className="text-cyan-400" />
            <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
          </div>
          <div>
            <h1 className="text-sm font-bold text-slate-100 tracking-wider uppercase">
              Neural Brain Map
            </h1>
            <p className="text-[10px] text-slate-500 tracking-widest">
              ALDECI · Live Knowledge Graph
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {stats && (
            <div className="flex items-center gap-6 text-xs">
              <Stat icon={<Layers size={12} />} label="Nodes" value={stats.total_nodes.toLocaleString()} color="#00d4ff" />
              <Stat icon={<Network size={12} />} label="Edges" value={stats.total_edges.toLocaleString()} color="#00e676" />
              <Stat icon={<Zap size={12} />}    label="Density" value={(stats.density * 100).toFixed(4) + "%"} color="#b47cff" />
            </div>
          )}
          <div className="flex items-center gap-2">
            <button
              onClick={fetchData}
              className="p-1.5 rounded text-slate-500 hover:text-cyan-400 transition-colors"
              title="Refresh"
            >
              <RefreshCw size={14} />
            </button>
            <button
              onClick={() => setFullscreen((f) => !f)}
              className="p-1.5 rounded text-slate-500 hover:text-cyan-400 transition-colors"
              title={fullscreen ? "Exit fullscreen" : "Fullscreen"}
            >
              {fullscreen ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
            </button>
          </div>
        </div>
      </div>

      {/* Main area */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left HUD panel */}
        <motion.div
          initial={{ x: -20, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          transition={{ delay: 0.2 }}
          className="w-52 flex-shrink-0 flex flex-col gap-4 p-4 border-r overflow-y-auto"
          style={{ background: "rgba(8,12,20,0.95)", borderColor: "#0d1828" }}
        >
          {/* Node type legend */}
          <section>
            <SectionHeader icon={<Activity size={11} />} label="Node Types" />
            <div className="space-y-2 mt-2">
              {legendItems.map(({ type, count, fill, label }) => (
                <LegendDot key={type} color={fill} label={label ?? type} count={count} />
              ))}
            </div>
          </section>

          {/* Orgs */}
          {orgItems.length > 0 && (
            <section>
              <SectionHeader icon={<Shield size={11} />} label="Organizations" />
              <div className="space-y-1.5 mt-2">
                {orgItems.map(([org, count]) => (
                  <div key={org} className="flex items-center justify-between text-xs">
                    <span className="text-slate-500 truncate max-w-[110px]">{org}</span>
                    <span className="text-slate-400 tabular-nums">{count}</span>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Physics info */}
          <section>
            <SectionHeader icon={<Cpu size={11} />} label="Simulation" />
            <div className="space-y-1 mt-2 text-[10px] text-slate-600">
              <div className="flex justify-between">
                <span>Rendered nodes</span>
                <span className="text-slate-400">{Math.min(rawNodes.length, 300)}</span>
              </div>
              <div className="flex justify-between">
                <span>Synapses</span>
                <span className="text-slate-400">{simEdgesRef.current.length}</span>
              </div>
              <div className="flex justify-between">
                <span>Engine</span>
                <span className="text-slate-400">Canvas 2D</span>
              </div>
            </div>
          </section>

          {/* Instructions */}
          <section className="mt-auto">
            <div className="text-[10px] text-slate-600 space-y-1 leading-relaxed">
              <p><span className="text-slate-500">Hover</span> — node detail</p>
              <p><span className="text-slate-500">Click</span> — pin detail panel</p>
            </div>
          </section>
        </motion.div>

        {/* Canvas */}
        <div ref={containerRef} className="relative flex-1 overflow-hidden">
          {/* Loading overlay */}
          <AnimatePresence>
            {loading && (
              <motion.div
                initial={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="absolute inset-0 flex flex-col items-center justify-center z-10"
                style={{ background: "#050810" }}
              >
                <div className="relative mb-6">
                  <Brain size={48} className="text-cyan-500 opacity-60" />
                  <motion.div
                    animate={{ rotate: 360 }}
                    transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                    className="absolute inset-0 rounded-full border-t-2 border-cyan-400"
                  />
                </div>
                <p className="text-xs text-slate-500 tracking-widest uppercase">
                  Mapping neural connections…
                </p>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Error overlay */}
          {error && !loading && (
            <div className="absolute inset-0 flex flex-col items-center justify-center z-10">
              <AlertTriangle size={36} className="text-red-500 mb-3" />
              <p className="text-sm text-red-400 mb-4">{error}</p>
              <button
                onClick={fetchData}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium border transition-colors"
                style={{
                  borderColor: "#ff4d4d44",
                  background: "#ff4d4d11",
                  color: "#ff8080",
                }}
              >
                <RefreshCw size={12} /> Retry
              </button>
            </div>
          )}

          {/* Empty state */}
          {!loading && !error && rawNodes.length === 0 && (
            <div className="absolute inset-0 flex flex-col items-center justify-center z-10">
              <Brain size={48} className="text-slate-700 mb-4" />
              <p className="text-sm text-slate-600">No brain nodes found.</p>
              <p className="text-xs text-slate-700 mt-1">
                Ingest events into the brain pipeline to populate the graph.
              </p>
            </div>
          )}

          <canvas
            ref={canvasRef}
            className="w-full h-full block"
            onMouseMove={handleMouseMove}
            onClick={handleClick}
            onMouseLeave={() => setHoveredId(null)}
          />

          {/* Node detail panel (pinned on click) */}
          <NodeDetailPanel node={selectedNode} onClose={() => setSelectedNode(null)} />

          {/* Hover tooltip (follows cursor) */}
          {hoveredId && !selectedNode && (
            <HoverTooltip
              node={simNodesRef.current.find((n) => n.id === hoveredId) ?? null}
              mouseX={mousePos.x}
              mouseY={mousePos.y}
            />
          )}

          {/* Live indicator */}
          <div
            className="absolute bottom-4 left-4 flex items-center gap-2 px-3 py-1.5 rounded-full text-[10px] border"
            style={{
              background: "rgba(8,12,20,0.85)",
              borderColor: "#0d2040",
              color: "#4ade80",
            }}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
            LIVE · {simNodesRef.current.length} neurons active
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Small helpers ─────────────────────────────────────────────────────────────
function Stat({
  icon,
  label,
  value,
  color,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  color: string;
}) {
  return (
    <div className="flex items-center gap-1.5">
      <span style={{ color }}>{icon}</span>
      <span className="text-slate-600">{label}</span>
      <span className="font-bold" style={{ color }}>
        {value}
      </span>
    </div>
  );
}

function SectionHeader({ icon, label }: { icon: React.ReactNode; label: string }) {
  return (
    <div className="flex items-center gap-1.5 text-[10px] text-slate-600 uppercase tracking-widest border-b pb-1.5" style={{ borderColor: "#0d1828" }}>
      <span className="text-cyan-700">{icon}</span>
      {label}
      <ChevronRight size={9} className="ml-auto" />
    </div>
  );
}
