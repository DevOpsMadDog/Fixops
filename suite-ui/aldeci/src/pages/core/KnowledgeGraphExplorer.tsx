import { useEffect, useState, useCallback, useRef } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Skeleton } from '@/components/ui/skeleton';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'sonner';
import {
  Search, RefreshCw, Filter, Download,
  Network, Share2, Eye, EyeOff, Info, ChevronRight,
} from 'lucide-react';
import { api } from '../../lib/api';

interface GraphNode {
  id: string;
  type: string;
  properties: Record<string, unknown>;
  connections: number;
}

interface GraphEdge {
  source: string;
  target: string;
  relationship: string;
  weight?: number;
}

interface GraphStats {
  total_nodes: number;
  total_edges: number;
  node_types: Record<string, number>;
  edge_types: Record<string, number>;
  density: number;
  avg_connections: number;
}

// Canvas colors by node type
const nodeCanvasColors: Record<string, string> = {
  CVE: '#ef4444', CWE: '#f97316', Asset: '#3b82f6', Finding: '#eab308',
  Remediation: '#22c55e', Attack: '#a855f7', Evidence: '#06b6d4',
  User: '#6366f1', Scan: '#ec4899', Policy: '#10b981',
  exposure_case: '#f59e0b', scan: '#ec4899', cve: '#ef4444',
  finding: '#eab308', asset: '#3b82f6', remediation: '#22c55e',
};

const nodeTypeColors: Record<string, string> = {
  CVE: 'bg-red-500/20 text-red-400 border-red-500/30',
  CWE: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  Asset: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  Finding: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  Remediation: 'bg-green-500/20 text-green-400 border-green-500/30',
  Attack: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  Evidence: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  User: 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30',
  Scan: 'bg-pink-500/20 text-pink-400 border-pink-500/30',
  Policy: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
};

// ── Force-directed graph on canvas ──
interface SimNode {
  id: string;
  type: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  connections: number;
  properties: Record<string, unknown>;
  highlighted?: boolean;
}
interface SimEdge { source: string; target: string; relationship: string; }

function ForceGraph({
  nodes,
  edges,
  onSelectNode,
  highlightIds,
  showLabels,
}: {
  nodes: GraphNode[];
  edges: GraphEdge[];
  onSelectNode: (n: GraphNode) => void;
  highlightIds: Set<string>;
  showLabels: boolean;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const simNodesRef = useRef<SimNode[]>([]);
  const simEdgesRef = useRef<SimEdge[]>([]);
  const animRef = useRef<number>(0);
  const dragRef = useRef<{ nodeIdx: number; offsetX: number; offsetY: number } | null>(null);
  const panRef = useRef({ x: 0, y: 0 });
  const zoomRef = useRef(1);
  const isPanningRef = useRef(false);
  const lastMouseRef = useRef({ x: 0, y: 0 });
  const hoveredRef = useRef<number>(-1);
  const sizeRef = useRef({ w: 900, h: 600 });

  // Resize canvas to fill container
  useEffect(() => {
    const container = containerRef.current;
    const canvas = canvasRef.current;
    if (!container || !canvas) return;

    const observer = new ResizeObserver(entries => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect;
        const dpr = window.devicePixelRatio || 1;
        canvas.width = width * dpr;
        canvas.height = height * dpr;
        canvas.style.width = `${width}px`;
        canvas.style.height = `${height}px`;
        const ctx = canvas.getContext('2d');
        if (ctx) ctx.scale(dpr, dpr);
        sizeRef.current = { w: width, h: height };
      }
    });
    observer.observe(container);
    return () => observer.disconnect();
  }, []);

  // Initialize simulation nodes
  useEffect(() => {
    const { w, h } = sizeRef.current;
    simNodesRef.current = nodes.map((n, i) => ({
      id: n.id, type: n.type, connections: n.connections, properties: n.properties,
      x: w / 2 + (Math.cos(i * 2.399) * Math.min(w, h) * 0.3) + (Math.random() - 0.5) * 100,
      y: h / 2 + (Math.sin(i * 2.399) * Math.min(w, h) * 0.3) + (Math.random() - 0.5) * 100,
      vx: 0, vy: 0,
      highlighted: highlightIds.has(n.id),
    }));
    simEdgesRef.current = edges.map(e => ({ source: e.source, target: e.target, relationship: e.relationship }));
  }, [nodes, edges, highlightIds]);

  // Physics + render loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    let running = true;
    const dpr = window.devicePixelRatio || 1;

    const tick = () => {
      if (!running) return;
      const sn = simNodesRef.current;
      const se = simEdgesRef.current;
      const { w, h } = sizeRef.current;
      if (sn.length === 0) { animRef.current = requestAnimationFrame(tick); return; }

      // Physics: repulsion
      for (let i = 0; i < sn.length; i++) {
        for (let j = i + 1; j < sn.length; j++) {
          const dx = sn[j].x - sn[i].x, dy = sn[j].y - sn[i].y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const force = 3000 / (dist * dist);
          const fx = (dx / dist) * force, fy = (dy / dist) * force;
          sn[i].vx -= fx; sn[i].vy -= fy;
          sn[j].vx += fx; sn[j].vy += fy;
        }
      }

      // Physics: attraction along edges
      const idxMap = new Map(sn.map((n, i) => [n.id, i]));
      for (const e of se) {
        const si = idxMap.get(e.source), ti = idxMap.get(e.target);
        if (si === undefined || ti === undefined) continue;
        const dx = sn[ti].x - sn[si].x, dy = sn[ti].y - sn[si].y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = (dist - 120) * 0.01;
        const fx = (dx / dist) * force, fy = (dy / dist) * force;
        sn[si].vx += fx; sn[si].vy += fy;
        sn[ti].vx -= fx; sn[ti].vy -= fy;
      }

      // Center gravity
      const cx = w / 2, cy = h / 2;
      for (const n of sn) {
        n.vx += (cx - n.x) * 0.001;
        n.vy += (cy - n.y) * 0.001;
        n.vx *= 0.9; n.vy *= 0.9;
        if (dragRef.current === null || sn[dragRef.current.nodeIdx] !== n) {
          n.x += n.vx; n.y += n.vy;
        }
      }

      // Render
      ctx.save();
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);

      // Draw subtle grid
      ctx.strokeStyle = 'rgba(100,116,139,0.06)';
      ctx.lineWidth = 1;
      const gridSize = 40 * zoomRef.current;
      const offsetX = panRef.current.x % gridSize;
      const offsetY = panRef.current.y % gridSize;
      for (let x = offsetX; x < w; x += gridSize) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
      }
      for (let y = offsetY; y < h; y += gridSize) {
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
      }

      ctx.translate(panRef.current.x, panRef.current.y);
      ctx.scale(zoomRef.current, zoomRef.current);

      // Draw edges
      for (const e of se) {
        const si = idxMap.get(e.source), ti = idxMap.get(e.target);
        if (si === undefined || ti === undefined) continue;
        const sNode = sn[si], tNode = sn[ti];
        const isHighlighted = sNode.highlighted || tNode.highlighted;

        ctx.beginPath();
        ctx.moveTo(sNode.x, sNode.y);
        ctx.lineTo(tNode.x, tNode.y);
        ctx.strokeStyle = isHighlighted ? 'rgba(99,102,241,0.5)' : 'rgba(100,116,139,0.18)';
        ctx.lineWidth = isHighlighted ? 2 : 1;
        ctx.stroke();

        // Edge label at midpoint
        if (showLabels) {
          const mx = (sNode.x + tNode.x) / 2, my = (sNode.y + tNode.y) / 2;
          ctx.fillStyle = isHighlighted ? 'rgba(99,102,241,0.7)' : 'rgba(148,163,184,0.4)';
          ctx.font = '8px system-ui, sans-serif';
          ctx.textAlign = 'center';
          ctx.fillText(e.relationship, mx, my - 3);
        }
      }

      // Draw nodes
      for (let i = 0; i < sn.length; i++) {
        const n = sn[i];
        const r = Math.max(8, Math.min(24, 6 + n.connections * 2));
        const nType = n.type || 'unknown';
        const color = nodeCanvasColors[nType] || nodeCanvasColors[nType.toLowerCase()] || '#64748b';
        const isHovered = i === hoveredRef.current;
        const isHighlighted = n.highlighted;

        // Glow effect for highlighted/hovered nodes
        if (isHighlighted || isHovered) {
          const glowSize = isHovered ? r + 10 : r + 6;
          const gradient = ctx.createRadialGradient(n.x, n.y, r * 0.5, n.x, n.y, glowSize);
          gradient.addColorStop(0, color + '44');
          gradient.addColorStop(1, color + '00');
          ctx.beginPath(); ctx.arc(n.x, n.y, glowSize, 0, Math.PI * 2);
          ctx.fillStyle = gradient; ctx.fill();
        }

        // Node circle with gradient
        const gradient = ctx.createRadialGradient(n.x - r * 0.3, n.y - r * 0.3, r * 0.1, n.x, n.y, r);
        gradient.addColorStop(0, color + 'ee');
        gradient.addColorStop(1, color + '99');
        ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.fillStyle = gradient; ctx.fill();
        ctx.strokeStyle = isHighlighted ? '#6366f1' : color;
        ctx.lineWidth = isHighlighted ? 3 : 2; ctx.stroke();

        // Label
        if (showLabels || isHovered || isHighlighted) {
          ctx.fillStyle = '#e2e8f0';
          ctx.font = `${isHovered ? 'bold 11px' : '9px'} system-ui, sans-serif`;
          ctx.textAlign = 'center';
          const nId = n.id || 'unknown';
          const label = nId.length > 22 ? nId.slice(0, 20) + '…' : nId;
          ctx.fillText(label, n.x, n.y + r + 14);
        }

        // Type badge inside node
        ctx.fillStyle = '#ffffffdd';
        ctx.font = 'bold 7px system-ui, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(nType.toUpperCase(), n.x, n.y + 3);
      }

      ctx.restore();
      animRef.current = requestAnimationFrame(tick);
    };

    animRef.current = requestAnimationFrame(tick);
    return () => { running = false; cancelAnimationFrame(animRef.current); };
  }, [nodes, edges, showLabels]);

  // Mouse handlers
  const getCanvasPos = (e: React.MouseEvent) => {
    const rect = canvasRef.current!.getBoundingClientRect();
    return {
      x: (e.clientX - rect.left - panRef.current.x) / zoomRef.current,
      y: (e.clientY - rect.top - panRef.current.y) / zoomRef.current,
    };
  };

  const findNode = (mx: number, my: number) => {
    const sn = simNodesRef.current;
    for (let i = sn.length - 1; i >= 0; i--) {
      const r = Math.max(8, Math.min(24, 6 + sn[i].connections * 2));
      const dx = mx - sn[i].x, dy = my - sn[i].y;
      if (dx * dx + dy * dy < (r + 4) * (r + 4)) return i;
    }
    return -1;
  };

  const onMouseDown = (e: React.MouseEvent) => {
    const pos = getCanvasPos(e);
    const idx = findNode(pos.x, pos.y);
    if (idx >= 0) {
      dragRef.current = { nodeIdx: idx, offsetX: pos.x - simNodesRef.current[idx].x, offsetY: pos.y - simNodesRef.current[idx].y };
    } else {
      isPanningRef.current = true;
      lastMouseRef.current = { x: e.clientX, y: e.clientY };
    }
  };

  const onMouseMove = (e: React.MouseEvent) => {
    if (dragRef.current) {
      const pos = getCanvasPos(e);
      const n = simNodesRef.current[dragRef.current.nodeIdx];
      n.x = pos.x - dragRef.current.offsetX;
      n.y = pos.y - dragRef.current.offsetY;
      n.vx = 0; n.vy = 0;
    } else if (isPanningRef.current) {
      panRef.current.x += e.clientX - lastMouseRef.current.x;
      panRef.current.y += e.clientY - lastMouseRef.current.y;
      lastMouseRef.current = { x: e.clientX, y: e.clientY };
    } else {
      const pos = getCanvasPos(e);
      hoveredRef.current = findNode(pos.x, pos.y);
      canvasRef.current!.style.cursor = hoveredRef.current >= 0 ? 'pointer' : 'grab';
    }
  };

  const onMouseUp = () => {
    if (dragRef.current) {
      const n = simNodesRef.current[dragRef.current.nodeIdx];
      onSelectNode({ id: n.id, type: n.type, connections: n.connections, properties: n.properties });
    }
    dragRef.current = null;
    isPanningRef.current = false;
  };

  const onWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const scale = e.deltaY > 0 ? 0.92 : 1.08;
    zoomRef.current = Math.max(0.2, Math.min(4, zoomRef.current * scale));
  };

  return (
    <div ref={containerRef} className="w-full h-[500px] relative">
      <canvas
        ref={canvasRef}
        className="w-full h-full rounded-xl"
        onMouseDown={onMouseDown}
        onMouseMove={onMouseMove}
        onMouseUp={onMouseUp}
        onMouseLeave={onMouseUp}
        onWheel={onWheel}
        role="img"
        aria-label="Interactive knowledge graph visualization showing relationships between security entities"
      />

      {/* Minimap */}
      <div className="absolute bottom-3 right-3 w-32 h-20 rounded-lg border border-border/40 bg-background/60 backdrop-blur-sm overflow-hidden pointer-events-none">
        <svg viewBox={`0 0 ${sizeRef.current.w} ${sizeRef.current.h}`} className="w-full h-full">
          {simEdgesRef.current.map((e, i) => {
            const sn = simNodesRef.current;
            const idxMap = new Map(sn.map((n, idx) => [n.id, idx]));
            const si = idxMap.get(e.source), ti = idxMap.get(e.target);
            if (si === undefined || ti === undefined) return null;
            return (
              <line
                key={i}
                x1={sn[si].x} y1={sn[si].y}
                x2={sn[ti].x} y2={sn[ti].y}
                stroke="rgba(100,116,139,0.2)" strokeWidth={2}
              />
            );
          })}
          {simNodesRef.current.map(n => {
            const color = nodeCanvasColors[n.type] || nodeCanvasColors[n.type?.toLowerCase()] || '#64748b';
            return (
              <circle
                key={n.id}
                cx={n.x} cy={n.y} r={4}
                fill={color}
                opacity={0.8}
              />
            );
          })}
          {/* Viewport indicator */}
          <rect
            x={-panRef.current.x / zoomRef.current}
            y={-panRef.current.y / zoomRef.current}
            width={sizeRef.current.w / zoomRef.current}
            height={sizeRef.current.h / zoomRef.current}
            fill="none"
            stroke="rgba(99,102,241,0.5)"
            strokeWidth={4}
            rx={4}
          />
        </svg>
      </div>
    </div>
  );
}

// ── Loading Skeleton ──
function GraphSkeleton() {
  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div className="space-y-2">
          <Skeleton className="h-8 w-72" />
          <Skeleton className="h-4 w-96" />
        </div>
        <Skeleton className="h-9 w-24" />
      </div>
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-20 rounded-lg" />
        ))}
      </div>
      <Skeleton className="h-10 w-full" />
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          <Skeleton className="h-[500px] rounded-xl" />
        </div>
        <div className="space-y-4">
          <Skeleton className="h-40 rounded-lg" />
          <Skeleton className="h-60 rounded-lg" />
        </div>
      </div>
    </div>
  );
}

const KnowledgeGraphExplorer = () => {
  const [stats, setStats] = useState<GraphStats | null>(null);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [neighbors, setNeighbors] = useState<GraphNode[]>([]);
  const [loading, setLoading] = useState(true);
  const [nodeTypeFilter, setNodeTypeFilter] = useState<string>('all');
  const [showLabels, setShowLabels] = useState(true);
  const [highlightIds, setHighlightIds] = useState<Set<string>>(new Set());

  // Map API node (node_id, node_type) to GraphNode (id, type)
  const mapNode = (n: Record<string, unknown>): GraphNode => ({
    id: (n.node_id || n.id || 'unknown') as string,
    type: (n.node_type || n.type || 'unknown') as string,
    properties: (n.properties || {}) as Record<string, unknown>,
    connections: typeof n.connections === 'number' ? n.connections : 0,
  });

  // Map API edge (edge_type) to GraphEdge (relationship)
  const mapEdge = (e: Record<string, unknown>): GraphEdge => ({
    source: (e.source || '') as string,
    target: (e.target || '') as string,
    relationship: (e.edge_type || e.relationship || 'related') as string,
    weight: typeof e.weight === 'number' ? e.weight : (typeof e.confidence === 'number' ? e.confidence : 1),
  });

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [statsRes, nodesRes, edgesRes] = await Promise.all([
        api.get('/api/v1/brain/stats').catch(() => ({ data: { total_nodes: 0, total_edges: 0, node_types: {}, edge_types: {}, density: 0, avg_connections: 0 } })),
        api.get('/api/v1/brain/nodes', { params: { limit: 200 } }).catch(() => ({ data: { nodes: [] } })),
        api.get('/api/v1/brain/all-edges', { params: { limit: 500 } }).catch(() => ({ data: { edges: [] } })),
      ]);
      setStats(statsRes.data);
      const rawNodes = (nodesRes.data?.nodes || []) as Record<string, unknown>[];
      const rawEdges = (edgesRes.data?.edges || []) as Record<string, unknown>[];
      const mappedEdges = rawEdges.map(mapEdge);
      // Compute connection counts from edges
      const connCounts: Record<string, number> = {};
      for (const e of mappedEdges) {
        connCounts[e.source] = (connCounts[e.source] || 0) + 1;
        connCounts[e.target] = (connCounts[e.target] || 0) + 1;
      }
      const mappedNodes = rawNodes.map(n => {
        const node = mapNode(n);
        node.connections = connCounts[node.id] || node.connections || 0;
        return node;
      });
      setNodes(mappedNodes);
      setEdges(mappedEdges);
      toast.success(`Loaded ${mappedNodes.length} nodes, ${mappedEdges.length} edges`);
    } catch (e) {
      console.error('Brain fetch error', e);
      toast.error('Failed to load knowledge graph data');
    }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleSearch = async () => {
    if (!searchQuery.trim()) {
      setHighlightIds(new Set());
      return;
    }
    try {
      const res = await api.get('/api/v1/brain/search', { params: { query: searchQuery, limit: 50 } });
      const raw = (res.data?.results || res.data?.nodes || []) as Record<string, unknown>[];
      const searchNodes = raw.map(mapNode);
      // Highlight matching nodes on the existing graph
      const matchIds = new Set(searchNodes.map(n => n.id));
      setHighlightIds(matchIds);
      if (searchNodes.length > 0) {
        toast.success(`Found ${searchNodes.length} matching entities`);
      } else {
        toast.info('No matching entities found');
      }
    } catch (e) {
      console.error('Search error', e);
      toast.error('Search failed');
    }
  };

  const handleSelectNode = async (node: GraphNode) => {
    setSelectedNode(node);
    // Highlight selected node and its neighbors
    const newHighlight = new Set<string>([node.id]);
    if (!node.id) { setNeighbors([]); return; }
    try {
      const res = await api.get(`/api/v1/brain/nodes/${encodeURIComponent(node.id)}/neighbors`).catch(() => ({ data: { neighbors: [] } }));
      const raw = (res.data?.neighbors || res.data?.nodes || []) as Record<string, unknown>[];
      const neighborNodes = raw.map(mapNode);
      setNeighbors(neighborNodes);
      neighborNodes.forEach(n => newHighlight.add(n.id));
      setHighlightIds(newHighlight);
    } catch (e) {
      console.error('Neighbors error', e);
    }
  };

  const handleExportGraph = () => {
    const exportData = {
      nodes: nodes.map(n => ({ id: n.id, type: n.type, connections: n.connections })),
      edges: edges.map(e => ({ source: e.source, target: e.target, relationship: e.relationship })),
      stats,
      exported_at: new Date().toISOString(),
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `knowledge-graph-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Graph exported successfully');
  };

  const filteredNodes = nodeTypeFilter === 'all' ? nodes : nodes.filter(n => n.type === nodeTypeFilter);

  if (loading) return <GraphSkeleton />;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-violet-400 to-purple-500 bg-clip-text text-transparent">
            Knowledge Graph Explorer
          </h1>
          <p className="text-muted-foreground mt-1">
            Explore interconnected security intelligence — entities, relationships, and patterns
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={handleExportGraph} aria-label="Export graph data">
            <Download className="w-4 h-4 mr-1.5" />
            Export
          </Button>
          <Button variant="outline" size="sm" onClick={fetchData} aria-label="Refresh graph data">
            <RefreshCw className="w-4 h-4 mr-1.5" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        {[
          { label: 'Total Nodes', value: stats?.total_nodes ?? 0, color: 'text-blue-400', icon: Network },
          { label: 'Total Edges', value: stats?.total_edges ?? 0, color: 'text-purple-400', icon: Share2 },
          { label: 'Node Types', value: Object.keys(stats?.node_types || {}).length, color: 'text-green-400', icon: Filter },
          { label: 'Edge Types', value: Object.keys(stats?.edge_types || {}).length, color: 'text-yellow-400', icon: Share2 },
          { label: 'Density', value: (stats?.density ?? 0).toFixed(4), color: 'text-cyan-400', icon: Info },
          { label: 'Avg Connections', value: (stats?.avg_connections ?? 0).toFixed(1), color: 'text-pink-400', icon: Network },
        ].map((s, i) => (
          <motion.div key={i} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04, ease: [0.16, 1, 0.3, 1] }}>
            <Card className="border-border/50 bg-card/50 hover:bg-card/80 transition-colors">
              <CardContent className="pt-4 pb-3">
                <div className="flex items-center justify-between mb-1">
                  <s.icon className={`w-4 h-4 ${s.color} opacity-60`} />
                </div>
                <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
                <div className="text-xs text-muted-foreground">{s.label}</div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Search + Controls */}
      <div className="flex gap-2 items-center">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search entities by ID, type, or property..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSearch()}
            className="pl-10"
            aria-label="Search knowledge graph entities"
          />
        </div>
        <Button onClick={handleSearch} aria-label="Search">
          <Search className="w-4 h-4 mr-1.5" />
          Search
        </Button>
        {highlightIds.size > 0 && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => { setHighlightIds(new Set()); setSearchQuery(''); }}
            aria-label="Clear search highlights"
          >
            Clear
          </Button>
        )}
        <Button
          variant="outline"
          size="icon"
          className="h-9 w-9"
          onClick={() => setShowLabels(prev => !prev)}
          aria-label={showLabels ? 'Hide labels' : 'Show labels'}
          title={showLabels ? 'Hide labels' : 'Show labels'}
        >
          {showLabels ? <Eye className="w-4 h-4" /> : <EyeOff className="w-4 h-4" />}
        </Button>
      </div>

      {/* Main Content */}
      <Tabs defaultValue="graph" className="space-y-4">
        <TabsList>
          <TabsTrigger value="graph" aria-label="Live graph view">
            <Network className="w-4 h-4 mr-1.5" />
            Live Graph
          </TabsTrigger>
          <TabsTrigger value="nodes" aria-label={`Nodes tab - ${filteredNodes.length} items`}>
            Nodes ({filteredNodes.length})
          </TabsTrigger>
          <TabsTrigger value="relationships" aria-label={`Relationships tab - ${edges.length} items`}>
            Relationships ({edges.length})
          </TabsTrigger>
          <TabsTrigger value="types" aria-label="Type distribution view">
            Type Distribution
          </TabsTrigger>
          {selectedNode && <TabsTrigger value="detail">Node Detail</TabsTrigger>}
        </TabsList>

        <TabsContent value="graph">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2">
              <Card className="border-border/50 bg-card/50 overflow-hidden">
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <span className="inline-block w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                      Force-Directed Graph
                    </CardTitle>
                    <div className="flex items-center gap-1 text-[10px] text-muted-foreground">
                      <span>drag nodes</span>
                      <span className="text-muted-foreground/40">·</span>
                      <span>scroll to zoom</span>
                      <span className="text-muted-foreground/40">·</span>
                      <span>pan background</span>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="p-2">
                  {nodes.length === 0 ? (
                    <div className="h-[500px] flex flex-col items-center justify-center text-center">
                      <Network className="w-16 h-16 text-muted-foreground/20 mb-4" />
                      <p className="text-muted-foreground font-medium">No graph data yet</p>
                      <p className="text-sm text-muted-foreground/60 mt-1 max-w-md">
                        Run scans or ingest findings to populate the knowledge graph.
                        Entities and their relationships will appear here automatically.
                      </p>
                      <Button variant="outline" className="mt-4" onClick={fetchData}>
                        <RefreshCw className="w-4 h-4 mr-1.5" />
                        Refresh
                      </Button>
                    </div>
                  ) : (
                    <ForceGraph
                      nodes={nodes}
                      edges={edges}
                      onSelectNode={handleSelectNode}
                      highlightIds={highlightIds}
                      showLabels={showLabels}
                    />
                  )}
                </CardContent>
              </Card>
              {/* Legend */}
              <div className="flex flex-wrap gap-2 mt-3">
                {Object.entries(nodeCanvasColors).filter(([k]) => k.charAt(0) === k.charAt(0).toUpperCase()).map(([type, color]) => (
                  <button
                    key={type}
                    className={`flex items-center gap-1.5 text-xs px-2 py-1 rounded-md transition-colors ${
                      nodeTypeFilter === type
                        ? 'bg-primary/10 text-primary border border-primary/20'
                        : 'text-muted-foreground hover:text-foreground hover:bg-muted/30'
                    }`}
                    onClick={() => setNodeTypeFilter(nodeTypeFilter === type ? 'all' : type)}
                    aria-label={`Filter by ${type} nodes`}
                  >
                    <span className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} /> {type}
                  </button>
                ))}
              </div>
            </div>
            <div className="space-y-4">
              <AnimatePresence mode="wait">
                {selectedNode ? (
                  <motion.div key="selected" initial={{ opacity: 0, x: 12 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -12 }}>
                    <Card className="border-border/50 border-l-2 border-l-primary">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm flex items-center gap-2">
                          <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
                          Selected Entity
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <Badge className={nodeTypeColors[selectedNode.type] || 'bg-gray-500/20 text-gray-400'}>{selectedNode.type}</Badge>
                        <div className="font-mono text-sm mt-2 text-foreground break-all">{selectedNode.id}</div>
                        <div className="text-xs text-muted-foreground mt-1">{selectedNode.connections} connections</div>
                        <div className="mt-3 space-y-1">
                          {Object.entries(selectedNode.properties || {}).slice(0, 10).map(([k, v]) => (
                            <div key={k} className="flex justify-between text-xs border-b border-border/20 py-1">
                              <span className="text-muted-foreground">{k}</span>
                              <span className="font-mono text-foreground truncate ml-2 max-w-[140px]">{String(v)}</span>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                    <Card className="border-border/50 mt-4">
                      <CardHeader className="pb-2"><CardTitle className="text-sm">Neighbors ({neighbors.length})</CardTitle></CardHeader>
                      <CardContent className="max-h-64 overflow-y-auto">
                        {neighbors.map(n => (
                          <div
                            key={n.id}
                            className="p-2 hover:bg-card/60 rounded cursor-pointer text-xs flex items-center gap-2 group"
                            onClick={() => handleSelectNode(n)}
                          >
                            <Badge className={`text-[9px] ${nodeTypeColors[n.type] || 'bg-gray-500/20'}`}>{n.type}</Badge>
                            <span className="truncate text-foreground flex-1">{n.id}</span>
                            <ChevronRight className="w-3 h-3 opacity-0 group-hover:opacity-100 text-muted-foreground transition-opacity" />
                          </div>
                        ))}
                        {neighbors.length === 0 && <div className="text-xs text-muted-foreground text-center py-4">No neighbors found</div>}
                      </CardContent>
                    </Card>
                  </motion.div>
                ) : (
                  <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                    <Card className="border-border/50">
                      <CardContent className="pt-8 pb-8 text-center text-muted-foreground text-sm">
                        <Network className="w-12 h-12 mx-auto mb-3 text-muted-foreground/20" />
                        <p className="font-medium mb-1">Select a Node</p>
                        <p className="text-xs text-muted-foreground/60">
                          Click or drag a node on the graph to inspect its properties and connections.
                        </p>
                      </CardContent>
                    </Card>
                  </motion.div>
                )}
              </AnimatePresence>
              {/* Node type breakdown */}
              <Card className="border-border/50">
                <CardHeader className="pb-2"><CardTitle className="text-sm">Entity Breakdown</CardTitle></CardHeader>
                <CardContent className="space-y-1.5">
                  {Object.entries(stats?.node_types || {}).sort(([, a], [, b]) => (b as number) - (a as number)).map(([type, count]) => {
                    const total = stats?.total_nodes || 1;
                    const pct = ((count as number) / total * 100);
                    return (
                      <div key={type} className="space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <div className="flex items-center gap-1.5">
                            <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: nodeCanvasColors[type] || nodeCanvasColors[(type || '').toLowerCase()] || '#64748b' }} />
                            <span className="text-foreground capitalize">{type}</span>
                          </div>
                          <span className="font-mono text-muted-foreground">{String(count)}</span>
                        </div>
                        {/* Progress bar */}
                        <div className="h-1 bg-muted/30 rounded-full overflow-hidden">
                          <motion.div
                            className="h-full rounded-full"
                            style={{ backgroundColor: nodeCanvasColors[type] || '#64748b' }}
                            initial={{ width: 0 }}
                            animate={{ width: `${pct}%` }}
                            transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
                          />
                        </div>
                      </div>
                    );
                  })}
                  {Object.keys(stats?.node_types || {}).length === 0 && (
                    <div className="text-xs text-muted-foreground text-center py-4">No entities found</div>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="nodes">
          {/* Type filter chips */}
          <div className="flex flex-wrap gap-2 mb-4">
            <Badge className={`cursor-pointer ${nodeTypeFilter === 'all' ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'}`} onClick={() => setNodeTypeFilter('all')}>All</Badge>
            {Object.keys(stats?.node_types || {}).map(t => (
              <Badge key={t} className={`cursor-pointer ${nodeTypeFilter === t ? 'bg-primary text-primary-foreground' : (nodeTypeColors[t] || 'bg-muted text-muted-foreground')}`} onClick={() => setNodeTypeFilter(t)}>
                {t} ({(stats?.node_types || {})[t]})
              </Badge>
            ))}
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {filteredNodes.slice(0, 60).map((node, i) => (
              <motion.div key={node.id} initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: i * 0.02 }}>
                <Card
                  className={`border-border/50 cursor-pointer hover:bg-card/80 transition-colors ${selectedNode?.id === node.id ? 'ring-2 ring-primary' : ''}`}
                  onClick={() => handleSelectNode(node)}
                  tabIndex={0}
                  onKeyDown={e => e.key === 'Enter' && handleSelectNode(node)}
                  role="button"
                  aria-label={`${node.type} node: ${node.id}`}
                >
                  <CardContent className="pt-4 pb-3">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge className={nodeTypeColors[node.type] || 'bg-gray-500/20 text-gray-400'}>{node.type}</Badge>
                      <span className="text-xs text-muted-foreground">{node.connections} connections</span>
                    </div>
                    <div className="text-sm font-medium truncate text-foreground">{node.id}</div>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>
          {filteredNodes.length === 0 && (
            <div className="text-center py-12">
              <Network className="w-12 h-12 mx-auto text-muted-foreground/20 mb-3" />
              <p className="text-muted-foreground">No nodes found</p>
            </div>
          )}
        </TabsContent>

        <TabsContent value="relationships">
          <Card className="border-border/50">
            <CardHeader><CardTitle>Edge Types</CardTitle></CardHeader>
            <CardContent>
              <div className="space-y-2">
                {Object.entries(stats?.edge_types || {}).map(([type, count]) => (
                  <div key={type} className="flex items-center justify-between p-3 border border-border/30 rounded-lg hover:bg-card/60 transition-colors">
                    <div className="flex items-center gap-2">
                      <Share2 className="w-4 h-4 text-muted-foreground" />
                      <span className="text-sm font-medium text-foreground">{type}</span>
                    </div>
                    <Badge variant="outline">{String(count)}</Badge>
                  </div>
                ))}
                {Object.keys(stats?.edge_types || {}).length === 0 && (
                  <div className="text-center py-12">
                    <Share2 className="w-12 h-12 mx-auto text-muted-foreground/20 mb-3" />
                    <p className="text-muted-foreground">No relationships found</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="types">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {Object.entries(stats?.node_types || {}).sort(([, a], [, b]) => (b as number) - (a as number)).map(([type, count], i) => (
              <motion.div key={type} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
                <Card className="border-border/50 bg-card/50 hover:bg-card/80 transition-colors">
                  <CardContent className="pt-5 pb-4 text-center">
                    <div className="w-10 h-10 rounded-lg mx-auto mb-2 flex items-center justify-center" style={{ backgroundColor: (nodeCanvasColors[type] || '#64748b') + '20' }}>
                      <Network className="w-5 h-5" style={{ color: nodeCanvasColors[type] || '#64748b' }} />
                    </div>
                    <div className="text-3xl font-bold text-foreground">{String(count)}</div>
                    <Badge className={`mt-2 ${nodeTypeColors[type] || 'bg-gray-500/20 text-gray-400'}`}>{type}</Badge>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>
          {Object.keys(stats?.node_types || {}).length === 0 && (
            <div className="text-center py-12">
              <Network className="w-12 h-12 mx-auto text-muted-foreground/20 mb-3" />
              <p className="text-muted-foreground">No type distribution data</p>
            </div>
          )}
        </TabsContent>

        {selectedNode && (
          <TabsContent value="detail">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card className="border-border/50">
                <CardHeader><CardTitle>Node Properties</CardTitle></CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 mb-3">
                      <Badge className={nodeTypeColors[selectedNode.type] || 'bg-gray-500/20 text-gray-400'}>{selectedNode.type}</Badge>
                      <span className="font-mono text-sm text-foreground">{selectedNode.id}</span>
                    </div>
                    {Object.entries(selectedNode.properties || {}).map(([k, v]) => (
                      <div key={k} className="flex justify-between py-1.5 border-b border-border/20">
                        <span className="text-sm text-muted-foreground">{k}</span>
                        <span className="text-sm text-foreground font-mono max-w-[200px] truncate">{String(v)}</span>
                      </div>
                    ))}
                    {Object.keys(selectedNode.properties || {}).length === 0 && (
                      <p className="text-sm text-muted-foreground py-4 text-center">No properties available</p>
                    )}
                  </div>
                </CardContent>
              </Card>
              <Card className="border-border/50">
                <CardHeader><CardTitle>Neighbors ({neighbors.length})</CardTitle></CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {neighbors.map(n => (
                      <div key={n.id} className="p-2 border border-border/30 rounded cursor-pointer hover:bg-card/60 transition-colors group flex items-center gap-2" onClick={() => handleSelectNode(n)}>
                        <Badge className={nodeTypeColors[n.type] || 'bg-gray-500/20 text-gray-400'} >{n.type}</Badge>
                        <span className="text-sm truncate text-foreground flex-1">{n.id}</span>
                        <ChevronRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 text-muted-foreground transition-opacity" />
                      </div>
                    ))}
                    {neighbors.length === 0 && <div className="text-center py-4 text-muted-foreground">No neighbors found.</div>}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
};

export default KnowledgeGraphExplorer;
