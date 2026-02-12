import { useEffect, useState, useCallback, useRef } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { motion } from 'framer-motion';
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
interface SimNode { id: string; type: string; x: number; y: number; vx: number; vy: number; connections: number; properties: Record<string, unknown>; }
interface SimEdge { source: string; target: string; relationship: string; }

function ForceGraph({ nodes, edges, onSelectNode }: { nodes: GraphNode[]; edges: GraphEdge[]; onSelectNode: (n: GraphNode) => void }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const simNodesRef = useRef<SimNode[]>([]);
  const simEdgesRef = useRef<SimEdge[]>([]);
  const animRef = useRef<number>(0);
  const dragRef = useRef<{ nodeIdx: number; offsetX: number; offsetY: number } | null>(null);
  const panRef = useRef({ x: 0, y: 0 });
  const zoomRef = useRef(1);
  const isPanningRef = useRef(false);
  const lastMouseRef = useRef({ x: 0, y: 0 });
  const hoveredRef = useRef<number>(-1);

  // Initialize simulation nodes
  useEffect(() => {
    const w = 900, h = 600;
    simNodesRef.current = nodes.map((n, i) => ({
      id: n.id, type: n.type, connections: n.connections, properties: n.properties,
      x: w / 2 + (Math.cos(i * 2.399) * 180) + (Math.random() - 0.5) * 100,
      y: h / 2 + (Math.sin(i * 2.399) * 180) + (Math.random() - 0.5) * 100,
      vx: 0, vy: 0,
    }));
    simEdgesRef.current = edges.map(e => ({ source: e.source, target: e.target, relationship: e.relationship }));
  }, [nodes, edges]);

  // Physics + render loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    let running = true;

    const tick = () => {
      if (!running) return;
      const sn = simNodesRef.current;
      const se = simEdgesRef.current;
      if (sn.length === 0) { animRef.current = requestAnimationFrame(tick); return; }

      // Physics: repulsion
      for (let i = 0; i < sn.length; i++) {
        for (let j = i + 1; j < sn.length; j++) {
          let dx = sn[j].x - sn[i].x, dy = sn[j].y - sn[i].y;
          let dist = Math.sqrt(dx * dx + dy * dy) || 1;
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
        let dx = sn[ti].x - sn[si].x, dy = sn[ti].y - sn[si].y;
        let dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = (dist - 120) * 0.01;
        const fx = (dx / dist) * force, fy = (dy / dist) * force;
        sn[si].vx += fx; sn[si].vy += fy;
        sn[ti].vx -= fx; sn[ti].vy -= fy;
      }

      // Center gravity
      const cx = canvas.width / 2, cy = canvas.height / 2;
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
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.translate(panRef.current.x, panRef.current.y);
      ctx.scale(zoomRef.current, zoomRef.current);

      // Draw edges
      for (const e of se) {
        const si = idxMap.get(e.source), ti = idxMap.get(e.target);
        if (si === undefined || ti === undefined) continue;
        ctx.beginPath();
        ctx.moveTo(sn[si].x, sn[si].y);
        ctx.lineTo(sn[ti].x, sn[ti].y);
        ctx.strokeStyle = 'rgba(100,116,139,0.25)';
        ctx.lineWidth = 1;
        ctx.stroke();
        // Edge label at midpoint
        const mx = (sn[si].x + sn[ti].x) / 2, my = (sn[si].y + sn[ti].y) / 2;
        ctx.fillStyle = 'rgba(148,163,184,0.5)';
        ctx.font = '8px sans-serif';
        ctx.fillText(e.relationship, mx + 2, my - 2);
      }

      // Draw nodes
      for (let i = 0; i < sn.length; i++) {
        const n = sn[i];
        const r = Math.max(8, Math.min(22, 6 + n.connections * 2));
        const nType = n.type || 'unknown';
        const color = nodeCanvasColors[nType] || nodeCanvasColors[nType.toLowerCase()] || '#64748b';
        // Glow for hovered
        if (i === hoveredRef.current) {
          ctx.beginPath(); ctx.arc(n.x, n.y, r + 6, 0, Math.PI * 2);
          ctx.fillStyle = color + '33'; ctx.fill();
        }
        // Node circle
        ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.fillStyle = color + 'cc'; ctx.fill();
        ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.stroke();
        // Label
        ctx.fillStyle = '#e2e8f0';
        ctx.font = `${i === hoveredRef.current ? 'bold 11px' : '9px'} sans-serif`;
        ctx.textAlign = 'center';
        const nId = n.id || 'unknown';
        const label = nId.length > 20 ? nId.slice(0, 18) + '…' : nId;
        ctx.fillText(label, n.x, n.y + r + 12);
        // Type badge
        ctx.fillStyle = color;
        ctx.font = 'bold 7px sans-serif';
        ctx.fillText(nType.toUpperCase(), n.x, n.y + 3);
      }

      ctx.restore();
      animRef.current = requestAnimationFrame(tick);
    };

    animRef.current = requestAnimationFrame(tick);
    return () => { running = false; cancelAnimationFrame(animRef.current); };
  }, [nodes, edges]);

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
      const r = Math.max(8, Math.min(22, 6 + sn[i].connections * 2));
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
    zoomRef.current = Math.max(0.3, Math.min(3, zoomRef.current * scale));
  };

  return (
    <canvas
      ref={canvasRef}
      width={900}
      height={600}
      className="w-full rounded-xl border border-border/30 bg-background/80"
      style={{ height: 500 }}
      onMouseDown={onMouseDown}
      onMouseMove={onMouseMove}
      onMouseUp={onMouseUp}
      onMouseLeave={onMouseUp}
      onWheel={onWheel}
    />
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
    } catch (e) { console.error('Brain fetch error', e); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleSearch = async () => {
    if (!searchQuery.trim()) return;
    try {
      const res = await api.get('/api/v1/brain/search', { params: { query: searchQuery, limit: 50 } });
      const raw = (res.data?.results || res.data?.nodes || []) as Record<string, unknown>[];
      setNodes(raw.map(mapNode));
    } catch (e) { console.error('Search error', e); }
  };

  const handleSelectNode = async (node: GraphNode) => {
    setSelectedNode(node);
    if (!node.id) { setNeighbors([]); return; }
    try {
      const res = await api.get(`/api/v1/brain/nodes/${encodeURIComponent(node.id)}/neighbors`).catch(() => ({ data: { neighbors: [] } }));
      const raw = (res.data?.neighbors || res.data?.nodes || []) as Record<string, unknown>[];
      setNeighbors(raw.map(mapNode));
    } catch (e) { console.error('Neighbors error', e); }
  };

  const filteredNodes = nodeTypeFilter === 'all' ? nodes : nodes.filter(n => n.type === nodeTypeFilter);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-violet-400 to-purple-500 bg-clip-text text-transparent">Knowledge Graph Explorer</h1>
          <p className="text-muted-foreground mt-1">Explore interconnected security intelligence — entities, relationships, and patterns</p>
        </div>
        <Button variant="outline" onClick={fetchData}>Refresh</Button>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        {[
          { label: 'Total Nodes', value: stats?.total_nodes ?? 0, color: 'text-blue-400' },
          { label: 'Total Edges', value: stats?.total_edges ?? 0, color: 'text-purple-400' },
          { label: 'Node Types', value: Object.keys(stats?.node_types || {}).length, color: 'text-green-400' },
          { label: 'Edge Types', value: Object.keys(stats?.edge_types || {}).length, color: 'text-yellow-400' },
          { label: 'Density', value: (stats?.density ?? 0).toFixed(4), color: 'text-cyan-400' },
          { label: 'Avg Connections', value: (stats?.avg_connections ?? 0).toFixed(1), color: 'text-pink-400' },
        ].map((s, i) => (
          <motion.div key={i} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }}>
            <Card className="border-border/50 bg-card/50">
              <CardContent className="pt-4 pb-3">
                <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
                <div className="text-xs text-muted-foreground">{s.label}</div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Search */}
      <div className="flex gap-2">
        <Input placeholder="Search entities by ID, type, or property..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleSearch()} className="flex-1" />
        <Button onClick={handleSearch}>Search</Button>
      </div>

      {/* Main Content */}
      <Tabs defaultValue="graph" className="space-y-4">
        <TabsList>
          <TabsTrigger value="graph">🕸️ Live Graph</TabsTrigger>
          <TabsTrigger value="nodes">Nodes ({filteredNodes.length})</TabsTrigger>
          <TabsTrigger value="relationships">Relationships ({edges.length})</TabsTrigger>
          <TabsTrigger value="types">Type Distribution</TabsTrigger>
          {selectedNode && <TabsTrigger value="detail">Node Detail</TabsTrigger>}
        </TabsList>

        <TabsContent value="graph">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2">
              <Card className="border-border/50 bg-card/50 overflow-hidden">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <span className="inline-block w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                    Force-Directed Graph — drag nodes · scroll to zoom · pan background
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-2">
                  {loading ? (
                    <div className="h-[500px] flex items-center justify-center text-muted-foreground">Loading graph...</div>
                  ) : (
                    <ForceGraph nodes={nodes} edges={edges} onSelectNode={handleSelectNode} />
                  )}
                </CardContent>
              </Card>
              {/* Legend */}
              <div className="flex flex-wrap gap-2 mt-3">
                {Object.entries(nodeCanvasColors).filter(([k]) => k.charAt(0) === k.charAt(0).toUpperCase()).map(([type, color]) => (
                  <div key={type} className="flex items-center gap-1.5 text-xs text-muted-foreground">
                    <span className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} /> {type}
                  </div>
                ))}
              </div>
            </div>
            <div className="space-y-4">
              {selectedNode ? (
                <>
                  <Card className="border-border/50">
                    <CardHeader className="pb-2"><CardTitle className="text-sm">Selected Entity</CardTitle></CardHeader>
                    <CardContent>
                      <Badge className={nodeTypeColors[selectedNode.type] || 'bg-gray-500/20 text-gray-400'}>{selectedNode.type}</Badge>
                      <div className="font-mono text-sm mt-2 text-foreground break-all">{selectedNode.id}</div>
                      <div className="text-xs text-muted-foreground mt-1">{selectedNode.connections} connections</div>
                      <div className="mt-3 space-y-1">
                        {Object.entries(selectedNode.properties || {}).slice(0, 8).map(([k, v]) => (
                          <div key={k} className="flex justify-between text-xs border-b border-border/20 py-0.5">
                            <span className="text-muted-foreground">{k}</span>
                            <span className="font-mono text-foreground truncate ml-2 max-w-[140px]">{String(v)}</span>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                  <Card className="border-border/50">
                    <CardHeader className="pb-2"><CardTitle className="text-sm">Neighbors ({neighbors.length})</CardTitle></CardHeader>
                    <CardContent className="max-h-64 overflow-y-auto">
                      {neighbors.map(n => (
                        <div key={n.id} className="p-1.5 hover:bg-card/60 rounded cursor-pointer text-xs flex items-center gap-1.5" onClick={() => handleSelectNode(n)}>
                          <Badge className={`text-[9px] ${nodeTypeColors[n.type] || 'bg-gray-500/20'}`}>{n.type}</Badge>
                          <span className="truncate text-foreground">{n.id}</span>
                        </div>
                      ))}
                      {neighbors.length === 0 && <div className="text-xs text-muted-foreground text-center py-4">Click a node to see neighbors</div>}
                    </CardContent>
                  </Card>
                </>
              ) : (
                <Card className="border-border/50">
                  <CardContent className="pt-8 pb-8 text-center text-muted-foreground text-sm">
                    <div className="text-4xl mb-3">🕸️</div>
                    Click or drag a node on the graph to inspect its properties and connections.
                  </CardContent>
                </Card>
              )}
              {/* Node type breakdown */}
              <Card className="border-border/50">
                <CardHeader className="pb-2"><CardTitle className="text-sm">Entity Breakdown</CardTitle></CardHeader>
                <CardContent className="space-y-1.5">
                  {Object.entries(stats?.node_types || {}).sort(([, a], [, b]) => (b as number) - (a as number)).map(([type, count]) => (
                    <div key={type} className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-1.5">
                        <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: nodeCanvasColors[type] || nodeCanvasColors[(type || '').toLowerCase()] || '#64748b' }} />
                        <span className="text-foreground capitalize">{type}</span>
                      </div>
                      <span className="font-mono text-muted-foreground">{String(count)}</span>
                    </div>
                  ))}
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
          {loading ? <div className="text-center py-8 text-muted-foreground">Loading graph data...</div> : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {filteredNodes.slice(0, 60).map((node, i) => (
                <motion.div key={node.id} initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: i * 0.02 }}>
                  <Card className={`border-border/50 cursor-pointer hover:bg-card/80 transition-colors ${selectedNode?.id === node.id ? 'ring-2 ring-primary' : ''}`} onClick={() => handleSelectNode(node)}>
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
          )}
        </TabsContent>

        <TabsContent value="relationships">
          <Card className="border-border/50">
            <CardHeader><CardTitle>Edge Types</CardTitle></CardHeader>
            <CardContent>
              <div className="space-y-2">
                {Object.entries(stats?.edge_types || {}).map(([type, count]) => (
                  <div key={type} className="flex items-center justify-between p-3 border border-border/30 rounded-lg">
                    <span className="text-sm font-medium text-foreground">{type}</span>
                    <Badge variant="outline">{String(count)}</Badge>
                  </div>
                ))}
                {Object.keys(stats?.edge_types || {}).length === 0 && <div className="text-center py-8 text-muted-foreground">No relationships found.</div>}
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
                    <div className="text-3xl font-bold text-foreground">{String(count)}</div>
                    <Badge className={`mt-2 ${nodeTypeColors[type] || 'bg-gray-500/20 text-gray-400'}`}>{type}</Badge>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>
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
                      <div key={k} className="flex justify-between py-1 border-b border-border/20">
                        <span className="text-sm text-muted-foreground">{k}</span>
                        <span className="text-sm text-foreground font-mono">{String(v)}</span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
              <Card className="border-border/50">
                <CardHeader><CardTitle>Neighbors ({neighbors.length})</CardTitle></CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {neighbors.map(n => (
                      <div key={n.id} className="p-2 border border-border/30 rounded cursor-pointer hover:bg-card/60 transition-colors" onClick={() => handleSelectNode(n)}>
                        <div className="flex items-center gap-2">
                          <Badge className={nodeTypeColors[n.type] || 'bg-gray-500/20 text-gray-400'} >{n.type}</Badge>
                          <span className="text-sm truncate text-foreground">{n.id}</span>
                        </div>
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

