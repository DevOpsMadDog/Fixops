import { useEffect, useState, useCallback } from 'react';
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

const KnowledgeGraphExplorer = () => {
  const [stats, setStats] = useState<GraphStats | null>(null);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [neighbors, setNeighbors] = useState<GraphNode[]>([]);
  const [loading, setLoading] = useState(true);
  const [nodeTypeFilter, setNodeTypeFilter] = useState<string>('all');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [statsRes, nodesRes, edgesRes] = await Promise.all([
        api.get('/api/v1/brain/stats').catch(() => ({ data: { total_nodes: 0, total_edges: 0, node_types: {}, edge_types: {}, density: 0, avg_connections: 0 } })),
        api.get('/api/v1/brain/nodes', { params: { limit: 200 } }).catch(() => ({ data: { nodes: [] } })),
        api.post('/api/v1/brain/edges', { limit: 500 }).catch(() => ({ data: { edges: [] } })),
      ]);
      setStats(statsRes.data);
      setNodes(nodesRes.data?.nodes || []);
      setEdges(edgesRes.data?.edges || []);
    } catch (e) { console.error('Brain fetch error', e); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleSearch = async () => {
    if (!searchQuery.trim()) return;
    try {
      const res = await api.get('/api/v1/brain/search', { params: { query: searchQuery, limit: 50 } });
      setNodes(res.data?.results || res.data?.nodes || []);
    } catch (e) { console.error('Search error', e); }
  };

  const handleSelectNode = async (node: GraphNode) => {
    setSelectedNode(node);
    try {
      const res = await api.get(`/api/v1/brain/nodes/${node.id}/neighbors`).catch(() => ({ data: { neighbors: [] } }));
      setNeighbors(res.data?.neighbors || []);
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
      <Tabs defaultValue="nodes" className="space-y-4">
        <TabsList>
          <TabsTrigger value="nodes">Nodes ({filteredNodes.length})</TabsTrigger>
          <TabsTrigger value="relationships">Relationships ({edges.length})</TabsTrigger>
          <TabsTrigger value="types">Type Distribution</TabsTrigger>
          {selectedNode && <TabsTrigger value="detail">Node Detail</TabsTrigger>}
        </TabsList>

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

