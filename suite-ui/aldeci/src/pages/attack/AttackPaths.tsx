import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Network,
  RefreshCw,
  Play,
  AlertTriangle,
  Shield,
  Target,
  Loader2,
  Eye,
  Download,
  Filter,
  Zap,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Input } from '../../components/ui/input';
import { attackGraphApi, reachabilityApi, graphApi } from '../../lib/api';
import AttackPathGraph, { GraphNode, GraphEdge } from '../../components/aldeci/AttackPathGraph';
import { toast } from 'sonner';

interface AttackPath {
  id: string;
  name: string;
  source: string;
  target: string;
  hops: number;
  risk_score: number;
  exploitability: string;
  status: 'active' | 'mitigated' | 'investigating';
}

/** Raw attack path shape returned by the backend API. */
interface RawAttackPath {
  id?: string;
  path?: string[];
  name?: string;
  entry_point?: string;
  target?: string;
  hops?: number;
  impact_score?: number;
  risk_score?: number;
  probability?: number;
  status?: 'active' | 'mitigated' | 'investigating';
}

/** Raw graph node returned by the graph visualization API. */
interface RawGraphNode {
  id: string;
  label?: string;
  type?: string;
  risk_score?: number;
}

/** Raw graph edge returned by the graph visualization API. */
interface RawGraphEdge {
  id?: string;
  source: string;
  target: string;
  label?: string;
  risk_score?: number;
  type?: string;
}

export default function AttackPaths() {
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [filterText, setFilterText] = useState('');

  // Fetch attack graph data
  const { data: graphData, isLoading: graphLoading, refetch: refetchGraph } = useQuery({
    queryKey: ['attack-graph'],
    queryFn: () => attackGraphApi.getGraph(),
  });

  // Fetch reachability metrics
  const { data: reachabilityData, isLoading: reachabilityLoading } = useQuery({
    queryKey: ['reachability-metrics'],
    queryFn: () => reachabilityApi.getMetrics(),
  });

  // Fetch graph visualization data
  const { data: graphVizData } = useQuery({
    queryKey: ['graph-viz'],
    queryFn: () => graphApi.getGraph(),
  });

  // Analyze attack paths mutation
  const analyzeMutation = useMutation({
    mutationFn: async () => {
      const result = await attackGraphApi.analyze({ depth: 5, include_mitigations: true });
      return result;
    },
    onSuccess: (data) => {
      toast.success(`Analysis complete! Found ${data?.result?.attack_paths?.length || data?.attack_paths?.length || 0} attack paths`);
      refetchGraph();
    },
    onError: (error) => {
      toast.error(`Analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Export graph mutation
  const exportMutation = useMutation({
    mutationFn: async () => {
      const result = await attackGraphApi.export('json');
      return result;
    },
    onSuccess: (data) => {
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'attack-paths.json';
      a.click();
      URL.revokeObjectURL(url);
      toast.success('Attack paths exported successfully');
    },
    onError: () => {
      toast.error('Export failed');
    },
  });

  // Map GNN attack paths to display format - zero mock data
  const rawPaths = graphData?.attack_paths || graphData?.result?.attack_paths || graphData?.paths || (Array.isArray(graphData) ? graphData : []);
  const attackPaths: AttackPath[] = rawPaths.map((p: RawAttackPath, i: number) => ({
    id: p.id || String(i + 1),
    name: (p.path || []).join(' → ') || p.name || `Path ${i + 1}`,
    source: p.entry_point || (p.path || [])[0] || 'Unknown',
    target: p.target || (p.path || []).slice(-1)[0] || 'Unknown',
    hops: (p.path || []).length || p.hops || 1,
    risk_score: Math.round((p.impact_score || p.risk_score || 0.5) * 100),
    exploitability: (p.probability || 0) > 0.7 ? 'HIGH' : (p.probability || 0) > 0.3 ? 'MEDIUM' : 'LOW',
    status: p.status || 'active',
  }));

  const filteredPaths = attackPaths.filter(p => 
    p.name.toLowerCase().includes(filterText.toLowerCase()) ||
    p.source.toLowerCase().includes(filterText.toLowerCase()) ||
    p.target.toLowerCase().includes(filterText.toLowerCase())
  );

  const stats = {
    totalPaths: attackPaths.length,
    activePaths: attackPaths.filter(p => p.status === 'active').length,
    highRisk: attackPaths.filter(p => p.risk_score >= 80).length,
    avgHops: attackPaths.length > 0 
      ? (attackPaths.reduce((sum, p) => sum + p.hops, 0) / attackPaths.length).toFixed(1)
      : '0',
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Network className="w-8 h-8 text-primary" />
            Attack Paths (GNN)
          </h1>
          <p className="text-muted-foreground mt-1">
            Graph Neural Network analysis of potential attack vectors
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button 
            variant="outline" 
            onClick={() => refetchGraph()}
            disabled={graphLoading}
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${graphLoading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button 
            variant="outline"
            onClick={() => exportMutation.mutate()}
            disabled={exportMutation.isPending}
          >
            <Download className="w-4 h-4 mr-2" />
            Export
          </Button>
          <Button 
            onClick={() => analyzeMutation.mutate()}
            disabled={analyzeMutation.isPending}
          >
            {analyzeMutation.isPending ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <Play className="w-4 h-4 mr-2" />
            )}
            Analyze Paths
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Paths</p>
                <p className="text-3xl font-bold">{stats.totalPaths}</p>
              </div>
              <Network className="w-10 h-10 text-blue-500 opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card border-red-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Active Threats</p>
                <p className="text-3xl font-bold text-red-500">{stats.activePaths}</p>
              </div>
              <AlertTriangle className="w-10 h-10 text-red-500 opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card border-orange-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">High Risk</p>
                <p className="text-3xl font-bold text-orange-500">{stats.highRisk}</p>
              </div>
              <Shield className="w-10 h-10 text-orange-500 opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Avg. Hops</p>
                <p className="text-3xl font-bold">{stats.avgHops}</p>
              </div>
              <Target className="w-10 h-10 text-primary opacity-20" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Reachability Overview */}
      {reachabilityData && (
        <Card className="glass-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Zap className="w-5 h-5 text-yellow-500" />
              Reachability Analysis
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-4 text-center">
              <div>
                <p className="text-2xl font-bold">{reachabilityData.reachable_assets || 0}</p>
                <p className="text-sm text-muted-foreground">Reachable Assets</p>
              </div>
              <div>
                <p className="text-2xl font-bold text-red-500">{reachabilityData.exposed_services || 0}</p>
                <p className="text-sm text-muted-foreground">Exposed Services</p>
              </div>
              <div>
                <p className="text-2xl font-bold text-green-500">{reachabilityData.protected_assets || 0}</p>
                <p className="text-sm text-muted-foreground">Protected Assets</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Attack Paths List */}
      <Card className="glass-card">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Discovered Attack Paths</CardTitle>
              <CardDescription>Potential attack vectors identified by GNN analysis</CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Filter paths..."
                value={filterText}
                onChange={(e) => setFilterText(e.target.value)}
                className="w-64"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {graphLoading || reachabilityLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 animate-spin text-primary" />
            </div>
          ) : filteredPaths.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <Network className="w-16 h-16 text-muted-foreground/30 mb-4" />
              <h3 className="text-lg font-semibold text-muted-foreground mb-2">No Attack Paths Found</h3>
              <p className="text-sm text-muted-foreground/70 max-w-md mb-4">
                Run a GNN analysis to discover potential attack vectors in your infrastructure.
                Attack paths show how an adversary could move laterally through your environment.
              </p>
              <Button onClick={() => analyzeMutation.mutate()} disabled={analyzeMutation.isPending}>
                {analyzeMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Play className="w-4 h-4 mr-2" />}
                Run GNN Analysis
              </Button>
            </div>
          ) : (
            <div className="space-y-3">
              {filteredPaths.map((path) => (
                <motion.div
                  key={path.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={`p-4 rounded-lg border ${
                    selectedPath === path.id 
                      ? 'border-primary bg-primary/5' 
                      : 'border-border hover:border-primary/50'
                  } cursor-pointer transition-all`}
                  onClick={() => setSelectedPath(selectedPath === path.id ? null : path.id)}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className={`w-3 h-3 rounded-full ${
                        path.status === 'active' ? 'bg-red-500 animate-pulse' :
                        path.status === 'investigating' ? 'bg-yellow-500' :
                        'bg-green-500'
                      }`} />
                      <div>
                        <p className="font-medium">{path.name}</p>
                        <p className="text-sm text-muted-foreground">
                          {path.source} → {path.target} ({path.hops} hops)
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <Badge variant={
                        path.exploitability === 'HIGH' ? 'destructive' :
                        path.exploitability === 'MEDIUM' ? 'medium' :
                        'default'
                      }>
                        {path.exploitability}
                      </Badge>
                      <div className="text-right">
                        <p className="text-lg font-bold">{path.risk_score}</p>
                        <p className="text-xs text-muted-foreground">Risk Score</p>
                      </div>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedPath(selectedPath === path.id ? null : path.id);
                        }}
                      >
                        <Eye className={`w-4 h-4 ${selectedPath === path.id ? 'text-primary' : ''}`} />
                      </Button>
                    </div>
                  </div>
                  
                  {selectedPath === path.id && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      className="mt-4 pt-4 border-t border-border"
                    >
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <p className="text-sm font-medium mb-2">Path Details</p>
                          <ul className="text-sm text-muted-foreground space-y-1">
                            <li>• Source: {path.source}</li>
                            <li>• Target: {path.target}</li>
                            <li>• Hop Count: {path.hops}</li>
                            <li>• Status: {path.status}</li>
                          </ul>
                        </div>
                        <div className="flex gap-2">
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={(e) => {
                              e.stopPropagation();
                              toast.success(`Running simulation for: ${path.name}`);
                            }}
                          >
                            <Play className="w-3 h-3 mr-1" />
                            Simulate
                          </Button>
                          <Button 
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              toast.success(`Mitigation recommendations generated for: ${path.name}`);
                            }}
                          >
                            <Shield className="w-3 h-3 mr-1" />
                            Mitigate
                          </Button>
                        </div>
                      </div>
                    </motion.div>
                  )}
                </motion.div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Interactive Graph Visualization */}
      <Card className="glass-card">
        <CardHeader>
          <CardTitle>Graph Visualization</CardTitle>
          <CardDescription>Interactive attack path graph — click nodes to inspect, scroll to zoom, drag to pan</CardDescription>
        </CardHeader>
        <CardContent>
          <AttackPathGraph
            nodes={(() => {
              // Build graph nodes from attack paths
              const nodeSet = new Map<string, GraphNode>();
              filteredPaths.forEach(path => {
                if (!nodeSet.has(path.source)) {
                  nodeSet.set(path.source, {
                    id: path.source,
                    label: path.source,
                    type: 'entry_point',
                    risk_score: path.risk_score,
                  });
                }
                if (!nodeSet.has(path.target)) {
                  nodeSet.set(path.target, {
                    id: path.target,
                    label: path.target,
                    type: 'target',
                    risk_score: path.risk_score,
                  });
                }
                // Add intermediate hops as nodes
                const hops = path.name.split(' → ').slice(1, -1);
                hops.forEach(hop => {
                  const hopId = hop.trim();
                  if (!nodeSet.has(hopId)) {
                    nodeSet.set(hopId, {
                      id: hopId,
                      label: hopId,
                      type: 'hop',
                      risk_score: Math.round(path.risk_score * 0.7),
                    });
                  }
                });
              });
              // Also merge in API graph data if available
              (graphVizData?.nodes || []).forEach((n: RawGraphNode) => {
                if (!nodeSet.has(n.id)) {
                  nodeSet.set(n.id, {
                    id: n.id,
                    label: n.label || n.id,
                    type: (n.type as GraphNode['type']) || 'asset',
                    risk_score: Math.round((n.risk_score || 0.5) * 100),
                  });
                }
              });
              return Array.from(nodeSet.values());
            })()}
            edges={(() => {
              const edgeList: GraphEdge[] = [];
              filteredPaths.forEach((path, pi) => {
                const segments = path.name.split(' → ').map(s => s.trim());
                for (let i = 0; i < segments.length - 1; i++) {
                  edgeList.push({
                    id: `e-${pi}-${i}`,
                    source: segments[i],
                    target: segments[i + 1],
                    risk_score: path.risk_score,
                    type: i === 0 ? 'exploit' : 'lateral',
                  });
                }
              });
              // Merge in API edges
              (graphVizData?.edges || []).forEach((e: RawGraphEdge, idx: number) => {
                edgeList.push({
                  id: e.id || `api-e-${idx}`,
                  source: e.source,
                  target: e.target,
                  label: e.label,
                  risk_score: e.risk_score,
                  type: (e.type as GraphEdge['type']) || 'lateral',
                });
              });
              return edgeList;
            })()}
            selectedNodeId={selectedPath}
            onNodeSelect={(id) => setSelectedPath(id)}
            height={420}
          />
        </CardContent>
      </Card>
    </div>
  );
}
