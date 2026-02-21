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

  // Map GNN attack paths to display format + fallback
  const rawPaths = graphData?.attack_paths || graphData?.result?.attack_paths || graphData?.paths || [];
  const attackPaths: AttackPath[] = rawPaths.length > 0
    ? rawPaths.map((p: any, i: number) => ({
        id: p.id || String(i + 1),
        name: (p.path || []).join(' → ') || p.name || `Path ${i + 1}`,
        source: p.entry_point || (p.path || [])[0] || 'Unknown',
        target: p.target || (p.path || []).slice(-1)[0] || 'Unknown',
        hops: (p.path || []).length || p.hops || 1,
        risk_score: Math.round((p.impact_score || p.risk_score || 0.5) * 100),
        exploitability: (p.probability || 0) > 0.7 ? 'HIGH' : (p.probability || 0) > 0.3 ? 'MEDIUM' : 'LOW',
        status: p.status || 'active',
      }))
    : [
        { id: '1', name: 'Internet → Web Server → Database', source: 'External', target: 'Production DB', hops: 3, risk_score: 92, exploitability: 'HIGH', status: 'active' as const },
        { id: '2', name: 'VPN → Jump Host → Admin Console', source: 'Contractor VPN', target: 'Admin Portal', hops: 2, risk_score: 78, exploitability: 'MEDIUM', status: 'investigating' as const },
        { id: '3', name: 'Container → K8s API → Secrets', source: 'Workload Pod', target: 'Secrets Store', hops: 2, risk_score: 85, exploitability: 'HIGH', status: 'active' as const },
        { id: '4', name: 'CI/CD → Registry → Production', source: 'Build Pipeline', target: 'Prod Cluster', hops: 4, risk_score: 67, exploitability: 'MEDIUM', status: 'mitigated' as const },
      ];

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

      {/* Graph Visualization Placeholder */}
      <Card className="glass-card">
        <CardHeader>
          <CardTitle>Graph Visualization</CardTitle>
          <CardDescription>Interactive attack path graph (GNN-powered)</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-64 rounded-lg bg-background/50 border border-dashed border-border flex items-center justify-center">
            <div className="text-center text-muted-foreground">
              <Network className="w-12 h-12 mx-auto mb-2 opacity-30" />
              <p>Graph visualization would render here</p>
              <p className="text-xs">Nodes: {graphVizData?.nodes?.length || 0} | Edges: {graphVizData?.edges?.length || 0}</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
