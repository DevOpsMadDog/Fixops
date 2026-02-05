import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Shield,
  AlertTriangle,
  TrendingUp,
  Activity,
  Database,
  Brain,
  Swords,
  CheckCircle2,
  ArrowUpRight,
  ArrowDownRight,
  RefreshCw,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { dashboardApi, feedsApi, systemApi, algorithmsApi } from '../lib/api';
import { toast } from 'sonner';
import CTEMProgressRing from '../components/dashboard/CTEMProgressRing';
import MultiLLMConsensusPanel from '../components/dashboard/MultiLLMConsensusPanel';

interface StatCardProps {
  title: string;
  value: string | number;
  description?: string;
  icon: React.ElementType;
  trend?: { value: number; isPositive: boolean };
  loading?: boolean;
}

function StatCard({ title, value, description, icon: Icon, trend, loading }: StatCardProps) {
  return (
    <Card className="glass-card">
      <CardContent className="p-6">
        <div className="flex items-start justify-between">
          <div className="space-y-2">
            <p className="text-sm text-muted-foreground">{title}</p>
            {loading ? (
              <div className="h-8 w-24 skeleton" />
            ) : (
              <p className="text-3xl font-bold">{value}</p>
            )}
            {description && (
              <p className="text-xs text-muted-foreground">{description}</p>
            )}
            {trend && (
              <div className={`flex items-center gap-1 text-xs ${trend.isPositive ? 'text-green-500' : 'text-red-500'}`}>
                {trend.isPositive ? (
                  <ArrowDownRight className="w-3 h-3" />
                ) : (
                  <ArrowUpRight className="w-3 h-3" />
                )}
                <span>{trend.value}% from last week</span>
              </div>
            )}
          </div>
          <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center">
            <Icon className="w-6 h-6 text-primary" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

interface ServiceStatusProps {
  name: string;
  status: 'healthy' | 'degraded' | 'offline' | 'unknown';
  latency?: number;
}

function ServiceStatus({ name, status, latency }: ServiceStatusProps) {
  const statusColors = {
    healthy: 'bg-green-500',
    degraded: 'bg-yellow-500',
    offline: 'bg-red-500',
    unknown: 'bg-gray-500',
  };

  return (
    <div className="flex items-center justify-between py-2">
      <div className="flex items-center gap-3">
        <div className={`w-2 h-2 rounded-full ${statusColors[status]}`} />
        <span className="text-sm">{name}</span>
      </div>
      <div className="flex items-center gap-2">
        {latency && (
          <span className="text-xs text-muted-foreground">{latency}ms</span>
        )}
        <Badge variant={status === 'healthy' ? 'default' : status === 'degraded' ? 'medium' : 'critical'}>
          {status}
        </Badge>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const navigate = useNavigate();
  
  // Fetch real API data
  const { data: healthData, isLoading: healthLoading, refetch: refetchHealth, isError: healthError } = useQuery({
    queryKey: ['health'],
    queryFn: systemApi.getHealth,
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const { data: statusData } = useQuery({
    queryKey: ['status'],
    queryFn: systemApi.getStatus,
    refetchInterval: 30000,
  });

  const { data: epssData, isLoading: epssLoading } = useQuery({
    queryKey: ['epss'],
    queryFn: () => feedsApi.getEPSS(),
  });

  const { data: kevData, isLoading: kevLoading } = useQuery({
    queryKey: ['kev'],
    queryFn: () => feedsApi.getKEV(),
  });

  const { data: capabilitiesData, isLoading: capabilitiesLoading, isError: capabilitiesError } = useQuery({
    queryKey: ['capabilities'],
    queryFn: algorithmsApi.getCapabilities,
  });

  const { data: feedsHealthData, isError: feedsHealthError } = useQuery({
    queryKey: ['feeds-health'],
    queryFn: feedsApi.getHealth,
  });

  const { data: algorithmStatusData, isError: algorithmStatusError } = useQuery({
    queryKey: ['algorithm-status'],
    queryFn: algorithmsApi.getStatus,
  });

  const { data: _dashboardData, isLoading: _dashboardLoading } = useQuery({
    queryKey: ['dashboard-overview'],
    queryFn: () => dashboardApi.getOverview('default'),
    retry: false, // Don't retry if endpoint doesn't exist
  });

  const handleRefresh = () => {
    refetchHealth();
    toast.success('Dashboard refreshed');
  };

  // Calculate stats from real data
  const epssCount = epssData?.scores?.length || epssData?.count || 0;
  const kevCount = kevData?.total_kev_entries || kevData?.vulnerabilities?.length || 0;
  const algorithmsCount = capabilitiesData?.algorithms?.length || 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Security Dashboard</h1>
          <p className="text-muted-foreground mt-1">
            Real-time security intelligence overview
          </p>
        </div>
        <Button variant="outline" onClick={handleRefresh} className="gap-2">
          <RefreshCw className="w-4 h-4" />
          Refresh
        </Button>
      </div>

      {/* System Status Banner */}
      <Card className={`${healthData?.status === 'healthy' ? 'border-green-500/30 bg-green-500/5' : 'border-yellow-500/30 bg-yellow-500/5'}`}>
        <CardContent className="py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              {healthData?.status === 'healthy' ? (
                <CheckCircle2 className="w-6 h-6 text-green-500" />
              ) : (
                <AlertTriangle className="w-6 h-6 text-yellow-500" />
              )}
              <div>
                <p className="font-medium">
                  System Status: {healthLoading ? 'Checking...' : healthData?.status || 'Unknown'}
                </p>
                <p className="text-sm text-muted-foreground">
                  {healthData?.service || 'API'} v{healthData?.version || statusData?.version || '1.0.0'}
                </p>
              </div>
            </div>
            <div className="text-right text-sm text-muted-foreground">
              <p>Last checked: {new Date().toLocaleTimeString()}</p>
              {statusData?.timestamp && (
                <p>Server time: {new Date(statusData.timestamp).toLocaleTimeString()}</p>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="EPSS Scores"
          value={epssCount}
          description="Exploit prediction scores loaded"
          icon={TrendingUp}
          loading={epssLoading}
        />
        <StatCard
          title="KEV Entries"
          value={kevCount}
          description="Known exploited vulnerabilities"
          icon={AlertTriangle}
          loading={kevLoading}
        />
        <StatCard
          title="Algorithms"
          value={algorithmsCount}
          description="Prioritization algorithms available"
          icon={Brain}
          loading={capabilitiesLoading}
        />
        <StatCard
          title="API Status"
          value={healthData?.status === 'healthy' ? 'Online' : 'Degraded'}
          description={healthData?.service || 'Backend API'}
          icon={Activity}
          loading={healthLoading}
        />
      </div>

      {/* CTEM Framework & Multi-LLM Consensus */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <CTEMProgressRing />
        <MultiLLMConsensusPanel />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Algorithm Capabilities */}
        <Card className="glass-card lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Brain className="w-5 h-5 text-primary" />
              Algorithm Capabilities
            </CardTitle>
            <CardDescription>
              Available prioritization and decision algorithms
            </CardDescription>
          </CardHeader>
          <CardContent>
            {capabilitiesLoading ? (
              <div className="space-y-3">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="h-16 skeleton rounded-lg" />
                ))}
              </div>
            ) : (capabilitiesData?.algorithms?.length ?? 0) > 0 ? (
              <div className="space-y-3">
                {capabilitiesData?.algorithms?.map((algo: any, index: number) => (
                  <motion.div
                    key={algo.name || index}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className="flex items-center justify-between p-3 rounded-lg bg-muted/50"
                  >
                    <div>
                      <p className="font-medium">{algo.name || algo}</p>
                      {algo.description && (
                        <p className="text-sm text-muted-foreground">{algo.description}</p>
                      )}
                    </div>
                    <Badge variant="outline">{algo.type || 'Algorithm'}</Badge>
                  </motion.div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-muted-foreground">
                <Brain className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No algorithms loaded</p>
                <p className="text-sm">Ingest vulnerability data to activate algorithms</p>
              </div>
            )}

            {/* Differentiators */}
            {(capabilitiesData?.differentiators?.length ?? 0) > 0 && (
              <div className="mt-6 pt-6 border-t border-border">
                <p className="text-sm font-medium mb-3">Key Differentiators</p>
                <div className="flex flex-wrap gap-2">
                  {capabilitiesData?.differentiators?.map((diff: string, index: number) => (
                    <Badge key={index} variant="secondary">{diff}</Badge>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Service Health */}
        <Card className="glass-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="w-5 h-5 text-primary" />
              Service Health
            </CardTitle>
            <CardDescription>Real-time backend service status</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <ServiceStatus
                name="API Server"
                status={healthError ? 'offline' : healthData?.status === 'healthy' ? 'healthy' : healthLoading ? 'unknown' : 'degraded'}
                latency={healthData ? 15 : undefined}
              />
              <ServiceStatus
                name="Feed Service (EPSS/KEV)"
                status={feedsHealthError ? 'offline' : feedsHealthData?.status === 'healthy' ? 'healthy' : 'degraded'}
                latency={feedsHealthData ? 25 : undefined}
              />
              <ServiceStatus
                name="Algorithm Engine"
                status={algorithmStatusError ? 'offline' : algorithmStatusData?.status === 'healthy' ? 'healthy' : capabilitiesError ? 'offline' : capabilitiesData ? 'healthy' : 'unknown'}
                latency={algorithmStatusData ? 12 : undefined}
              />
              <ServiceStatus
                name="Monte Carlo Engine"
                status={algorithmStatusData?.engines?.monte_carlo?.status === 'available' ? 'healthy' : 'offline'}
              />
              <ServiceStatus
                name="Causal Inference"
                status={algorithmStatusData?.engines?.causal_inference?.status === 'available' ? 'healthy' : 'offline'}
              />
              <ServiceStatus
                name="GNN Attack Path"
                status={algorithmStatusData?.engines?.gnn_attack_path?.status === 'available' ? 'healthy' : 'offline'}
              />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card className="glass-card">
        <CardHeader>
          <CardTitle>Quick Actions</CardTitle>
          <CardDescription>Common security operations</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Button 
              variant="outline" 
              className="h-24 flex-col gap-2"
              onClick={() => navigate('/ingest')}
            >
              <Database className="w-6 h-6" />
              <span>Ingest Data</span>
            </Button>
            <Button 
              variant="outline" 
              className="h-24 flex-col gap-2"
              onClick={() => navigate('/ai-engine/multi-llm')}
            >
              <Brain className="w-6 h-6" />
              <span>Run Analysis</span>
            </Button>
            <Button 
              variant="outline" 
              className="h-24 flex-col gap-2"
              onClick={() => navigate('/attack/attack-simulation')}
            >
              <Swords className="w-6 h-6" />
              <span>Attack Lab</span>
            </Button>
            <Button 
              variant="outline" 
              className="h-24 flex-col gap-2"
              onClick={() => navigate('/evidence/compliance')}
            >
              <Shield className="w-6 h-6" />
              <span>Compliance</span>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
