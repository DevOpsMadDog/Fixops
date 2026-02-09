import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useMemo } from 'react';
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
  Workflow,
  Sparkles,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { dashboardApi, feedsApi, systemApi, algorithmsApi } from '../lib/api';
import { toast } from 'sonner';
import CTEMProgressRing from '../components/dashboard/CTEMProgressRing';
import MultiLLMConsensusPanel from '../components/dashboard/MultiLLMConsensusPanel';

// Stagger animation variants
const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.08 } },
};
const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 200, damping: 20 } },
};

// Floating Orb background component
function FloatingOrbs() {
  const orbs = useMemo(() => [
    { x: '10%', y: '20%', size: 180, color: 'bg-blue-500/8', delay: 0 },
    { x: '80%', y: '10%', size: 220, color: 'bg-purple-500/8', delay: 1.5 },
    { x: '60%', y: '70%', size: 150, color: 'bg-cyan-500/6', delay: 3 },
    { x: '30%', y: '80%', size: 200, color: 'bg-emerald-500/6', delay: 2 },
  ], []);
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none -z-10">
      {orbs.map((orb, i) => (
        <motion.div
          key={i}
          className={`absolute rounded-full ${orb.color} blur-3xl`}
          style={{ left: orb.x, top: orb.y, width: orb.size, height: orb.size }}
          animate={{ x: [0, 30, -20, 0], y: [0, -25, 15, 0], scale: [1, 1.1, 0.95, 1] }}
          transition={{ duration: 12 + i * 2, repeat: Infinity, ease: 'easeInOut', delay: orb.delay }}
        />
      ))}
    </div>
  );
}

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
    <motion.div variants={itemVariants} whileHover={{ scale: 1.03, y: -4 }} transition={{ type: 'spring', stiffness: 300 }}>
      <Card className="glass-card backdrop-blur-md bg-gray-900/40 border-gray-700/40 hover:border-primary/30 hover:shadow-lg hover:shadow-primary/5 transition-all duration-300">
        <CardContent className="p-6">
          <div className="flex items-start justify-between">
            <div className="space-y-2">
              <p className="text-sm text-muted-foreground">{title}</p>
              {loading ? (
                <div className="h-8 w-24 skeleton rounded-md animate-pulse bg-gray-700/30" />
              ) : (
                <motion.p className="text-3xl font-bold" initial={{ opacity: 0, scale: 0.5 }} animate={{ opacity: 1, scale: 1 }} transition={{ type: 'spring', delay: 0.2 }}>
                  {value}
                </motion.p>
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
            <motion.div
              className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center"
              whileHover={{ rotate: 12 }}
              transition={{ type: 'spring', stiffness: 300 }}
            >
              <Icon className="w-6 h-6 text-primary" />
            </motion.div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
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
    <motion.div className="flex items-center justify-between py-2" whileHover={{ x: 4 }} transition={{ type: 'spring', stiffness: 300 }}>
      <div className="flex items-center gap-3">
        <div className="relative">
          <div className={`w-2.5 h-2.5 rounded-full ${statusColors[status]}`} />
          {status === 'healthy' && (
            <motion.div
              className={`absolute inset-0 rounded-full ${statusColors[status]}`}
              animate={{ scale: [1, 2.5], opacity: [0.6, 0] }}
              transition={{ duration: 2, repeat: Infinity, ease: 'easeOut' }}
            />
          )}
        </div>
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
    </motion.div>
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
    <div className="relative space-y-6">
      <FloatingOrbs />

      {/* Animated Header */}
      <motion.div initial={{ opacity: 0, y: -30 }} animate={{ opacity: 1, y: 0 }} transition={{ type: 'spring', stiffness: 150 }}
        className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-400 via-purple-400 to-cyan-400 bg-clip-text text-transparent">
            <motion.span initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 }}>
              ⚡ Security Command Center
            </motion.span>
          </h1>
          <p className="text-muted-foreground mt-1">
            Real-time security intelligence overview
          </p>
        </div>
        <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
          <Button variant="outline" onClick={handleRefresh} className="gap-2 border-gray-600/50 hover:border-primary/50 hover:bg-primary/5 transition-all">
            <motion.span animate={{ rotate: 0 }} whileHover={{ rotate: 180 }} transition={{ duration: 0.4 }}>
              <RefreshCw className="w-4 h-4" />
            </motion.span>
            Refresh
          </Button>
        </motion.div>
      </motion.div>

      {/* System Status Banner */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
        <Card className={`backdrop-blur-md ${healthData?.status === 'healthy' ? 'border-green-500/30 bg-green-500/5' : 'border-yellow-500/30 bg-yellow-500/5'} hover:shadow-lg transition-shadow`}>
          <CardContent className="py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {healthData?.status === 'healthy' ? (
                  <motion.div animate={{ scale: [1, 1.15, 1] }} transition={{ duration: 2, repeat: Infinity }}>
                    <CheckCircle2 className="w-6 h-6 text-green-500" />
                  </motion.div>
                ) : (
                  <motion.div animate={{ rotate: [0, 5, -5, 0] }} transition={{ duration: 1, repeat: Infinity }}>
                    <AlertTriangle className="w-6 h-6 text-yellow-500" />
                  </motion.div>
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
      </motion.div>

      {/* Stats Grid */}
      <motion.div variants={containerVariants} initial="hidden" animate="visible"
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
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
      </motion.div>

      {/* CTEM Framework & Multi-LLM Consensus */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
        className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <CTEMProgressRing />
        <MultiLLMConsensusPanel />
      </motion.div>

      {/* Main Content Grid */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}
        className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Algorithm Capabilities */}
        <Card className="glass-card lg:col-span-2 backdrop-blur-md bg-gray-900/40 border-gray-700/40 hover:border-primary/20 transition-all duration-300">
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
        <Card className="glass-card backdrop-blur-md bg-gray-900/40 border-gray-700/40 hover:border-primary/20 transition-all duration-300">
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
                latency={healthData?.latency}
              />
              <ServiceStatus
                name="Feed Service (EPSS/KEV)"
                status={feedsHealthError ? 'offline' : feedsHealthData?.status === 'healthy' ? 'healthy' : 'degraded'}
                latency={feedsHealthData?.latency}
              />
              <ServiceStatus
                name="Algorithm Engine"
                status={algorithmStatusError ? 'offline' : algorithmStatusData?.status === 'healthy' ? 'healthy' : capabilitiesError ? 'offline' : capabilitiesData ? 'healthy' : 'unknown'}
                latency={algorithmStatusData?.latency}
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
      </motion.div>

      {/* Quick Actions */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.5 }}>
        <Card className="glass-card backdrop-blur-md bg-gray-900/40 border-gray-700/40">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-primary" />
              Quick Actions
            </CardTitle>
            <CardDescription>Common security operations</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <motion.div whileHover={{ scale: 1.05, y: -4 }} whileTap={{ scale: 0.95 }}>
                <Button variant="outline" className="h-24 w-full flex-col gap-2 border-gray-600/50 hover:border-blue-500/50 hover:bg-blue-500/5 transition-all"
                  onClick={() => navigate('/ingest')}>
                  <Database className="w-6 h-6" />
                  <span>Ingest Data</span>
                </Button>
              </motion.div>
              <motion.div whileHover={{ scale: 1.05, y: -4 }} whileTap={{ scale: 0.95 }}>
                <Button variant="outline" className="h-24 w-full flex-col gap-2 border-gray-600/50 hover:border-purple-500/50 hover:bg-purple-500/5 transition-all"
                  onClick={() => navigate('/core/brain-pipeline')}>
                  <Workflow className="w-6 h-6" />
                  <span>Brain Pipeline</span>
                </Button>
              </motion.div>
              <motion.div whileHover={{ scale: 1.05, y: -4 }} whileTap={{ scale: 0.95 }}>
                <Button variant="outline" className="h-24 w-full flex-col gap-2 border-gray-600/50 hover:border-cyan-500/50 hover:bg-cyan-500/5 transition-all"
                  onClick={() => navigate('/ai-engine/multi-llm')}>
                  <Brain className="w-6 h-6" />
                  <span>Run Analysis</span>
                </Button>
              </motion.div>
              <motion.div whileHover={{ scale: 1.05, y: -4 }} whileTap={{ scale: 0.95 }}>
                <Button variant="outline" className="h-24 w-full flex-col gap-2 border-gray-600/50 hover:border-red-500/50 hover:bg-red-500/5 transition-all"
                  onClick={() => navigate('/attack/attack-simulation')}>
                  <Swords className="w-6 h-6" />
                  <span>Attack Lab</span>
                </Button>
              </motion.div>
              <motion.div whileHover={{ scale: 1.05, y: -4 }} whileTap={{ scale: 0.95 }}>
                <Button variant="outline" className="h-24 w-full flex-col gap-2 border-gray-600/50 hover:border-green-500/50 hover:bg-green-500/5 transition-all"
                  onClick={() => navigate('/evidence/soc2')}>
                  <Shield className="w-6 h-6" />
                  <span>SOC2 Evidence</span>
                </Button>
              </motion.div>
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
