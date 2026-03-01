import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Activity,
  Heart,
  Server,
  Clock,
  Cpu,
  HardDrive,
  Wifi,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { toast } from 'sonner';
import { api } from '../../lib/api';

// ─── Interfaces ──────────────────────────────────────────────────────────────

interface HealthStatus {
  status: string;
  uptime?: string;
  services?: Record<string, string>;
  memory_usage?: number;
  cpu_usage?: number;
  disk_usage?: number;
  database?: string;
  timestamp?: string;
}

interface VersionInfo {
  version: string;
  build?: string;
  environment?: string;
  python_version?: string;
  platform?: string;
}

// ─── Animation Variants ───────────────────────────────────────────────────────

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.05,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 16 },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      type: 'spring' as const,
      stiffness: 260,
      damping: 22,
    },
  },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

const serviceStatusColor = (status: string): string => {
  const s = status?.toLowerCase();
  if (s === 'healthy' || s === 'up' || s === 'running' || s === 'ok') return 'bg-green-500';
  if (s === 'degraded' || s === 'slow') return 'bg-yellow-500';
  return 'bg-red-500';
};

const overallStatusVariant = (status: string): 'default' | 'destructive' | 'secondary' => {
  const s = status?.toLowerCase();
  if (s === 'healthy' || s === 'ok') return 'default';
  if (s === 'degraded') return 'secondary';
  return 'destructive';
};

const overallStatusLabel = (status: string): string =>
  status ? status.toUpperCase() : 'UNKNOWN';

// ─── Skeleton ─────────────────────────────────────────────────────────────────

function HealthSkeleton() {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {Array.from({ length: 4 }, (_, i) => (
          <Card key={i} className="border-gray-700/30 bg-gray-900/40">
            <CardContent className="p-4">
              <div className="h-8 w-20 bg-gray-700/40 rounded animate-pulse mb-2" />
              <div className="h-3 w-16 bg-gray-700/30 rounded animate-pulse" />
            </CardContent>
          </Card>
        ))}
      </div>
      <Card className="border-gray-700/30 bg-gray-900/40">
        <CardContent className="p-6 space-y-3">
          {Array.from({ length: 5 }, (_, i) => (
            <div key={i} className="flex items-center gap-4 animate-pulse">
              <div className="h-3 w-3 bg-gray-700/40 rounded-full" />
              <div className="h-4 w-32 bg-gray-700/40 rounded" />
              <div className="flex-1" />
              <div className="h-4 w-16 bg-gray-700/30 rounded" />
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Resource Bar ─────────────────────────────────────────────────────────────

interface ResourceBarProps {
  label: string;
  value: number | undefined;
  icon: React.ReactNode;
}

function ResourceBar({ label, value, icon }: ResourceBarProps) {
  const pct = value ?? 0;
  const barColor =
    pct >= 90 ? 'bg-red-500' : pct >= 70 ? 'bg-yellow-500' : 'bg-green-500';

  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-sm">
        <span className="flex items-center gap-2 text-gray-300">
          {icon}
          {label}
        </span>
        <span className="text-gray-400 tabular-nums">{pct.toFixed(1)}%</span>
      </div>
      <div className="h-2 w-full rounded-full bg-gray-700/50 overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${barColor}`}
          style={{ width: `${Math.min(pct, 100)}%` }}
        />
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function SystemHealth() {
  const {
    data: health,
    isLoading: healthLoading,
    refetch: refetchHealth,
  } = useQuery({
    queryKey: ['system-health'],
    queryFn: async () => {
      const res = await api.get('/api/v1/health');
      return (res.data || res) as HealthStatus;
    },
    refetchInterval: 30000,
  });

  const { data: version } = useQuery({
    queryKey: ['system-version'],
    queryFn: async () => {
      const res = await api.get('/api/v1/version');
      return (res.data || res) as VersionInfo;
    },
    retry: false,
  });

  const handleRefresh = async () => {
    await refetchHealth();
    toast.success('Health data refreshed');
  };

  const services = health?.services ? Object.entries(health.services) : [];
  const hasResources =
    health?.cpu_usage !== undefined ||
    health?.memory_usage !== undefined ||
    health?.disk_usage !== undefined;

  return (
    <div className="p-6 space-y-8">
      {/* ── Header ── */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-green-400 via-emerald-400 to-teal-400 bg-clip-text text-transparent">
            System Health
          </h1>
          <p className="mt-1 text-sm text-gray-400">
            Live platform status and resource usage
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={handleRefresh}
          className="gap-2 border-gray-700/50 bg-gray-900/40 text-gray-300 hover:bg-gray-800/60 hover:text-white"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
      </div>

      {/* ── Loading skeleton ── */}
      {healthLoading && <HealthSkeleton />}

      {/* ── Loaded content ── */}
      {!healthLoading && (
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="space-y-6"
        >
          {/* ── Top stats row ── */}
          <motion.div
            variants={itemVariants}
            className="grid grid-cols-2 md:grid-cols-4 gap-4"
          >
            {/* Status */}
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardContent className="p-4 flex flex-col gap-2">
                <div className="flex items-center gap-2 text-xs text-gray-500 uppercase tracking-wider">
                  <Heart className="h-3.5 w-3.5" />
                  Status
                </div>
                <div className="flex items-center gap-2">
                  <span
                    className={`inline-block h-2.5 w-2.5 rounded-full ${
                      health?.status?.toLowerCase() === 'healthy' ||
                      health?.status?.toLowerCase() === 'ok'
                        ? 'bg-green-400 animate-pulse'
                        : health?.status?.toLowerCase() === 'degraded'
                        ? 'bg-yellow-400 animate-pulse'
                        : 'bg-red-400'
                    }`}
                  />
                  <Badge
                    variant={overallStatusVariant(health?.status ?? '')}
                    className="text-xs font-semibold"
                  >
                    {overallStatusLabel(health?.status ?? '')}
                  </Badge>
                </div>
              </CardContent>
            </Card>

            {/* Version */}
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardContent className="p-4 flex flex-col gap-2">
                <div className="flex items-center gap-2 text-xs text-gray-500 uppercase tracking-wider">
                  <Server className="h-3.5 w-3.5" />
                  Version
                </div>
                <p className="text-lg font-bold text-gray-100 truncate">
                  {version?.version ?? 'N/A'}
                </p>
                {version?.build && (
                  <p className="text-xs text-gray-500">Build {version.build}</p>
                )}
              </CardContent>
            </Card>

            {/* Uptime */}
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardContent className="p-4 flex flex-col gap-2">
                <div className="flex items-center gap-2 text-xs text-gray-500 uppercase tracking-wider">
                  <Clock className="h-3.5 w-3.5" />
                  Uptime
                </div>
                <p className="text-lg font-bold text-gray-100 truncate">
                  {health?.uptime ?? 'N/A'}
                </p>
              </CardContent>
            </Card>

            {/* Environment */}
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardContent className="p-4 flex flex-col gap-2">
                <div className="flex items-center gap-2 text-xs text-gray-500 uppercase tracking-wider">
                  <Activity className="h-3.5 w-3.5" />
                  Environment
                </div>
                <p className="text-lg font-bold text-gray-100 truncate capitalize">
                  {version?.environment ?? 'N/A'}
                </p>
                {version?.python_version && (
                  <p className="text-xs text-gray-500">Python {version.python_version}</p>
                )}
              </CardContent>
            </Card>
          </motion.div>

          {/* ── Services section ── */}
          {services.length > 0 && (
            <motion.div variants={itemVariants}>
              <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
                <CardHeader className="pb-3">
                  <CardTitle className="flex items-center gap-2 text-gray-100">
                    <Wifi className="h-4 w-4 text-emerald-400" />
                    Services
                  </CardTitle>
                  <CardDescription className="text-gray-500">
                    Individual subsystem health
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  {services.map(([name, status]) => (
                    <div
                      key={name}
                      className="flex items-center gap-3 rounded-lg px-3 py-2 hover:bg-gray-800/40 transition-colors"
                    >
                      <span
                        className={`h-2.5 w-2.5 rounded-full flex-shrink-0 ${serviceStatusColor(status)}`}
                      />
                      <span className="flex-1 text-sm font-medium text-gray-200 capitalize">
                        {name.replace(/_/g, ' ')}
                      </span>
                      {status?.toLowerCase() === 'healthy' ||
                      status?.toLowerCase() === 'up' ||
                      status?.toLowerCase() === 'ok' ||
                      status?.toLowerCase() === 'running' ? (
                        <CheckCircle2 className="h-4 w-4 text-green-400 flex-shrink-0" />
                      ) : (
                        <AlertTriangle className="h-4 w-4 text-yellow-400 flex-shrink-0" />
                      )}
                      <span className="text-xs text-gray-400 w-20 text-right capitalize">
                        {status}
                      </span>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </motion.div>
          )}

          {/* ── Resource usage ── */}
          {hasResources && (
            <motion.div variants={itemVariants}>
              <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
                <CardHeader className="pb-3">
                  <CardTitle className="flex items-center gap-2 text-gray-100">
                    <Cpu className="h-4 w-4 text-emerald-400" />
                    Resource Usage
                  </CardTitle>
                  <CardDescription className="text-gray-500">
                    Current system resource consumption
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <ResourceBar
                    label="CPU"
                    value={health?.cpu_usage}
                    icon={<Cpu className="h-3.5 w-3.5 text-gray-400" />}
                  />
                  <ResourceBar
                    label="Memory"
                    value={health?.memory_usage}
                    icon={<Activity className="h-3.5 w-3.5 text-gray-400" />}
                  />
                  <ResourceBar
                    label="Disk"
                    value={health?.disk_usage}
                    icon={<HardDrive className="h-3.5 w-3.5 text-gray-400" />}
                  />
                </CardContent>
              </Card>
            </motion.div>
          )}

          {/* ── System details ── */}
          <motion.div variants={itemVariants}>
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-gray-100">
                  <Server className="h-4 w-4 text-emerald-400" />
                  System Details
                </CardTitle>
                <CardDescription className="text-gray-500">
                  Raw API response data
                </CardDescription>
              </CardHeader>
              <CardContent>
                <pre className="text-xs bg-gray-950/50 font-mono p-4 rounded-lg overflow-auto text-gray-300 leading-relaxed max-h-64">
                  {JSON.stringify({ health, version }, null, 2)}
                </pre>
              </CardContent>
            </Card>
          </motion.div>
        </motion.div>
      )}
    </div>
  );
}
