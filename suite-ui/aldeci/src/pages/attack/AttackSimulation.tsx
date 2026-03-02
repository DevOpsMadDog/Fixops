import { useState, useCallback } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Swords,
  Shield,
  Activity,
  AlertTriangle,
  Network,
  Crosshair,
  Radar,
  Globe,
  Bug,
  Lock,
  Server,
  RefreshCw,
  Zap,
  Clock,
  CheckCircle2,
  XCircle,
  BarChart3,
  FileWarning,
  Cpu,
  Play,
  Skull,
  Eye,
  TrendingUp,
  Layers,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Badge } from '../../components/ui/badge';
import { Button } from '../../components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../../components/ui/tabs';
import { ScrollArea } from '../../components/ui/scroll-area';
import MPTEChat from '../../components/attack/MPTEChat';
import {
  microPentestApi,
  reachabilityApi,
  pentagiApi,
  attackGraphApi,
} from '../../lib/api';
import { toast } from 'sonner';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface AttackScenario {
  id: string;
  name: string;
  description: string;
  icon: React.ElementType;
  attackType: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  mitreTechnique: string;
}

interface ThreatActor {
  name: string;
  type: string;
  confidence: number;
  techniques: string[];
}

interface GraphNode {
  id: string;
  type: string;
  risk_score?: number;
  label?: string;
}

interface GraphEdge {
  source: string;
  target: string;
  type?: string;
  weight?: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const APPLE_EASE: [number, number, number, number] = [0.16, 1, 0.3, 1];

const CONTAINER_VARIANTS = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.05, ease: APPLE_EASE },
  },
};

const ITEM_VARIANTS = {
  hidden: { opacity: 0, y: 16 },
  visible: { opacity: 1, y: 0, transition: { ease: APPLE_EASE, duration: 0.4 } },
};

const ATTACK_SCENARIOS: AttackScenario[] = [
  {
    id: 'sqli',
    name: 'SQL Injection',
    description: 'Test for SQL injection vulnerabilities via parameterized payloads',
    icon: Bug,
    attackType: 'sql_injection',
    severity: 'critical',
    mitreTechnique: 'T1190',
  },
  {
    id: 'xss',
    name: 'Cross-Site Scripting',
    description: 'Detect reflected and stored XSS vectors in web applications',
    icon: FileWarning,
    attackType: 'xss',
    severity: 'high',
    mitreTechnique: 'T1059.007',
  },
  {
    id: 'ssrf',
    name: 'Server-Side Request Forgery',
    description: 'Probe for SSRF exploits targeting internal infrastructure',
    icon: Server,
    attackType: 'ssrf',
    severity: 'critical',
    mitreTechnique: 'T1190',
  },
  {
    id: 'rce',
    name: 'Remote Code Execution',
    description: 'Simulate RCE attempts through deserialization and command injection',
    icon: Skull,
    attackType: 'rce',
    severity: 'critical',
    mitreTechnique: 'T1203',
  },
  {
    id: 'auth-bypass',
    name: 'Auth Bypass',
    description: 'Test authentication and authorization controls for bypass flaws',
    icon: Lock,
    attackType: 'auth_bypass',
    severity: 'high',
    mitreTechnique: 'T1078',
  },
  {
    id: 'path-traversal',
    name: 'Path Traversal',
    description: 'Attempt directory traversal to access sensitive files outside webroot',
    icon: Layers,
    attackType: 'path_traversal',
    severity: 'high',
    mitreTechnique: 'T1083',
  },
];

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  info: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
};

function severityBadge(level: string) {
  return SEVERITY_COLORS[level] || SEVERITY_COLORS.info;
}

// ---------------------------------------------------------------------------
// Skeleton helpers
// ---------------------------------------------------------------------------

function SkeletonBlock({ className }: { className: string }) {
  return <div className={`bg-gray-700/30 rounded animate-pulse ${className}`} />;
}

function StatCardSkeleton() {
  return (
    <Card className="border-gray-700/30 bg-gray-900/40">
      <CardContent className="p-4">
        <SkeletonBlock className="h-5 w-5 mb-3" />
        <SkeletonBlock className="h-7 w-14 mb-1" />
        <SkeletonBlock className="h-3 w-24" />
      </CardContent>
    </Card>
  );
}

function TableSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-4">
          <SkeletonBlock className="h-4 w-4 rounded-full" />
          <SkeletonBlock className="h-4 flex-1" />
          <SkeletonBlock className="h-4 w-20" />
          <SkeletonBlock className="h-4 w-16" />
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Error state
// ---------------------------------------------------------------------------

function ErrorState({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="w-14 h-14 rounded-2xl bg-red-500/10 flex items-center justify-center mb-4">
        <AlertTriangle className="w-7 h-7 text-red-400" />
      </div>
      <p className="text-sm text-muted-foreground mb-4 max-w-sm">{message}</p>
      <Button variant="outline" size="sm" onClick={onRetry} className="gap-2">
        <RefreshCw className="w-3.5 h-3.5" />
        Retry
      </Button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Empty state
// ---------------------------------------------------------------------------

function EmptyState({ icon: Icon, title, description }: { icon: React.ElementType; title: string; description: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="w-14 h-14 rounded-2xl bg-slate-500/10 flex items-center justify-center mb-4">
        <Icon className="w-7 h-7 text-slate-400" />
      </div>
      <p className="text-sm font-medium text-slate-300 mb-1">{title}</p>
      <p className="text-xs text-muted-foreground max-w-xs">{description}</p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

export default function AttackSimulation() {
  const [activeTab, setActiveTab] = useState('simulation');
  const [simulationTarget, setSimulationTarget] = useState('');

  // ── Data fetching ─────────────────────────────────────────────────────
  const {
    data: pentestStatus,
    isLoading: pentestLoading,
    isError: pentestError,
    refetch: refetchPentest,
  } = useQuery({
    queryKey: ['pentest-health'],
    queryFn: () => microPentestApi.getHealth(),
    retry: 1,
    staleTime: 30_000,
  });

  const {
    data: reachabilityData,
    isLoading: reachLoading,
    isError: reachError,
    refetch: refetchReach,
  } = useQuery({
    queryKey: ['reachability-metrics'],
    queryFn: () => reachabilityApi.getMetrics(),
    retry: 1,
    staleTime: 30_000,
  });

  const {
    data: graphData,
    isLoading: graphLoading,
    isError: graphError,
    refetch: refetchGraph,
  } = useQuery({
    queryKey: ['attack-graph'],
    queryFn: () => attackGraphApi.getGraph(),
    retry: 1,
    staleTime: 60_000,
  });

  const {
    data: pentagiHealth,
    isLoading: pentagiLoading,
  } = useQuery({
    queryKey: ['pentagi-health'],
    queryFn: () => pentagiApi.health(),
    retry: 1,
    staleTime: 30_000,
  });

  const {
    data: capabilitiesData,
    isLoading: capsLoading,
  } = useQuery({
    queryKey: ['pentagi-capabilities'],
    queryFn: () => pentagiApi.capabilities(),
    retry: 1,
    staleTime: 60_000,
  });

  const {
    data: threatIntelData,
    isLoading: threatLoading,
    isError: threatError,
    refetch: refetchThreat,
  } = useQuery({
    queryKey: ['pentagi-threat-intel'],
    queryFn: () => pentagiApi.threatIntel({ cve_id: 'CVE-2024-3400' }),
    retry: 1,
    staleTime: 120_000,
    enabled: activeTab === 'threat-intel',
  });

  const {
    data: surfaceAnalysis,
    isLoading: surfaceLoading,
    isError: surfaceError,
    refetch: refetchSurface,
  } = useQuery({
    queryKey: ['attack-surface-analysis'],
    queryFn: () => attackGraphApi.analyze({}),
    retry: 1,
    staleTime: 120_000,
    enabled: activeTab === 'attack-surface',
  });

  // ── Mutations ─────────────────────────────────────────────────────────

  const simulateMutation = useMutation({
    mutationFn: (scenario: AttackScenario) =>
      pentagiApi.simulate({
        target: simulationTarget || 'localhost',
        attack_type: scenario.attackType,
      }),
    onSuccess: (_data, scenario) => {
      toast.success(`${scenario.name} simulation launched`);
    },
    onError: (err: Error, scenario) => {
      toast.error(`${scenario.name} simulation failed: ${err.message}`);
    },
  });

  const handleLaunchScenario = useCallback(
    (scenario: AttackScenario) => {
      simulateMutation.mutate(scenario);
    },
    [simulateMutation],
  );

  // ── Derived data ──────────────────────────────────────────────────────

  const typedPentest = pentestStatus as Record<string, unknown> | undefined;
  const typedReach = reachabilityData as Record<string, unknown> | undefined;
  const typedGraph = graphData as Record<string, unknown> | undefined;
  const typedPentagi = pentagiHealth as Record<string, unknown> | undefined;
  const typedCaps = capabilitiesData as Record<string, unknown> | undefined;

  const engineStatus = typedPentest?.status as string | undefined;
  const isEngineReady = engineStatus === 'ready' || engineStatus === 'healthy' || engineStatus === 'ok';

  const capabilityList = (typedCaps?.capabilities || typedCaps?.tools || []) as string[];
  const capabilityCount = capabilityList.length;

  const activeSimulations = (typedPentest?.active_simulations as number) || (typedPentest?.active_tests as number) || 0;
  const totalPaths =
    ((typedGraph?.attack_paths as unknown[])?.length) ||
    ((typedGraph?.paths as unknown[])?.length) ||
    (typedGraph?.total_paths as number) ||
    0;
  const criticalPaths = (typedReach?.critical_reachable as number) || 0;
  const blockedPaths = (typedReach?.blocked_paths as number) || 0;

  const headerLoading = pentestLoading || pentagiLoading || capsLoading;

  // ── Stats cards ───────────────────────────────────────────────────────

  const stats = [
    {
      label: 'Active Simulations',
      value: activeSimulations,
      icon: Activity,
      color: 'text-blue-400',
      bg: 'bg-blue-500/10',
    },
    {
      label: 'Attack Paths',
      value: totalPaths,
      icon: Network,
      color: 'text-purple-400',
      bg: 'bg-purple-500/10',
    },
    {
      label: 'Critical Paths',
      value: criticalPaths,
      icon: AlertTriangle,
      color: 'text-red-400',
      bg: 'bg-red-500/10',
    },
    {
      label: 'Blocked',
      value: blockedPaths,
      icon: Shield,
      color: 'text-green-400',
      bg: 'bg-green-500/10',
    },
    {
      label: 'Capabilities',
      value: capabilityCount,
      icon: Cpu,
      color: 'text-amber-400',
      bg: 'bg-amber-500/10',
    },
    {
      label: 'Engine Uptime',
      value: (typedPentagi?.uptime_minutes as number)
        ? `${Math.round(typedPentagi?.uptime_minutes as number)}m`
        : (typedPentest?.uptime as string) || '--',
      icon: Clock,
      color: 'text-cyan-400',
      bg: 'bg-cyan-500/10',
    },
  ];

  // ── Render ────────────────────────────────────────────────────────────

  return (
    <motion.div
      className="space-y-6"
      variants={CONTAINER_VARIANTS}
      initial="hidden"
      animate="visible"
    >
      {/* ─── Header ───────────────────────────────────────────────────── */}
      <motion.div variants={ITEM_VARIANTS} className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-red-500 to-orange-500 flex items-center justify-center shadow-lg shadow-red-500/20">
            <Swords className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Attack Lab</h1>
            <p className="text-sm text-muted-foreground">
              AI-powered attack simulation and MPTE verification
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {/* Engine status badge */}
          {headerLoading ? (
            <SkeletonBlock className="h-7 w-28 rounded-full" />
          ) : (
            <Badge
              variant="outline"
              className={
                isEngineReady
                  ? 'border-green-500/40 text-green-400 gap-1.5'
                  : 'border-yellow-500/40 text-yellow-400 gap-1.5'
              }
            >
              <span
                className={`w-2 h-2 rounded-full ${isEngineReady ? 'bg-green-500 shadow-green-500/50 shadow-sm' : 'bg-yellow-500 animate-pulse'}`}
              />
              {engineStatus || 'Initializing'}
            </Badge>
          )}

          {/* Risk level indicator */}
          {criticalPaths > 0 && (
            <Badge variant="outline" className="border-red-500/30 text-red-400 gap-1.5">
              <AlertTriangle className="w-3 h-3" />
              {criticalPaths} Critical
            </Badge>
          )}

          {capabilityCount > 0 && (
            <Badge variant="outline" className="border-indigo-500/30 text-indigo-400 gap-1.5">
              <Zap className="w-3 h-3" />
              {capabilityCount} Tools
            </Badge>
          )}
        </div>
      </motion.div>

      {/* ─── Stats Row ────────────────────────────────────────────────── */}
      <motion.div variants={ITEM_VARIANTS} className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {pentestLoading || reachLoading || graphLoading
          ? Array.from({ length: 6 }).map((_, i) => <StatCardSkeleton key={i} />)
          : stats.map((stat, idx) => (
              <motion.div
                key={stat.label}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: idx * 0.04, ease: APPLE_EASE, duration: 0.35 }}
              >
                <Card className="border-gray-700/30 bg-gray-900/40 hover:bg-gray-900/60 transition-colors">
                  <CardContent className="p-4">
                    <div className="flex items-center gap-3">
                      <div className={`p-2 rounded-lg ${stat.bg}`}>
                        <stat.icon className={`w-4 h-4 ${stat.color}`} />
                      </div>
                      <div className="min-w-0">
                        <p className="text-xl font-bold tabular-nums truncate">{stat.value}</p>
                        <p className="text-[11px] text-muted-foreground truncate">{stat.label}</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
      </motion.div>

      {/* ─── Tabbed Content ───────────────────────────────────────────── */}
      <motion.div variants={ITEM_VARIANTS}>
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
          <TabsList className="bg-gray-900/60 border border-gray-700/30 p-1">
            <TabsTrigger value="simulation" className="gap-1.5 data-[state=active]:bg-gray-800">
              <Crosshair className="w-3.5 h-3.5" />
              Live Simulation
            </TabsTrigger>
            <TabsTrigger value="attack-surface" className="gap-1.5 data-[state=active]:bg-gray-800">
              <Radar className="w-3.5 h-3.5" />
              Attack Surface
            </TabsTrigger>
            <TabsTrigger value="threat-intel" className="gap-1.5 data-[state=active]:bg-gray-800">
              <Globe className="w-3.5 h-3.5" />
              Threat Intel
            </TabsTrigger>
            <TabsTrigger value="history" className="gap-1.5 data-[state=active]:bg-gray-800">
              <BarChart3 className="w-3.5 h-3.5" />
              Results History
            </TabsTrigger>
          </TabsList>

          {/* ── Tab: Live Simulation ────────────────────────────────── */}
          <TabsContent value="simulation" className="space-y-4">
            {/* Scenario quick-start */}
            <Card className="bg-gradient-to-br from-gray-900/80 via-slate-900/60 to-gray-900/80 border-gray-700/30">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Play className="w-4 h-4 text-orange-400" />
                  Quick-Start Scenarios
                </CardTitle>
                <CardDescription className="text-xs">
                  Launch a pre-configured attack simulation against a target
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Target input */}
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={simulationTarget}
                    onChange={(e) => setSimulationTarget(e.target.value)}
                    placeholder="Target URL or hostname (default: localhost)"
                    className="flex-1 bg-gray-800/60 border border-gray-700/40 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-orange-500/30 placeholder:text-gray-500"
                  />
                </div>

                {/* Scenario cards */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                  {ATTACK_SCENARIOS.map((scenario) => (
                    <button
                      key={scenario.id}
                      onClick={() => handleLaunchScenario(scenario)}
                      disabled={simulateMutation.isPending}
                      className="group relative text-left p-4 rounded-xl border border-gray-700/30 bg-gray-800/30 hover:bg-gray-800/60 hover:border-gray-600/50 transition-all duration-200"
                    >
                      <div className="flex items-start gap-3">
                        <div className={`p-2 rounded-lg ${scenario.severity === 'critical' ? 'bg-red-500/10' : 'bg-orange-500/10'}`}>
                          <scenario.icon
                            className={`w-4 h-4 ${scenario.severity === 'critical' ? 'text-red-400' : 'text-orange-400'}`}
                          />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-sm font-medium">{scenario.name}</span>
                            <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${severityBadge(scenario.severity)}`}>
                              {scenario.severity.toUpperCase()}
                            </Badge>
                          </div>
                          <p className="text-xs text-muted-foreground leading-relaxed">
                            {scenario.description}
                          </p>
                          <p className="text-[10px] text-gray-500 mt-1.5 font-mono">
                            MITRE {scenario.mitreTechnique}
                          </p>
                        </div>
                      </div>
                      {/* Hover play indicator */}
                      <div className="absolute top-3 right-3 opacity-0 group-hover:opacity-100 transition-opacity">
                        <Play className="w-3.5 h-3.5 text-orange-400" />
                      </div>
                    </button>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* MPTE Chat interface */}
            <MPTEChat />
          </TabsContent>

          {/* ── Tab: Attack Surface ─────────────────────────────────── */}
          <TabsContent value="attack-surface" className="space-y-4">
            <AttackSurfaceTab
              graphData={typedGraph}
              surfaceAnalysis={surfaceAnalysis as Record<string, unknown> | undefined}
              graphLoading={graphLoading}
              surfaceLoading={surfaceLoading}
              graphError={graphError}
              surfaceError={surfaceError}
              refetchGraph={refetchGraph}
              refetchSurface={refetchSurface}
            />
          </TabsContent>

          {/* ── Tab: Threat Intel ────────────────────────────────────── */}
          <TabsContent value="threat-intel" className="space-y-4">
            <ThreatIntelTab
              threatData={threatIntelData as Record<string, unknown> | undefined}
              isLoading={threatLoading}
              isError={threatError}
              refetch={refetchThreat}
            />
          </TabsContent>

          {/* ── Tab: Results History ─────────────────────────────────── */}
          <TabsContent value="history" className="space-y-4">
            <ResultsHistoryTab
              pentestStatus={typedPentest}
              reachData={typedReach}
              isLoading={pentestLoading || reachLoading}
              isError={pentestError || reachError}
              refetch={() => {
                refetchPentest();
                refetchReach();
              }}
            />
          </TabsContent>
        </Tabs>
      </motion.div>
    </motion.div>
  );
}

// ===========================================================================
// Sub-tab Components
// ===========================================================================

// ---------------------------------------------------------------------------
// Attack Surface Tab
// ---------------------------------------------------------------------------

function AttackSurfaceTab({
  graphData,
  surfaceAnalysis,
  graphLoading,
  surfaceLoading,
  graphError,
  surfaceError,
  refetchGraph,
  refetchSurface,
}: {
  graphData: Record<string, unknown> | undefined;
  surfaceAnalysis: Record<string, unknown> | undefined;
  graphLoading: boolean;
  surfaceLoading: boolean;
  graphError: boolean;
  surfaceError: boolean;
  refetchGraph: () => void;
  refetchSurface: () => void;
}) {
  const isLoading = graphLoading || surfaceLoading;
  const isError = graphError && surfaceError;

  if (isError) {
    return (
      <ErrorState
        message="Unable to load attack surface data. Ensure the backend is running."
        onRetry={() => {
          refetchGraph();
          refetchSurface();
        }}
      />
    );
  }

  const nodes = (graphData?.nodes || graphData?.infrastructure || []) as GraphNode[];
  const edges = (graphData?.edges || graphData?.connections || []) as GraphEdge[];
  const criticalPathsArr = (surfaceAnalysis?.critical_paths || surfaceAnalysis?.attack_paths || []) as unknown[];
  const riskScore = (surfaceAnalysis?.risk_score as number) || (graphData?.risk_score as number) || 0;
  const mitigations = (surfaceAnalysis?.mitigations || []) as { name: string; effectiveness: number }[];

  // Node type breakdown
  const nodeTypes: Record<string, number> = {};
  nodes.forEach((n) => {
    const t = n.type || 'unknown';
    nodeTypes[t] = (nodeTypes[t] || 0) + 1;
  });

  // Risk distribution from nodes
  let highRiskNodes = 0;
  let mediumRiskNodes = 0;
  let lowRiskNodes = 0;
  nodes.forEach((n) => {
    const rs = n.risk_score || 0;
    if (rs >= 0.7) highRiskNodes++;
    else if (rs >= 0.4) mediumRiskNodes++;
    else lowRiskNodes++;
  });

  const surfaceStats = [
    { label: 'Total Nodes', value: nodes.length, icon: Layers, color: 'text-indigo-400', bg: 'bg-indigo-500/10' },
    { label: 'Connections', value: edges.length, icon: Network, color: 'text-purple-400', bg: 'bg-purple-500/10' },
    { label: 'Critical Paths', value: criticalPathsArr.length, icon: AlertTriangle, color: 'text-red-400', bg: 'bg-red-500/10' },
    {
      label: 'Risk Score',
      value: typeof riskScore === 'number' ? riskScore.toFixed(2) : '--',
      icon: TrendingUp,
      color: riskScore >= 0.7 ? 'text-red-400' : riskScore >= 0.4 ? 'text-yellow-400' : 'text-green-400',
      bg: riskScore >= 0.7 ? 'bg-red-500/10' : riskScore >= 0.4 ? 'bg-yellow-500/10' : 'bg-green-500/10',
    },
  ];

  return (
    <div className="space-y-4">
      {/* Surface stats */}
      {isLoading ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <StatCardSkeleton key={i} />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {surfaceStats.map((s) => (
            <Card key={s.label} className="border-gray-700/30 bg-gray-900/40">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg ${s.bg}`}>
                    <s.icon className={`w-4 h-4 ${s.color}`} />
                  </div>
                  <div>
                    <p className="text-xl font-bold tabular-nums">{s.value}</p>
                    <p className="text-[11px] text-muted-foreground">{s.label}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Node type breakdown */}
        <Card className="bg-gradient-to-br from-gray-900/80 via-slate-900/60 to-gray-900/80 border-gray-700/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Layers className="w-4 h-4 text-indigo-400" />
              Node Type Breakdown
            </CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <TableSkeleton rows={4} />
            ) : Object.keys(nodeTypes).length === 0 ? (
              <EmptyState
                icon={Layers}
                title="No nodes discovered"
                description="Run an attack graph analysis to discover infrastructure nodes."
              />
            ) : (
              <ScrollArea className="h-[220px]">
                <div className="space-y-2">
                  {Object.entries(nodeTypes)
                    .sort(([, a], [, b]) => b - a)
                    .map(([type, count]) => (
                      <div
                        key={type}
                        className="flex items-center justify-between p-2.5 rounded-lg bg-gray-800/30 border border-gray-700/20"
                      >
                        <div className="flex items-center gap-2.5">
                          <div className="w-2 h-2 rounded-full bg-indigo-400" />
                          <span className="text-sm capitalize">{type.replace(/_/g, ' ')}</span>
                        </div>
                        <Badge variant="outline" className="text-xs font-mono border-gray-600/40">
                          {count}
                        </Badge>
                      </div>
                    ))}
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>

        {/* Risk distribution */}
        <Card className="bg-gradient-to-br from-gray-900/80 via-slate-900/60 to-gray-900/80 border-gray-700/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Eye className="w-4 h-4 text-amber-400" />
              Risk Distribution
            </CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <TableSkeleton rows={3} />
            ) : nodes.length === 0 ? (
              <EmptyState
                icon={Eye}
                title="No risk data"
                description="Analyze the attack surface to see risk distribution."
              />
            ) : (
              <div className="space-y-4 pt-2">
                {[
                  { label: 'High Risk', count: highRiskNodes, color: 'bg-red-500', textColor: 'text-red-400' },
                  { label: 'Medium Risk', count: mediumRiskNodes, color: 'bg-yellow-500', textColor: 'text-yellow-400' },
                  { label: 'Low Risk', count: lowRiskNodes, color: 'bg-green-500', textColor: 'text-green-400' },
                ].map((row) => {
                  const pct = nodes.length > 0 ? (row.count / nodes.length) * 100 : 0;
                  return (
                    <div key={row.label} className="space-y-1.5">
                      <div className="flex items-center justify-between text-sm">
                        <span className={row.textColor}>{row.label}</span>
                        <span className="text-muted-foreground font-mono text-xs">
                          {row.count} ({pct.toFixed(0)}%)
                        </span>
                      </div>
                      <div className="h-2 rounded-full bg-gray-800 overflow-hidden">
                        <motion.div
                          className={`h-full rounded-full ${row.color}`}
                          initial={{ width: 0 }}
                          animate={{ width: `${pct}%` }}
                          transition={{ duration: 0.8, ease: APPLE_EASE }}
                        />
                      </div>
                    </div>
                  );
                })}

                {/* Mitigations */}
                {mitigations.length > 0 && (
                  <div className="pt-3 border-t border-gray-700/30">
                    <p className="text-xs text-muted-foreground mb-2">Active Mitigations</p>
                    <div className="space-y-1.5">
                      {mitigations.slice(0, 5).map((m, i) => (
                        <div key={i} className="flex items-center justify-between text-xs">
                          <span className="text-slate-300">{m.name}</span>
                          <Badge
                            variant="outline"
                            className={`text-[10px] ${
                              m.effectiveness >= 0.8
                                ? 'border-green-500/30 text-green-400'
                                : 'border-yellow-500/30 text-yellow-400'
                            }`}
                          >
                            {(m.effectiveness * 100).toFixed(0)}%
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Threat Intel Tab
// ---------------------------------------------------------------------------

function ThreatIntelTab({
  threatData,
  isLoading,
  isError,
  refetch,
}: {
  threatData: Record<string, unknown> | undefined;
  isLoading: boolean;
  isError: boolean;
  refetch: () => void;
}) {
  if (isError) {
    return (
      <ErrorState
        message="Failed to fetch threat intelligence data. The PentAGI service may be unavailable."
        onRetry={refetch}
      />
    );
  }

  const threatActors = (threatData?.threat_actors || threatData?.actors || []) as ThreatActor[];
  const cveExploits = (threatData?.exploits || threatData?.cve_exploits || []) as {
    cve_id: string;
    severity: string;
    description: string;
    epss_score?: number;
    in_kev?: boolean;
  }[];
  const attackVectors = (threatData?.attack_vectors || threatData?.vectors || []) as {
    name: string;
    frequency: number;
    severity: string;
  }[];
  const recommendations = (threatData?.recommendations || []) as string[];
  const overallThreatLevel = (threatData?.threat_level as string) || (threatData?.overall_risk as string) || 'unknown';

  return (
    <div className="space-y-4">
      {/* Threat level banner */}
      {isLoading ? (
        <SkeletonBlock className="h-16 w-full rounded-xl" />
      ) : (
        <Card
          className={`border-gray-700/30 ${
            overallThreatLevel === 'critical' || overallThreatLevel === 'high'
              ? 'bg-gradient-to-r from-red-950/40 to-gray-900/60'
              : overallThreatLevel === 'medium'
                ? 'bg-gradient-to-r from-yellow-950/30 to-gray-900/60'
                : 'bg-gradient-to-r from-gray-900/80 to-gray-900/60'
          }`}
        >
          <CardContent className="p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-red-500/10">
                <Globe className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <p className="text-sm font-medium">Threat Intelligence Summary</p>
                <p className="text-xs text-muted-foreground">
                  {threatActors.length} actors tracked, {cveExploits.length} active exploits,{' '}
                  {attackVectors.length} vectors
                </p>
              </div>
            </div>
            <Badge
              variant="outline"
              className={severityBadge(overallThreatLevel)}
            >
              {overallThreatLevel.toUpperCase()}
            </Badge>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Threat Actors */}
        <Card className="bg-gradient-to-br from-gray-900/80 via-slate-900/60 to-gray-900/80 border-gray-700/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Skull className="w-4 h-4 text-red-400" />
              Threat Actors
            </CardTitle>
            <CardDescription className="text-xs">Known adversaries targeting similar infrastructure</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <TableSkeleton rows={4} />
            ) : threatActors.length === 0 ? (
              <EmptyState
                icon={Skull}
                title="No threat actors identified"
                description="Threat actor data will appear here when intelligence is available."
              />
            ) : (
              <ScrollArea className="h-[260px]">
                <div className="space-y-2">
                  {threatActors.map((actor, i) => (
                    <motion.div
                      key={actor.name || i}
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.05, ease: APPLE_EASE }}
                      className="p-3 rounded-lg bg-gray-800/30 border border-gray-700/20"
                    >
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-sm font-medium">{actor.name}</span>
                        <Badge variant="outline" className="text-[10px] border-gray-600/40">
                          {actor.type || 'APT'}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2 mb-2">
                        <span className="text-[11px] text-muted-foreground">Confidence:</span>
                        <div className="flex-1 h-1.5 rounded-full bg-gray-700/50 overflow-hidden">
                          <motion.div
                            className={`h-full rounded-full ${
                              actor.confidence >= 0.8
                                ? 'bg-red-500'
                                : actor.confidence >= 0.5
                                  ? 'bg-yellow-500'
                                  : 'bg-blue-500'
                            }`}
                            initial={{ width: 0 }}
                            animate={{ width: `${(actor.confidence || 0) * 100}%` }}
                            transition={{ duration: 0.6, ease: APPLE_EASE }}
                          />
                        </div>
                        <span className="text-[10px] text-muted-foreground font-mono">
                          {((actor.confidence || 0) * 100).toFixed(0)}%
                        </span>
                      </div>
                      {actor.techniques?.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {actor.techniques.slice(0, 4).map((t) => (
                            <Badge
                              key={t}
                              variant="outline"
                              className="text-[9px] px-1.5 py-0 border-gray-600/30 text-gray-400 font-mono"
                            >
                              {t}
                            </Badge>
                          ))}
                          {actor.techniques.length > 4 && (
                            <span className="text-[9px] text-gray-500">
                              +{actor.techniques.length - 4} more
                            </span>
                          )}
                        </div>
                      )}
                    </motion.div>
                  ))}
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>

        {/* CVE Exploits */}
        <Card className="bg-gradient-to-br from-gray-900/80 via-slate-900/60 to-gray-900/80 border-gray-700/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Bug className="w-4 h-4 text-orange-400" />
              Active Exploits
            </CardTitle>
            <CardDescription className="text-xs">CVEs with known exploitation in the wild</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <TableSkeleton rows={4} />
            ) : cveExploits.length === 0 ? (
              <EmptyState
                icon={Bug}
                title="No active exploits found"
                description="CVE exploit intelligence will populate when available."
              />
            ) : (
              <ScrollArea className="h-[260px]">
                <div className="space-y-2">
                  {cveExploits.map((exploit, i) => (
                    <motion.div
                      key={exploit.cve_id || i}
                      initial={{ opacity: 0, x: 8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.05, ease: APPLE_EASE }}
                      className="p-3 rounded-lg bg-gray-800/30 border border-gray-700/20"
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-mono font-medium text-orange-300">
                          {exploit.cve_id}
                        </span>
                        <Badge
                          variant="outline"
                          className={`text-[10px] ${severityBadge(exploit.severity?.toLowerCase() || 'medium')}`}
                        >
                          {(exploit.severity || 'MEDIUM').toUpperCase()}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground mb-2 line-clamp-2">
                        {exploit.description || 'No description available'}
                      </p>
                      <div className="flex items-center gap-3 text-[10px] text-gray-500">
                        {exploit.epss_score !== undefined && (
                          <span>
                            EPSS: <span className="text-amber-400 font-mono">{(exploit.epss_score * 100).toFixed(1)}%</span>
                          </span>
                        )}
                        {exploit.in_kev && (
                          <Badge variant="outline" className="text-[9px] px-1 py-0 border-red-500/30 text-red-400">
                            CISA KEV
                          </Badge>
                        )}
                      </div>
                    </motion.div>
                  ))}
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Attack Vectors + Recommendations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Attack Vectors */}
        <Card className="bg-gradient-to-br from-gray-900/80 via-slate-900/60 to-gray-900/80 border-gray-700/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Crosshair className="w-4 h-4 text-purple-400" />
              Attack Vectors
            </CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <TableSkeleton rows={4} />
            ) : attackVectors.length === 0 ? (
              <EmptyState
                icon={Crosshair}
                title="No attack vectors cataloged"
                description="Attack vector analysis will appear after threat intel processing."
              />
            ) : (
              <div className="space-y-2">
                {attackVectors.map((vec, i) => {
                  const maxFreq = Math.max(...attackVectors.map((v) => v.frequency || 1), 1);
                  const pct = ((vec.frequency || 0) / maxFreq) * 100;
                  return (
                    <div key={vec.name || i} className="space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-slate-300">{vec.name}</span>
                        <div className="flex items-center gap-2">
                          <Badge
                            variant="outline"
                            className={`text-[9px] px-1 py-0 ${severityBadge(vec.severity?.toLowerCase() || 'medium')}`}
                          >
                            {(vec.severity || 'medium').toUpperCase()}
                          </Badge>
                          <span className="text-muted-foreground font-mono w-8 text-right">{vec.frequency}</span>
                        </div>
                      </div>
                      <div className="h-1.5 rounded-full bg-gray-800 overflow-hidden">
                        <motion.div
                          className="h-full rounded-full bg-purple-500"
                          initial={{ width: 0 }}
                          animate={{ width: `${pct}%` }}
                          transition={{ duration: 0.6, delay: i * 0.05, ease: APPLE_EASE }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Recommendations */}
        <Card className="bg-gradient-to-br from-gray-900/80 via-slate-900/60 to-gray-900/80 border-gray-700/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Shield className="w-4 h-4 text-green-400" />
              Recommendations
            </CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <TableSkeleton rows={4} />
            ) : recommendations.length === 0 ? (
              <EmptyState
                icon={Shield}
                title="No recommendations yet"
                description="Actionable recommendations will appear after intelligence analysis."
              />
            ) : (
              <ScrollArea className="h-[200px]">
                <div className="space-y-2">
                  {recommendations.map((rec, i) => (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: i * 0.04, ease: APPLE_EASE }}
                      className="flex items-start gap-2.5 p-2.5 rounded-lg bg-gray-800/30 border border-gray-700/20"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5 text-green-400 mt-0.5 shrink-0" />
                      <span className="text-xs text-slate-300 leading-relaxed">{rec}</span>
                    </motion.div>
                  ))}
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Results History Tab
// ---------------------------------------------------------------------------

function ResultsHistoryTab({
  pentestStatus,
  reachData,
  isLoading,
  isError,
  refetch,
}: {
  pentestStatus: Record<string, unknown> | undefined;
  reachData: Record<string, unknown> | undefined;
  isLoading: boolean;
  isError: boolean;
  refetch: () => void;
}) {
  if (isError) {
    return (
      <ErrorState
        message="Failed to load results history. Check backend connectivity."
        onRetry={refetch}
      />
    );
  }

  const completedTests = (pentestStatus?.completed_tests as number) || (pentestStatus?.total_completed as number) || 0;
  const totalTests = (pentestStatus?.total_tests as number) || (pentestStatus?.total_runs as number) || 0;
  const successRate = totalTests > 0 ? ((completedTests / totalTests) * 100) : 0;
  const lastRunTime = (pentestStatus?.last_run as string) || (pentestStatus?.last_test_time as string) || null;
  const recentResults = (pentestStatus?.recent_results || pentestStatus?.history || []) as {
    id: string;
    target: string;
    status: string;
    severity: string;
    findings_count: number;
    timestamp: string;
    duration_seconds?: number;
  }[];

  // Reachability summary
  const totalReachable = (reachData?.total_reachable as number) || 0;
  const totalUnreachable = (reachData?.total_unreachable as number) || 0;
  const reachabilityRate =
    totalReachable + totalUnreachable > 0
      ? (totalReachable / (totalReachable + totalUnreachable)) * 100
      : 0;

  const historyStats = [
    { label: 'Completed Tests', value: completedTests, icon: CheckCircle2, color: 'text-green-400', bg: 'bg-green-500/10' },
    { label: 'Total Runs', value: totalTests, icon: Activity, color: 'text-blue-400', bg: 'bg-blue-500/10' },
    {
      label: 'Success Rate',
      value: `${successRate.toFixed(0)}%`,
      icon: TrendingUp,
      color: successRate >= 80 ? 'text-green-400' : successRate >= 50 ? 'text-yellow-400' : 'text-red-400',
      bg: successRate >= 80 ? 'bg-green-500/10' : successRate >= 50 ? 'bg-yellow-500/10' : 'bg-red-500/10',
    },
    {
      label: 'Reachability',
      value: `${reachabilityRate.toFixed(0)}%`,
      icon: Radar,
      color: reachabilityRate > 50 ? 'text-red-400' : 'text-green-400',
      bg: reachabilityRate > 50 ? 'bg-red-500/10' : 'bg-green-500/10',
    },
  ];

  return (
    <div className="space-y-4">
      {/* Summary stats */}
      {isLoading ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <StatCardSkeleton key={i} />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {historyStats.map((s) => (
            <Card key={s.label} className="border-gray-700/30 bg-gray-900/40">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg ${s.bg}`}>
                    <s.icon className={`w-4 h-4 ${s.color}`} />
                  </div>
                  <div>
                    <p className="text-xl font-bold tabular-nums">{s.value}</p>
                    <p className="text-[11px] text-muted-foreground">{s.label}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Last run info */}
      {lastRunTime && !isLoading && (
        <Card className="border-gray-700/30 bg-gray-900/40">
          <CardContent className="p-3 flex items-center gap-3 text-xs text-muted-foreground">
            <Clock className="w-3.5 h-3.5" />
            Last simulation: {new Date(lastRunTime).toLocaleString()}
          </CardContent>
        </Card>
      )}

      {/* Results table */}
      <Card className="bg-gradient-to-br from-gray-900/80 via-slate-900/60 to-gray-900/80 border-gray-700/30">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-blue-400" />
            Simulation Results
          </CardTitle>
          <CardDescription className="text-xs">
            Historical record of all completed attack simulations
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <TableSkeleton rows={6} />
          ) : recentResults.length === 0 ? (
            <EmptyState
              icon={BarChart3}
              title="No simulation results yet"
              description="Run an attack simulation from the Live Simulation tab to see results here."
            />
          ) : (
            <ScrollArea className="h-[360px]">
              <div className="space-y-2">
                <AnimatePresence>
                  {recentResults.map((result, i) => (
                    <motion.div
                      key={result.id || i}
                      initial={{ opacity: 0, y: 12 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: i * 0.03, ease: APPLE_EASE }}
                      className="flex items-center gap-4 p-3 rounded-lg bg-gray-800/30 border border-gray-700/20 hover:bg-gray-800/50 transition-colors"
                    >
                      {/* Status indicator */}
                      <div className="shrink-0">
                        {result.status === 'completed' || result.status === 'success' ? (
                          <CheckCircle2 className="w-4 h-4 text-green-400" />
                        ) : result.status === 'failed' || result.status === 'error' ? (
                          <XCircle className="w-4 h-4 text-red-400" />
                        ) : (
                          <Activity className="w-4 h-4 text-yellow-400 animate-pulse" />
                        )}
                      </div>

                      {/* Target */}
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{result.target || 'Unknown Target'}</p>
                        <p className="text-[10px] text-muted-foreground">
                          {result.timestamp ? new Date(result.timestamp).toLocaleString() : '--'}
                          {result.duration_seconds ? ` -- ${result.duration_seconds}s` : ''}
                        </p>
                      </div>

                      {/* Findings */}
                      <div className="flex items-center gap-2 shrink-0">
                        {result.findings_count > 0 && (
                          <Badge variant="outline" className="text-[10px] border-gray-600/40 font-mono">
                            {result.findings_count} findings
                          </Badge>
                        )}
                        <Badge
                          variant="outline"
                          className={`text-[10px] ${severityBadge(result.severity?.toLowerCase() || 'info')}`}
                        >
                          {(result.severity || result.status || 'unknown').toUpperCase()}
                        </Badge>
                      </div>
                    </motion.div>
                  ))}
                </AnimatePresence>
              </div>
            </ScrollArea>
          )}
        </CardContent>
      </Card>

      {/* Reachability summary */}
      {!isLoading && (totalReachable > 0 || totalUnreachable > 0) && (
        <Card className="bg-gradient-to-br from-gray-900/80 via-slate-900/60 to-gray-900/80 border-gray-700/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Radar className="w-4 h-4 text-cyan-400" />
              Reachability Summary
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-6">
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-red-400">Reachable</span>
                  <span className="font-mono text-xs text-muted-foreground">{totalReachable}</span>
                </div>
                <div className="h-2 rounded-full bg-gray-800 overflow-hidden">
                  <motion.div
                    className="h-full rounded-full bg-red-500"
                    initial={{ width: 0 }}
                    animate={{ width: `${reachabilityRate}%` }}
                    transition={{ duration: 0.8, ease: APPLE_EASE }}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-green-400">Unreachable</span>
                  <span className="font-mono text-xs text-muted-foreground">{totalUnreachable}</span>
                </div>
                <div className="h-2 rounded-full bg-gray-800 overflow-hidden">
                  <motion.div
                    className="h-full rounded-full bg-green-500"
                    initial={{ width: 0 }}
                    animate={{ width: `${100 - reachabilityRate}%` }}
                    transition={{ duration: 0.8, ease: APPLE_EASE }}
                  />
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
