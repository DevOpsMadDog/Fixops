import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  FileSignature,
  Download,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Shield,
  FileText,
  RefreshCw,
  Loader2,
  ExternalLink,
  BarChart3,
  Activity,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Progress } from '../../components/ui/progress';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../../components/ui/tabs';
import { api, complianceApi, auditApi } from '../../lib/api';
import { toast } from 'sonner';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ComplianceFramework {
  id: string;
  name: string;
  description: string;
  controls_total: number;
  controls_passing: number;
  controls_failing: number;
  last_assessed: string;
  status: 'compliant' | 'non-compliant' | 'partial' | 'pending';
  version?: string;
  category?: string;
}

interface AuditLog {
  id: string;
  action?: string;
  message?: string;
  timestamp?: string;
  user?: string;
  severity?: string;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const APPLE_EASE = [0.16, 1, 0.3, 1] as const;

const STATUS_CONFIG = {
  compliant: {
    badge: 'bg-green-500/20 text-green-400 border-green-500/30',
    label: 'Compliant',
    icon: CheckCircle2,
  },
  'non-compliant': {
    badge: 'bg-red-500/20 text-red-400 border-red-500/30',
    label: 'Non-Compliant',
    icon: AlertTriangle,
  },
  partial: {
    badge: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    label: 'Partial',
    icon: Activity,
  },
  pending: {
    badge: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
    label: 'Pending',
    icon: Clock,
  },
} as const;

// ─── Skeleton ─────────────────────────────────────────────────────────────────

function ComplianceSkeleton() {
  return (
    <div className="space-y-4">
      {Array.from({ length: 4 }, (_, i) => (
        <div key={i} className="rounded-xl border border-gray-700/30 bg-gray-900/40 p-5 animate-pulse">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-gray-700/40" />
              <div className="space-y-2">
                <div className="h-4 w-36 bg-gray-700/40 rounded" />
                <div className="h-3 w-56 bg-gray-700/30 rounded" />
              </div>
            </div>
            <div className="h-6 w-20 bg-gray-700/40 rounded-full" />
          </div>
          <div className="h-2 w-full bg-gray-700/30 rounded" />
        </div>
      ))}
    </div>
  );
}

// ─── Container Variants ──────────────────────────────────────────────────────

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.06 } },
};

const itemVariants = {
  hidden: { opacity: 0, y: 14, scale: 0.97 },
  visible: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: { ease: APPLE_EASE, duration: 0.5 },
  },
};

// ─── Main Component ──────────────────────────────────────────────────────────

export default function ComplianceReports() {
  const queryClient = useQueryClient();
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null);

  // ── Fetch compliance frameworks from real API ─────────────────────────────

  const {
    data: frameworksRaw,
    isLoading: frameworksLoading,
    refetch: refetchFrameworks,
  } = useQuery({
    queryKey: ['compliance-frameworks'],
    queryFn: async () => {
      const res = await api.get('/api/v1/compliance-engine/frameworks');
      const data = res.data;
      // Handle various response shapes
      const list = data?.frameworks ?? data?.items ?? (Array.isArray(data) ? data : []);
      return list as ComplianceFramework[];
    },
    retry: false,
    refetchInterval: 120_000,
  });

  // ── Fetch compliance status for overall posture ───────────────────────────

  const { data: complianceStatus } = useQuery({
    queryKey: ['compliance-status'],
    queryFn: () => complianceApi.getStatus(),
    retry: false,
  });

  // ── Fetch audit trail for activity feed ───────────────────────────────────

  const { data: auditData } = useQuery({
    queryKey: ['compliance-audit-trail'],
    queryFn: () => auditApi.getLogs({ limit: 10 }),
    retry: false,
  });

  // ── Generate report mutation ──────────────────────────────────────────────

  const generateReportMutation = useMutation({
    mutationFn: async (frameworkId: string) => {
      return complianceApi.generateReport(frameworkId);
    },
    onSuccess: (_, frameworkId) => {
      toast.success(`Report generation started for ${frameworkId}`);
      queryClient.invalidateQueries({ queryKey: ['compliance-frameworks'] });
    },
    onError: (error: Error) => {
      toast.error(`Failed to generate report: ${error.message}`);
    },
  });

  // ── Collect evidence mutation ─────────────────────────────────────────────

  const collectEvidenceMutation = useMutation({
    mutationFn: async (frameworkId: string) => {
      return complianceApi.collectEvidence(frameworkId);
    },
    onSuccess: (_, frameworkId) => {
      toast.success(`Evidence collection started for ${frameworkId}`);
    },
    onError: (error: Error) => {
      toast.error(`Evidence collection failed: ${error.message}`);
    },
  });

  // ── Normalize frameworks ──────────────────────────────────────────────────

  const frameworks: ComplianceFramework[] = useMemo(() => {
    if (frameworksRaw && frameworksRaw.length > 0) {
      return frameworksRaw.map((f) => ({
        id: f.id ?? f.name?.toLowerCase().replace(/\s+/g, '-') ?? 'unknown',
        name: f.name ?? 'Unknown Framework',
        description: f.description ?? '',
        controls_total: f.controls_total ?? 0,
        controls_passing: f.controls_passing ?? 0,
        controls_failing: f.controls_failing ?? 0,
        last_assessed: f.last_assessed ?? new Date().toISOString(),
        status: f.status ?? 'pending',
        version: f.version,
        category: f.category,
      }));
    }
    return [];
  }, [frameworksRaw]);

  // ── Derived stats ─────────────────────────────────────────────────────────

  const totalControls = frameworks.reduce((acc, f) => acc + f.controls_total, 0);
  const passingControls = frameworks.reduce((acc, f) => acc + f.controls_passing, 0);
  const failingControls = frameworks.reduce((acc, f) => acc + f.controls_failing, 0);
  const overallCompliance = totalControls > 0 ? Math.round((passingControls / totalControls) * 100) : 0;
  const compliantCount = frameworks.filter((f) => f.status === 'compliant').length;
  const auditLogs: AuditLog[] = (auditData as { logs?: AuditLog[] })?.logs ?? [];

  const getCompliancePercentage = (f: ComplianceFramework) =>
    f.controls_total > 0 ? Math.round((f.controls_passing / f.controls_total) * 100) : 0;

  return (
    <div className="space-y-6 p-6">
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <motion.div
        initial={{ opacity: 0, y: -14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ ease: APPLE_EASE, duration: 0.5 }}
        className="flex items-start justify-between gap-4 flex-wrap"
      >
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-emerald-500 to-teal-500 flex items-center justify-center shadow-lg shadow-emerald-500/20">
            <FileSignature className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-3xl font-bold bg-gradient-to-r from-emerald-400 to-teal-400 bg-clip-text text-transparent">
              Compliance Reports
            </h1>
            <p className="text-sm text-gray-400 mt-0.5">
              Regulatory compliance tracking and automated evidence generation
            </p>
          </div>
        </div>
        <Button
          variant="outline"
          onClick={() => refetchFrameworks()}
          className="border-gray-700 text-gray-400 hover:text-gray-200 gap-2"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </Button>
      </motion.div>

      {/* ── Stats Row ──────────────────────────────────────────────────── */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.08, ease: APPLE_EASE }}
        className="grid grid-cols-2 md:grid-cols-5 gap-3"
      >
        {[
          {
            label: 'Overall Compliance',
            value: frameworksLoading ? '…' : `${overallCompliance}%`,
            icon: Shield,
            accent: 'text-emerald-400',
          },
          {
            label: 'Controls Passing',
            value: frameworksLoading ? '…' : passingControls,
            icon: CheckCircle2,
            accent: 'text-green-400',
          },
          {
            label: 'Controls Failing',
            value: frameworksLoading ? '…' : failingControls,
            icon: AlertTriangle,
            accent: 'text-red-400',
          },
          {
            label: 'Frameworks',
            value: frameworksLoading ? '…' : frameworks.length,
            icon: FileText,
            accent: 'text-blue-400',
          },
          {
            label: 'Fully Compliant',
            value: frameworksLoading ? '…' : compliantCount,
            icon: BarChart3,
            accent: 'text-cyan-400',
          },
        ].map(({ label, value, icon: Icon, accent }, i) => (
          <motion.div
            key={label}
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.04, ease: APPLE_EASE }}
          >
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-xs text-gray-500 uppercase tracking-wider">{label}</span>
                  <Icon className={`w-4 h-4 ${accent} opacity-60`} />
                </div>
                <div className={`text-2xl font-bold ${accent}`}>{value}</div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </motion.div>

      {/* ── Compliance Status Banner ──────────────────────────────────── */}
      {complianceStatus && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.15 }}
        >
          <Card className="border-gray-700/30 bg-gradient-to-r from-emerald-900/20 to-teal-900/20 backdrop-blur-md">
            <CardContent className="p-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Shield className="w-5 h-5 text-emerald-400" />
                <span className="text-sm text-gray-300">
                  Compliance Posture: <strong className="text-emerald-400">{overallCompliance}%</strong>
                  {' · '}
                  {compliantCount} of {frameworks.length} frameworks fully compliant
                </span>
              </div>
              {totalControls > 0 && (
                <Progress value={overallCompliance} className="w-32 h-2 bg-gray-800" />
              )}
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* ── Main Content ──────────────────────────────────────────────── */}
      <Tabs defaultValue="frameworks">
        <TabsList className="bg-gray-900/60 border border-gray-700/40 mb-5">
          <TabsTrigger
            value="frameworks"
            className="data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-300"
          >
            <Shield className="w-4 h-4 mr-2" />
            Frameworks ({frameworks.length})
          </TabsTrigger>
          <TabsTrigger
            value="activity"
            className="data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-300"
          >
            <Clock className="w-4 h-4 mr-2" />
            Activity
          </TabsTrigger>
        </TabsList>

        {/* ── Frameworks Tab ──────────────────────────────────────────── */}
        <TabsContent value="frameworks" className="mt-0">
          {frameworksLoading ? (
            <ComplianceSkeleton />
          ) : frameworks.length === 0 ? (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex flex-col items-center justify-center gap-4 py-20 text-gray-600"
            >
              <Shield className="w-12 h-12 opacity-40" />
              <div className="text-center">
                <p className="text-sm font-medium text-gray-400">No compliance frameworks configured</p>
                <p className="text-xs text-gray-600 mt-1">
                  Frameworks will appear here once the compliance engine is initialized
                </p>
              </div>
            </motion.div>
          ) : (
            <motion.div
              variants={containerVariants}
              initial="hidden"
              animate="visible"
              className="space-y-3"
            >
              {frameworks.map((framework) => {
                const percentage = getCompliancePercentage(framework);
                const isSelected = selectedFramework === framework.id;
                const statusCfg =
                  STATUS_CONFIG[framework.status] ?? STATUS_CONFIG.pending;
                const StatusIcon = statusCfg.icon;

                return (
                  <motion.div key={framework.id} variants={itemVariants}>
                    <Card
                      className={`border-gray-700/30 bg-gray-900/40 backdrop-blur-md cursor-pointer transition-all hover:border-gray-600/50 ${
                        isSelected ? 'ring-1 ring-emerald-500/30 border-emerald-500/20' : ''
                      }`}
                      onClick={() =>
                        setSelectedFramework(isSelected ? null : framework.id)
                      }
                    >
                      <CardContent className="p-5">
                        {/* Framework Row */}
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-lg bg-gray-800/60 border border-gray-700/30 flex items-center justify-center">
                              <FileSignature className="w-5 h-5 text-emerald-400" />
                            </div>
                            <div>
                              <div className="flex items-center gap-2">
                                <h3 className="font-semibold text-gray-200">{framework.name}</h3>
                                {framework.version && (
                                  <Badge variant="outline" className="text-[9px] border-gray-700 text-gray-500">
                                    v{framework.version}
                                  </Badge>
                                )}
                              </div>
                              <p className="text-xs text-gray-500 mt-0.5">{framework.description}</p>
                            </div>
                          </div>
                          <div className="flex items-center gap-3 shrink-0">
                            <Badge className={`border ${statusCfg.badge}`}>
                              <StatusIcon className="w-3 h-3 mr-1" />
                              {statusCfg.label}
                            </Badge>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={(e) => {
                                e.stopPropagation();
                                generateReportMutation.mutate(framework.id);
                              }}
                              disabled={generateReportMutation.isPending}
                              className="text-gray-400 hover:text-gray-200"
                            >
                              {generateReportMutation.isPending ? (
                                <Loader2 className="w-4 h-4 animate-spin" />
                              ) : (
                                <Download className="w-4 h-4" />
                              )}
                            </Button>
                          </div>
                        </div>

                        {/* Progress Bar */}
                        <div className="space-y-2">
                          <div className="flex justify-between text-sm">
                            <span className="text-gray-500">
                              {framework.controls_passing} / {framework.controls_total} controls
                            </span>
                            <span
                              className={`font-semibold ${
                                percentage === 100
                                  ? 'text-green-400'
                                  : percentage >= 80
                                  ? 'text-yellow-400'
                                  : 'text-red-400'
                              }`}
                            >
                              {percentage}%
                            </span>
                          </div>
                          <div className="w-full bg-gray-800/50 rounded-full h-2 overflow-hidden">
                            <motion.div
                              className={`h-full rounded-full ${
                                percentage === 100
                                  ? 'bg-green-500'
                                  : percentage >= 80
                                  ? 'bg-gradient-to-r from-yellow-500 to-green-500'
                                  : 'bg-gradient-to-r from-red-500 to-yellow-500'
                              }`}
                              initial={{ width: 0 }}
                              animate={{ width: `${percentage}%` }}
                              transition={{ ease: APPLE_EASE, duration: 0.8, delay: 0.1 }}
                            />
                          </div>
                          <div className="flex items-center gap-2 text-xs text-gray-600">
                            <Clock className="w-3 h-3" />
                            Last assessed:{' '}
                            {framework.last_assessed
                              ? new Date(framework.last_assessed).toLocaleDateString()
                              : 'Never'}
                          </div>
                        </div>

                        {/* Expanded Details */}
                        <AnimatePresence>
                          {isSelected && (
                            <motion.div
                              initial={{ height: 0, opacity: 0 }}
                              animate={{ height: 'auto', opacity: 1 }}
                              exit={{ height: 0, opacity: 0 }}
                              transition={{ duration: 0.25 }}
                              className="overflow-hidden"
                            >
                              <div className="mt-4 pt-4 border-t border-gray-700/30">
                                <div className="grid grid-cols-3 gap-3">
                                  <div className="text-center p-3 rounded-lg bg-green-500/10 border border-green-500/20">
                                    <p className="text-lg font-bold text-green-400">
                                      {framework.controls_passing}
                                    </p>
                                    <p className="text-xs text-gray-500">Passing</p>
                                  </div>
                                  <div className="text-center p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                                    <p className="text-lg font-bold text-red-400">
                                      {framework.controls_failing}
                                    </p>
                                    <p className="text-xs text-gray-500">Failing</p>
                                  </div>
                                  <div className="text-center p-3 rounded-lg bg-gray-500/10 border border-gray-500/20">
                                    <p className="text-lg font-bold text-gray-400">
                                      {framework.controls_total -
                                        framework.controls_passing -
                                        framework.controls_failing}
                                    </p>
                                    <p className="text-xs text-gray-500">Not Assessed</p>
                                  </div>
                                </div>
                                <div className="flex gap-2 mt-4">
                                  <Button
                                    size="sm"
                                    className="flex-1 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      collectEvidenceMutation.mutate(framework.id);
                                    }}
                                    disabled={collectEvidenceMutation.isPending}
                                  >
                                    {collectEvidenceMutation.isPending ? (
                                      <Loader2 className="w-4 h-4 mr-1.5 animate-spin" />
                                    ) : (
                                      <ExternalLink className="w-4 h-4 mr-1.5" />
                                    )}
                                    Collect Evidence
                                  </Button>
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    className="flex-1 border-gray-700/50 text-gray-400 hover:text-gray-200"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      generateReportMutation.mutate(framework.id);
                                    }}
                                    disabled={generateReportMutation.isPending}
                                  >
                                    <Download className="w-4 h-4 mr-1.5" />
                                    Download Report
                                  </Button>
                                </div>
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </CardContent>
                    </Card>
                  </motion.div>
                );
              })}
            </motion.div>
          )}
        </TabsContent>

        {/* ── Activity Tab ─────────────────────────────────────────────── */}
        <TabsContent value="activity" className="mt-0">
          <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
            <CardHeader>
              <CardTitle className="text-base text-gray-200 flex items-center gap-2">
                <Clock className="w-4 h-4 text-emerald-400" />
                Recent Compliance Activity
              </CardTitle>
              <CardDescription className="text-gray-500">
                Audit trail of compliance assessments and evidence generation
              </CardDescription>
            </CardHeader>
            <CardContent>
              {auditLogs.length === 0 ? (
                <div className="flex flex-col items-center justify-center gap-3 py-12 text-gray-600">
                  <Clock className="w-10 h-10 opacity-40" />
                  <p className="text-sm">No recent compliance activity</p>
                </div>
              ) : (
                <motion.div
                  variants={containerVariants}
                  initial="hidden"
                  animate="visible"
                  className="space-y-2"
                >
                  {auditLogs.map((log, index) => (
                    <motion.div
                      key={log.id ?? index}
                      variants={itemVariants}
                      className="flex items-center gap-3 p-3 rounded-lg border border-gray-700/20 bg-gray-800/20 hover:bg-gray-800/30 transition-colors"
                    >
                      <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm text-gray-300 truncate">
                          {log.action ?? log.message ?? 'Compliance check completed'}
                        </p>
                        <p className="text-xs text-gray-600">
                          {log.timestamp
                            ? new Date(log.timestamp).toLocaleString()
                            : 'Just now'}
                          {log.user && (
                            <span className="ml-2 text-gray-500">by {log.user}</span>
                          )}
                        </p>
                      </div>
                      {log.severity && (
                        <Badge
                          variant="outline"
                          className={`text-[10px] capitalize ${
                            log.severity === 'critical'
                              ? 'border-red-500/30 text-red-400'
                              : log.severity === 'high'
                              ? 'border-orange-500/30 text-orange-400'
                              : 'border-gray-600 text-gray-400'
                          }`}
                        >
                          {log.severity}
                        </Badge>
                      )}
                    </motion.div>
                  ))}
                </motion.div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
