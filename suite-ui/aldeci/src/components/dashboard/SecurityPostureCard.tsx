import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Shield, TrendingDown, TrendingUp, AlertTriangle, CheckCircle2,
  ArrowRight,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Skeleton } from '../ui/skeleton';
import { useNavigate } from 'react-router-dom';
import { api, feedsApi } from '../../lib/api';

interface PostureMetric {
  label: string;
  value: number | string;
  target: number | string;
  status: 'good' | 'warning' | 'critical';
  description: string;
}

export default function SecurityPostureCard() {
  const navigate = useNavigate();

  const { data: healthData } = useQuery({
    queryKey: ['posture-health'],
    queryFn: () => api.get('/api/v1/health').then(r => r.data),
    retry: 1,
    staleTime: 30_000,
  });

  const { data: kevData } = useQuery({
    queryKey: ['posture-kev'],
    queryFn: () => feedsApi.getKEV(),
    retry: 1,
    staleTime: 60_000,
  });

  const { data: remMetrics } = useQuery({
    queryKey: ['posture-rem'],
    queryFn: () => api.get('/api/v1/remediation/metrics').then(r => r.data).catch(() => null),
    retry: 0,
    staleTime: 60_000,
  });

  const { data: complianceData } = useQuery({
    queryKey: ['posture-compliance'],
    queryFn: () => api.get('/api/v1/analytics/dashboard/compliance-status').then(r => r.data).catch(() => null),
    retry: 0,
    staleTime: 60_000,
  });

  const scannerStatus = useQuery({
    queryKey: ['posture-scanners'],
    queryFn: async () => {
      const checks = ['sast', 'dast', 'secrets', 'container', 'cspm'];
      let online = 0;
      for (const s of checks) {
        try {
          const res = await api.get(`/api/v1/${s}/status`, { timeout: 3000 });
          const status = String(res.data?.status || '').toLowerCase();
          if (['ready', 'healthy', 'active', 'ok', 'running'].includes(status)) online++;
        } catch {
          // scanner offline
        }
      }
      return { online, total: 8 }; // 5 API + 3 built-in
    },
    retry: 0,
    staleTime: 30_000,
  });

  const isLoading = !healthData;

  // Compute posture score (0-100)
  const apiOnline = healthData?.status === 'healthy' ? 1 : 0;
  const scannerPct = scannerStatus.data ? (scannerStatus.data.online + 3) / scannerStatus.data.total * 100 : 0;
  const slaCompliance = remMetrics?.sla_compliance_pct ?? remMetrics?.sla_compliance ?? 0;
  const complianceScore = complianceData?.compliance_score ?? complianceData?.score ?? 0;
  const kevCount = kevData?.total_kev_entries ?? kevData?.vulnerabilities?.length ?? 0;

  // Overall posture: weighted average
  const postureScore = Math.round(
    (apiOnline * 20) +
    (scannerPct * 0.3) +
    (Math.min(slaCompliance, 100) * 0.2) +
    (Math.min(complianceScore, 100) * 0.2) +
    (kevCount > 0 ? 10 : 0)
  );

  const postureLevel = postureScore >= 70 ? 'good' : postureScore >= 40 ? 'warning' : 'critical';
  const postureColors = {
    good: { text: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', ring: '#22c55e' },
    warning: { text: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/30', ring: '#f59e0b' },
    critical: { text: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/30', ring: '#ef4444' },
  };
  const colors = postureColors[postureLevel];

  const metrics: PostureMetric[] = [
    {
      label: 'API Health',
      value: apiOnline ? 'Online' : 'Offline',
      target: 'Online',
      status: apiOnline ? 'good' : 'critical',
      description: 'Backend API connectivity',
    },
    {
      label: 'Scanners',
      value: `${(scannerStatus.data?.online ?? 0) + 3}/8`,
      target: '8/8',
      status: (scannerStatus.data?.online ?? 0) + 3 >= 6 ? 'good' : 'warning',
      description: 'Native scanner coverage',
    },
    {
      label: 'SLA Compliance',
      value: `${Math.round(slaCompliance)}%`,
      target: '95%',
      status: slaCompliance >= 90 ? 'good' : slaCompliance >= 70 ? 'warning' : 'critical',
      description: 'Remediation SLA adherence',
    },
    {
      label: 'Compliance',
      value: complianceScore > 0 ? `${Math.round(complianceScore)}%` : 'N/A',
      target: '90%',
      status: complianceScore >= 80 ? 'good' : complianceScore >= 50 ? 'warning' : 'critical',
      description: 'Framework compliance rate',
    },
  ];

  const statusIcons = {
    good: CheckCircle2,
    warning: AlertTriangle,
    critical: AlertTriangle,
  };

  const statusColors = {
    good: 'text-emerald-400',
    warning: 'text-amber-400',
    critical: 'text-red-400',
  };

  if (isLoading) {
    return (
      <Card className="glass-card backdrop-blur-md bg-gray-900/40 border-gray-700/40">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Shield className="w-4 h-4 text-primary" />
            Security Posture
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4">
            <Skeleton className="w-20 h-20 rounded-full" />
            <div className="space-y-2">
              <Skeleton className="h-6 w-32" />
              <Skeleton className="h-4 w-48" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            {[1,2,3,4].map(i => <Skeleton key={i} className="h-16 rounded-lg" />)}
          </div>
        </CardContent>
      </Card>
    );
  }

  // Score ring SVG
  const radius = 30;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (postureScore / 100) * circumference;

  return (
    <Card className={`glass-card backdrop-blur-md bg-gray-900/40 ${colors.border} hover:border-primary/20 transition-all duration-300`}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <Shield className={`w-4 h-4 ${colors.text}`} />
            Security Posture
          </CardTitle>
          <Button
            variant="ghost"
            size="sm"
            className="text-xs text-muted-foreground"
            onClick={() => navigate('/executive')}
            aria-label="View executive dashboard"
          >
            Details <ArrowRight className="w-3 h-3 ml-1" />
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {/* Score Ring + Summary */}
        <div className="flex items-center gap-5 mb-4">
          <div className="relative">
            <svg width={76} height={76} viewBox="0 0 76 76">
              <circle cx={38} cy={38} r={radius} fill="none" stroke="currentColor" strokeWidth={6} className="text-gray-700/30" />
              <motion.circle
                cx={38} cy={38} r={radius} fill="none" stroke={colors.ring}
                strokeWidth={6} strokeLinecap="round"
                strokeDasharray={circumference}
                initial={{ strokeDashoffset: circumference }}
                animate={{ strokeDashoffset: offset }}
                transition={{ duration: 1.2, ease: 'easeOut' }}
                transform="rotate(-90 38 38)"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <motion.span
                className={`text-xl font-bold ${colors.text}`}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.5 }}
              >
                {postureScore}
              </motion.span>
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <Badge className={`${colors.bg} ${colors.text} border ${colors.border}`}>
                {postureLevel === 'good' ? 'Strong' : postureLevel === 'warning' ? 'Needs Attention' : 'At Risk'}
              </Badge>
              {postureLevel === 'good' ? (
                <TrendingDown className="w-4 h-4 text-emerald-400" />
              ) : (
                <TrendingUp className="w-4 h-4 text-amber-400" />
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              {kevCount > 0 ? `${kevCount} KEV entries tracked` : 'No KEV data loaded'}
            </p>
          </div>
        </div>

        {/* Metrics Grid */}
        <div className="grid grid-cols-2 gap-2">
          {metrics.map((metric, i) => {
            const StatusIcon = statusIcons[metric.status];
            return (
              <motion.div
                key={metric.label}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 + i * 0.06, ease: [0.16, 1, 0.3, 1] }}
                className="border border-border/30 rounded-lg p-2.5 hover:bg-muted/20 transition-colors"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">{metric.label}</span>
                  <StatusIcon className={`w-3 h-3 ${statusColors[metric.status]}`} />
                </div>
                <div className="flex items-baseline gap-1.5">
                  <span className={`text-sm font-bold ${statusColors[metric.status]}`}>{metric.value}</span>
                  <span className="text-[10px] text-muted-foreground/50">/ {metric.target}</span>
                </div>
              </motion.div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
