import { motion } from 'framer-motion';
import { useQuery } from '@tanstack/react-query';
import { Shield, AlertTriangle, TrendingDown, CheckCircle2 } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { api } from '../../lib/api';

interface GaugeProps {
  score: number; // 0-100
  label?: string;
  size?: number;
}

/**
 * Animated SVG gauge with sweeping needle animation.
 * Apple-quality physics-based animation.
 */
function GaugeArc({ score, label = 'Risk Score', size = 200 }: GaugeProps) {
  const cx = size / 2;
  const cy = size / 2;
  const radius = (size - 32) / 2;
  const startAngle = -225; // degrees
  const endAngle = 45;
  const range = endAngle - startAngle; // 270 degrees
  const needleAngle = startAngle + (score / 100) * range;

  // Arc path helper
  const polarToCartesian = (angle: number) => {
    const rad = (angle * Math.PI) / 180;
    return {
      x: cx + radius * Math.cos(rad),
      y: cy + radius * Math.sin(rad),
    };
  };

  const describeArc = (start: number, end: number) => {
    const s = polarToCartesian(start);
    const e = polarToCartesian(end);
    const largeArc = end - start > 180 ? 1 : 0;
    return `M ${s.x} ${s.y} A ${radius} ${radius} 0 ${largeArc} 1 ${e.x} ${e.y}`;
  };

  // Color based on score
  const getColor = (s: number) => {
    if (s >= 80) return '#ef4444'; // red - critical
    if (s >= 60) return '#f97316'; // orange - high
    if (s >= 40) return '#f59e0b'; // amber - medium
    if (s >= 20) return '#3b82f6'; // blue - low
    return '#22c55e'; // green - minimal
  };

  const getRiskLabel = (s: number) => {
    if (s >= 80) return 'Critical';
    if (s >= 60) return 'High';
    if (s >= 40) return 'Medium';
    if (s >= 20) return 'Low';
    return 'Minimal';
  };

  const color = getColor(score);
  const riskLabel = getRiskLabel(score);
  const needleEnd = polarToCartesian(needleAngle);

  return (
    <div className="relative" style={{ width: size, height: size * 0.7 }}>
      <svg width={size} height={size * 0.7} viewBox={`0 0 ${size} ${size * 0.75}`}>
        {/* Background arc */}
        <path
          d={describeArc(startAngle, endAngle)}
          fill="none"
          stroke="rgba(100,116,139,0.2)"
          strokeWidth="12"
          strokeLinecap="round"
        />

        {/* Colored segments */}
        <path d={describeArc(startAngle, startAngle + range * 0.2)} fill="none" stroke="#22c55e" strokeWidth="12" strokeLinecap="round" opacity="0.3" />
        <path d={describeArc(startAngle + range * 0.2, startAngle + range * 0.4)} fill="none" stroke="#3b82f6" strokeWidth="12" strokeLinecap="round" opacity="0.3" />
        <path d={describeArc(startAngle + range * 0.4, startAngle + range * 0.6)} fill="none" stroke="#f59e0b" strokeWidth="12" strokeLinecap="round" opacity="0.3" />
        <path d={describeArc(startAngle + range * 0.6, startAngle + range * 0.8)} fill="none" stroke="#f97316" strokeWidth="12" strokeLinecap="round" opacity="0.3" />
        <path d={describeArc(startAngle + range * 0.8, endAngle)} fill="none" stroke="#ef4444" strokeWidth="12" strokeLinecap="round" opacity="0.3" />

        {/* Active arc up to score */}
        <motion.path
          d={describeArc(startAngle, needleAngle)}
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          initial={{ pathLength: 0, opacity: 0 }}
          animate={{ pathLength: 1, opacity: 1 }}
          transition={{ duration: 1.5, ease: [0.16, 1, 0.3, 1] }}
        />

        {/* Needle */}
        <motion.line
          x1={cx}
          y1={cy}
          x2={needleEnd.x}
          y2={needleEnd.y}
          stroke={color}
          strokeWidth="3"
          strokeLinecap="round"
          initial={{ x2: cx, y2: cy }}
          animate={{ x2: needleEnd.x, y2: needleEnd.y }}
          transition={{ duration: 1.8, type: 'spring', stiffness: 60, damping: 15 }}
        />

        {/* Center dot */}
        <circle cx={cx} cy={cy} r="5" fill={color} />
        <circle cx={cx} cy={cy} r="3" fill="rgba(15,23,42,0.8)" />

        {/* Score text */}
        <motion.text
          x={cx}
          y={cy + 20}
          textAnchor="middle"
          className="text-3xl font-bold"
          fill={color}
          initial={{ opacity: 0, scale: 0.5 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.8, duration: 0.5 }}
        >
          {score}
        </motion.text>

        {/* Label */}
        <text x={cx} y={cy + 40} textAnchor="middle" fill="rgb(148,163,184)" fontSize="11" fontWeight="500">
          {label}
        </text>
      </svg>

      {/* Risk level badge */}
      <motion.div
        initial={{ opacity: 0, y: 5 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 1 }}
        className="absolute bottom-0 left-1/2 -translate-x-1/2"
      >
        <span
          className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-semibold border"
          style={{
            backgroundColor: `${color}15`,
            borderColor: `${color}40`,
            color: color,
          }}
        >
          {score >= 60 ? <AlertTriangle className="w-3 h-3" /> : <Shield className="w-3 h-3" />}
          {riskLabel} Risk
        </span>
      </motion.div>
    </div>
  );
}

/**
 * RiskScoreGauge — Full card component fetching real risk data from API.
 * Shows animated gauge with risk breakdown stats.
 */
export default function RiskScoreGauge() {
  // Fetch real analytics data
  const { data: analyticsData, isLoading } = useQuery({
    queryKey: ['analytics-overview'],
    queryFn: async () => {
      const resp = await api.get('/api/v1/analytics/dashboard/overview');
      return resp.data;
    },
    retry: 1,
  });

  const { data: brainData } = useQuery({
    queryKey: ['brain-stats-gauge'],
    queryFn: async () => {
      const resp = await api.get('/api/v1/brain/stats');
      return resp.data;
    },
    retry: 1,
  });

  // Calculate risk score from real data
  const totalFindings = analyticsData?.total_findings ?? analyticsData?.findings_count ?? 0;
  const criticalCount = analyticsData?.critical ?? analyticsData?.severity_breakdown?.critical ?? 0;
  const highCount = analyticsData?.high ?? analyticsData?.severity_breakdown?.high ?? 0;
  const mediumCount = analyticsData?.medium ?? analyticsData?.severity_breakdown?.medium ?? 0;

  // Risk score formula: weighted severity distribution (0-100)
  const rawScore = totalFindings > 0
    ? Math.min(100, Math.round(
        ((criticalCount * 10 + highCount * 5 + mediumCount * 2) / Math.max(totalFindings, 1)) * 10
      ))
    : brainData?.findings_processed ? 35 : 0;

  const riskScore = Math.max(0, Math.min(100, rawScore));

  const pipelineProcessed = brainData?.findings_processed ?? 0;
  const dedupRate = brainData?.dedup_rate ?? brainData?.dedup_percentage ?? 0;
  const noiseReduction = brainData?.noise_reduction ?? 0;

  if (isLoading) {
    return (
      <Card className="glass-card backdrop-blur-md bg-gray-900/40 border-gray-700/40">
        <CardContent className="flex items-center justify-center py-12">
          <div className="space-y-3 text-center">
            <div className="w-[200px] h-[140px] bg-gray-700/20 rounded-lg animate-pulse mx-auto" />
            <div className="h-4 w-32 bg-gray-700/20 rounded animate-pulse mx-auto" />
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="glass-card backdrop-blur-md bg-gray-900/40 border-gray-700/40 hover:border-primary/20 transition-all duration-300 overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-br from-indigo-500/5 to-transparent pointer-events-none" />
      <CardHeader className="relative pb-2">
        <CardTitle className="flex items-center gap-2 text-base">
          <Shield className="w-5 h-5 text-primary" />
          Security Risk Score
        </CardTitle>
      </CardHeader>
      <CardContent className="relative flex flex-col items-center">
        <GaugeArc score={riskScore} size={220} />

        {/* Stats below gauge */}
        <div className="grid grid-cols-3 gap-4 w-full mt-4 pt-4 border-t border-gray-700/30">
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 1.2 }}
            className="text-center"
          >
            <p className="text-lg font-bold text-red-400">{criticalCount + highCount}</p>
            <p className="text-[10px] text-gray-500 uppercase tracking-wider">Critical+High</p>
          </motion.div>
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 1.4 }}
            className="text-center"
          >
            <p className="text-lg font-bold text-blue-400">{pipelineProcessed}</p>
            <p className="text-[10px] text-gray-500 uppercase tracking-wider">Processed</p>
          </motion.div>
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 1.6 }}
            className="text-center"
          >
            <div className="flex items-center justify-center gap-1">
              {noiseReduction > 0 ? (
                <TrendingDown className="w-3 h-3 text-emerald-400" />
              ) : (
                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
              )}
              <p className="text-lg font-bold text-emerald-400">
                {dedupRate > 0 ? `${Math.round(dedupRate)}%` : noiseReduction > 0 ? `${Math.round(noiseReduction)}%` : '0%'}
              </p>
            </div>
            <p className="text-[10px] text-gray-500 uppercase tracking-wider">Noise Reduced</p>
          </motion.div>
        </div>
      </CardContent>
    </Card>
  );
}

export { GaugeArc };
