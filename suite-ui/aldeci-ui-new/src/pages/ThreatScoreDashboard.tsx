/**
 * Threat Score Dashboard
 *
 * Composite threat scoring across all assets.
 *   1. KPI cards: Total Assets Scored, Critical Assets (≥80), Average Score, Scored Today
 *   2. Top Threats table (by score)
 *   3. Score Distribution — count cards for critical/high/medium/low
 *
 * API: GET /api/v1/threat-scores/{stats,top-threats,scores}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  AlertTriangle, RefreshCw, BarChart3, Target, TrendingUp, Activity,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data (fallback) ───────────────────────────────────────

const MOCK_STATS = {
  total_assets_scored: 1284,
  critical_assets: 47,
  average_score: 38.2,
  assets_scored_today: 213,
};

const MOCK_TOP_THREATS = [
  { asset_id: "asset-db-prod-01",   asset_type: "database",  score: 94, risk_level: "critical", calculated_at: "2026-04-16T08:00:00Z" },
  { asset_id: "asset-api-gateway",  asset_type: "service",   score: 87, risk_level: "critical", calculated_at: "2026-04-16T08:05:00Z" },
  { asset_id: "asset-k8s-node-04",  asset_type: "container", score: 82, risk_level: "critical", calculated_at: "2026-04-16T08:10:00Z" },
  { asset_id: "asset-vpn-endpoint", asset_type: "network",   score: 76, risk_level: "high",     calculated_at: "2026-04-16T08:15:00Z" },
  { asset_id: "asset-web-app-03",   asset_type: "webapp",    score: 71, risk_level: "high",     calculated_at: "2026-04-16T08:20:00Z" },
  { asset_id: "asset-auth-svc",     asset_type: "service",   score: 65, risk_level: "high",     calculated_at: "2026-04-16T08:25:00Z" },
  { asset_id: "asset-s3-bucket-07", asset_type: "storage",   score: 51, risk_level: "medium",   calculated_at: "2026-04-16T08:30:00Z" },
  { asset_id: "asset-ci-runner-02", asset_type: "compute",   score: 38, risk_level: "medium",   calculated_at: "2026-04-16T08:35:00Z" },
];

const MOCK_DISTRIBUTION = {
  critical: 47,
  high: 183,
  medium: 412,
  low: 642,
};

// ── Helpers ────────────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score >= 80) return "text-red-400";
  if (score >= 60) return "text-orange-400";
  if (score >= 40) return "text-yellow-400";
  return "text-green-400";
}

function scoreBg(score: number): string {
  if (score >= 80) return "bg-red-500";
  if (score >= 60) return "bg-orange-500";
  if (score >= 40) return "bg-yellow-500";
  return "bg-green-500";
}

function RiskLevelBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
    info:     "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border text-muted-foreground")}>
      {level}
    </Badge>
  );
}

function fmtTime(ts: string): string {
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

// ── Component ──────────────────────────────────────────────────

export default function ThreatScoreDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
  const [loading, setLoading] = useState(true);
    stats: any | null;
    topThreats: any[] | null;
    distribution: any | null;
  }>({ stats: null, topThreats: null, distribution: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/threat-scores/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/threat-scores/top-threats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/threat-scores/scores?org_id=${ORG_ID}`),
    ]).then(([statsRes, topRes, scoresRes]) => {
      setLiveData({
        stats:        statsRes.status  === "fulfilled" ? statsRes.value  : null,
        topThreats:   topRes.status    === "fulfilled" ? topRes.value    : null,
        distribution: scoresRes.status === "fulfilled" ? scoresRes.value : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats        = liveData.stats        ?? MOCK_STATS;
  const topThreats   = liveData.topThreats   ?? MOCK_TOP_THREATS;
  const distribution = liveData.distribution ?? MOCK_DISTRIBUTION;

  const distTotal = (distribution.critical ?? 0) + (distribution.high ?? 0) + (distribution.medium ?? 0) + (distribution.low ?? 0);

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Threat Score Intelligence"
        description="Composite threat scoring across all assets"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Assets Scored"  value={stats.total_assets_scored.toLocaleString()} icon={Target}      trend="up"     />
        <KpiCard title="Critical Assets"      value={stats.critical_assets}                       icon={AlertTriangle} trend="down" className="border-red-500/20" />
        <KpiCard title="Average Score"        value={stats.average_score.toFixed(1)}              icon={BarChart3}   trend="flat" className="border-blue-500/20" />
        <KpiCard title="Scored Today"         value={stats.assets_scored_today}                   icon={Activity}    trend="up"     className="border-green-500/20" />
      </div>

      {/* Top Threats Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              Top Threats by Score
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {topThreats.filter((t: any) => (t.score ?? 0) >= 80).length} critical
            </Badge>
          </div>
          <CardDescription className="text-xs">Highest-scoring assets requiring immediate attention</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Asset ID</TableHead>
                  <TableHead className="text-[11px] h-8">Asset Type</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Score</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Level</TableHead>
                  <TableHead className="text-[11px] h-8">Calculated At</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {topThreats.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  topThreats.map((t: any, i: number) => (
                  <TableRow key={t.asset_id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{t.asset_id}</TableCell>
                    <TableCell className="py-2 text-xs capitalize">{(t.asset_type ?? "").replace(/_/g, " ")}</TableCell>
                    <TableCell className="py-2 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <div className="h-1.5 w-16 rounded-full bg-muted/30 overflow-hidden">
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${t.score ?? 0}%` }}
                            transition={{ duration: 0.6, delay: i * 0.05 }}
                            )))}
                          />
                        </div>
                        <span className={cn("text-xs font-bold tabular-nums w-6 text-right", scoreColor(t.score ?? 0))}>
                          {t.score ?? 0}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="py-2"><RiskLevelBadge level={t.risk_level ?? "low"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{fmtTime(t.calculated_at)}</TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Score Distribution */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-purple-400" />
            Score Distribution
          </CardTitle>
          <CardDescription className="text-xs">Asset count by risk band across {distTotal.toLocaleString()} scored assets</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            {[
              { label: "Critical (≥80)", count: distribution.critical ?? 0, color: "text-red-400",    bg: "bg-red-500/10 border-red-500/20" },
              { label: "High (60–79)",   count: distribution.high ?? 0,     color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/20" },
              { label: "Medium (40–59)", count: distribution.medium ?? 0,   color: "text-yellow-400", bg: "bg-yellow-500/10 border-yellow-500/20" },
              { label: "Low (<40)",      count: distribution.low ?? 0,      color: "text-green-400",  bg: "bg-green-500/10 border-green-500/20" },
            ].map((band) => (
              <motion.div
                key={band.label}
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.3 }}
                className={cn("rounded-lg border p-4 text-center", band.bg)}
              >
                <div className={cn("text-2xl font-bold tabular-nums", band.color)}>
                  {band.count.toLocaleString()}
                </div>
                <div className="mt-1 text-[11px] text-muted-foreground">{band.label}</div>
                {distTotal > 0 && (
                  <div className={cn("mt-0.5 text-[10px] font-medium", band.color)}>
                    {((band.count / distTotal) * 100).toFixed(1)}%
                  </div>
                )}
              </motion.div>
            ))}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
