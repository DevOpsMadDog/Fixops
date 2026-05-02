/**
 * Threat Exposure Dashboard
 *
 * Asset exposure correlation with threat intelligence.
 *   1. KPI cards: Total Assets, Critical Exposure, Average Score, Correlations Today
 *   2. Top Exposed Assets (bar cards)
 *   3. Assets table
 *
 * API: GET /api/v1/threat-exposure/{stats,top-exposed,assets}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Target, RefreshCw, AlertTriangle, BarChart2, Activity } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

function exposureColor(score: number): string {
  if (score >= 80) return "bg-red-500";
  if (score >= 60) return "bg-orange-500";
  if (score >= 40) return "bg-yellow-500";
  return "bg-green-500";
}

function exposureTextColor(score: number): string {
  if (score >= 80) return "text-red-400";
  if (score >= 60) return "text-orange-400";
  if (score >= 40) return "text-yellow-400";
  return "text-green-400";
}

function ExposureLevelBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border text-muted-foreground")}>
      {level}
    </Badge>
  );
}

interface ExposureStats {
  total_assets?: number;
  critical_exposure?: number;
  average_score?: number;
  correlations_today?: number;
}

interface TopExposedAsset {
  asset_name?: string;
  asset_type?: string;
  exposure_score?: number;
  threat_count?: number;
}

interface Asset {
  id?: string;
  name?: string;
  type?: string;
  exposure_score?: number;
  level?: string;
  threat_count?: number;
  last_assessed?: string;
}

export default function ThreatExposureDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<ExposureStats>({});
  const [topExposed, setTopExposed] = useState<TopExposedAsset[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [error, setError] = useState<string | null>(null);

  const fetchData = () => {
    setLoading(true);
    setError(null);
    Promise.allSettled([
      apiFetch("/api/v1/threat-exposure/stats?org_id=default"),
      apiFetch("/api/v1/threat-exposure/top-exposed?org_id=default"),
      apiFetch("/api/v1/threat-exposure/assets?org_id=default"),
    ]).then(([statsRes, topRes, assetsRes]) => {
      if (statsRes.status === "fulfilled") setStats(statsRes.value ?? {});
      else setError("Failed to load exposure data");

      if (topRes.status === "fulfilled") {
        const v = topRes.value;
        setTopExposed(Array.isArray(v) ? v : (v?.assets ?? v?.items ?? []));
      }
      if (assetsRes.status === "fulfilled") {
        const v = assetsRes.value;
        setAssets(Array.isArray(v) ? v : (v?.assets ?? v?.items ?? []));
      }
    }).finally(() => setLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  if (loading) {
    return (
      <div className="flex flex-col gap-6">
        <div className="h-10 w-64 rounded bg-muted animate-pulse" />
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => <div key={i} className="h-24 rounded bg-muted animate-pulse" />)}
        </div>
        <div className="h-48 rounded bg-muted animate-pulse" />
        <div className="h-64 rounded bg-muted animate-pulse" />
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Threat Exposure Manager"
        description="Asset exposure correlation with threat intelligence"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Assets"       value={stats.total_assets ?? 0}       icon={Target}        trend="flat" />
        <KpiCard title="Critical Exposure"  value={stats.critical_exposure ?? 0}  icon={AlertTriangle} trend="down" className="border-red-500/20" />
        <KpiCard title="Average Score"      value={stats.average_score ?? 0}      icon={BarChart2}     trend="flat" className="border-yellow-500/20" />
        <KpiCard title="Correlations Today" value={stats.correlations_today ?? 0} icon={Activity}      trend="up"   className="border-blue-500/20" />
      </div>

      {/* Top Exposed Assets */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-orange-400" />
            Top Exposed Assets
          </CardTitle>
          <CardDescription className="text-xs">Highest exposure score assets with threat correlation</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {topExposed.length === 0 ? (
            <EmptyState
              title="No exposure data"
              description="Run a threat correlation scan to see top exposed assets."
              icon={Target}
            />
          ) : (
            topExposed.map((a, i) => (
              <div key={i} className="space-y-1">
                <div className="flex items-center justify-between text-[12px]">
                  <span className="font-medium">{a.asset_name}</span>
                  <div className="flex items-center gap-2">
                    <Badge className="text-[10px] border border-gray-500/30 text-gray-400 bg-gray-500/10 font-mono uppercase">
                      {a.asset_type}
                    </Badge>
                    <span className="text-[10px] text-muted-foreground">{a.threat_count} threats</span>
                    <span className={cn("font-bold font-mono text-[13px]", exposureTextColor(a.exposure_score ?? 0))}>
                      {a.exposure_score}
                    </span>
                  </div>
                </div>
                <div className="h-1.5 rounded-full bg-muted overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${a.exposure_score ?? 0}%` }}
                    transition={{ duration: 0.6, delay: i * 0.08 }}
                    className={cn("h-full rounded-full", exposureColor(a.exposure_score ?? 0))}
                  />
                </div>
              </div>
            ))
          )}
        </CardContent>
      </Card>

      {/* Assets Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Target className="h-4 w-4 text-blue-400" />
              Asset Inventory
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {assets.length} assets
            </Badge>
          </div>
          <CardDescription className="text-xs">All assets with exposure scores and threat counts</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {error ? (
            <div className="p-6">
              <EmptyState
                title="Failed to load assets"
                description={error}
                icon={AlertTriangle}
              />
            </div>
          ) : assets.length === 0 ? (
            <div className="p-6">
              <EmptyState
                title="No assets found"
                description="Connect asset sources to begin tracking threat exposure across your inventory."
                icon={Target}
              />
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Asset ID</TableHead>
                    <TableHead className="text-[11px] h-8">Asset Name</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Score</TableHead>
                    <TableHead className="text-[11px] h-8">Level</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Threats</TableHead>
                    <TableHead className="text-[11px] h-8">Last Assessed</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {assets.map((a, i) => (
                    <TableRow key={a.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{a.id}</TableCell>
                      <TableCell className="py-2 text-[12px] font-medium">{a.name}</TableCell>
                      <TableCell className="py-2">
                        <Badge className="text-[10px] border border-gray-500/30 text-gray-400 bg-gray-500/10 font-mono uppercase">
                          {a.type}
                        </Badge>
                      </TableCell>
                      <TableCell className={cn("py-2 text-right font-bold font-mono text-[13px]", exposureTextColor(a.exposure_score ?? 0))}>
                        {a.exposure_score}
                      </TableCell>
                      <TableCell className="py-2"><ExposureLevelBadge level={a.level ?? "low"} /></TableCell>
                      <TableCell className="py-2 text-right text-[11px] font-mono">{a.threat_count}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{a.last_assessed}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
