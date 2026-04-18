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
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

const MOCK_STATS = {
  total_assets: 1248,
  critical_exposure: 23,
  average_score: 41.7,
  correlations_today: 847,
};

const MOCK_TOP_EXPOSED = [
  { asset_name: "prod-api-gateway",    asset_type: "api",     exposure_score: 94, threat_count: 12 },
  { asset_name: "db-cluster-primary",  asset_type: "database", exposure_score: 88, threat_count: 9 },
  { asset_name: "auth-service-v2",     asset_type: "service",  exposure_score: 81, threat_count: 7 },
  { asset_name: "s3-customer-data",    asset_type: "storage",  exposure_score: 76, threat_count: 6 },
  { asset_name: "vpn-gateway-main",    asset_type: "network",  exposure_score: 63, threat_count: 5 },
];

const MOCK_ASSETS = [
  { id: "ast-001", name: "prod-api-gateway",    type: "api",      exposure_score: 94, level: "critical", threat_count: 12, last_assessed: "2026-04-16" },
  { id: "ast-002", name: "db-cluster-primary",  type: "database", exposure_score: 88, level: "critical", threat_count: 9,  last_assessed: "2026-04-16" },
  { id: "ast-003", name: "auth-service-v2",     type: "service",  exposure_score: 81, level: "high",     threat_count: 7,  last_assessed: "2026-04-15" },
  { id: "ast-004", name: "s3-customer-data",    type: "storage",  exposure_score: 76, level: "high",     threat_count: 6,  last_assessed: "2026-04-15" },
  { id: "ast-005", name: "vpn-gateway-main",    type: "network",  exposure_score: 63, level: "medium",   threat_count: 5,  last_assessed: "2026-04-14" },
  { id: "ast-006", name: "jenkins-build-server",type: "compute",  exposure_score: 35, level: "low",      threat_count: 2,  last_assessed: "2026-04-14" },
];

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

export default function ThreatExposureDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{ stats: any | null; topExposed: any[] | null; assets: any[] | null }>({
  const [loading, setLoading] = useState(true);
    stats: null, topExposed: null, assets: null,
  });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/threat-exposure/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/threat-exposure/top-exposed?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/threat-exposure/assets?org_id=${ORG_ID}`),
    ]).then(([statsRes, topRes, assetsRes]) => {
      setLiveData({
        stats:      statsRes.status  === "fulfilled" ? statsRes.value  : null,
        topExposed: topRes.status    === "fulfilled" ? topRes.value    : null,
        assets:     assetsRes.status === "fulfilled" ? assetsRes.value : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats      = liveData.stats      ?? MOCK_STATS;
  const topExposed = liveData.topExposed ?? MOCK_TOP_EXPOSED;
  const assets     = liveData.assets     ?? MOCK_ASSETS;

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
      <PageHeader
        title="Threat Exposure Manager"
        description="Asset exposure correlation with threat intelligence"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Assets"        value={stats.total_assets}        icon={Target
    setLoading(false);}       trend="flat" />
        <KpiCard title="Critical Exposure"   value={stats.critical_exposure}   icon={AlertTriangle} trend="down" className="border-red-500/20" />
        <KpiCard title="Average Score"       value={stats.average_score}       icon={BarChart2}    trend="flat" className="border-yellow-500/20" />
        <KpiCard title="Correlations Today"  value={stats.correlations_today}  icon={Activity}     trend="up"   className="border-blue-500/20" />
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
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            topExposed.map((a: any, i: number) => (
            <div key={i} className="space-y-1">
              <div className="flex items-center justify-between text-[12px]">
                <span className="font-medium">{a.asset_name}</span>
                <div className="flex items-center gap-2">
                  <Badge className="text-[10px] border border-gray-500/30 text-gray-400 bg-gray-500/10 font-mono uppercase">
                    {a.asset_type}
                  </Badge>
                  <span className="text-[10px] text-muted-foreground">{a.threat_count} threats</span>
                  <span className={cn("font-bold font-mono text-[13px]", exposureTextColor(a.exposure_score))}>
                    {a.exposure_score}
                  </span>
                </div>
              </div>
              <div className="h-1.5 rounded-full bg-muted overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${a.exposure_score}%` }}
                  transition={{ duration: 0.6, delay: i * 0.08 }}
                  className={cn("h-full rounded-full", exposureColor(a.exposure_score))}
                />
              </div>
            </div>
          ))}
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
                {assets.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  assets.map((a: any, i: number) => (
                  <TableRow key={a.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{a.id}</TableCell>
                    <TableCell className="py-2 text-[12px] font-medium">{a.name}</TableCell>
                    <TableCell className="py-2">
                      <Badge className="text-[10px] border border-gray-500/30 text-gray-400 bg-gray-500/10 font-mono uppercase">
                        {a.type}
                      </Badge>
                    </TableCell>
                    <TableCell className={cn("py-2 text-right font-bold font-mono text-[13px]", exposureTextColor(a.exposure_score))}>
                      {a.exposure_score}
                    </TableCell>
                    <TableCell className="py-2"><ExposureLevelBadge level={a.level ?? "low"} /></TableCell>
                    <TableCell className="py-2 text-right text-[11px] font-mono">{a.threat_count}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{a.last_assessed}</TableCell>
                  </TableRow>
                ))}
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
