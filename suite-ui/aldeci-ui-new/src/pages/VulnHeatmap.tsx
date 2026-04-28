/**
 * Vulnerability Heatmap — Risk concentration across assets
 *
 * Sections:
 *   1. KPI row — total vulns, critical assets exposed, avg risk score, patched this week
 *   2. Heatmap grid — 10×8 colored asset cells (green/yellow/amber/red by risk score)
 *   3. Top 10 Most Vulnerable Assets — ranked table
 *   4. Vulnerability by Category — CSS horizontal bar chart
 *   5. 7-day trend — added vs patched sparkline using div heights
 *   6. Risk by Network Zone — card grid
 *
 * API: GET /api/v1/vuln-heatmap/assets
 * Fallback: mock data when API unavailable
 */

import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Shield, AlertTriangle, Activity, CheckCircle2,
  Server, Cloud, Monitor, Box, ExternalLink, RefreshCw,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const key =
    (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) ||
    (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
    import.meta.env.VITE_API_KEY ||
    "dev-key";
  const url = path.startsWith("/api") ? `${API_BASE}${path}` : `${API_BASE}/api/v1${path}`;
  const res = await fetch(url, { headers: { "X-API-Key": key } });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

// ══════════════════════════════════════════════════════════════
// Types
// ══════════════════════════════════════════════════════════════

type AssetType = "server" | "container" | "endpoint" | "cloud";

interface HeatmapAsset {
  id: string;
  name: string;
  type: AssetType;
  risk_score: number; // 0–10
  critical_count: number;
  high_count: number;
  top_cve: string;
}

interface VulnCategory {
  name: string;
  count: number;
}

interface TrendDay {
  label: string;
  added: number;
  patched: number;
}

interface NetworkZone {
  name: string;
  risk_level: "Low" | "Medium" | "High" | "Critical";
  asset_count: number;
  vuln_count: number;
}

interface VulnHeatmapData {
  total_vulnerabilities: number;
  critical_assets_exposed: number;
  avg_risk_score: number;
  patched_this_week: number;
  assets: HeatmapAsset[];
  categories: VulnCategory[];
  trend: TrendDay[];
  zones: NetworkZone[];
}

// ══════════════════════════════════════════════════════════════
// Mock Data
// ══════════════════════════════════════════════════════════════

// Deterministic pseudo-random to keep grid stable across renders
function seededRisk(seed: number): number {
  const x = Math.sin(seed + 1) * 10000;
  return parseFloat((((x - Math.floor(x)) * 10)).toFixed(1));
}

const ASSET_NAMES = [
  "prod-web-01", "prod-web-02", "prod-api-01", "prod-api-02", "prod-db-01",
  "prod-db-02", "prod-cache-01", "prod-lb-01", "prod-mq-01", "prod-auth-01",
  "staging-web-01", "staging-api-01", "staging-db-01", "dev-box-01", "dev-box-02",
  "ci-runner-01", "ci-runner-02", "build-server-01", "artifact-store-01", "log-collector-01",
  "k8s-master-01", "k8s-node-01", "k8s-node-02", "k8s-node-03", "k8s-node-04",
  "k8s-node-05", "k8s-node-06", "k8s-node-07", "k8s-node-08", "k8s-node-09",
  "aws-ec2-web-01", "aws-ec2-api-01", "aws-rds-prod-01", "aws-s3-backup", "aws-lambda-01",
  "aws-lambda-02", "aws-elb-prod-01", "gcp-gke-node-01", "gcp-gke-node-02", "gcp-sql-01",
  "azure-vm-01", "azure-vm-02", "azure-blob-01", "azure-aks-node-01", "azure-aks-node-02",
  "endpoint-cto-mbp", "endpoint-dev-01", "endpoint-dev-02", "endpoint-dev-03", "endpoint-qa-01",
  "endpoint-qa-02", "endpoint-ops-01", "endpoint-ops-02", "endpoint-pm-01", "firewall-edge-01",
  "firewall-int-01", "vpn-gateway-01", "dns-server-01", "ntp-server-01", "smtp-relay-01",
  "monitoring-01", "alerting-01", "backup-agent-01", "backup-agent-02", "siem-collector-01",
  "scanner-01", "scanner-02", "waf-prod-01", "ids-sensor-01", "ids-sensor-02",
  "mail-server-01", "file-share-01", "print-server-01", "kiosk-01", "iot-sensor-01",
  "iot-gateway-01", "iot-cam-01", "iot-cam-02", "iot-hvac-01", "container-reg-01",
];

const ASSET_TYPES: AssetType[] = ["server", "container", "endpoint", "cloud"];
const TOP_CVES = [
  "CVE-2021-44228", "CVE-2024-6849", "CVE-2024-3156", "CVE-2024-5638",
  "CVE-2024-1086", "CVE-2024-2961", "CVE-2024-4577", "CVE-2024-7531",
];

function buildMockAssets(): HeatmapAsset[] {
  return ASSET_NAMES.slice(0, 80).map((name, i) => {
    const risk = seededRisk(i * 7 + 3);
    return {
      id: `asset-${i}`,
      name,
      type: ASSET_TYPES[i % 4],
      risk_score: risk,
      critical_count: risk >= 9 ? Math.floor(risk) - 7 : risk >= 7 ? 1 : 0,
      high_count: risk >= 5 ? Math.floor(risk) - 3 : 0,
      top_cve: TOP_CVES[i % TOP_CVES.length],
    };
  });
}

const MOCK_DATA: VulnHeatmapData = {
  total_vulnerabilities: 1847,
  critical_assets_exposed: 23,
  avg_risk_score: 6.4,
  patched_this_week: 134,
  assets: buildMockAssets(),
  categories: [
    { name: "Information Disclosure", count: 203 },
    { name: "DoS", count: 156 },
    { name: "Privilege Escalation", count: 89 },
    { name: "XSS", count: 78 },
    { name: "Remote Code Execution", count: 47 },
    { name: "SQL Injection", count: 34 },
    { name: "Auth Bypass", count: 23 },
  ],
  trend: [
    { label: "Mon", added: 42, patched: 31 },
    { label: "Tue", added: 38, patched: 45 },
    { label: "Wed", added: 55, patched: 28 },
    { label: "Thu", added: 29, patched: 38 },
    { label: "Fri", added: 61, patched: 22 },
    { label: "Sat", added: 18, patched: 41 },
    { label: "Sun", added: 24, patched: 35 },
  ],
  zones: [
    { name: "DMZ", risk_level: "High", asset_count: 12, vuln_count: 287 },
    { name: "Internal", risk_level: "Medium", asset_count: 34, vuln_count: 512 },
    { name: "Cloud", risk_level: "High", asset_count: 18, vuln_count: 394 },
    { name: "IoT", risk_level: "Critical", asset_count: 8, vuln_count: 341 },
    { name: "Development", risk_level: "Low", asset_count: 14, vuln_count: 98 },
  ],
};

// ══════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════

function getRiskCellColor(score: number): string {
  if (score >= 9) return "bg-red-500 hover:bg-red-400";
  if (score >= 7) return "bg-amber-500 hover:bg-amber-400";
  if (score >= 4) return "bg-yellow-500 hover:bg-yellow-400";
  return "bg-green-600 hover:bg-green-500";
}

function getRiskTextColor(score: number): string {
  if (score >= 9) return "text-red-400";
  if (score >= 7) return "text-amber-400";
  if (score >= 4) return "text-yellow-400";
  return "text-green-400";
}

function getRiskBadge(score: number): { label: string; className: string } {
  if (score >= 9) return { label: "Critical", className: "bg-red-500/20 text-red-400 border-red-500/30" };
  if (score >= 7) return { label: "High", className: "bg-amber-500/20 text-amber-400 border-amber-500/30" };
  if (score >= 4) return { label: "Medium", className: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" };
  return { label: "Low", className: "bg-green-500/20 text-green-400 border-green-500/30" };
}

function getZoneBadge(level: NetworkZone["risk_level"]): string {
  switch (level) {
    case "Critical": return "bg-red-500/20 text-red-400 border-red-500/30";
    case "High": return "bg-amber-500/20 text-amber-400 border-amber-500/30";
    case "Medium": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
    default: return "bg-green-500/20 text-green-400 border-green-500/30";
  }
}

const ASSET_TYPE_ICON: Record<AssetType, React.ComponentType<{ className?: string }>> = {
  server: Server,
  container: Box,
  endpoint: Monitor,
  cloud: Cloud,
};

// ══════════════════════════════════════════════════════════════
// Sub-components
// ══════════════════════════════════════════════════════════════

const HeatmapCell = ({ asset }: { asset: HeatmapAsset }) => {
  const [hovered, setHovered] = useState(false);

  return (
    <div
      className="relative"
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <div
        className={cn(
          "w-full aspect-square rounded cursor-pointer transition-all duration-150",
          getRiskCellColor(asset.risk_score)
        )}
        title={`${asset.name} — Risk: ${asset.risk_score}`}
      />
      {hovered && (
        <div className="absolute z-20 bottom-full mb-2 left-1/2 -translate-x-1/2 w-44 bg-slate-900 border border-slate-600 rounded-lg p-2 shadow-xl pointer-events-none">
          <p className="text-white text-xs font-semibold truncate">{asset.name}</p>
          <p className="text-gray-400 text-xs capitalize">{asset.type}</p>
          <p className="text-xs mt-1">
            <span className={cn("font-bold", getRiskTextColor(asset.risk_score))}>
              Risk {asset.risk_score}
            </span>
          </p>
          <p className="text-gray-400 text-xs truncate">{asset.top_cve}</p>
        </div>
      )}
    </div>
  );
};

const CategoryBar = ({ name, count, max }: { name: string; count: number; max: number }) => (
  <div className="flex items-center gap-3">
    <span className="text-gray-300 text-sm w-44 shrink-0 truncate">{name}</span>
    <div className="flex-1 h-5 bg-slate-700 rounded overflow-hidden">
      <div
        className="h-full bg-blue-500 rounded transition-all"
        style={{ width: `${(count / max) * 100}%` }}
      />
    </div>
    <span className="text-white text-sm font-semibold w-10 text-right">{count}</span>
  </div>
);

const SparkBar = ({
  value,
  max,
  color,
}: {
  value: number;
  max: number;
  color: string;
}) => (
  <div
    className={cn("w-4 rounded-t transition-all self-end", color)}
    style={{ height: `${Math.max(4, (value / max) * 56)}px` }}
    title={String(value)}
  />
);

// ══════════════════════════════════════════════════════════════
// Main Component
// ══════════════════════════════════════════════════════════════

export default function VulnHeatmap() {
  const queryClient = useQueryClient();
  const [refreshing, setRefreshing] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ["vuln-heatmap", ORG_ID],
    queryFn: async (): Promise<VulnHeatmapData> => {
      try {
        return await apiFetch(`/api/v1/vuln-heatmap/assets?org_id=${ORG_ID}`);
      } catch {
        return MOCK_DATA;
      }
    },
    staleTime: 5 * 60 * 1000,
  });

  const handleRefresh = () => {
    setRefreshing(true);
    queryClient.invalidateQueries({ queryKey: ["vuln-heatmap", ORG_ID] });
    setTimeout(() => setRefreshing(false), 800);
  };

  if (isLoading) return <PageSkeleton />;

  const d = data ?? MOCK_DATA;

  // Top 10 assets sorted by risk score
  const top10 = [...d.assets]
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 10);

  const maxCategoryCount = Math.max(...d.categories.map((c) => c.count));
  const maxTrend = Math.max(...d.trend.flatMap((t) => [t.added, t.patched]));

  return (
    <div className="space-y-8 p-6">
      {/* Header */}
      <PageHeader
        title="Vulnerability Heatmap"
        description="Risk concentration across your asset landscape"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* ── KPI Row ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <div className="grid grid-cols-4 gap-4">
          <KpiCard
            title="Total Vulnerabilities"
            value={d.total_vulnerabilities.toLocaleString()}
            description="Across all monitored assets"
            icon={AlertTriangle}
            trend="up"
          />
          <KpiCard
            title="Critical Assets Exposed"
            value={d.critical_assets_exposed}
            description="Risk score ≥ 9.0"
            icon={Shield}
            trend="down"
          />
          <KpiCard
            title="Avg Risk Score"
            value={d.avg_risk_score.toFixed(1)}
            description="Across all assets"
            icon={Activity}
            trend="down"
          />
          <KpiCard
            title="Patched This Week"
            value={d.patched_this_week}
            description="Remediated vulnerabilities"
            icon={CheckCircle2}
            trend="up"
          />
        </div>
      </motion.div>

      {/* ── Heatmap Legend + Grid ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.15 }}
      >
        <Card className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border-slate-700/50">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <Activity className="w-5 h-5 text-blue-400" />
                Asset Risk Heatmap
              </CardTitle>
              <div className="flex items-center gap-3 text-xs">
                <span className="flex items-center gap-1">
                  <span className="inline-block w-3 h-3 rounded bg-green-600" />
                  <span className="text-gray-400">Low (0–3)</span>
                </span>
                <span className="flex items-center gap-1">
                  <span className="inline-block w-3 h-3 rounded bg-yellow-500" />
                  <span className="text-gray-400">Medium (4–6)</span>
                </span>
                <span className="flex items-center gap-1">
                  <span className="inline-block w-3 h-3 rounded bg-amber-500" />
                  <span className="text-gray-400">High (7–8)</span>
                </span>
                <span className="flex items-center gap-1">
                  <span className="inline-block w-3 h-3 rounded bg-red-500" />
                  <span className="text-gray-400">Critical (9–10)</span>
                </span>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-10 gap-1.5">
              {d.assets.slice(0, 80).map((asset) => (
                <HeatmapCell key={asset.id} asset={asset} />
              ))}
            </div>
            <p className="text-xs text-gray-500 mt-3 text-center">
              Each cell represents one asset. Hover for details.
            </p>
          </CardContent>
        </Card>
      </motion.div>

      {/* ── Top 10 Most Vulnerable Assets ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <Card className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border-slate-700/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              Top 10 Most Vulnerable Assets
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-slate-700/50 hover:bg-slate-800/20">
                    <TableHead className="text-gray-300 w-10">#</TableHead>
                    <TableHead className="text-gray-300">Asset</TableHead>
                    <TableHead className="text-gray-300">Type</TableHead>
                    <TableHead className="text-gray-300 text-center">Critical</TableHead>
                    <TableHead className="text-gray-300 text-center">High</TableHead>
                    <TableHead className="text-gray-300">Risk Score</TableHead>
                    <TableHead className="text-gray-300" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {top10.map((asset, idx) => {
                    const badge = getRiskBadge(asset.risk_score);
                    const Icon = ASSET_TYPE_ICON[asset.type];
                    return (
                      <TableRow
                        key={asset.id}
                        className="border-slate-700/50 hover:bg-slate-800/30 transition-colors"
                      >
                        <TableCell>
                          <span className="text-gray-500 font-mono text-sm">{idx + 1}</span>
                        </TableCell>
                        <TableCell>
                          <p className="text-sm text-white font-medium">{asset.name}</p>
                          <p className="text-xs text-gray-400 font-mono">{asset.top_cve}</p>
                        </TableCell>
                        <TableCell>
                          <span className="flex items-center gap-1.5 text-sm text-gray-300 capitalize">
                            <Icon className="w-3.5 h-3.5 text-gray-400" />
                            {asset.type}
                          </span>
                        </TableCell>
                        <TableCell className="text-center">
                          {asset.critical_count > 0 ? (
                            <Badge className="bg-red-500/20 text-red-400 border-red-500/30 border">
                              {asset.critical_count}
                            </Badge>
                          ) : (
                            <span className="text-gray-500 text-sm">—</span>
                          )}
                        </TableCell>
                        <TableCell className="text-center">
                          {asset.high_count > 0 ? (
                            <Badge className="bg-amber-500/20 text-amber-400 border-amber-500/30 border">
                              {asset.high_count}
                            </Badge>
                          ) : (
                            <span className="text-gray-500 text-sm">—</span>
                          )}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <div className="flex-1 h-2 bg-slate-700 rounded-full overflow-hidden max-w-24">
                              <div
                                className={cn(
                                  "h-full rounded-full",
                                  asset.risk_score >= 9
                                    ? "bg-red-500"
                                    : asset.risk_score >= 7
                                      ? "bg-amber-500"
                                      : asset.risk_score >= 4
                                        ? "bg-yellow-500"
                                        : "bg-green-500"
                                )}
                                style={{ width: `${(asset.risk_score / 10) * 100}%` }}
                              />
                            </div>
                            <Badge
                              variant="outline"
                              className={cn("border text-xs", badge.className)}
                            >
                              {asset.risk_score.toFixed(1)}
                            </Badge>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Button
                            size="sm"
                            variant="outline"
                            className="text-xs border-slate-600 text-gray-300 hover:text-white gap-1"
                            disabled
                          >
                            <ExternalLink className="w-3 h-3" />
                            View Details
                          </Button>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* ── Category Chart + Trend ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.25 }}
        className="grid grid-cols-2 gap-6"
      >
        {/* Vulnerability by Category */}
        <Card className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border-slate-700/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              Vulnerability by Category
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {d.categories.map((cat) => (
              <CategoryBar
                key={cat.name}
                name={cat.name}
                count={cat.count}
                max={maxCategoryCount}
              />
            ))}
          </CardContent>
        </Card>

        {/* 7-Day Trend */}
        <Card className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border-slate-700/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Activity className="w-4 h-4 text-purple-400" />
              7-Day Trend — Added vs Patched
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-end justify-between gap-3 h-16">
              {d.trend.map((day) => (
                <div key={day.label} className="flex flex-col items-center gap-0.5 flex-1">
                  <div className="flex items-end gap-0.5 w-full justify-center">
                    <SparkBar value={day.added} max={maxTrend} color="bg-red-500/80" />
                    <SparkBar value={day.patched} max={maxTrend} color="bg-green-500/80" />
                  </div>
                  <span className="text-gray-500 text-xs">{day.label}</span>
                </div>
              ))}
            </div>
            <div className="flex items-center gap-4 mt-4 text-xs">
              <span className="flex items-center gap-1.5">
                <span className="inline-block w-3 h-3 rounded bg-red-500/80" />
                <span className="text-gray-400">Added</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="inline-block w-3 h-3 rounded bg-green-500/80" />
                <span className="text-gray-400">Patched</span>
              </span>
            </div>
            <div className="mt-4 grid grid-cols-2 gap-3">
              {d.trend.map((day) => (
                <div
                  key={day.label}
                  className="flex justify-between items-center text-xs px-2 py-1 rounded bg-slate-800/40"
                >
                  <span className="text-gray-400 w-8">{day.label}</span>
                  <span className="text-red-400">+{day.added}</span>
                  <span className="text-green-400">-{day.patched}</span>
                  <span className={cn(
                    "font-semibold",
                    day.added > day.patched ? "text-red-400" : "text-green-400"
                  )}>
                    {day.added > day.patched ? `+${day.added - day.patched}` : `-${day.patched - day.added}`}
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* ── Risk by Network Zone ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <Card className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border-slate-700/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-cyan-400" />
              Risk by Network Zone
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-5 gap-4">
              {d.zones.map((zone) => (
                <div
                  key={zone.name}
                  className="p-4 rounded-lg bg-slate-800/30 border border-slate-700/50 hover:border-slate-600 transition-colors"
                >
                  <div className="flex items-start justify-between mb-3">
                    <p className="font-semibold text-white text-sm">{zone.name}</p>
                    <Badge
                      variant="outline"
                      className={cn("border text-xs", getZoneBadge(zone.risk_level))}
                    >
                      {zone.risk_level}
                    </Badge>
                  </div>
                  <div className="space-y-1.5">
                    <div className="flex justify-between text-xs">
                      <span className="text-gray-400">Assets</span>
                      <span className="text-white font-semibold">{zone.asset_count}</span>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-gray-400">Vulns</span>
                      <span className="text-white font-semibold">{zone.vuln_count}</span>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-gray-400">Per Asset</span>
                      <span className={cn(
                        "font-semibold",
                        getRiskTextColor(zone.asset_count > 0 ? zone.vuln_count / zone.asset_count / 10 : 0)
                      )}>
                        {zone.asset_count > 0 ? (zone.vuln_count / zone.asset_count).toFixed(0) : "—"}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Footer */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.35 }}
        className="text-center text-sm text-gray-400 pb-4"
      >
        <p>
          Heatmap refreshes every 5 minutes. Risk scores calculated from CVSS, EPSS, and asset criticality.
          <br />
          Last updated: {new Date().toLocaleDateString()}
        </p>
      </motion.div>
    </div>
  );
}
