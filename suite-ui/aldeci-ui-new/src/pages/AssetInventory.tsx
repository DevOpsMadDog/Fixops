/**
 * Asset Inventory
 *
 * Stats bar, filterable asset table, click-to-open detail panel.
 * Route: /assets
 *
 * API: GET /api/v1/assets  — falls back to mock data on failure.
 */

import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  Server,
  Container,
  Cloud,
  Monitor,
  Database,
  AlertTriangle,
  Activity,
  Eye,
  X,
  ChevronRight,
  Clock,
  GitBranch,
  Package,
  ShieldAlert,
  User,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type AssetType = "server" | "container" | "cloud" | "endpoint" | "database";
type Env = "prod" | "staging" | "dev";
type AssetStatus = "active" | "inactive" | "unknown";

interface Asset {
  id: string;
  name: string;
  type: AssetType;
  risk_score: number;
  owner: string;
  env: Env;
  status: AssetStatus;
  last_seen: string;
  incidents: number;
  findings: number;
  ip?: string;
  os?: string;
  tags?: string[];
}

// ═══════════════════════════════════════════════════════════
// Mock data
// ═══════════════════════════════════════════════════════════

const MOCK_ASSETS: Asset[] = [
  { id: "a1", name: "prod-api-01", type: "server", risk_score: 87, owner: "platform-team", env: "prod", status: "active", last_seen: "1m ago", incidents: 2, findings: 14, ip: "10.0.1.42", os: "Ubuntu 22.04", tags: ["api", "critical"] },
  { id: "a2", name: "k8s-worker-03", type: "container", risk_score: 45, owner: "infra-team", env: "prod", status: "active", last_seen: "5m ago", incidents: 0, findings: 3, ip: "10.0.2.15", os: "Container/Alpine", tags: ["k8s"] },
  { id: "a3", name: "aws-s3-data-lake", type: "cloud", risk_score: 62, owner: "data-team", env: "prod", status: "active", last_seen: "10m ago", incidents: 1, findings: 7, tags: ["s3", "data", "pii"] },
  { id: "a4", name: "dev-laptop-jdoe", type: "endpoint", risk_score: 23, owner: "john.doe", env: "dev", status: "active", last_seen: "2h ago", incidents: 0, findings: 1, ip: "192.168.1.55", os: "macOS 14.4", tags: ["laptop"] },
  { id: "a5", name: "postgres-primary", type: "database", risk_score: 71, owner: "dba-team", env: "prod", status: "active", last_seen: "3m ago", incidents: 1, findings: 9, ip: "10.0.3.20", os: "Postgres 15", tags: ["db", "critical"] },
  { id: "a6", name: "k8s-ingress-01", type: "container", risk_score: 55, owner: "infra-team", env: "prod", status: "active", last_seen: "2m ago", incidents: 0, findings: 4, ip: "10.0.2.1", os: "Container/nginx", tags: ["ingress"] },
  { id: "a7", name: "staging-api-02", type: "server", risk_score: 38, owner: "platform-team", env: "staging", status: "active", last_seen: "15m ago", incidents: 0, findings: 2, ip: "10.1.1.10", os: "Ubuntu 22.04", tags: ["api"] },
  { id: "a8", name: "gcp-pubsub-events", type: "cloud", risk_score: 29, owner: "data-team", env: "prod", status: "active", last_seen: "1h ago", incidents: 0, findings: 0, tags: ["gcp", "events"] },
];

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

const TYPE_CONFIG: Record<AssetType, { label: string; icon: typeof Server; color: string }> = {
  server:    { label: "Server",    icon: Server,    color: "text-cyan-400 bg-cyan-500/10" },
  container: { label: "Container", icon: Container, color: "text-blue-400 bg-blue-500/10" },
  cloud:     { label: "Cloud",     icon: Cloud,     color: "text-purple-400 bg-purple-500/10" },
  endpoint:  { label: "Endpoint",  icon: Monitor,   color: "text-green-400 bg-green-500/10" },
  database:  { label: "Database",  icon: Database,  color: "text-orange-400 bg-orange-500/10" },
};

const ENV_BADGE: Record<Env, string> = {
  prod:    "bg-red-500/10 text-red-400",
  staging: "bg-yellow-500/10 text-yellow-400",
  dev:     "bg-blue-500/10 text-blue-400",
};

function riskColor(score: number): string {
  if (score >= 75) return "text-red-400 bg-red-500/10";
  if (score >= 50) return "text-orange-400 bg-orange-500/10";
  if (score >= 25) return "text-yellow-400 bg-yellow-500/10";
  return "text-green-400 bg-green-500/10";
}

function riskLabel(score: number): string {
  if (score >= 75) return "Critical";
  if (score >= 50) return "High";
  if (score >= 25) return "Medium";
  return "Low";
}

// ═══════════════════════════════════════════════════════════
// Detail Panel
// ═══════════════════════════════════════════════════════════

const TIMELINE_EVENTS = [
  { time: "2m ago", event: "Vulnerability scan completed", type: "info" },
  { time: "1h ago", event: "Configuration drift detected", type: "warning" },
  { time: "3h ago", event: "Agent heartbeat OK", type: "success" },
  { time: "1d ago", event: "Patch applied: CVE-2024-1234", type: "success" },
  { time: "2d ago", event: "New finding: SQL injection risk", type: "danger" },
];

function DetailPanel({ asset, onClose }: { asset: Asset; onClose: () => void }) {
  const TypeIcon = TYPE_CONFIG[asset.type].icon;

  return (
    <motion.div
      initial={{ opacity: 0, x: 32 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 32 }}
      transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
      className="w-80 shrink-0 border-l border-border bg-card flex flex-col overflow-hidden"
    >
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-border">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className={cn("rounded p-1.5", TYPE_CONFIG[asset.type].color)}>
            <TypeIcon className="w-4 h-4" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-semibold truncate">{asset.name}</p>
            <p className="text-xs text-muted-foreground">{TYPE_CONFIG[asset.type].label}</p>
          </div>
        </div>
        <Button size="sm" variant="ghost" className="h-7 w-7 p-0 shrink-0" onClick={onClose} aria-label="Close panel">
          <X className="w-4 h-4" />
        </Button>
      </div>

      <ScrollArea className="flex-1">
        <div className="px-5 py-4 space-y-5">
          {/* Risk score */}
          <div>
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">Risk Score</p>
            <div className="flex items-center gap-3">
              <span className={cn("text-3xl font-bold tabular-nums", riskColor(asset.risk_score).split(" ")[0])}>
                {asset.risk_score}
              </span>
              <Badge className={cn("text-xs border-0", riskColor(asset.risk_score))}>
                {riskLabel(asset.risk_score)}
              </Badge>
            </div>
            {/* Bar */}
            <div className="mt-2 h-1.5 rounded-full bg-muted overflow-hidden">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${asset.risk_score}%` }}
                transition={{ delay: 0.2, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
                className={cn("h-full rounded-full",
                  asset.risk_score >= 75 ? "bg-red-400" :
                  asset.risk_score >= 50 ? "bg-orange-400" :
                  asset.risk_score >= 25 ? "bg-yellow-400" : "bg-green-400"
                )}
              />
            </div>
          </div>

          <Separator />

          {/* Details */}
          <div>
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2.5">Details</p>
            <dl className="space-y-2">
              {[
                { label: "Owner",       value: asset.owner },
                { label: "Environment", value: asset.env },
                { label: "Status",      value: asset.status },
                { label: "Last Seen",   value: asset.last_seen },
                ...(asset.ip  ? [{ label: "IP Address", value: asset.ip }]  : []),
                ...(asset.os  ? [{ label: "OS / Runtime", value: asset.os }] : []),
              ].map(({ label, value }) => (
                <div key={label} className="flex items-start justify-between gap-2">
                  <dt className="text-xs text-muted-foreground shrink-0">{label}</dt>
                  <dd className="text-xs text-right font-medium truncate">{value}</dd>
                </div>
              ))}
            </dl>
          </div>

          {/* Tags */}
          {asset.tags && asset.tags.length > 0 && (
            <>
              <Separator />
              <div>
                <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">Tags</p>
                <div className="flex flex-wrap gap-1.5">
                  {asset.tags.map((tag) => (
                    <span key={tag} className="text-xs px-2 py-0.5 rounded bg-accent text-accent-foreground font-mono">
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            </>
          )}

          <Separator />

          {/* Linked counts */}
          <div className="grid grid-cols-2 gap-3">
            <Card className="p-3">
              <div className="flex items-center gap-2 mb-1">
                <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                <p className="text-xs text-muted-foreground">Incidents</p>
              </div>
              <p className="text-xl font-bold tabular-nums">{asset.incidents}</p>
            </Card>
            <Card className="p-3">
              <div className="flex items-center gap-2 mb-1">
                <AlertTriangle className="w-3.5 h-3.5 text-yellow-400" />
                <p className="text-xs text-muted-foreground">Findings</p>
              </div>
              <p className="text-xl font-bold tabular-nums">{asset.findings}</p>
            </Card>
          </div>

          <Separator />

          {/* Activity timeline */}
          <div>
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-3">Recent Activity</p>
            <div className="relative pl-4 space-y-3 before:absolute before:left-1.5 before:top-1 before:bottom-1 before:w-px before:bg-border">
              {TIMELINE_EVENTS.map(({ time, event, type }) => (
                <div key={time + event} className="relative">
                  <div className={cn(
                    "absolute -left-2.5 top-1 w-2 h-2 rounded-full border border-background",
                    type === "danger"  && "bg-red-400",
                    type === "warning" && "bg-yellow-400",
                    type === "success" && "bg-green-400",
                    type === "info"    && "bg-blue-400",
                  )} />
                  <p className="text-xs font-medium leading-tight">{event}</p>
                  <p className="text-[10px] text-muted-foreground mt-0.5">{time}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </ScrollArea>
    </motion.div>
  );
}

// ═══════════════════════════════════════════════════════════
// Asset Row
// ═══════════════════════════════════════════════════════════

function AssetRow({
  asset,
  selected,
  onClick,
  index,
}: {
  asset: Asset;
  selected: boolean;
  onClick: () => void;
  index: number;
}) {
  const TypeIcon = TYPE_CONFIG[asset.type].icon;

  return (
    <motion.tr
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.03, duration: 0.25 }}
      onClick={onClick}
      className={cn(
        "border-b border-border/50 cursor-pointer transition-colors group",
        selected ? "bg-primary/5" : "hover:bg-accent/30",
      )}
    >
      <td className="py-3 px-4">
        <div className="flex items-center gap-2.5">
          <div className={cn("rounded p-1", TYPE_CONFIG[asset.type].color)}>
            <TypeIcon className="w-3.5 h-3.5" />
          </div>
          <span className="text-sm font-medium font-mono">{asset.name}</span>
        </div>
      </td>
      <td className="py-3 px-4">
        <span className="text-xs text-muted-foreground">{TYPE_CONFIG[asset.type].label}</span>
      </td>
      <td className="py-3 px-4">
        <span className={cn("inline-flex items-center rounded px-2 py-0.5 text-xs font-bold tabular-nums", riskColor(asset.risk_score))}>
          {asset.risk_score}
        </span>
      </td>
      <td className="py-3 px-4">
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <User className="w-3 h-3" />
          {asset.owner}
        </div>
      </td>
      <td className="py-3 px-4">
        <span className={cn("text-xs px-2 py-0.5 rounded font-medium", ENV_BADGE[asset.env])}>
          {asset.env}
        </span>
      </td>
      <td className="py-3 px-4 text-xs text-muted-foreground">
        <div className="flex items-center gap-1">
          <Clock className="w-3 h-3" />
          {asset.last_seen}
        </div>
      </td>
      <td className="py-3 px-4">
        <div className="flex items-center gap-1.5">
          <Activity className="w-3 h-3 text-green-400" />
          <span className="text-xs">{asset.status}</span>
        </div>
      </td>
      <td className="py-3 px-4 text-right">
        <ChevronRight className={cn("w-4 h-4 text-muted-foreground transition-transform", selected && "rotate-90 text-primary")} />
      </td>
    </motion.tr>
  );
}

// ═══════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════

export default function AssetInventory() {
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [envFilter, setEnvFilter]   = useState<string>("all");
  const [riskFilter, setRiskFilter] = useState<string>("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const { data: assets } = useQuery<Asset[]>({
    queryKey: ["assets"],
    queryFn: async () => {
      const res = await fetch(`${API}/api/v1/assets`);
      if (!res.ok) throw new Error("assets api unavailable");
      return res.json();
    },
    retry: 1,
    staleTime: 60_000,
    initialData: MOCK_ASSETS,
  });

  const filtered = useMemo(() => {
    if (!assets) return [];
    return assets.filter((a) => {
      if (typeFilter !== "all" && a.type !== typeFilter) return false;
      if (envFilter  !== "all" && a.env  !== envFilter)  return false;
      if (riskFilter === "critical" && a.risk_score < 75) return false;
      if (riskFilter === "high"     && (a.risk_score < 50 || a.risk_score >= 75)) return false;
      if (riskFilter === "medium"   && (a.risk_score < 25 || a.risk_score >= 50)) return false;
      if (riskFilter === "low"      && a.risk_score >= 25) return false;
      return true;
    });
  }, [assets, typeFilter, envFilter, riskFilter]);

  const selectedAsset = assets?.find((a) => a.id === selectedId) ?? null;

  const totalAssets    = assets?.length ?? 0;
  const criticalAssets = assets?.filter((a) => a.risk_score >= 75).length ?? 0;
  const highAssets     = assets?.filter((a) => a.risk_score >= 50 && a.risk_score < 75).length ?? 0;
  const unknownAssets  = assets?.filter((a) => a.status === "unknown").length ?? 0;

  return (
    <div className="flex flex-col gap-6 p-6 h-full">
      {/* Header */}
      <PageHeader
        title="Asset Inventory"
        description="Unified view of all monitored assets across cloud, on-prem, and endpoints"
        badge="CSPM"
      />

      {/* Stats bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard title="Total Assets"   value={totalAssets}    icon={Server}        />
        <KpiCard title="Critical Risk"  value={criticalAssets} icon={AlertTriangle} trend="down" trendLabel="Needs attention" />
        <KpiCard title="High Risk"      value={highAssets}     icon={Eye}           trend="flat" trendLabel="Monitor closely" />
        <KpiCard title="Unmanaged"      value={unknownAssets}  icon={Package}       trend="flat" trendLabel="Unknown status" />
      </div>

      {/* Table + Detail panel */}
      <div className="flex flex-1 overflow-hidden rounded-lg border border-border bg-card min-h-0">
        {/* Table section */}
        <div className="flex flex-col flex-1 min-w-0">
          {/* Filter bar */}
          <div className="flex items-center gap-3 px-4 py-3 border-b border-border">
            <span className="text-xs text-muted-foreground font-medium uppercase tracking-wide">Filter:</span>
            <Select value={typeFilter} onValueChange={setTypeFilter}>
              <SelectTrigger className="h-8 w-36 text-xs">
                <SelectValue placeholder="All Types" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="server">Server</SelectItem>
                <SelectItem value="container">Container</SelectItem>
                <SelectItem value="cloud">Cloud</SelectItem>
                <SelectItem value="endpoint">Endpoint</SelectItem>
                <SelectItem value="database">Database</SelectItem>
              </SelectContent>
            </Select>
            <Select value={envFilter} onValueChange={setEnvFilter}>
              <SelectTrigger className="h-8 w-32 text-xs">
                <SelectValue placeholder="All Envs" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Envs</SelectItem>
                <SelectItem value="prod">Production</SelectItem>
                <SelectItem value="staging">Staging</SelectItem>
                <SelectItem value="dev">Dev</SelectItem>
              </SelectContent>
            </Select>
            <Select value={riskFilter} onValueChange={setRiskFilter}>
              <SelectTrigger className="h-8 w-32 text-xs">
                <SelectValue placeholder="All Risk" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Risk</SelectItem>
                <SelectItem value="critical">Critical (75+)</SelectItem>
                <SelectItem value="high">High (50-74)</SelectItem>
                <SelectItem value="medium">Medium (25-49)</SelectItem>
                <SelectItem value="low">Low (&lt;25)</SelectItem>
              </SelectContent>
            </Select>
            <span className="text-xs text-muted-foreground ml-auto">
              {filtered.length} of {totalAssets} assets
            </span>
          </div>

          {/* Table */}
          <ScrollArea className="flex-1">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-xs text-muted-foreground sticky top-0 bg-card z-10">
                  <th className="py-2.5 px-4 text-left font-medium">Name</th>
                  <th className="py-2.5 px-4 text-left font-medium">Type</th>
                  <th className="py-2.5 px-4 text-left font-medium">Risk</th>
                  <th className="py-2.5 px-4 text-left font-medium">Owner</th>
                  <th className="py-2.5 px-4 text-left font-medium">Env</th>
                  <th className="py-2.5 px-4 text-left font-medium">Last Seen</th>
                  <th className="py-2.5 px-4 text-left font-medium">Status</th>
                  <th className="py-2.5 px-4 w-8" />
                </tr>
              </thead>
              <tbody>
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="py-16 text-center text-sm text-muted-foreground">
                      No assets match the selected filters
                    </td>
                  </tr>
                ) : (
                  filtered.map((asset, i) => (
                    <AssetRow
                      key={asset.id}
                      asset={asset}
                      selected={selectedId === asset.id}
                      onClick={() => setSelectedId(selectedId === asset.id ? null : asset.id)}
                      index={i}
                    />
                  ))
                  )}
                </tbody>
            </table>
          </ScrollArea>
        </div>

        {/* Detail Panel */}
        <AnimatePresence>
          {selectedAsset && (
            <DetailPanel
              asset={selectedAsset}
              onClose={() => setSelectedId(null)}
            />
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
