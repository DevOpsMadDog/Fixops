/**
 * Deception Analytics Dashboard
 *
 * Advanced deception technology analytics — honeypots, canary tokens, attacker intelligence.
 *   1. KPI cards: Total Assets, Active Assets, Total Interactions, Unique Attacker IPs
 *   2. Deception Assets table
 *   3. Attacker Interactions table
 *
 * API: GET /api/v1/deception-analytics/{stats,assets,interactions}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Crosshair, RefreshCw, Wifi, Users, Activity, AlertOctagon,
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
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data (fallback) ───────────────────────────────────────

const MOCK_STATS = {
  total_assets:          48,
  active_assets:         41,
  total_interactions:   1293,
  unique_attacker_ips:   87,
};

const MOCK_ASSETS = [
  { asset_name: "Honeypot-SSH-DMZ",      asset_type: "honeypot",     decoy_category: "network",    interaction_count: 312, last_interaction: "2026-04-16T10:05:00Z" },
  { asset_name: "Canary-AWS-Keys",        asset_type: "canary_token", decoy_category: "credential", interaction_count: 24,  last_interaction: "2026-04-16T09:42:11Z" },
  { asset_name: "Fake-DB-Server",         asset_type: "honeypot",     decoy_category: "database",   interaction_count: 189, last_interaction: "2026-04-16T09:15:33Z" },
  { asset_name: "Canary-S3-Bucket",       asset_type: "canary_token", decoy_category: "cloud",      interaction_count: 7,   last_interaction: "2026-04-15T22:31:00Z" },
  { asset_name: "Honeypot-RDP-01",        asset_type: "honeypot",     decoy_category: "network",    interaction_count: 441, last_interaction: "2026-04-16T10:11:22Z" },
  { asset_name: "Fake-Admin-Account",     asset_type: "decoy_user",   decoy_category: "identity",   interaction_count: 56,  last_interaction: "2026-04-16T08:55:04Z" },
  { asset_name: "Canary-HR-Spreadsheet",  asset_type: "canary_token", decoy_category: "file",       interaction_count: 3,   last_interaction: "2026-04-14T14:22:55Z" },
  { asset_name: "Honeypot-SMB-Internal",  asset_type: "honeypot",     decoy_category: "network",    interaction_count: 261, last_interaction: "2026-04-16T09:58:17Z" },
];

const MOCK_INTERACTIONS = [
  { attacker_technique: "SSH Brute Force",         severity: "high",     source_ip: "203.0.113.42",  confidence_score: 0.97, asset_id: "hp-ssh-dmz"    },
  { attacker_technique: "RDP Scanning",             severity: "medium",   source_ip: "198.51.100.7",  confidence_score: 0.88, asset_id: "hp-rdp-01"     },
  { attacker_technique: "Credential Token Access",  severity: "critical", source_ip: "185.220.101.21",confidence_score: 0.99, asset_id: "can-aws-keys"  },
  { attacker_technique: "SMB Enumeration",          severity: "medium",   source_ip: "192.168.10.55", confidence_score: 0.85, asset_id: "hp-smb-int"    },
  { attacker_technique: "SQL Injection Probe",      severity: "high",     source_ip: "45.155.205.90", confidence_score: 0.93, asset_id: "fake-db-srv"   },
  { attacker_technique: "Admin Account Reuse",      severity: "high",     source_ip: "10.0.5.112",    confidence_score: 0.91, asset_id: "fake-admin"    },
  { attacker_technique: "S3 Bucket Enumeration",    severity: "medium",   source_ip: "52.89.142.201", confidence_score: 0.78, asset_id: "can-s3-bkt"   },
  { attacker_technique: "File Exfiltration Attempt",severity: "critical", source_ip: "77.91.78.14",   confidence_score: 0.96, asset_id: "can-hr-xls"   },
];

// ── Badge helpers ──────────────────────────────────────────────

function AssetTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    honeypot:    "border-orange-500/30 text-orange-400 bg-orange-500/10",
    canary_token:"border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    decoy_user:  "border-blue-500/30 text-blue-400 bg-blue-500/10",
    decoy_file:  "border-purple-500/30 text-purple-400 bg-purple-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>
      {type?.replace(/_/g, " ")}
    </Badge>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    low:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border text-muted-foreground")}>
      {severity}
    </Badge>
  );
}

function DecoyCategory({ category }: { category: string }) {
  const map: Record<string, string> = {
    network:    "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    credential: "border-red-500/30 text-red-400 bg-red-500/10",
    database:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    cloud:      "border-sky-500/30 text-sky-400 bg-sky-500/10",
    identity:   "border-purple-500/30 text-purple-400 bg-purple-500/10",
    file:       "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[category] ?? "border-border text-muted-foreground")}>
      {category}
    </Badge>
  );
}

function confidenceColor(score: number): string {
  if (score >= 0.95) return "text-green-400";
  if (score >= 0.85) return "text-amber-400";
  return "text-red-400";
}

function fmtTime(ts: string): string {
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

// ── Component ──────────────────────────────────────────────────

export default function DeceptionAnalyticsDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
    stats: any | null;
    assets: any[] | null;
    interactions: any[] | null;
  }>({ stats: null, assets: null, interactions: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/deception-analytics/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/deception-analytics/assets?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/deception-analytics/interactions?org_id=${ORG_ID}`),
    ]).then(([statsRes, assetsRes, interactionsRes]) => {
      setLiveData({
        stats:        statsRes.status        === "fulfilled" ? statsRes.value        : null,
        assets:       assetsRes.status       === "fulfilled" ? assetsRes.value       : null,
        interactions: interactionsRes.status === "fulfilled" ? interactionsRes.value : null,
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
  const assets       = liveData.assets       ?? MOCK_ASSETS;
  const interactions = liveData.interactions ?? MOCK_INTERACTIONS;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Deception Analytics"
        description="Honeypot and canary token telemetry — attacker intelligence and interaction analysis"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Assets"         value={stats.total_assets}         icon={Crosshair}    trend="up"   />
        <KpiCard title="Active Assets"        value={stats.active_assets}        icon={Wifi}         trend="up"   className="border-green-500/20" />
        <KpiCard title="Total Interactions"   value={stats.total_interactions}   icon={Activity}     trend="up"   className="border-orange-500/20" />
        <KpiCard title="Unique Attacker IPs"  value={stats.unique_attacker_ips}  icon={Users}        trend="up"   className="border-red-500/20" />
      </div>

      {/* Assets Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Crosshair className="h-4 w-4 text-orange-400" />
              Deception Assets
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {assets.length} assets
            </Badge>
          </div>
          <CardDescription className="text-xs">Deployed honeypots, canary tokens, and decoy resources</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Asset Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Interactions</TableHead>
                  <TableHead className="text-[11px] h-8">Last Interaction</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {assets.map((a: any, i: number) => (
                  <TableRow key={a.asset_name ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px]">{a.asset_name}</TableCell>
                    <TableCell className="py-2"><AssetTypeBadge type={a.asset_type ?? "honeypot"} /></TableCell>
                    <TableCell className="py-2"><DecoyCategory category={a.decoy_category ?? "network"} /></TableCell>
                    <TableCell className="py-2 text-right text-[11px] font-semibold text-orange-400">{a.interaction_count}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{fmtTime(a.last_interaction)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Interactions Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertOctagon className="h-4 w-4" />
              Attacker Interactions
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {interactions.filter((i: any) => i.severity === "critical").length} critical
            </Badge>
          </div>
          <CardDescription className="text-xs">Recorded attacker techniques, source IPs, and confidence scores</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Technique</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Source IP</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Confidence</TableHead>
                  <TableHead className="text-[11px] h-8">Asset</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {interactions.map((ia: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium">{ia.attacker_technique}</TableCell>
                    <TableCell className="py-2"><SeverityBadge severity={ia.severity ?? "medium"} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-blue-400">{ia.source_ip}</TableCell>
                    <TableCell className={cn("py-2 text-right text-[11px] font-semibold", confidenceColor(ia.confidence_score))}>
                      {((ia.confidence_score ?? 0) * 100).toFixed(0)}%
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{ia.asset_id}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
