/**
 * Dark Web Monitoring Dashboard
 *
 * Tracks dark web mentions, credential exposures, and keyword alerts.
 *   1. KPI cards: Total Mentions, Open Mentions, Critical Exposures, Keywords Tracked
 *   2. Recent dark web mentions table
 *   3. Credential exposures table
 *
 * API: GET /api/v1/dark-web/{stats,mentions,credential-exposures}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Eye, RefreshCw, AlertTriangle, ShieldAlert, Key, Globe,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// == API helpers ================================================
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

// == Mock data (fallback) =======================================

const MOCK_STATS = {
  total_mentions: 147,
  open_mentions: 34,
  critical_exposures: 8,
  keywords_tracked: 52,
};

const MOCK_MENTIONS = [
  { id: "m-001", source_category: "paste_site",   mention_type: "credential_leak",  risk_score: 92, status: "open",     detected_at: "2026-04-16T08:14:00Z" },
  { id: "m-002", source_category: "dark_forum",   mention_type: "brand_mention",    risk_score: 45, status: "reviewed", detected_at: "2026-04-16T07:30:00Z" },
  { id: "m-003", source_category: "marketplace",  mention_type: "data_for_sale",    risk_score: 88, status: "open",     detected_at: "2026-04-15T22:11:00Z" },
  { id: "m-004", source_category: "telegram",     mention_type: "insider_threat",   risk_score: 71, status: "open",     detected_at: "2026-04-15T19:45:00Z" },
  { id: "m-005", source_category: "paste_site",   mention_type: "api_key_leak",     risk_score: 95, status: "resolved", detected_at: "2026-04-14T14:20:00Z" },
  { id: "m-006", source_category: "dark_forum",   mention_type: "vulnerability_tip", risk_score: 60, status: "reviewed", detected_at: "2026-04-14T10:05:00Z" },
  { id: "m-007", source_category: "marketplace",  mention_type: "data_for_sale",    risk_score: 80, status: "open",     detected_at: "2026-04-13T16:33:00Z" },
  { id: "m-008", source_category: "irc_channel",  mention_type: "brand_mention",    risk_score: 30, status: "resolved", detected_at: "2026-04-13T09:00:00Z" },
];

const MOCK_EXPOSURES = [
  { id: "e-001", affected_system: "corp-email",       exposure_type: "password_hash",    severity: "critical", status: "open"     },
  { id: "e-002", affected_system: "vpn-gateway",      exposure_type: "credentials",      severity: "critical", status: "open"     },
  { id: "e-003", affected_system: "github-repo",      exposure_type: "api_key",          severity: "high",     status: "resolved" },
  { id: "e-004", affected_system: "crm-system",       exposure_type: "pii_dump",         severity: "high",     status: "open"     },
  { id: "e-005", affected_system: "cloud-console",    exposure_type: "iam_credentials",  severity: "critical", status: "open"     },
  { id: "e-006", affected_system: "employee-portal",  exposure_type: "session_tokens",   severity: "medium",   status: "reviewed" },
  { id: "e-007", affected_system: "devops-pipeline",  exposure_type: "env_secrets",      severity: "high",     status: "open"     },
];

// == Badge helpers ==============================================

function RiskScoreBadge({ score }: { score: number }) {
  const cls =
    score >= 80 ? "border-red-500/30 text-red-400 bg-red-500/10" :
    score >= 50 ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
                  "border-green-500/30 text-green-400 bg-green-500/10";
  return (
    <Badge className={cn("text-[10px] border font-mono", cls)}>{score}</Badge>
  );
}

function MentionStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:     "border-red-500/30 text-red-400 bg-red-500/10",
    reviewed: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    resolved: "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border text-muted-foreground")}>
      {severity}
    </Badge>
  );
}

function fmtTime(ts: string): string {
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

// == Component ==================================================

export default function DarkWebMonitoringDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [liveData, setLiveData] = useState<{ stats: any | null; mentions: any[] | null; exposures: any[] | null; }>({ stats: null, mentions: null, exposures: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/dark-web/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/dark-web/mentions?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/dark-web/credential-exposures?org_id=${ORG_ID}`),
    ]).then(([statsRes, mentionsRes, exposuresRes]) => {
      setLiveData({
        stats:     statsRes.status    === "fulfilled" ? statsRes.value    : null,
        mentions:  mentionsRes.status === "fulfilled" ? mentionsRes.value : null,
        exposures: exposuresRes.status === "fulfilled" ? exposuresRes.value : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats     = liveData.stats     ?? MOCK_STATS;
  const mentions  = liveData.mentions  ?? MOCK_MENTIONS;
  const exposures = liveData.exposures ?? MOCK_EXPOSURES;

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
        title="Dark Web Monitoring"
        description="Track credential exposures, brand mentions, and data leaks on the dark web"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Mentions"      value={stats.total_mentions}      icon={Globe}       trend="up"   />
        <KpiCard title="Open Mentions"       value={stats.open_mentions}       icon={Eye}         trend="up"   className="border-amber-500/20" />
        <KpiCard title="Critical Exposures"  value={stats.critical_exposures}  icon={AlertTriangle} trend="up" className="border-red-500/20" />
        <KpiCard title="Keywords Tracked"    value={stats.keywords_tracked}    icon={ShieldAlert} trend="flat" className="border-blue-500/20" />
      </div>

      {/* Mentions Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Globe className="h-4 w-4 text-purple-400" />
              Recent Dark Web Mentions
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {mentions.length} records
            </Badge>
          </div>
          <CardDescription className="text-xs">Latest mentions across paste sites, dark forums, and marketplaces</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Source Category</TableHead>
                  <TableHead className="text-[11px] h-8">Mention Type</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Score</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Detected</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {mentions.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  mentions.map((m: any, i: number) => (
                  <TableRow key={m.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{m.id}</TableCell>
                    <TableCell className="py-2 text-[11px] capitalize">{(m.source_category ?? "").replace(/_/g, " ")}</TableCell>
                    <TableCell className="py-2 text-[11px] capitalize">{(m.mention_type ?? "").replace(/_/g, " ")}</TableCell>
                    <TableCell className="py-2"><RiskScoreBadge score={m.risk_score ?? 0} /></TableCell>
                    <TableCell className="py-2"><MentionStatusBadge status={m.status ?? "open"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{fmtTime(m.detected_at)}</TableCell>
                  </TableRow>
                ))
              )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Credential Exposures Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <Key className="h-4 w-4" />
              Credential Exposures
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {exposures.filter((e: any) => e.severity === "critical").length} critical
            </Badge>
          </div>
          <CardDescription className="text-xs">Exposed credentials, API keys, and sensitive data found on dark web</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Affected System</TableHead>
                  <TableHead className="text-[11px] h-8">Exposure Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {exposures.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  exposures.map((e: any, i: number) => (
                  <TableRow key={e.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{e.id}</TableCell>
                    <TableCell className="py-2 text-[11px]">{e.affected_system}</TableCell>
                    <TableCell className="py-2 text-[11px] capitalize">{(e.exposure_type ?? "").replace(/_/g, " ")}</TableCell>
                    <TableCell className="py-2"><SeverityBadge severity={e.severity ?? "medium"} /></TableCell>
                    <TableCell className="py-2"><MentionStatusBadge status={e.status ?? "open"} /></TableCell>
                  </TableRow>
                ))
              )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
