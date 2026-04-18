/**
 * ITDR Dashboard — Identity Threat Detection & Response
 *
 * Detects and responds to identity-based threats across the environment.
 *   1. KPI cards: Total Threats, Open Threats, Critical Threats, Response Actions
 *   2. Identity threats table
 *   3. Response actions table
 *
 * API: GET /api/v1/itdr/{stats,threats,response-actions}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  ShieldAlert, RefreshCw, AlertTriangle, UserX, Zap, CheckCircle,
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
  total_threats: 89,
  open_threats: 21,
  critical_threats: 6,
  response_actions_count: 44,
};

const MOCK_THREATS = [
  { id: "t-001", threat_type: "credential_stuffing",      severity: "critical", confidence_score: 94, status: "open",       detected_at: "2026-04-16T09:10:00Z" },
  { id: "t-002", threat_type: "impossible_travel",         severity: "high",     confidence_score: 88, status: "open",       detected_at: "2026-04-16T08:45:00Z" },
  { id: "t-003", threat_type: "privilege_escalation",      severity: "critical", confidence_score: 91, status: "mitigated",  detected_at: "2026-04-16T07:20:00Z" },
  { id: "t-004", threat_type: "mfa_bypass_attempt",        severity: "high",     confidence_score: 82, status: "open",       detected_at: "2026-04-15T22:30:00Z" },
  { id: "t-005", threat_type: "lateral_movement",          severity: "critical", confidence_score: 96, status: "open",       detected_at: "2026-04-15T20:15:00Z" },
  { id: "t-006", threat_type: "account_takeover",          severity: "high",     confidence_score: 79, status: "resolved",   detected_at: "2026-04-15T18:00:00Z" },
  { id: "t-007", threat_type: "brute_force",               severity: "medium",   confidence_score: 70, status: "resolved",   detected_at: "2026-04-15T14:10:00Z" },
  { id: "t-008", threat_type: "shadow_admin_creation",     severity: "critical", confidence_score: 98, status: "open",       detected_at: "2026-04-14T11:55:00Z" },
];

const MOCK_ACTIONS = [
  { id: "a-001", action_type: "account_lock",         status: "completed", automated: true,  threat_id: "t-001", executed_at: "2026-04-16T09:11:00Z" },
  { id: "a-002", action_type: "session_revocation",   status: "completed", automated: true,  threat_id: "t-002", executed_at: "2026-04-16T08:46:00Z" },
  { id: "a-003", action_type: "mfa_enforce",          status: "completed", automated: false, threat_id: "t-003", executed_at: "2026-04-16T07:25:00Z" },
  { id: "a-004", action_type: "alert_soc",            status: "pending",   automated: true,  threat_id: "t-004", executed_at: "2026-04-15T22:31:00Z" },
  { id: "a-005", action_type: "network_isolate",      status: "completed", automated: false, threat_id: "t-005", executed_at: "2026-04-15T20:20:00Z" },
  { id: "a-006", action_type: "password_reset",       status: "completed", automated: true,  threat_id: "t-006", executed_at: "2026-04-15T18:05:00Z" },
];

// ── Badge helpers ──────────────────────────────────────────────

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

function ThreatStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:      "border-red-500/30 text-red-400 bg-red-500/10",
    mitigated: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    resolved:  "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

function ActionStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    completed: "border-green-500/30 text-green-400 bg-green-500/10",
    pending:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    failed:    "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

function fmtTime(ts: string): string {
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

// ── Component ──────────────────────────────────────────────────

export default function ITDRDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
  const [loading, setLoading] = useState(true);
    stats: any | null;
    threats: any[] | null;
    actions: any[] | null;
  }>({ stats: null, threats: null, actions: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/itdr/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/itdr/threats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/itdr/response-actions?org_id=${ORG_ID}`),
    ]).then(([statsRes, threatsRes, actionsRes]) => {
      setLiveData({
        stats:   statsRes.status   === "fulfilled" ? statsRes.value   : null,
        threats: threatsRes.status === "fulfilled" ? threatsRes.value : null,
        actions: actionsRes.status === "fulfilled" ? actionsRes.value : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats   = liveData.stats   ?? MOCK_STATS;
  const threats = liveData.threats ?? MOCK_THREATS;
  const actions = liveData.actions ?? MOCK_ACTIONS;

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
        title="Identity Threat Detection & Response"
        description="Detect and respond to identity-based attacks across the environment"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Threats"          value={stats.total_threats
    setLoading(false);}           icon={ShieldAlert}   trend="up"   />
        <KpiCard title="Open Threats"           value={stats.open_threats}            icon={AlertTriangle} trend="up"   className="border-amber-500/20" />
        <KpiCard title="Critical Threats"       value={stats.critical_threats}        icon={UserX}         trend="up"   className="border-red-500/20" />
        <KpiCard title="Response Actions"       value={stats.response_actions_count}  icon={Zap}           trend="flat" className="border-blue-500/20" />
      </div>

      {/* Threats Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <UserX className="h-4 w-4 text-red-400" />
              Identity Threats
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {threats.length} records
            </Badge>
          </div>
          <CardDescription className="text-xs">Active and historical identity-based attack detections</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Threat Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Confidence</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Detected</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {threats.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  threats.map((t: any, i: number) => (
                  <TableRow key={t.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{t.id}</TableCell>
                    <TableCell className="py-2 text-[11px] capitalize">{(t.threat_type ?? "").replace(/_/g, " ")}</TableCell>
                    <TableCell className="py-2"><SeverityBadge severity={t.severity ?? "medium"} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px]">{t.confidence_score ?? 0}%</TableCell>
                    <TableCell className="py-2"><ThreatStatusBadge status={t.status ?? "open"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{fmtTime(t.detected_at)}</TableCell>
                  </TableRow>
                ))}
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Response Actions Table */}
      <Card className="border-blue-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-blue-400">
              <Zap className="h-4 w-4" />
              Response Actions
            </CardTitle>
            <Badge className="text-[10px] border border-blue-500/30 text-blue-400 bg-blue-500/10">
              {actions.filter((a: any) => a.automated).length} automated
            </Badge>
          </div>
          <CardDescription className="text-xs">Automated and manual response actions taken against detected threats</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Action Type</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Automated</TableHead>
                  <TableHead className="text-[11px] h-8">Threat ID</TableHead>
                  <TableHead className="text-[11px] h-8">Executed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {actions.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  actions.map((a: any, i: number) => (
                  <TableRow key={a.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{a.id}</TableCell>
                    <TableCell className="py-2 text-[11px] capitalize">{(a.action_type ?? "").replace(/_/g, " ")}</TableCell>
                    <TableCell className="py-2"><ActionStatusBadge status={a.status ?? "pending"} /></TableCell>
                    <TableCell className="py-2 text-center">
                      {a.automated
                        ? <CheckCircle className="h-3.5 w-3.5 text-green-400 inline" />
                        : <span className="text-[11px] text-muted-foreground">manual</span>}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{a.threat_id}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{fmtTime(a.executed_at)}</TableCell>
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
