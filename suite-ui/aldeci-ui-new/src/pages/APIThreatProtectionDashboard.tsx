/**
 * API Threat Protection Dashboard
 *
 * API threat detection rules and event monitoring for API security.
 *   1. KPIs: Active Rules, Total Events, Blocked Events, Top Threat Type
 *   2. Threat events table (threat_type, source_ip, endpoint, action_taken, severity, detected_at)
 *
 * Route: /api-threat-protection
 * API: GET /api/v1/api-threat-protection
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ShieldOff, RefreshCw, AlertTriangle, Ban, Zap } from "lucide-react";

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

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_EVENTS = [
  { id: "evt-001", threat_type: "SQL Injection",        source_ip: "185.220.101.47", endpoint: "/api/v1/users",       action_taken: "blocked",  severity: "critical", detected_at: "2026-04-16 10:23:11" },
  { id: "evt-002", threat_type: "Rate Limit Abuse",     source_ip: "45.33.32.156",   endpoint: "/api/v1/auth/login",  action_taken: "throttled", severity: "high",     detected_at: "2026-04-16 10:21:05" },
  { id: "evt-003", threat_type: "BOLA",                 source_ip: "91.108.4.14",    endpoint: "/api/v1/accounts/99", action_taken: "blocked",  severity: "critical", detected_at: "2026-04-16 10:19:47" },
  { id: "evt-004", threat_type: "Credential Stuffing",  source_ip: "198.51.100.22",  endpoint: "/api/v1/auth/token",  action_taken: "blocked",  severity: "high",     detected_at: "2026-04-16 10:17:30" },
  { id: "evt-005", threat_type: "XSS Attempt",          source_ip: "203.0.113.44",   endpoint: "/api/v1/comments",   action_taken: "sanitized", severity: "medium",   detected_at: "2026-04-16 10:15:12" },
  { id: "evt-006", threat_type: "Path Traversal",       source_ip: "103.21.244.0",   endpoint: "/api/v1/files",      action_taken: "blocked",  severity: "high",     detected_at: "2026-04-16 10:12:55" },
  { id: "evt-007", threat_type: "Mass Assignment",      source_ip: "162.158.0.1",    endpoint: "/api/v1/profile",    action_taken: "logged",   severity: "medium",   detected_at: "2026-04-16 10:10:03" },
  { id: "evt-008", threat_type: "Excessive Data Exp",   source_ip: "172.64.0.1",     endpoint: "/api/v1/export",     action_taken: "blocked",  severity: "high",     detected_at: "2026-04-16 10:08:44" },
];

const MOCK_STATS = { active_rules: 34, total_events: 847, blocked_events: 623, top_threat_type: "Rate Limit Abuse" };

// ── Badge helpers ──────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border")}>
      {severity}
    </Badge>
  );
}

function ActionBadge({ action }: { action: string }) {
  const map: Record<string, string> = {
    blocked:   "border-red-500/30 text-red-400 bg-red-500/10",
    throttled: "border-orange-500/30 text-orange-400 bg-orange-500/10",
    sanitized: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    logged:    "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[action] ?? "border-border")}>
      {action}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function APIThreatProtectionDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveEvents, setLiveEvents] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/api-threat-protection/events?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/api-threat-protection/stats?org_id=${ORG_ID}`),
    ]).then(([eventsRes, statsRes]) => {
      if (eventsRes.status === "fulfilled") setLiveEvents(eventsRes.value?.events ?? eventsRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const events = liveEvents ?? MOCK_EVENTS;
  const stats  = liveStats  ?? MOCK_STATS;

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
        title="API Threat Protection"
        description="Real-time API threat detection, OWASP API Top 10 monitoring, and automated blocking rules"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Rules"    value={stats.active_rules}    icon={Zap}           trend="flat" className="border-red-500/20" />
        <KpiCard title="Total Events"    value={stats.total_events}    icon={AlertTriangle}  trend="up"   className="border-orange-500/20" />
        <KpiCard title="Blocked Events"  value={stats.blocked_events}  icon={Ban}           trend="up"   className="border-red-500/20" />
        <KpiCard title="Top Threat Type" value={stats.top_threat_type} icon={ShieldOff}     trend="flat" className="border-amber-500/20" />
      </div>

      {/* Events Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <ShieldOff className="h-4 w-4" />
              Threat Events
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {events.filter((e: any) => e.action_taken === "blocked").length} blocked
            </Badge>
          </div>
          <CardDescription className="text-xs">
            API threat events with source IP, targeted endpoint, and enforcement action taken
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Threat Type</TableHead>
                  <TableHead className="text-[11px] h-8">Source IP</TableHead>
                  <TableHead className="text-[11px] h-8">Endpoint</TableHead>
                  <TableHead className="text-[11px] h-8">Action</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Detected At</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  events.map((evt: any, i: number) => (
                  <TableRow key={evt.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-red-300">
                      {evt.threat_type ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">
                      {evt.source_ip ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-orange-300 max-w-[180px] truncate">
                      {evt.endpoint ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <ActionBadge action={evt.action_taken ?? "logged"} />
                    </TableCell>
                    <TableCell className="py-2">
                      <SeverityBadge severity={evt.severity ?? "low"} />
                    </TableCell>
                    <TableCell className="py-2 text-right text-[11px] text-muted-foreground">
                      {evt.detected_at ?? "—"}
                    </TableCell>
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
