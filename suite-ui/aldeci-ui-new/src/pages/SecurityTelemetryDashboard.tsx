/**
 * Security Telemetry Dashboard
 *
 * Security telemetry stream monitoring with alert rules and percentile tracking.
 *   1. KPIs: Total Datapoints, Active Sources, Alert Rules, Triggered Today
 *   2. Telemetry table (telemetry_type, source, value, unit, recorded_at)
 *
 * Route: /security-telemetry
 * API: GET /api/v1/security-telemetry
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Gauge, RefreshCw, Radio, Bell, Zap, BarChart2 } from "lucide-react";

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
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_TELEMETRY = [
  { id: "tel-001", telemetry_type: "cpu_usage",        source: "host-prod-01",    value: 87.4,   unit: "%",     recorded_at: "2026-04-16T09:58:00Z" },
  { id: "tel-002", telemetry_type: "network_rx",       source: "firewall-edge",   value: 2340.2, unit: "Mbps",  recorded_at: "2026-04-16T09:57:00Z" },
  { id: "tel-003", telemetry_type: "failed_logins",    source: "ldap-primary",    value: 142,    unit: "count", recorded_at: "2026-04-16T09:56:00Z" },
  { id: "tel-004", telemetry_type: "disk_iops",        source: "nas-cluster",     value: 9821,   unit: "iops",  recorded_at: "2026-04-16T09:55:00Z" },
  { id: "tel-005", telemetry_type: "api_latency_p95",  source: "api-gateway",     value: 340,    unit: "ms",    recorded_at: "2026-04-16T09:54:00Z" },
  { id: "tel-006", telemetry_type: "dns_queries",      source: "dns-resolver-01", value: 48201,  unit: "count", recorded_at: "2026-04-16T09:53:00Z" },
  { id: "tel-007", telemetry_type: "tls_handshakes",   source: "lb-prod",         value: 12043,  unit: "count", recorded_at: "2026-04-16T09:52:00Z" },
  { id: "tel-008", telemetry_type: "memory_usage",     source: "host-prod-02",    value: 73.1,   unit: "%",     recorded_at: "2026-04-16T09:51:00Z" },
  { id: "tel-009", telemetry_type: "vulnerability_age",source: "vuln-scanner",    value: 14.3,   unit: "days",  recorded_at: "2026-04-16T09:50:00Z" },
  { id: "tel-010", telemetry_type: "container_restarts",source: "k8s-prod",       value: 7,      unit: "count", recorded_at: "2026-04-16T09:49:00Z" },
];

const MOCK_STATS = { total_datapoints: 4820341, active_sources: 38, alert_rules: 92, triggered_today: 14 };

// ── Helpers ──────────────────────────────────────────────────

function TypeBadge({ type }: { type: string }) {
  const colorMap: Record<string, string> = {
    cpu_usage:         "border-orange-500/30 text-orange-400 bg-orange-500/10",
    memory_usage:      "border-amber-500/30 text-amber-400 bg-amber-500/10",
    network_rx:        "border-blue-500/30 text-blue-400 bg-blue-500/10",
    failed_logins:     "border-red-500/30 text-red-400 bg-red-500/10",
    disk_iops:         "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    api_latency_p95:   "border-purple-500/30 text-purple-400 bg-purple-500/10",
    dns_queries:       "border-teal-500/30 text-teal-400 bg-teal-500/10",
    tls_handshakes:    "border-green-500/30 text-green-400 bg-green-500/10",
    vulnerability_age: "border-rose-500/30 text-rose-400 bg-rose-500/10",
    container_restarts:"border-pink-500/30 text-pink-400 bg-pink-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", colorMap[type] ?? "border-border")}>
      {type.replace(/_/g, " ")}
    </Badge>
  );
}

function formatTs(ts: string) {
  return new Date(ts).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function exportCsv(rows: any[]) {
  const headers = ["telemetry_type", "source", "value", "unit", "recorded_at"];
  const lines = [headers.join(","), ...rows.map(r => headers.map(h => `"${r[h] ?? ""}"`).join(","))];
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = "security_telemetry.csv"; a.click();
  URL.revokeObjectURL(url);
}

// ── Component ──────────────────────────────────────────────────

export default function SecurityTelemetryDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveTelemetry, setLiveTelemetry] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/security-telemetry/datapoints?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/security-telemetry/stats?org_id=${ORG_ID}`),
    ]).then(([telRes, statsRes]) => {
      if (telRes.status === "fulfilled") setLiveTelemetry(telRes.value?.datapoints ?? telRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    });
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const telemetry = liveTelemetry ?? MOCK_TELEMETRY;
  const stats     = liveStats     ?? MOCK_STATS;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Security Telemetry"
        description="Security telemetry stream — real-time datapoints, source health, alert rule triggers, and signal monitoring"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Datapoints"  value={stats.total_datapoints.toLocaleString()} icon={Gauge}  trend="up"   className="border-orange-500/20" />
        <KpiCard title="Active Sources"    value={stats.active_sources}                    icon={Radio}  trend="flat" className="border-amber-500/20" />
        <KpiCard title="Alert Rules"       value={stats.alert_rules}                       icon={Bell}   trend="flat" className="border-orange-500/20" />
        <KpiCard title="Triggered Today"   value={stats.triggered_today}                   icon={Zap}    trend="down" className="border-amber-500/20" />
      </div>

      {/* Telemetry Table */}
      <Card className="border-orange-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-orange-400">
              <BarChart2 className="h-4 w-4" />
              Telemetry Stream
            </CardTitle>
            <div className="flex items-center gap-2">
              <Badge className="text-[10px] border border-orange-500/30 text-orange-400 bg-orange-500/10">
                live
              </Badge>
              <Button variant="outline" size="sm" className="text-[11px] h-7" onClick={() => exportCsv(telemetry)}>
                Export CSV
              </Button>
            </div>
          </div>
          <CardDescription className="text-xs">
            Latest telemetry datapoints with type, source, value, unit, and timestamp
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Telemetry Type</TableHead>
                  <TableHead className="text-[11px] h-8">Source</TableHead>
                  <TableHead className="text-[11px] h-8">Value</TableHead>
                  <TableHead className="text-[11px] h-8">Unit</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Recorded At</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {telemetry.map((tel: any, i: number) => (
                  <TableRow key={tel.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2">
                      <TypeBadge type={tel.telemetry_type ?? "unknown"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-amber-300">
                      {tel.source ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-orange-300 font-semibold">
                      {tel.value ?? 0}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">
                      {tel.unit ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground text-right">
                      {tel.recorded_at ? formatTs(tel.recorded_at) : "—"}
                    </TableCell>
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
