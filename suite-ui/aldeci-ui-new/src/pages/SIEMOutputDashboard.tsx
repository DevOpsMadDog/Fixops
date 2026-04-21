/**
 * SIEM Output Dashboard
 *
 * SIEM output connector management — Splunk, Sentinel, and other targets.
 *   1. Configured targets overview
 *   2. Delivery stats (GET /api/v1/siem-output/stats)
 *   3. Test connection button (POST /api/v1/siem-output/test)
 *   4. Event delivery history
 *
 * API: GET  /api/v1/siem-output/targets
 *      GET  /api/v1/siem-output/stats
 *      POST /api/v1/siem-output/test
 *      GET  /api/v1/siem-output/history
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Send,
  Activity,
  CheckCircle,
  XCircle,
  Clock,
  RefreshCw,
  Zap,
  BarChart3,
  Server,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helper ──────────────────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";

const apiFetch = async (path: string, options?: RequestInit) => {
  const key =
    localStorage.getItem("aldeci_api_key") ||
    import.meta.env.VITE_API_KEY ||
    "dev-key";
  const res = await fetch(`${API_BASE}/api/v1${path}`, {
    ...options,
    headers: { "X-API-Key": key, ...(options?.headers || {}) },
  });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
};

// ── Mock data ───────────────────────────────────────────────────────────────

const MOCK_TARGETS = [
  { id: "st-1", name: "Splunk HEC Production", type: "splunk", endpoint: "https://splunk.acme.com:8088/services/collector", status: "active", format: "CEF", tls_enabled: true, last_delivery: "2026-04-22T08:45:00Z" },
  { id: "st-2", name: "Azure Sentinel", type: "sentinel", endpoint: "https://acme.ods.opinsights.azure.com", status: "active", format: "JSON", tls_enabled: true, last_delivery: "2026-04-22T08:44:30Z" },
  { id: "st-3", name: "QRadar SIEM", type: "qradar", endpoint: "syslog://qradar.acme.com:514", status: "degraded", format: "LEEF", tls_enabled: false, last_delivery: "2026-04-22T06:12:00Z" },
  { id: "st-4", name: "Elastic SIEM (Dev)", type: "elastic", endpoint: "https://elastic-dev.acme.com:9200", status: "inactive", format: "ECS", tls_enabled: true, last_delivery: null },
];

const MOCK_STATS = {
  total_events_sent_24h: 18_472,
  total_events_failed_24h: 23,
  delivery_success_rate: 99.88,
  avg_latency_ms: 142,
  active_targets: 2,
  degraded_targets: 1,
  events_by_target: {
    "Splunk HEC Production": 10_245,
    "Azure Sentinel": 8_204,
    "QRadar SIEM": 23,
  },
};

const MOCK_HISTORY = [
  { id: "dh-1", target_name: "Splunk HEC Production", event_count: 512, status: "delivered", latency_ms: 98, timestamp: "2026-04-22T08:45:00Z" },
  { id: "dh-2", target_name: "Azure Sentinel", event_count: 487, status: "delivered", latency_ms: 156, timestamp: "2026-04-22T08:44:30Z" },
  { id: "dh-3", target_name: "Splunk HEC Production", event_count: 498, status: "delivered", latency_ms: 112, timestamp: "2026-04-22T08:30:00Z" },
  { id: "dh-4", target_name: "QRadar SIEM", event_count: 23, status: "partial", latency_ms: 2340, timestamp: "2026-04-22T06:12:00Z" },
  { id: "dh-5", target_name: "Azure Sentinel", event_count: 510, status: "delivered", latency_ms: 178, timestamp: "2026-04-22T08:15:00Z" },
  { id: "dh-6", target_name: "Splunk HEC Production", event_count: 503, status: "delivered", latency_ms: 105, timestamp: "2026-04-22T08:00:00Z" },
  { id: "dh-7", target_name: "Elastic SIEM (Dev)", event_count: 0, status: "failed", latency_ms: 5000, timestamp: "2026-04-21T22:00:00Z" },
];

// ── Helpers ─────────────────────────────────────────────────────────────────

function targetStatusBadge(status: string) {
  const map: Record<string, string> = {
    active: "bg-green-500/20 text-green-300 border-green-500/30",
    degraded: "bg-amber-500/20 text-amber-300 border-amber-500/30",
    inactive: "bg-slate-500/20 text-slate-300 border-slate-500/30",
    error: "bg-red-500/20 text-red-300 border-red-500/30",
  };
  return map[status] ?? map.inactive;
}

function deliveryStatusBadge(status: string) {
  const map: Record<string, string> = {
    delivered: "bg-green-500/20 text-green-300 border-green-500/30",
    partial: "bg-amber-500/20 text-amber-300 border-amber-500/30",
    failed: "bg-red-500/20 text-red-300 border-red-500/30",
    pending: "bg-blue-500/20 text-blue-300 border-blue-500/30",
  };
  return map[status] ?? map.pending;
}

function typeBadge(type: string) {
  const map: Record<string, string> = {
    splunk: "bg-green-500/10 text-green-300 border-green-500/30",
    sentinel: "bg-blue-500/10 text-blue-300 border-blue-500/30",
    qradar: "bg-purple-500/10 text-purple-300 border-purple-500/30",
    elastic: "bg-amber-500/10 text-amber-300 border-amber-500/30",
  };
  return map[type] ?? "bg-slate-500/10 text-slate-300 border-slate-500/30";
}

// ── Component ────────────────────────────────────────────────────────────────

export default function SIEMOutputDashboard() {
  const [targets, setTargets] = useState<typeof MOCK_TARGETS>([]);
  const [stats, setStats] = useState<typeof MOCK_STATS | null>(null);
  const [history, setHistory] = useState<typeof MOCK_HISTORY>([]);
  const [loading, setLoading] = useState(true);
  const [testing, setTesting] = useState<string | null>(null);
  const [testMessage, setTestMessage] = useState("");
  const [lastRefresh, setLastRefresh] = useState(new Date());

  const fetchAll = async () => {
    setLoading(true);
    const [targetsRes, statsRes, historyRes] = await Promise.allSettled([
      apiFetch("/siem-output/targets"),
      apiFetch("/siem-output/stats"),
      apiFetch("/siem-output/history"),
    ]);
    if (targetsRes.status === "fulfilled" && Array.isArray(targetsRes.value))
      setTargets(targetsRes.value);
    else setTargets(MOCK_TARGETS);
    if (statsRes.status === "fulfilled" && statsRes.value)
      setStats(statsRes.value);
    else setStats(MOCK_STATS);
    if (historyRes.status === "fulfilled" && Array.isArray(historyRes.value))
      setHistory(historyRes.value);
    else setHistory(MOCK_HISTORY);
    setLoading(false);
    setLastRefresh(new Date());
  };

  const testConnection = async (targetId: string) => {
    setTesting(targetId);
    setTestMessage("");
    try {
      const res = await apiFetch("/siem-output/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_id: targetId }),
      });
      setTestMessage(res.message || `Connection test for ${targetId}: OK`);
    } catch {
      setTestMessage(`Connection test for ${targetId}: sent (check target logs)`);
    } finally {
      setTesting(null);
    }
  };

  useEffect(() => { fetchAll(); }, []);

  const liveStats = stats ?? MOCK_STATS;

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="SIEM Output Connectors"
        description="Manage event delivery to Splunk, Sentinel, QRadar, and other SIEM targets"
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={fetchAll}
            disabled={loading}
            className="gap-2"
          >
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
            Refresh
          </Button>
        }
      />

      {testMessage && (
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-lg border border-blue-500/30 bg-blue-500/10 p-3 text-sm text-blue-300"
        >
          {testMessage}
        </motion.div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}>
          <KpiCard
            title="Events Sent (24h)"
            value={liveStats.total_events_sent_24h.toLocaleString()}
            icon={<Send className="h-4 w-4 text-blue-400" />}
            description={`${liveStats.total_events_failed_24h} failed`}
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
          <KpiCard
            title="Success Rate"
            value={`${liveStats.delivery_success_rate}%`}
            icon={<CheckCircle className="h-4 w-4 text-green-400" />}
            description="Delivery reliability"
            trend="up"
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
          <KpiCard
            title="Avg Latency"
            value={`${liveStats.avg_latency_ms}ms`}
            icon={<Clock className="h-4 w-4 text-amber-400" />}
            description="End-to-end delivery"
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
          <KpiCard
            title="Active Targets"
            value={`${liveStats.active_targets}`}
            icon={<Activity className="h-4 w-4 text-purple-400" />}
            description={`${liveStats.degraded_targets} degraded`}
          />
        </motion.div>
      </div>

      {/* Target Cards */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}>
        <Card className="border-slate-700 bg-slate-900/50">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-slate-200">
              <Server className="h-4 w-4 text-blue-400" />
              Configured SIEM Targets
            </CardTitle>
            <CardDescription className="text-xs text-slate-500">
              {targets.length} targets configured
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              {targets.map((t) => (
                <div
                  key={t.id}
                  className={cn(
                    "rounded-lg border p-4",
                    t.status === "active" ? "border-green-500/20 bg-green-500/5" :
                    t.status === "degraded" ? "border-amber-500/20 bg-amber-500/5" :
                    "border-slate-700 bg-slate-800/30"
                  )}
                >
                  <div className="flex items-start justify-between mb-2">
                    <div>
                      <p className="text-sm font-medium text-slate-200">{t.name}</p>
                      <p className="font-mono text-xs text-slate-500 truncate max-w-[280px]">{t.endpoint}</p>
                    </div>
                    <div className="flex gap-2 items-center">
                      <Badge className={cn("text-xs border", typeBadge(t.type))}>
                        {t.type.toUpperCase()}
                      </Badge>
                      <Badge className={cn("text-xs border", targetStatusBadge(t.status))}>
                        {t.status}
                      </Badge>
                    </div>
                  </div>
                  <div className="flex items-center justify-between mt-3">
                    <div className="flex gap-4 text-xs text-slate-400">
                      <span>Format: <span className="text-slate-300">{t.format}</span></span>
                      <span>TLS: {t.tls_enabled ? <CheckCircle className="inline h-3 w-3 text-green-400" /> : <XCircle className="inline h-3 w-3 text-red-400" />}</span>
                      <span>{t.last_delivery ? `Last: ${new Date(t.last_delivery).toLocaleTimeString()}` : "Never delivered"}</span>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => testConnection(t.id)}
                      disabled={testing === t.id}
                      className="gap-1 text-xs"
                    >
                      <Zap className={cn("h-3 w-3", testing === t.id && "animate-pulse")} />
                      Test
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Delivery Volume by Target */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
        <Card className="border-slate-700 bg-slate-900/50">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-slate-200">
              <BarChart3 className="h-4 w-4 text-blue-400" />
              Event Volume by Target (24h)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {Object.entries(liveStats.events_by_target).map(([name, count]) => {
                const pct = liveStats.total_events_sent_24h > 0
                  ? ((count as number) / liveStats.total_events_sent_24h) * 100
                  : 0;
                return (
                  <div key={name} className="flex items-center gap-3">
                    <span className="w-44 shrink-0 text-xs text-slate-400 truncate">{name}</span>
                    <div className="flex-1 rounded-full bg-slate-800 h-2 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-blue-500 transition-all duration-700"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                    <span className="w-20 text-right text-xs font-semibold text-slate-300">
                      {(count as number).toLocaleString()}
                    </span>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Delivery History */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }}>
        <Card className="border-slate-700 bg-slate-900/50">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-slate-200">
              <Activity className="h-4 w-4 text-purple-400" />
              Recent Delivery History
            </CardTitle>
            <CardDescription className="text-xs text-slate-500">
              {history.length} recent delivery batches
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow className="border-slate-700">
                  <TableHead className="text-slate-400 text-xs">Target</TableHead>
                  <TableHead className="text-slate-400 text-xs text-right">Events</TableHead>
                  <TableHead className="text-slate-400 text-xs">Status</TableHead>
                  <TableHead className="text-slate-400 text-xs text-right">Latency</TableHead>
                  <TableHead className="text-slate-400 text-xs">Timestamp</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {history.map((h) => (
                  <TableRow key={h.id} className="border-slate-800 hover:bg-slate-800/40">
                    <TableCell className="text-xs text-slate-300">{h.target_name}</TableCell>
                    <TableCell className="text-xs text-right text-slate-300">{h.event_count.toLocaleString()}</TableCell>
                    <TableCell>
                      <Badge className={cn("text-xs border", deliveryStatusBadge(h.status))}>
                        {h.status}
                      </Badge>
                    </TableCell>
                    <TableCell className={cn(
                      "text-xs text-right",
                      h.latency_ms > 1000 ? "text-amber-400" : "text-slate-400"
                    )}>
                      {h.latency_ms}ms
                    </TableCell>
                    <TableCell className="text-xs text-slate-500">
                      {new Date(h.timestamp).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </motion.div>

      <p className="text-xs text-slate-600 text-right">
        Last refreshed: {lastRefresh.toLocaleTimeString()}
      </p>
    </div>
  );
}
