/**
 * Security Telemetry Dashboard
 * Route: /security-telemetry
 * API: GET /api/v1/security-telemetry/datapoints
 *      GET /api/v1/security-telemetry/stats
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
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

interface TelemetryPoint {
  id?: string;
  telemetry_type?: string;
  source?: string;
  value?: number;
  unit?: string;
  recorded_at?: string;
}

interface TelemetryStats {
  total_datapoints?: number;
  active_sources?: number;
  alert_rules?: number;
  triggered_today?: number;
}

function TypeBadge({ type }: { type: string }) {
  const colorMap: Record<string, string> = {
    cpu_usage:          "border-orange-500/30 text-orange-400 bg-orange-500/10",
    memory_usage:       "border-amber-500/30 text-amber-400 bg-amber-500/10",
    network_rx:         "border-blue-500/30 text-blue-400 bg-blue-500/10",
    failed_logins:      "border-red-500/30 text-red-400 bg-red-500/10",
    disk_iops:          "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    api_latency_p95:    "border-purple-500/30 text-purple-400 bg-purple-500/10",
    dns_queries:        "border-teal-500/30 text-teal-400 bg-teal-500/10",
    tls_handshakes:     "border-green-500/30 text-green-400 bg-green-500/10",
    vulnerability_age:  "border-rose-500/30 text-rose-400 bg-rose-500/10",
    container_restarts: "border-pink-500/30 text-pink-400 bg-pink-500/10",
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

function exportCsv(rows: TelemetryPoint[]) {
  const headers: (keyof TelemetryPoint)[] = ["telemetry_type", "source", "value", "unit", "recorded_at"];
  const lines = [headers.join(","), ...rows.map(r => headers.map(h => `"${r[h] ?? ""}"`).join(","))];
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = "security_telemetry.csv"; a.click();
  URL.revokeObjectURL(url);
}

export default function SecurityTelemetryDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [telemetry, setTelemetry] = useState<TelemetryPoint[]>([]);
  const [stats, setStats] = useState<TelemetryStats>({});
  const [error, setError] = useState<string | null>(null);

  function load() {
    setLoading(true);
    setError(null);
    Promise.allSettled([
      apiFetch("/api/v1/security-telemetry/datapoints?org_id=default"),
      apiFetch("/api/v1/security-telemetry/stats?org_id=default"),
    ]).then(([telRes, statsRes]) => {
      if (telRes.status === "fulfilled") {
        const val = telRes.value;
        setTelemetry(val?.datapoints ?? val?.items ?? (Array.isArray(val) ? val : []));
      } else {
        setError("Telemetry API unavailable");
      }
      if (statsRes.status === "fulfilled") setStats(statsRes.value ?? {});
      setLoading(false);
    });
  }

  useEffect(() => { load(); }, []);

  const handleRefresh = () => { setRefreshing(true); load(); setTimeout(() => setRefreshing(false), 800); };

  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-orange-500" /></div>;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Security Telemetry"
        description="Security telemetry stream — real-time datapoints, source health, alert rule triggers, and signal monitoring"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Datapoints" value={(stats.total_datapoints ?? 0).toLocaleString()} icon={Gauge}  trend="up"   className="border-orange-500/20" />
        <KpiCard title="Active Sources"   value={stats.active_sources ?? 0}                      icon={Radio}  trend="flat" className="border-amber-500/20" />
        <KpiCard title="Alert Rules"      value={stats.alert_rules ?? 0}                         icon={Bell}   trend="flat" className="border-orange-500/20" />
        <KpiCard title="Triggered Today"  value={stats.triggered_today ?? 0}                     icon={Zap}    trend="down" className="border-amber-500/20" />
      </div>
      <Card className="border-orange-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-orange-400">
              <BarChart2 className="h-4 w-4" />Telemetry Stream
            </CardTitle>
            <div className="flex items-center gap-2">
              <Badge className="text-[10px] border border-orange-500/30 text-orange-400 bg-orange-500/10">live</Badge>
              {telemetry.length > 0 && (
                <Button variant="outline" size="sm" className="text-[11px] h-7" onClick={() => exportCsv(telemetry)}>Export CSV</Button>
              )}
            </div>
          </div>
          <CardDescription className="text-xs">Latest telemetry datapoints with type, source, value, unit, and timestamp</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {error || telemetry.length === 0 ? (
            <EmptyState icon={BarChart2} title={error ?? "No telemetry data"} description="Telemetry datapoints will appear here once security sources are connected." />
          ) : (
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
                  {telemetry.map((tel, i) => (
                    <TableRow key={tel.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2"><TypeBadge type={tel.telemetry_type ?? "unknown"} /></TableCell>
                      <TableCell className="py-2 font-mono text-[11px] text-amber-300">{tel.source ?? "—"}</TableCell>
                      <TableCell className="py-2 font-mono text-[11px] text-orange-300 font-semibold">{tel.value ?? 0}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{tel.unit ?? "—"}</TableCell>
                      <TableCell className="py-2 font-mono text-[11px] text-muted-foreground text-right">{tel.recorded_at ? formatTs(tel.recorded_at) : "—"}</TableCell>
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
