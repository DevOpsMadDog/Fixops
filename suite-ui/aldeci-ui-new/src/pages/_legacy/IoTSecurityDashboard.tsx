// FOLDED into AssetGraph 2026-04-27 — preserve for git history
/**
 * IoT Security Dashboard
 *
 * IoT device fleet monitoring and anomaly detection.
 *   1. KPI cards: Total Devices, Online Devices, Quarantined, Open Anomalies
 *   2. Devices table
 *   3. Anomalies table
 *
 * API: GET /api/v1/iot-security/{stats,devices,anomalies}
 */

import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { Wifi, RefreshCw, AlertTriangle, ShieldOff, Activity } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
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

// ── Badge helpers ──────────────────────────────────────────────

function DeviceStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    online:      "border-green-500/30 text-green-400 bg-green-500/10",
    offline:     "border-gray-500/30 text-gray-400 bg-gray-500/10",
    quarantined: "border-red-500/30 text-red-400 bg-red-500/10",
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

function AnomalyStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:     "border-red-500/30 text-red-400 bg-red-500/10",
    resolved: "border-green-500/30 text-green-400 bg-green-500/10",
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

export default function IoTSecurityDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [liveData, setLiveData] = useState<{
    stats: any | null;
    devices: any[] | null;
    anomalies: any[] | null;
  }>({ stats: null, devices: null, anomalies: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/iot-security/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/iot-security/devices?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/iot-security/anomalies?org_id=${ORG_ID}`),
    ]).then(([statsRes, devicesRes, anomaliesRes]) => {
      setLiveData({
        stats:     statsRes.status     === "fulfilled" ? statsRes.value     : null,
        devices:   devicesRes.status   === "fulfilled" ? devicesRes.value   : null,
        anomalies: anomaliesRes.status === "fulfilled" ? anomaliesRes.value : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); 
    setLoading(false);}, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats     = liveData.stats     ?? null;
  const devices   = liveData.devices   ?? [];
  const anomalies = liveData.anomalies ?? [];
  const hasAnyData = Boolean(stats) || devices.length > 0 || anomalies.length > 0;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  if (!hasAnyData) return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="IoT Security"
        description="IoT device fleet monitoring and behavioral anomaly detection"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />
      <EmptyState
        icon={Wifi}
        title="No IoT devices discovered"
        description="Connect an IoT collector or NDR sensor to populate this view."
        action={
          <Link to="/onboarding" className="inline-flex items-center gap-1 rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500">
            Start onboarding
          </Link>
        }
      />
    </motion.div>
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
        title="IoT Security"
        description="IoT device fleet monitoring and behavioral anomaly detection"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Devices"       value={stats?.total_devices ?? "—"}        icon={Wifi}          trend="flat" />
        <KpiCard title="Online Devices"      value={stats?.online_devices ?? "—"}       icon={Activity}      trend="up"   className="border-green-500/20" />
        <KpiCard title="Quarantined"         value={stats?.quarantined_devices ?? "—"}  icon={ShieldOff}     trend="down" className="border-red-500/20" />
        <KpiCard title="Open Anomalies"      value={stats?.open_anomalies ?? "—"}       icon={AlertTriangle} trend="down" className="border-amber-500/20" />
      </div>

      {/* Devices Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Wifi className="h-4 w-4 text-blue-400" />
              IoT Device Fleet
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {devices.length} devices
            </Badge>
          </div>
          <CardDescription className="text-xs">Connected IoT devices with risk scores and status</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Device Name</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8">Protocol</TableHead>
                  <TableHead className="text-[11px] h-8">IP Address</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Risk Score</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {devices.length === 0 ? (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={6} className="p-0">
                      <EmptyState
                        icon={Wifi}
                        title="No IoT devices yet"
                        description="Devices discovered via the IoT collector will appear here."
                      />
                    </TableCell>
                  </TableRow>
                ) : (
                  devices.map((d: any, i: number) => (
                  <TableRow key={d.device_name ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px]">{d.device_name}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{d.device_category}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{d.protocol}</TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{d.ip_address}</TableCell>
                    <TableCell className="py-2 text-[11px] text-right">
                      <span className={d.risk_score >= 70 ? "text-red-400" : d.risk_score >= 40 ? "text-amber-400" : "text-green-400"}>
                        {d.risk_score}
                      </span>
                    </TableCell>
                    <TableCell className="py-2"><DeviceStatusBadge status={d.status ?? "online"} /></TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Anomalies Table */}
      <Card className="border-amber-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
              <AlertTriangle className="h-4 w-4" />
              Detected Anomalies
            </CardTitle>
            <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">
              {anomalies.filter((a: any) => a.status === "open").length} open
            </Badge>
          </div>
          <CardDescription className="text-xs">Behavioral anomalies detected across IoT device fleet</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Anomaly Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Device ID</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Detected At</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {anomalies.length === 0 ? (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={5} className="p-0">
                      <EmptyState
                        icon={AlertTriangle}
                        title="No anomalies detected"
                        description="Behavioral anomalies from the IoT detector will be listed here."
                      />
                    </TableCell>
                  </TableRow>
                ) : (
                  anomalies.map((a: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px]">{a.anomaly_type}</TableCell>
                    <TableCell className="py-2"><SeverityBadge severity={a.severity ?? "medium"} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{a.device_id}</TableCell>
                    <TableCell className="py-2"><AnomalyStatusBadge status={a.status ?? "open"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{fmtTime(a.detected_at)}</TableCell>
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
