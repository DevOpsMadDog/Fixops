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
import { motion } from "framer-motion";
import { Wifi, RefreshCw, AlertTriangle, ShieldOff, Activity } from "lucide-react";
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
  total_devices: 512,
  online_devices: 489,
  quarantined_devices: 7,
  open_anomalies: 23,
};

const MOCK_DEVICES = [
  { device_name: "temp-sensor-01",  device_category: "Sensor",       protocol: "MQTT",    ip_address: "10.1.2.10",  risk_score: 12,  status: "online"      },
  { device_name: "smart-lock-02",   device_category: "Access",       protocol: "Z-Wave",  ip_address: "10.1.2.15",  risk_score: 45,  status: "online"      },
  { device_name: "hvac-ctrl-03",    device_category: "HVAC",         protocol: "BACnet",  ip_address: "10.1.3.20",  risk_score: 67,  status: "quarantined" },
  { device_name: "cam-parking-04",  device_category: "Camera",       protocol: "RTSP",    ip_address: "10.1.4.30",  risk_score: 78,  status: "online"      },
  { device_name: "badge-reader-05", device_category: "Access",       protocol: "Wiegand", ip_address: "10.1.5.11",  risk_score: 20,  status: "online"      },
  { device_name: "energy-meter-06", device_category: "Utility",      protocol: "Modbus",  ip_address: "10.1.6.55",  risk_score: 33,  status: "offline"     },
];

const MOCK_ANOMALIES = [
  { anomaly_type: "Unusual outbound traffic", severity: "high",     device_id: "cam-parking-04",  status: "open",     detected_at: "2026-04-16T08:22:11Z" },
  { anomaly_type: "Unauthorized protocol",    severity: "critical", device_id: "hvac-ctrl-03",    status: "open",     detected_at: "2026-04-16T07:55:03Z" },
  { anomaly_type: "Port scan detected",       severity: "medium",   device_id: "temp-sensor-01",  status: "resolved", detected_at: "2026-04-15T22:10:44Z" },
  { anomaly_type: "Firmware downgrade",       severity: "high",     device_id: "smart-lock-02",   status: "open",     detected_at: "2026-04-15T18:30:22Z" },
  { anomaly_type: "Repeated auth failures",   severity: "medium",   device_id: "badge-reader-05", status: "resolved", detected_at: "2026-04-15T14:05:09Z" },
];

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

  const stats     = liveData.stats     ?? MOCK_STATS;
  const devices   = liveData.devices   ?? MOCK_DEVICES;
  const anomalies = liveData.anomalies ?? MOCK_ANOMALIES;

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
        <KpiCard title="Total Devices"       value={stats.total_devices
    setLoading(false);}       icon={Wifi}         trend="flat" />
        <KpiCard title="Online Devices"      value={stats.online_devices}      icon={Activity}     trend="up"   className="border-green-500/20" />
        <KpiCard title="Quarantined"         value={stats.quarantined_devices} icon={ShieldOff}    trend="down" className="border-red-500/20" />
        <KpiCard title="Open Anomalies"      value={stats.open_anomalies}      icon={AlertTriangle} trend="down" className="border-amber-500/20" />
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
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
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
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
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
