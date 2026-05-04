/**
 * Firmware Security Dashboard
 *
 * Firmware vulnerability tracking and device posture management.
 *   1. KPI cards: Total Devices, Active Devices, Total Vulns, Unpatched Vulns
 *   2. Devices table
 *   3. Vulnerabilities table
 *
 * API: GET /api/v1/firmware-security/{stats,devices,vulnerabilities}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Cpu, RefreshCw, AlertTriangle, ShieldAlert, Shield } from "lucide-react";
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

// ── Badge helpers ──────────────────────────────────────────────

function RiskBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border text-muted-foreground")}>
      {level}
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

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:        "border-red-500/30 text-red-400 bg-red-500/10",
    in_progress: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    patched:     "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function FirmwareSecurityDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [liveData, setLiveData] = useState<{
    stats: any | null;
    devices: any[] | null;
    vulns: any[] | null;
  }>({ stats: null, devices: null, vulns: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/firmware-security/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/firmware-security/devices?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/firmware-security/vulnerabilities?org_id=${ORG_ID}`),
    ]).then(([statsRes, devicesRes, vulnsRes]) => {
      setLiveData({
        stats:   statsRes.status   === "fulfilled" ? statsRes.value   : null,
        devices: devicesRes.status === "fulfilled" ? devicesRes.value : null,
        vulns:   vulnsRes.status   === "fulfilled" ? vulnsRes.value   : null,
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

  const stats   = liveData.stats   ?? { total_devices: 0, active_devices: 0, total_vulns: 0, unpatched_vulns: 0 };
  const devices = liveData.devices ?? [];
  const vulns   = liveData.vulns   ?? [];

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
        title="Firmware Security"
        description="Device firmware vulnerability tracking and patch posture"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Devices"    value={stats.total_devices}   icon={Cpu}         trend="flat" />
        <KpiCard title="Active Devices"   value={stats.active_devices}  icon={Shield}       trend="up"   className="border-green-500/20" />
        <KpiCard title="Total Vulns"      value={stats.total_vulns}     icon={AlertTriangle} trend="down" className="border-amber-500/20" />
        <KpiCard title="Unpatched Vulns"  value={stats.unpatched_vulns} icon={ShieldAlert}  trend="down" className="border-red-500/20" />
      </div>

      {/* Devices Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Cpu className="h-4 w-4 text-blue-400" />
              Firmware Devices
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {devices.length} devices
            </Badge>
          </div>
          <CardDescription className="text-xs">Tracked devices with firmware version and risk posture</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Device Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Manufacturer</TableHead>
                  <TableHead className="text-[11px] h-8">Firmware</TableHead>
                  <TableHead className="text-[11px] h-8">Risk</TableHead>
                  <TableHead className="text-[11px] h-8">Last Scanned</TableHead>
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
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{d.device_type}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{d.manufacturer}</TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{d.firmware_version}</TableCell>
                    <TableCell className="py-2"><RiskBadge level={d.risk_level ?? "low"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{d.last_scanned}</TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Vulnerabilities Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <ShieldAlert className="h-4 w-4" />
              Firmware Vulnerabilities
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {vulns.filter((v: any) => v.status === "open").length} open
            </Badge>
          </div>
          <CardDescription className="text-xs">CVEs affecting device firmware components</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">CVE ID</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Affected Component</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Patch Available</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {vulns.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  vulns.map((v: any, i: number) => (
                  <TableRow key={v.cve_id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-blue-400">{v.cve_id}</TableCell>
                    <TableCell className="py-2"><SeverityBadge severity={v.severity ?? "medium"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{v.affected_component}</TableCell>
                    <TableCell className="py-2 text-center text-[11px]">
                      {v.patch_available
                        ? <span className="text-green-400">Yes</span>
                        : <span className="text-red-400">No</span>}
                    </TableCell>
                    <TableCell className="py-2"><StatusBadge status={v.status ?? "open"} /></TableCell>
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
