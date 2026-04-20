/**
 * OT Security Dashboard
 *
 * Operational Technology / ICS / SCADA asset monitoring and incident tracking.
 *   1. KPIs: OT Assets, Critical Assets, Active Alerts, Protocol Violations
 *   2. OT assets table (asset_id, type, zone, protocol, risk_level, last_seen)
 *
 * Route: /ot-security
 * API: GET /api/v1/ot-sec/assets
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Cpu, RefreshCw, AlertTriangle, Shield, Radio } from "lucide-react";

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

const MOCK_ASSETS = [
  { id: "OT-001", asset_id: "PLC-PROD-01",   type: "plc",          zone: "Level 1 — Control",    protocol: "Modbus TCP",    risk_level: "critical", last_seen: "1 min ago" },
  { id: "OT-002", asset_id: "HMI-OPS-03",    type: "hmi",          zone: "Level 2 — SCADA",      protocol: "EtherNet/IP",   risk_level: "high",     last_seen: "2 min ago" },
  { id: "OT-003", asset_id: "RTU-FIELD-07",  type: "rtu",          zone: "Level 0 — Field",      protocol: "DNP3",          risk_level: "high",     last_seen: "5 min ago" },
  { id: "OT-004", asset_id: "SCADA-SRV-01",  type: "scada_server", zone: "Level 3 — Operations", protocol: "OPC-UA",        risk_level: "critical", last_seen: "3 min ago" },
  { id: "OT-005", asset_id: "EWS-ENG-02",    type: "engineering_ws",zone: "Level 3 — Operations",protocol: "RDP/OPC",       risk_level: "medium",   last_seen: "15 min ago" },
  { id: "OT-006", asset_id: "IED-SUBST-12",  type: "ied",          zone: "Level 0 — Field",      protocol: "IEC 61850",     risk_level: "high",     last_seen: "8 min ago" },
  { id: "OT-007", asset_id: "HIST-DATA-01",  type: "historian",    zone: "Level 3 — Operations", protocol: "OPC-DA",        risk_level: "medium",   last_seen: "10 min ago" },
  { id: "OT-008", asset_id: "FWALL-PURDUE",  type: "firewall",     zone: "Level 3.5 — DMZ",      protocol: "TCP/IP",        risk_level: "low",      last_seen: "1 min ago" },
];

const MOCK_STATS = { ot_assets: 248, critical_assets: 34, active_alerts: 9, protocol_violations: 16 };

// ── Badge helpers ──────────────────────────────────────────────

function AssetTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    plc:            "border-emerald-500/30 text-emerald-400 bg-emerald-500/10",
    hmi:            "border-green-500/30 text-green-400 bg-green-500/10",
    rtu:            "border-teal-500/30 text-teal-400 bg-teal-500/10",
    scada_server:   "border-red-500/30 text-red-400 bg-red-500/10",
    engineering_ws: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    ied:            "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    historian:      "border-purple-500/30 text-purple-400 bg-purple-500/10",
    firewall:       "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono", map[type] ?? "border-border")}>
      {type.replace(/_/g, " ")}
    </Badge>
  );
}

function RiskLevelBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-emerald-500/30 text-emerald-400 bg-emerald-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border")}>{level}</Badge>;
}

function ProtocolBadge({ protocol }: { protocol: string }) {
  return (
    <Badge className="text-[10px] border border-emerald-500/30 text-emerald-300 bg-emerald-500/10 font-mono">
      {protocol}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function OTSecurityDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveAssets, setLiveAssets] = useState<any[] | null>(null);
  const [liveStats, setLiveStats]   = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/ot-sec/assets?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/ot-sec/stats?org_id=${ORG_ID}`),
    ]).then(([assetsRes, statsRes]) => {
      if (assetsRes.status === "fulfilled") setLiveAssets(assetsRes.value?.assets ?? assetsRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    });
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const assets = liveAssets ?? MOCK_ASSETS;
  const stats  = liveStats  ?? MOCK_STATS;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="OT Security"
        description="Operational technology asset monitoring — ICS, SCADA, PLC, and field device security"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="OT Assets"           value={stats.ot_assets}            icon={Cpu}           trend="flat" />
        <KpiCard title="Critical Assets"     value={stats.critical_assets}      icon={Shield}        trend="flat" className="border-emerald-500/20" />
        <KpiCard title="Active Alerts"       value={stats.active_alerts}        icon={AlertTriangle} trend="up"      className="border-red-500/20" />
        <KpiCard title="Protocol Violations" value={stats.protocol_violations}  icon={Radio}         trend="up"      className="border-amber-500/20" />
      </div>

      {/* OT Assets Table */}
      <Card className="border-emerald-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-emerald-400">
              <Cpu className="h-4 w-4" />
              OT Asset Inventory
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {assets.filter((a: any) => a.risk_level === "critical").length} critical
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Purdue model zone mapping — PLCs, HMIs, RTUs, SCADA servers, and field devices
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Asset ID</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Zone</TableHead>
                  <TableHead className="text-[11px] h-8">Protocol</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Level</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Last Seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {assets.map((asset: any, i: number) => (
                  <TableRow key={asset.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] font-semibold">
                      {asset.asset_id ?? asset.name ?? asset.id}
                    </TableCell>
                    <TableCell className="py-2">
                      <AssetTypeBadge type={asset.type ?? asset.asset_type ?? "plc"} />
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground max-w-[180px] truncate">
                      {asset.zone ?? asset.purdue_level ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <ProtocolBadge protocol={asset.protocol ?? asset.ot_protocol ?? "Modbus"} />
                    </TableCell>
                    <TableCell className="py-2">
                      <RiskLevelBadge level={asset.risk_level ?? asset.risk ?? "low"} />
                    </TableCell>
                    <TableCell className="py-2 text-right text-[11px] text-muted-foreground">
                      {asset.last_seen ?? "—"}
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
