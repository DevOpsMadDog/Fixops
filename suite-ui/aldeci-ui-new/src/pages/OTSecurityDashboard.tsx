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
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

async function apiFetch<T = any>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

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
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [assets, setAssets] = useState<any[]>([]);
  const [stats, setStats] = useState<any>({ ot_assets: 0, critical_assets: 0, active_alerts: 0, protocol_violations: 0 });

  const load = async () => {
    setRefreshing(true);
    setError(null);
    try {
      const [assetsRes, anomaliesRes] = await Promise.allSettled([
        apiFetch<any>("/api/v1/ot-security/assets"),
        apiFetch<any>("/api/v1/ot-security/anomalies"),
      ]);
      let assetsArr: any[] = [];
      if (assetsRes.status === "fulfilled") {
        const v = assetsRes.value;
        assetsArr = Array.isArray(v) ? v : (v?.assets ?? v?.items ?? []);
        setAssets(assetsArr);
      } else {
        setError((assetsRes.reason as Error).message);
      }
      let anArr: any[] = [];
      if (anomaliesRes.status === "fulfilled") {
        const v = anomaliesRes.value;
        anArr = Array.isArray(v) ? v : (v?.anomalies ?? v?.items ?? []);
      }
      setStats({
        ot_assets: assetsArr.length,
        critical_assets: assetsArr.filter((a: any) => a.risk_level === "critical").length,
        active_alerts: anArr.filter((x: any) => x.status !== "resolved").length,
        protocol_violations: anArr.filter((x: any) => (x.type ?? "").toLowerCase().includes("protocol")).length,
      });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const handleRefresh = () => { load(); };

  if (loading) return <PageSkeleton />;


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

      {error && <ErrorState message={error} onRetry={load} />}

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
          {assets.length === 0 && !error ? <EmptyState icon={Cpu} title="No OT assets" description="Register an OT/ICS/SCADA asset to populate this inventory." /> : (
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
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
