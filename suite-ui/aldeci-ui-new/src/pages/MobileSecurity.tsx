/**
 * Mobile Security (MDM) Dashboard
 *
 * Device enrollment, compliance, and threat management.
 *   1. KPIs: Total Devices, Enrolled, Compliant, Active Threats
 *   2. Platform breakdown — colored progress bars
 *   3. Device table (12 rows)
 *   4. MDM policy table (3 policies)
 *   5. Active threats feed (8 threats)
 *   6. Compliance trend — 6-month div-based bars
 *
 * API stubs: GET /api/v1/mdm/devices, /api/v1/mdm/threats, /api/v1/mdm/policies
 */

import { useState, useEffect } from "react";
import { getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { motion } from "framer-motion";

// ── API helpers ────────────────────────────────────────────────
const API_KEY = localStorage.getItem("aldeci.authToken") || import.meta.env.VITE_API_KEY || (getStoredAuthToken() ?? "");
const ORG_ID = "default";

async function apiFetch(path: string) {
  const res = await fetch(`/api/v1${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
import {
  Smartphone, Shield, AlertTriangle, CheckCircle, XCircle,
  RefreshCw, BarChart3, Lock, Activity,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

// ── Static config (badge colour maps — not domain data) ──

// ── Helpers ────────────────────────────────────────────────────

function SeverityBadge({ sev }: { sev: string }) {
  const cls =
    sev === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    sev === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    sev === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                         "border-border text-muted-foreground bg-muted/20";
  return <Badge className={cn("text-[10px] border", cls)}>{sev}</Badge>;
}

function PlatformBadge({ platform }: { platform: string }) {
  const cls =
    platform === "iOS"           ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
    platform === "Android"       ? "border-green-500/30 text-green-400 bg-green-500/10" :
                                   "border-slate-500/30 text-slate-400 bg-slate-500/10";
  return <Badge className={cn("text-[10px] border", cls)}>{platform}</Badge>;
}

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === "Active"       ? "border-red-500/30 text-red-400 bg-red-500/10" :
    status === "Investigating" ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    status === "Monitoring"   ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
                                "border-green-500/30 text-green-400 bg-green-500/10";
  return <Badge className={cn("text-[10px] border", cls)}>{status}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function MobileSecurity() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/edr/stats?org_id=${ORG_ID}`),
      apiFetch(`/edr/endpoints?org_id=${ORG_ID}&endpoint_type=mobile&limit=20`),
    ]).then(([statsRes, endpointsRes]) => {
      const stats     = statsRes.status     === "fulfilled" ? statsRes.value     : null;
      const endpoints = endpointsRes.status === "fulfilled" ? endpointsRes.value : null;
      // Map EDR endpoint shape to the device shape the template expects
      const devices = endpoints
        ? {
            count: endpoints.total ?? (Array.isArray(endpoints.endpoints) ? endpoints.endpoints.length : 0),
            devices: (Array.isArray(endpoints.endpoints) ? endpoints.endpoints : (Array.isArray(endpoints) ? endpoints : [])).map((e: any) => ({
              id: e.endpoint_id ?? e.id,
              device_name: e.hostname ?? e.device_name ?? e.name,
              platform: e.os_type ?? e.platform ?? "Unknown",
              os_version: e.os_version ?? "—",
              enrollment_status: e.enrollment_status ?? (e.is_managed ? "enrolled" : "pending"),
              compliance_status: e.compliance_status ?? (e.is_compliant ? "compliant" : "non_compliant"),
              risk_score: e.risk_score ?? 0,
              last_checkin: e.last_seen ?? e.last_checkin ?? "—",
            })),
          }
        : null;
      // Map EDR stats to mobile stats shape
      const mobileStats = stats
        ? {
            total_devices:   stats.total_endpoints ?? stats.total ?? 0,
            enrolled_count:  stats.managed_count   ?? stats.enrolled ?? 0,
            compliant_count: stats.compliant_count  ?? 0,
            active_threats:  stats.alert_count      ?? stats.active_threats ?? 0,
          }
        : null;
      if (mobileStats || devices) {
        setLiveData({ stats: mobileStats, devices, threats: null });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Mobile Security (MDM)"
        description="Device enrollment, compliance, and threat management"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Devices"  value={liveData?.stats?.total_devices  ?? liveData?.devices?.count ?? "—"} icon={Smartphone}   trend="up" />
        <KpiCard title="Enrolled"       value={liveData?.stats?.enrolled_count ?? "—"} icon={Shield}       trend="up" className="border-blue-500/20" />
        <KpiCard title="Compliant"      value={liveData?.stats?.compliant_count ?? "—"} icon={CheckCircle}  trend="up" className="border-green-500/20" />
        <KpiCard title="Active Threats" value={liveData?.stats?.active_threats  ?? liveData?.threats?.count ?? "—"} icon={AlertTriangle} trend="up" className="border-red-500/20" />
      </div>

      {/* Platform breakdown + Compliance trend */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Platform breakdown */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Smartphone className="h-4 w-4 text-blue-400" />
              Platform Breakdown
            </CardTitle>
            <CardDescription className="text-xs">Device distribution by operating system</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {(liveData?.stats?.platforms ?? []).length === 0 ? (
              <EmptyState icon={Smartphone} title="No platform data yet" description="Platform breakdown will appear once devices are enrolled." />
            ) : (liveData.stats.platforms as any[]).map((p: any) => {
              const pct: number = p.pct ?? p.percentage ?? 0;
              const label: string = p.label ?? p.platform ?? p.os_type ?? "Unknown";
              const count: number = p.count ?? 0;
              const colorMap: Record<string, string> = { iOS: "bg-blue-500", Android: "bg-green-500" };
              const textMap: Record<string, string> = { iOS: "text-blue-400", Android: "text-green-400" };
              const barColor = colorMap[label] ?? "bg-slate-500";
              const textColor = textMap[label] ?? "text-slate-400";
              return (
                <div key={label} className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <span className={cn("font-semibold", textColor)}>{label}</span>
                      <span className="text-muted-foreground text-[10px]">{count} devices</span>
                    </div>
                    <span className="font-bold tabular-nums">{pct}%</span>
                  </div>
                  <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${pct}%` }}
                      transition={{ duration: 0.8, ease: "easeOut" }}
                      className={cn("h-full rounded-full", barColor)}
                    />
                  </div>
                </div>
              );
            })}
            {liveData?.stats && (
              <div className="pt-2 text-[11px] text-muted-foreground border-t border-border/50">
                {liveData.stats.enrollment_rate != null ? `${liveData.stats.enrollment_rate}% enrollment rate` : ""}{liveData.stats.enrollment_rate != null && liveData.stats.compliance_rate != null ? " · " : ""}{liveData.stats.compliance_rate != null ? `${liveData.stats.compliance_rate}% compliance rate` : ""}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Compliance trend */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-purple-400" />
              Compliance Trend (6 months)
            </CardTitle>
            <CardDescription className="text-xs">Compliant vs non-compliant devices</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-3 h-36">
              {(liveData?.stats?.compliance_trend ?? []).length === 0 ? (
                <div className="flex-1 flex items-center justify-center">
                  <EmptyState icon={BarChart3} title="No trend data yet" description="Trend will appear after multiple compliance snapshots." />
                </div>
              ) : (liveData.stats.compliance_trend as any[]).map((m: any) => {
                const compliant: number = m.compliant ?? m.compliant_pct ?? 0;
                const non: number = m.non ?? m.non_compliant_pct ?? (100 - compliant);
                const month: string = m.month ?? m.label ?? "—";
                return (
                  <div key={month} className="flex-1 flex flex-col items-center gap-0.5">
                    <div className="w-full flex items-end gap-0.5 h-28">
                      <div className="flex-1 rounded-t bg-green-500/70 transition-all" style={{ height: `${compliant}%` }} title={`Compliant: ${compliant}%`} />
                      <div className="flex-1 rounded-t bg-red-500/70 transition-all" style={{ height: `${non}%` }} title={`Non-compliant: ${non}%`} />
                    </div>
                    <span className="text-[10px] text-muted-foreground">{month}</span>
                  </div>
                );
              })}
            </div>
            <div className="flex items-center gap-4 mt-3 text-[10px] text-muted-foreground">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-green-500/70 inline-block" />Compliant</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-red-500/70 inline-block" />Non-compliant</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Device table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Smartphone className="h-4 w-4 text-indigo-400" />
              Enrolled Devices
            </CardTitle>
            <Badge className="text-[10px] border border-indigo-500/30 text-indigo-400 bg-indigo-500/10">
              {liveData?.devices?.count ?? liveData?.devices?.devices?.length ?? 0} devices
            </Badge>
          </div>
          <CardDescription className="text-xs">All managed mobile devices with compliance status and risk score</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Device</TableHead>
                  <TableHead className="text-[11px] h-8">Platform</TableHead>
                  <TableHead className="text-[11px] h-8">OS Version</TableHead>
                  <TableHead className="text-[11px] h-8">Enrollment</TableHead>
                  <TableHead className="text-[11px] h-8">Compliant</TableHead>
                  <TableHead className="text-[11px] h-8">Risk</TableHead>
                  <TableHead className="text-[11px] h-8">Last Check-in</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.devices?.devices ?? []).length === 0 ? (
                  <TableRow><TableCell colSpan={8} className="py-6"><EmptyState icon={Smartphone} title="No devices enrolled yet" description="Devices will appear once mobile endpoints are registered." /></TableCell></TableRow>
                ) : (liveData.devices.devices as any[]).map((d: any, i: number) => {
                  const enrolledStatus = d.enrollment_status ?? d.enrolled ?? "Active";
                  const isCompliant = d.compliance_status === "compliant" || d.compliant === true;
                  const riskScore = d.risk_score ?? d.risk ?? 0;
                  return (
                  <TableRow key={d.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5 max-w-[160px] truncate">{d.device_name ?? d.name}</TableCell>
                    <TableCell className="py-2.5"><PlatformBadge platform={d.platform} /></TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{d.os_version ?? d.os}</TableCell>
                    <TableCell className="text-xs py-2.5">
                      <Badge className={cn("text-[10px] border",
                        enrolledStatus === "Active"  || enrolledStatus === "enrolled" ? "border-green-500/30 text-green-400 bg-green-500/10" :
                        enrolledStatus === "Pending" || enrolledStatus === "pending"  ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                                                   "border-border text-muted-foreground"
                      )}>{enrolledStatus}</Badge>
                    </TableCell>
                    <TableCell className="py-2.5">
                      {isCompliant
                        ? <CheckCircle className="h-4 w-4 text-green-400" />
                        : <XCircle className="h-4 w-4 text-red-400" />
                      }
                    </TableCell>
                    <TableCell className="py-2.5">
                      <span className={cn("text-xs font-bold tabular-nums",
                        riskScore >= 70 ? "text-red-400" : riskScore >= 40 ? "text-amber-400" : "text-green-400"
                      )}>{riskScore}</span>
                    </TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{d.last_checkin ?? d.lastSeen}</TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">Manage</Button>
                    </TableCell>
                  </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* MDM Policy cards */}
      <div>
        <h2 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <Lock className="h-4 w-4 text-amber-400" />
          MDM Policies
        </h2>
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          {(liveData?.policies ?? []).length === 0 ? (
            <div className="lg:col-span-3"><EmptyState icon={Lock} title="No MDM policies yet" description="Policies will appear once MDM configurations are loaded." /></div>
          ) : (liveData.policies as any[]).map((policy: any) => (
            <Card key={policy.name}>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-xs font-semibold">{policy.name}</CardTitle>
                  <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">Edit</Button>
                </div>
              </CardHeader>
              <CardContent className="space-y-2">
                {policy.rules.map((rule: any) => (
                  <div key={rule.label} className="flex items-center gap-2 text-xs">
                    {rule.enabled
                      ? <CheckCircle className="h-3.5 w-3.5 text-green-400 shrink-0" />
                      : <XCircle className="h-3.5 w-3.5 text-red-400 shrink-0" />
                    }
                    <span className={rule.enabled ? "text-foreground" : "text-muted-foreground line-through"}>
                      {rule.label}
                    </span>
                  </div>
                ))}
                <div className="pt-2 space-y-1">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-muted-foreground">Compliance</span>
                    <span className={cn("font-bold",
                      policy.compliance >= 90 ? "text-green-400" : policy.compliance >= 75 ? "text-yellow-400" : "text-red-400"
                    )}>{policy.compliance}%</span>
                  </div>
                  <div className="relative h-1.5 rounded-full bg-muted/30 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${policy.compliance}%` }}
                      transition={{ duration: 0.8, ease: "easeOut" }}
                      className={cn("h-full rounded-full",
                        policy.compliance >= 90 ? "bg-green-500" : policy.compliance >= 75 ? "bg-yellow-500" : "bg-red-500"
                      )}
                    />
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Active Threats feed */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <Activity className="h-4 w-4" />
              Active Threat Feed
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {(liveData?.threats?.threats ?? []).filter((t: any) => t.status === "Active" || t.status === "active").length} active
            </Badge>
          </div>
          <CardDescription className="text-xs">Recent mobile device security events requiring attention</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Device</TableHead>
                  <TableHead className="text-[11px] h-8">Threat Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Detected</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.threats?.threats ?? []).length === 0 ? (
                  <TableRow><TableCell colSpan={6} className="py-6"><EmptyState icon={Activity} title="No active threats" description="Mobile threat events will appear here once detected." /></TableCell></TableRow>
                ) : (liveData.threats.threats as any[]).map((t: any, i: number) => (
                  <TableRow key={t.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="text-xs py-2.5 max-w-[160px] truncate">{t.device_id ?? t.device}</TableCell>
                    <TableCell className="text-xs py-2.5">{t.threat_type ?? t.type}</TableCell>
                    <TableCell className="py-2.5"><SeverityBadge sev={t.severity} /></TableCell>
                    <TableCell className="py-2.5"><StatusBadge status={t.status} /></TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{t.detected_at ?? t.time}</TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] border-red-500/30 text-red-400 hover:bg-red-500/10">
                        Remediate
                      </Button>
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
