/**
 * Software License Security Dashboard
 *
 * OSS license compliance and vulnerability risk management.
 *   1. KPI cards: Total Packages, Unapproved, Open Violations, Critical Violations
 *   2. License Risk breakdown (4 count cards)
 *   3. License Records table
 *   4. Violations table
 *
 * API: GET /api/v1/license-security/{stats,records,violations}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { FileText, RefreshCw, XCircle, CheckCircle, AlertTriangle, Package } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, { headers: { "X-API-Key": API_KEY } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}


function RiskBadge({ risk }: { risk: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[risk] ?? "border-border text-muted-foreground")}>
      {risk}
    </Badge>
  );
}

function ViolationStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:       "border-red-500/30 text-red-400 bg-red-500/10",
    waived:     "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    remediated: "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

// recordMap is built from live records below in the component

export default function SoftwareLicenseDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{ stats: any | null; records: any[] | null; violations: any[] | null }>({
    stats: null, records: null, violations: null,
  });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/license-security/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/license-security/records?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/license-security/violations?org_id=${ORG_ID}`),
    ]).then(([statsRes, recordsRes, violationsRes]) => {
      setLiveData({
        stats:      statsRes.status      === "fulfilled" ? statsRes.value      : null,
        records:    recordsRes.status    === "fulfilled" ? recordsRes.value    : null,
        violations: violationsRes.status === "fulfilled" ? violationsRes.value : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats      = liveData.stats      ?? { total_packages: 0, unapproved_packages: 0, open_violations: 0, critical_violations: 0 };
  const records    = liveData.records    ?? [];
  const violations = liveData.violations ?? [];

  const recordMap: Record<string, string> = Object.fromEntries(
    records.map((r: any) => [r.id, r.package_name])
  );

  const breakdown = {
    critical: records.filter((r: any) => r.risk === "critical").length,
    high:     records.filter((r: any) => r.risk === "high").length,
    medium:   records.filter((r: any) => r.risk === "medium").length,
    low:      records.filter((r: any) => r.risk === "low").length,
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Software License Security"
        description="OSS license compliance and vulnerability risk management"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Packages"    value={stats.total_packages}    icon={Package}      trend="flat" />
        <KpiCard title="Unapproved"        value={stats.unapproved_packages} icon={XCircle}   trend="down" className="border-orange-500/20" />
        <KpiCard title="Open Violations"   value={stats.open_violations}   icon={AlertTriangle} trend="down" className="border-red-500/20" />
        <KpiCard title="Critical Violations" value={stats.critical_violations} icon={FileText} trend="down" className="border-red-500/20" />
      </div>

      {/* Risk Breakdown */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Card className="border-red-500/30">
          <CardContent className="pt-4 pb-3 text-center">
            <div className="text-2xl font-bold text-red-400">{breakdown.critical}</div>
            <div className="text-[11px] text-muted-foreground mt-1">Critical Risk</div>
          </CardContent>
        </Card>
        <Card className="border-orange-500/30">
          <CardContent className="pt-4 pb-3 text-center">
            <div className="text-2xl font-bold text-orange-400">{breakdown.high}</div>
            <div className="text-[11px] text-muted-foreground mt-1">High Risk</div>
          </CardContent>
        </Card>
        <Card className="border-yellow-500/30">
          <CardContent className="pt-4 pb-3 text-center">
            <div className="text-2xl font-bold text-yellow-400">{breakdown.medium}</div>
            <div className="text-[11px] text-muted-foreground mt-1">Medium Risk</div>
          </CardContent>
        </Card>
        <Card className="border-green-500/30">
          <CardContent className="pt-4 pb-3 text-center">
            <div className="text-2xl font-bold text-green-400">{breakdown.low}</div>
            <div className="text-[11px] text-muted-foreground mt-1">Low Risk</div>
          </CardContent>
        </Card>
      </div>

      {/* License Records Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Package className="h-4 w-4 text-blue-400" />
              License Records
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {records.length} packages
            </Badge>
          </div>
          <CardDescription className="text-xs">Package license types, risk levels, and approval status</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Package Name</TableHead>
                  <TableHead className="text-[11px] h-8">Version</TableHead>
                  <TableHead className="text-[11px] h-8">License</TableHead>
                  <TableHead className="text-[11px] h-8">Risk</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">OSS</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Vulns</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Approved</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {records.map((r: any, i: number) => (
                  <TableRow key={r.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[12px] font-medium font-mono">{r.package_name}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground font-mono">{r.version}</TableCell>
                    <TableCell className="py-2">
                      <Badge className="text-[10px] border border-blue-500/30 text-blue-400 bg-blue-500/10 font-mono">
                        {r.license_type}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-2"><RiskBadge risk={r.risk ?? "low"} /></TableCell>
                    <TableCell className="py-2 text-center">
                      {r.is_oss
                        ? <CheckCircle className="h-3.5 w-3.5 text-green-400 inline" />
                        : <XCircle    className="h-3.5 w-3.5 text-gray-500 inline" />}
                    </TableCell>
                    <TableCell className="py-2 text-right text-[11px] font-mono">{r.vulnerabilities}</TableCell>
                    <TableCell className="py-2 text-center">
                      {r.approved
                        ? <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">✓ Approved</Badge>
                        : <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">✗ Not Approved</Badge>}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Violations Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              License Violations
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {violations.filter((v: any) => v.status === "open").length} open
            </Badge>
          </div>
          <CardDescription className="text-xs">Detected license compliance violations and remediation status</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Package</TableHead>
                  <TableHead className="text-[11px] h-8">Violation Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {violations.map((v: any, i: number) => (
                  <TableRow key={v.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[12px] font-mono">
                      {recordMap[v.record_id] ?? v.record_id ?? "N/A"}
                    </TableCell>
                    <TableCell className="py-2">
                      <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10 font-mono">
                        {(v.violation_type ?? "").replace(/_/g, " ")}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-2"><RiskBadge risk={v.severity ?? "medium"} /></TableCell>
                    <TableCell className="py-2"><ViolationStatusBadge status={v.status ?? "open"} /></TableCell>
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
