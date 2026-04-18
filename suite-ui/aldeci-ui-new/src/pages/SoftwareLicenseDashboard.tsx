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

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

const MOCK_STATS = {
  total_packages: 412,
  unapproved_packages: 18,
  open_violations: 11,
  critical_violations: 3,
};

const MOCK_RISK_BREAKDOWN = { critical: 3, high: 8, medium: 21, low: 380 };

const MOCK_RECORDS = [
  { id: "lic-001", package_name: "log4j-core",        version: "2.14.1", license_type: "Apache-2.0", risk: "critical", is_oss: true,  vulnerabilities: 4, approved: false },
  { id: "lic-002", package_name: "openssl",            version: "1.1.1",  license_type: "OpenSSL",   risk: "high",     is_oss: true,  vulnerabilities: 2, approved: true  },
  { id: "lic-003", package_name: "lodash",             version: "4.17.21",license_type: "MIT",        risk: "medium",   is_oss: true,  vulnerabilities: 1, approved: true  },
  { id: "lic-004", package_name: "proprietary-sdk",   version: "3.0.0",  license_type: "Proprietary",risk: "low",      is_oss: false, vulnerabilities: 0, approved: true  },
  { id: "lic-005", package_name: "gpl-component",     version: "2.1.0",  license_type: "GPL-3.0",   risk: "high",     is_oss: true,  vulnerabilities: 0, approved: false },
  { id: "lic-006", package_name: "express",            version: "4.18.2", license_type: "MIT",        risk: "low",      is_oss: true,  vulnerabilities: 0, approved: true  },
];

const MOCK_VIOLATIONS = [
  { id: "vio-001", record_id: "lic-001", violation_type: "critical_vulnerability", severity: "critical", status: "open"      },
  { id: "vio-002", record_id: "lic-005", violation_type: "license_incompatibility",severity: "high",     status: "open"      },
  { id: "vio-003", record_id: "lic-002", violation_type: "unapproved_license",     severity: "medium",   status: "waived"    },
];

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

const recordMap = Object.fromEntries(MOCK_RECORDS.map((r) => [r.id, r.package_name]));

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

  const stats      = liveData.stats      ?? MOCK_STATS;
  const records    = liveData.records    ?? MOCK_RECORDS;
  const violations = liveData.violations ?? MOCK_VIOLATIONS;

  const breakdown = MOCK_RISK_BREAKDOWN;

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
                {records.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  records.map((r: any, i: number) => (
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
                ))
              )}
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
                {violations.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  violations.map((v: any, i: number) => (
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
