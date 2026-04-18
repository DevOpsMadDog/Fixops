/**
 * Endpoint Compliance Dashboard
 *
 * CIS benchmark compliance for endpoints (Windows / Linux / macOS / mobile).
 *   1. KPI cards: Total Endpoints, Compliant, Non-Compliant, Compliance Rate %
 *   2. Endpoints table with status badges and score bars
 *   3. Failed checks / violations list
 *   4. Department compliance breakdown
 *
 * API: GET /api/v1/endpoint-compliance/stats
 *      GET /api/v1/endpoint-compliance/endpoints
 *      GET /api/v1/endpoint-compliance/checks?status=failed
 *      GET /api/v1/endpoint-compliance/department-compliance
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Monitor,
  CheckCircle,
  XCircle,
  AlertTriangle,
  RefreshCw,
  BarChart3,
  ShieldCheck,
  Building2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helper ──────────────────────────────────────────────────────────────
const apiFetch = async (path: string) => {
  const key =
    localStorage.getItem("aldeci_api_key") ||
    import.meta.env.VITE_API_KEY ||
    "dev-key";
  const res = await fetch(`/api/v1${path}`, { headers: { "X-API-Key": key } });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
};

// ── Mock data ───────────────────────────────────────────────────────────────

const MOCK_STATS = {
  total_endpoints: 347,
  by_compliance_level: { compliant: 198, partial: 89, non_compliant: 60 },
  by_os_type: { windows: 180, linux: 112, macos: 55 },
  avg_compliance_score: 76.4,
  endpoints_below_target: 149,
  critical_failures_total: 42,
  compliant_rate: 57.1,
};

const MOCK_ENDPOINTS = [
  { id: "ep1",  hostname: "win-dc-01.corp",    os_type: "windows", os_version: "Server 2022", department: "Infrastructure", compliance_score: 94.2, compliance_level: "compliant",    critical_failures: 0, high_failures: 1, last_scan: "2026-04-16T06:00:00Z" },
  { id: "ep2",  hostname: "lin-web-02.prod",   os_type: "linux",   os_version: "Ubuntu 22.04", department: "Engineering",   compliance_score: 88.7, compliance_level: "compliant",    critical_failures: 0, high_failures: 2, last_scan: "2026-04-16T05:30:00Z" },
  { id: "ep3",  hostname: "mac-dev-07.local",  os_type: "macos",   os_version: "Sonoma 14.4", department: "Engineering",   compliance_score: 72.1, compliance_level: "partial",      critical_failures: 1, high_failures: 4, last_scan: "2026-04-15T22:00:00Z" },
  { id: "ep4",  hostname: "win-ws-142.corp",   os_type: "windows", os_version: "11 Pro",       department: "Finance",       compliance_score: 65.3, compliance_level: "partial",      critical_failures: 2, high_failures: 6, last_scan: "2026-04-15T18:00:00Z" },
  { id: "ep5",  hostname: "lin-db-04.prod",    os_type: "linux",   os_version: "RHEL 9.2",     department: "Database",      compliance_score: 91.0, compliance_level: "compliant",    critical_failures: 0, high_failures: 0, last_scan: "2026-04-16T04:00:00Z" },
  { id: "ep6",  hostname: "win-legacy-03.corp",os_type: "windows", os_version: "Server 2012 R2", department: "IT",         compliance_score: 38.4, compliance_level: "non_compliant", critical_failures: 5, high_failures: 9, last_scan: "2026-04-14T08:00:00Z" },
  { id: "ep7",  hostname: "mac-hr-12.local",   os_type: "macos",   os_version: "Ventura 13.6", department: "HR",           compliance_score: 59.7, compliance_level: "partial",      critical_failures: 2, high_failures: 5, last_scan: "2026-04-15T14:00:00Z" },
  { id: "ep8",  hostname: "lin-build-01.ci",   os_type: "linux",   os_version: "Ubuntu 20.04", department: "Engineering",  compliance_score: 44.2, compliance_level: "non_compliant", critical_failures: 4, high_failures: 7, last_scan: "2026-04-15T10:00:00Z" },
];

const MOCK_FAILED_CHECKS = [
  { id: "chk1", endpoint_id: "ep6", check_id: "CIS-1.1.1", check_name: "Password must meet complexity",    benchmark: "cis_windows_l1", category: "account_policy", severity: "critical", status: "failed", remediation: "Enable Windows Password Complexity policy" },
  { id: "chk2", endpoint_id: "ep8", check_id: "CIS-4.2.1", check_name: "SSH Protocol version 2 enforced", benchmark: "cis_ubuntu",     category: "network",        severity: "critical", status: "failed", remediation: "Set Protocol 2 in /etc/ssh/sshd_config" },
  { id: "chk3", endpoint_id: "ep3", check_id: "CIS-2.3.1", check_name: "Bluetooth disabled",               benchmark: "cis_macos",      category: "service",        severity: "high",    status: "failed", remediation: "Disable Bluetooth via MDM profile" },
  { id: "chk4", endpoint_id: "ep4", check_id: "CIS-1.2.3", check_name: "Account lockout threshold 5",     benchmark: "cis_windows_l1", category: "account_policy", severity: "high",    status: "failed", remediation: "Set lockout threshold to 5 failed attempts" },
  { id: "chk5", endpoint_id: "ep6", check_id: "CIS-9.1.1", check_name: "Windows Firewall enabled",        benchmark: "cis_windows_l1", category: "firewall",       severity: "critical", status: "failed", remediation: "Enable Windows Defender Firewall on all profiles" },
  { id: "chk6", endpoint_id: "ep8", check_id: "CIS-3.1.1", check_name: "IPv6 disabled if not required",  benchmark: "cis_ubuntu",     category: "network",        severity: "medium",  status: "failed", remediation: "Disable IPv6 in /etc/sysctl.conf if unused" },
  { id: "chk7", endpoint_id: "ep7", check_id: "CIS-2.1.2", check_name: "FTP service disabled",           benchmark: "cis_macos",      category: "service",        severity: "high",    status: "failed", remediation: "Disable FTP service via macOS Sharing settings" },
];

const MOCK_DEPT_COMPLIANCE = [
  { department: "Infrastructure", total_endpoints: 45, compliant: 38, partial: 5,  non_compliant: 2,  avg_compliance_score: 92.1, compliant_rate: 84.4, critical_failures: 2 },
  { department: "Engineering",    total_endpoints: 112, compliant: 67, partial: 31, non_compliant: 14, avg_compliance_score: 78.3, compliant_rate: 59.8, critical_failures: 8 },
  { department: "Finance",        total_endpoints: 38, compliant: 19, partial: 12, non_compliant: 7,  avg_compliance_score: 69.2, compliant_rate: 50.0, critical_failures: 7 },
  { department: "HR",             total_endpoints: 29, compliant: 14, partial: 11, non_compliant: 4,  avg_compliance_score: 71.5, compliant_rate: 48.3, critical_failures: 5 },
  { department: "Database",       total_endpoints: 22, compliant: 20, partial: 2,  non_compliant: 0,  avg_compliance_score: 93.8, compliant_rate: 90.9, critical_failures: 0 },
  { department: "IT",             total_endpoints: 61, compliant: 18, partial: 21, non_compliant: 22, avg_compliance_score: 58.6, compliant_rate: 29.5, critical_failures: 14 },
];

// ── Helpers ─────────────────────────────────────────────────────────────────

const OS_ICONS: Record<string, string> = {
  windows: "🪟", linux: "🐧", macos: "🍎", android: "🤖", ios: "📱",
};

function levelBadge(level: string) {
  const map: Record<string, string> = {
    compliant:     "bg-green-500/20 text-green-300 border-green-500/30",
    partial:       "bg-amber-500/20 text-amber-300 border-amber-500/30",
    non_compliant: "bg-red-500/20 text-red-300 border-red-500/30",
  };
  return map[level] ?? map.non_compliant;
}

function levelLabel(level: string) {
  const map: Record<string, string> = {
    compliant: "Compliant", partial: "Partial", non_compliant: "Non-Compliant",
  };
  return map[level] ?? level;
}

function scoreColor(score: number) {
  if (score >= 90) return "text-green-400";
  if (score >= 70) return "text-amber-400";
  return "text-red-400";
}

function scoreBgBar(score: number) {
  if (score >= 90) return "bg-green-500";
  if (score >= 70) return "bg-amber-500";
  return "bg-red-500";
}

function severityBadge(sev: string) {
  const map: Record<string, string> = {
    critical: "bg-red-500/20 text-red-300 border-red-500/30",
    high:     "bg-orange-500/20 text-orange-300 border-orange-500/30",
    medium:   "bg-amber-500/20 text-amber-300 border-amber-500/30",
    low:      "bg-blue-500/20 text-blue-300 border-blue-500/30",
  };
  return map[sev] ?? map.medium;
}

function benchmarkLabel(b: string) {
  const map: Record<string, string> = {
    cis_windows_l1: "CIS Win L1",
    cis_windows_l2: "CIS Win L2",
    cis_ubuntu:     "CIS Ubuntu",
    cis_rhel:       "CIS RHEL",
    cis_macos:      "CIS macOS",
    stig_win:       "STIG Win",
    disa_stig:      "DISA STIG",
  };
  return map[b] ?? b;
}

// ── Component ─────────────────────────────────────────────────────────────

export default function EndpointComplianceDashboard() {
  const [stats, setStats] = useState<typeof MOCK_STATS | null>(null);
  const [endpoints, setEndpoints] = useState<typeof MOCK_ENDPOINTS>([]);
  const [failedChecks, setFailedChecks] = useState<typeof MOCK_FAILED_CHECKS>([]);
  const [deptCompliance, setDeptCompliance] = useState<typeof MOCK_DEPT_COMPLIANCE>([]);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(new Date());

  const fetchAll = async () => {
    setLoading(true);
    const [statsRes, epRes, chkRes, deptRes] = await Promise.allSettled([
      apiFetch("/endpoint-compliance/stats"),
      apiFetch("/endpoint-compliance/endpoints"),
      apiFetch("/endpoint-compliance/checks?status=failed"),
      apiFetch("/endpoint-compliance/department-compliance"),
    ]);
    if (statsRes.status === "fulfilled") setStats(statsRes.value);
    else setStats(MOCK_STATS);
    if (epRes.status === "fulfilled" && Array.isArray(epRes.value)) setEndpoints(epRes.value);
    else setEndpoints(MOCK_ENDPOINTS);
    if (chkRes.status === "fulfilled" && Array.isArray(chkRes.value)) setFailedChecks(chkRes.value);
    else setFailedChecks(MOCK_FAILED_CHECKS);
    if (deptRes.status === "fulfilled" && Array.isArray(deptRes.value)) setDeptCompliance(deptRes.value);
    else setDeptCompliance(MOCK_DEPT_COMPLIANCE);
    setLoading(false);
    setLastRefresh(new Date());
  };

  useEffect(() => { fetchAll(); }, []);

  const liveStats = stats ?? MOCK_STATS;
  const compliantCount = liveStats.by_compliance_level?.compliant ?? MOCK_STATS.by_compliance_level.compliant;
  const nonCompliantCount = liveStats.by_compliance_level?.non_compliant ?? MOCK_STATS.by_compliance_level.non_compliant;

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="Endpoint Compliance"
        description="CIS benchmark compliance posture across all managed endpoints"
        icon={<Monitor className="h-6 w-6 text-purple-400" />}
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

      {/* KPI Cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}>
          <KpiCard
            title="Total Endpoints"
            value={liveStats.total_endpoints ?? MOCK_STATS.total_endpoints}
            icon={<Monitor className="h-4 w-4 text-purple-400" />}
            description={`${Object.values(liveStats.by_os_type ?? MOCK_STATS.by_os_type).length} OS types`}
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
          <KpiCard
            title="Compliant"
            value={compliantCount}
            icon={<CheckCircle className="h-4 w-4 text-green-400" />}
            description="Score >= 90%"
            trend="up"
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
          <KpiCard
            title="Non-Compliant"
            value={nonCompliantCount}
            icon={<XCircle className="h-4 w-4 text-red-400" />}
            description={`${liveStats.critical_failures_total ?? MOCK_STATS.critical_failures_total} critical failures`}
            trend="down"
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
          <KpiCard
            title="Compliance Rate"
            value={`${(liveStats.compliant_rate ?? MOCK_STATS.compliant_rate).toFixed(1)}%`}
            icon={<ShieldCheck className="h-4 w-4 text-amber-400" />}
            description={`Avg score: ${(liveStats.avg_compliance_score ?? MOCK_STATS.avg_compliance_score).toFixed(1)}%`}
          />
        </motion.div>
      </div>

      {/* OS Type Distribution */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.22 }}>
        <Card className="border-slate-700 bg-slate-900/50">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-slate-200">
              <BarChart3 className="h-4 w-4 text-purple-400" />
              Endpoint Distribution by OS
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-4">
              {Object.entries(liveStats.by_os_type ?? MOCK_STATS.by_os_type).map(([os, count]) => {
                const total = liveStats.total_endpoints ?? MOCK_STATS.total_endpoints;
                const pct = total > 0 ? Math.round(((count as number) / total) * 100) : 0;
                return (
                  <div key={os} className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/40 px-3 py-2">
                    <span className="text-lg">{OS_ICONS[os] ?? "💻"}</span>
                    <div>
                      <div className="text-xs font-medium text-slate-200 capitalize">{os}</div>
                      <div className="text-xs text-slate-500">{count as number} endpoints ({pct}%)</div>
                    </div>
                  </div>
                );
              })}
              <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2">
                <AlertTriangle className="h-4 w-4 text-amber-400" />
                <div>
                  <div className="text-xs font-medium text-amber-300">Below Target</div>
                  <div className="text-xs text-slate-500">{liveStats.endpoints_below_target ?? MOCK_STATS.endpoints_below_target} endpoints &lt; 80%</div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Endpoints Table */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.28 }}>
        <Card className="border-slate-700 bg-slate-900/50">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-slate-200">
              <Monitor className="h-4 w-4 text-purple-400" />
              Managed Endpoints
            </CardTitle>
            <CardDescription className="text-xs text-slate-500">
              Sorted by compliance score (lowest first)
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow className="border-slate-700">
                  <TableHead className="text-slate-400 text-xs">Hostname</TableHead>
                  <TableHead className="text-slate-400 text-xs">OS</TableHead>
                  <TableHead className="text-slate-400 text-xs">Department</TableHead>
                  <TableHead className="text-slate-400 text-xs">Status</TableHead>
                  <TableHead className="text-slate-400 text-xs">Critical</TableHead>
                  <TableHead className="text-slate-400 text-xs">Score</TableHead>
                  <TableHead className="text-slate-400 text-xs">Last Scan</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(endpoints.length > 0 ? endpoints : MOCK_ENDPOINTS)
                  .slice()
                  .sort((a, b) => a.compliance_score - b.compliance_score)
                  .map((ep) => (
                  <TableRow key={ep.id} className="border-slate-800 hover:bg-slate-800/40">
                    <TableCell className="font-mono text-xs text-slate-300">{ep.hostname}</TableCell>
                    <TableCell className="text-xs text-slate-400">
                      {OS_ICONS[ep.os_type] ?? "💻"} {ep.os_type}
                    </TableCell>
                    <TableCell className="text-xs text-slate-400">{ep.department || "—"}</TableCell>
                    <TableCell>
                      <Badge className={cn("text-xs border", levelBadge(ep.compliance_level))}>
                        {levelLabel(ep.compliance_level)}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs">
                      {ep.critical_failures > 0 ? (
                        <span className="text-red-400 font-medium">{ep.critical_failures}</span>
                      ) : (
                        <span className="text-green-400">0</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <div className="w-16 rounded-full bg-slate-800 h-1.5 overflow-hidden">
                          <div
                            className={cn("h-full rounded-full", scoreBgBar(ep.compliance_score))}
                            style={{ width: `${ep.compliance_score}%` }}
                          />
                        </div>
                        <span className={cn("text-xs font-semibold", scoreColor(ep.compliance_score))}>
                          {ep.compliance_score.toFixed(0)}%
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-slate-500">
                      {ep.last_scan ? new Date(ep.last_scan).toLocaleDateString() : "Never"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </motion.div>

      {/* Failed Checks + Department Compliance side-by-side */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        {/* Failed Checks */}
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }}>
          <Card className="border-slate-700 bg-slate-900/50 h-full">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-sm font-medium text-slate-200">
                <XCircle className="h-4 w-4 text-red-400" />
                Policy Violations
              </CardTitle>
              <CardDescription className="text-xs text-slate-500">
                {failedChecks.length} failed checks across endpoints
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {(failedChecks.length > 0 ? failedChecks : MOCK_FAILED_CHECKS).map((chk) => (
                  <div
                    key={chk.id}
                    className={cn(
                      "rounded-lg border p-3 text-xs",
                      chk.severity === "critical"
                        ? "border-red-500/30 bg-red-500/5"
                        : chk.severity === "high"
                        ? "border-orange-500/30 bg-orange-500/5"
                        : "border-slate-700 bg-slate-800/30"
                    )}
                  >
                    <div className="flex items-start justify-between gap-2 mb-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-slate-400">{chk.check_id}</span>
                        <Badge className={cn("text-xs border", severityBadge(chk.severity))}>
                          {chk.severity}
                        </Badge>
                        <Badge variant="outline" className="text-xs text-slate-500 border-slate-600">
                          {benchmarkLabel(chk.benchmark)}
                        </Badge>
                      </div>
                    </div>
                    <p className="font-medium text-slate-200 mb-1">{chk.check_name}</p>
                    <p className="text-slate-500 line-clamp-2">{chk.remediation}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Department Compliance */}
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}>
          <Card className="border-slate-700 bg-slate-900/50 h-full">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-sm font-medium text-slate-200">
                <Building2 className="h-4 w-4 text-blue-400" />
                Department Compliance
              </CardTitle>
              <CardDescription className="text-xs text-slate-500">
                Compliance rates by business unit
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {(deptCompliance.length > 0 ? deptCompliance : MOCK_DEPT_COMPLIANCE)
                  .slice()
                  .sort((a, b) => a.avg_compliance_score - b.avg_compliance_score)
                  .map((dept) => (
                  <div key={dept.department} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-slate-300">{dept.department}</span>
                        <span className="text-slate-500">{dept.total_endpoints} endpoints</span>
                        {dept.critical_failures > 0 && (
                          <span className="text-red-400">{dept.critical_failures} critical</span>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={cn("font-semibold", scoreColor(dept.avg_compliance_score))}>
                          {dept.avg_compliance_score.toFixed(1)}%
                        </span>
                        <Badge className={cn(
                          "text-xs border",
                          dept.compliant_rate >= 80
                            ? "bg-green-500/20 text-green-300 border-green-500/30"
                            : dept.compliant_rate >= 50
                            ? "bg-amber-500/20 text-amber-300 border-amber-500/30"
                            : "bg-red-500/20 text-red-300 border-red-500/30"
                        )}>
                          {dept.compliant_rate.toFixed(0)}% compliant
                        </Badge>
                      </div>
                    </div>
                    <div className="flex gap-0.5 h-2 rounded overflow-hidden">
                      {dept.compliant > 0 && (
                        <div
                          className="bg-green-500 h-full"
                          style={{ width: `${(dept.compliant / dept.total_endpoints) * 100}%` }}
                          title={`${dept.compliant} compliant`}
                        />
                      )}
                      {dept.partial > 0 && (
                        <div
                          className="bg-amber-500 h-full"
                          style={{ width: `${(dept.partial / dept.total_endpoints) * 100}%` }}
                          title={`${dept.partial} partial`}
                        />
                      )}
                      {dept.non_compliant > 0 && (
                        <div
                          className="bg-red-500 h-full"
                          style={{ width: `${(dept.non_compliant / dept.total_endpoints) * 100}%` }}
                          title={`${dept.non_compliant} non-compliant`}
                        />
                      )}
                    </div>
                  </div>
                ))}
                {/* Legend */}
                <div className="flex items-center gap-4 pt-2 text-xs text-slate-500">
                  <div className="flex items-center gap-1"><span className="w-3 h-1.5 rounded bg-green-500 inline-block" /> Compliant</div>
                  <div className="flex items-center gap-1"><span className="w-3 h-1.5 rounded bg-amber-500 inline-block" /> Partial</div>
                  <div className="flex items-center gap-1"><span className="w-3 h-1.5 rounded bg-red-500 inline-block" /> Non-Compliant</div>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      <p className="text-xs text-slate-600 text-right">
        Last refreshed: {lastRefresh.toLocaleTimeString()}
      </p>
    </div>
  );
}
