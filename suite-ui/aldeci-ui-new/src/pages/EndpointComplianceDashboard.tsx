// FOLDED into ComplianceCoverageHub (endpoint tab) at /comply/coverage 2026-05-02 — preserve for git history
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
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

const ORG_ID = "juice-shop-corp";

const apiFetch = async (path: string) => {
  const sep = path.includes("?") ? "&" : "?";
  const res = await fetch(buildApiUrl(`/api/v1${path}${sep}org_id=${ORG_ID}`), {
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": getStoredOrgId() },
  });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
};

// Mock data removed — page renders live data from /api/v1/endpoint-compliance/*

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
  const [stats, setStats] = useState<any | null>(null);
  const [endpoints, setEndpoints] = useState<any[]>([]);
  const [failedChecks, setFailedChecks] = useState<any[]>([]);
  const [deptCompliance, setDeptCompliance] = useState<any[]>([]);
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
    const norm = (v: any) => Array.isArray(v) ? v : (v?.items ?? []);
    if (statsRes.status === "fulfilled") setStats(statsRes.value); else setStats(null);
    setEndpoints(epRes.status === "fulfilled" ? norm(epRes.value) : []);
    setFailedChecks(chkRes.status === "fulfilled" ? norm(chkRes.value) : []);
    setDeptCompliance(deptRes.status === "fulfilled" ? norm(deptRes.value) : []);
    setLoading(false);
    setLastRefresh(new Date());
  };

  useEffect(() => { fetchAll(); }, []);

  if (loading && !stats) return <PageSkeleton />;

  const liveStats = stats ?? { total_endpoints: 0, by_compliance_level: { compliant: 0, partial: 0, non_compliant: 0 }, by_os_type: {}, avg_compliance_score: 0, endpoints_below_target: 0, critical_failures_total: 0, compliant_rate: 0 };
  const compliantCount = liveStats.by_compliance_level?.compliant ?? 0;
  const nonCompliantCount = liveStats.by_compliance_level?.non_compliant ?? 0;

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="Endpoint Compliance"
        description="CIS benchmark compliance posture across all managed endpoints"
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
            value={liveStats.total_endpoints ?? 0}
            icon={<Monitor className="h-4 w-4 text-purple-400" />}
            description={`${Object.values(liveStats.by_os_type ?? {}).length} OS types`}
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
            description={`${liveStats.critical_failures_total ?? 0} critical failures`}
            trend="down"
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
          <KpiCard
            title="Compliance Rate"
            value={`${(liveStats.compliant_rate ?? 0).toFixed(1)}%`}
            icon={<ShieldCheck className="h-4 w-4 text-amber-400" />}
            description={`Avg score: ${(liveStats.avg_compliance_score ?? 0).toFixed(1)}%`}
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
              {Object.entries(liveStats.by_os_type ?? {}).map(([os, count]) => {
                const total = liveStats.total_endpoints ?? 0;
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
                  <div className="text-xs text-slate-500">{liveStats.endpoints_below_target ?? 0} endpoints &lt; 80%</div>
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
                {endpoints
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
                {failedChecks.map((chk) => (
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
                {deptCompliance
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
