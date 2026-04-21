/**
 * Vulnerability Risk Queue
 *
 * Prioritized remediation backlog with composite risk scoring.
 *   1. KPIs: Critical Queue, High Queue, Avg Risk Score, SLA at Risk
 *   2. Priority queue table (15 rows) — CVE, asset, CVSS, EPSS, KEV, composite, team, status, SLA
 *   3. Risk distribution chart — horizontal bars Critical/High/Medium/Low/Info
 *   4. Team workload table — assigned, overdue, avg resolution time
 *   5. Risk acceptance panel — 8 risks in review with Approve/Reject
 *
 * API stubs: GET /api/v1/vulns/queue, /api/v1/vulns/distribution, /api/v1/vulns/risk-acceptance
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  AlertTriangle,
  Clock,
  Shield,
  Users,
  RefreshCw,
  CheckCircle2,
  XCircle,
  TrendingUp,
  BarChart3,
} from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "default";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const QUEUE = [
  { cve: "CVE-2025-29927", asset: "api-gateway-prod",   cvss: 9.8, epss: 0.94, kev: true,  composite: 9.7, team: "AppSec",   status: "open",        sla: "2026-04-16" },
  { cve: "CVE-2024-38856", asset: "auth-service-01",    cvss: 9.6, epss: 0.91, kev: true,  composite: 9.5, team: "AppSec",   status: "in-progress", sla: "2026-04-16" },
  { cve: "CVE-2025-21298", asset: "k8s-master-node",    cvss: 9.4, epss: 0.88, kev: false, composite: 9.1, team: "InfraSec", status: "open",        sla: "2026-04-17" },
  { cve: "CVE-2024-49113", asset: "ldap-server-01",     cvss: 9.0, epss: 0.82, kev: true,  composite: 9.0, team: "IAM Team", status: "open",        sla: "2026-04-17" },
  { cve: "CVE-2025-24813", asset: "web-proxy-prod",     cvss: 8.8, epss: 0.79, kev: false, composite: 8.6, team: "NetSec",   status: "in-progress", sla: "2026-04-18" },
  { cve: "CVE-2024-37085", asset: "vsphere-host-02",    cvss: 8.7, epss: 0.76, kev: true,  composite: 8.7, team: "CloudOps", status: "open",        sla: "2026-04-18" },
  { cve: "CVE-2025-0282",  asset: "vpn-gateway-ext",    cvss: 8.5, epss: 0.71, kev: true,  composite: 8.5, team: "NetSec",   status: "open",        sla: "2026-04-19" },
  { cve: "CVE-2024-50603", asset: "jenkins-build-01",   cvss: 8.3, epss: 0.68, kev: false, composite: 8.1, team: "DevSec",   status: "accepted",    sla: "2026-04-20" },
  { cve: "CVE-2025-24200", asset: "mobile-api-gw",      cvss: 8.1, epss: 0.62, kev: false, composite: 7.9, team: "AppSec",   status: "in-progress", sla: "2026-04-20" },
  { cve: "CVE-2024-41713", asset: "voip-pbx-01",        cvss: 7.9, epss: 0.58, kev: true,  composite: 7.9, team: "NetSec",   status: "open",        sla: "2026-04-21" },
  { cve: "CVE-2025-21333", asset: "hyperv-host-03",     cvss: 7.8, epss: 0.54, kev: false, composite: 7.6, team: "InfraSec", status: "open",        sla: "2026-04-22" },
  { cve: "CVE-2024-47076", asset: "print-server-01",    cvss: 7.5, epss: 0.49, kev: false, composite: 7.2, team: "InfraSec", status: "resolved",    sla: "2026-04-23" },
  { cve: "CVE-2025-26633", asset: "dc-windows-01",      cvss: 7.3, epss: 0.44, kev: false, composite: 7.0, team: "IAM Team", status: "in-progress", sla: "2026-04-24" },
  { cve: "CVE-2024-20767", asset: "coldfusion-app",     cvss: 7.1, epss: 0.41, kev: true,  composite: 7.1, team: "AppSec",   status: "open",        sla: "2026-04-25" },
  { cve: "CVE-2025-23006", asset: "sonicwall-fw-01",    cvss: 7.0, epss: 0.38, kev: true,  composite: 7.0, team: "NetSec",   status: "open",        sla: "2026-04-26" },
];

const DISTRIBUTION = [
  { label: "Critical", count: 47,  color: "bg-red-500",    text: "text-red-400",    max: 47 },
  { label: "High",     count: 124, color: "bg-amber-500",  text: "text-amber-400",  max: 124 },
  { label: "Medium",   count: 213, color: "bg-yellow-500", text: "text-yellow-400", max: 213 },
  { label: "Low",      count: 89,  color: "bg-blue-500",   text: "text-blue-400",   max: 213 },
  { label: "Info",     count: 31,  color: "bg-muted",      text: "text-muted-foreground", max: 213 },
];

const TEAMS = [
  { name: "AppSec",   assigned: 58, overdue: 9,  avgResolution: "4.1d" },
  { name: "CloudOps", assigned: 34, overdue: 4,  avgResolution: "3.2d" },
  { name: "InfraSec", assigned: 41, overdue: 6,  avgResolution: "5.0d" },
  { name: "DevSec",   assigned: 22, overdue: 2,  avgResolution: "2.8d" },
  { name: "NetSec",   assigned: 37, overdue: 5,  avgResolution: "4.5d" },
];

const RISK_ACCEPTANCE = [
  { id: "RA-041", cve: "CVE-2024-50603", asset: "jenkins-build-01", risk: "High",   reason: "Isolated network segment, no internet exposure", requestor: "DevSec" },
  { id: "RA-042", cve: "CVE-2025-21333", asset: "hyperv-host-03",   risk: "High",   reason: "Compensating control: IDS/IPS active on segment",  requestor: "InfraSec" },
  { id: "RA-043", cve: "CVE-2024-12693", asset: "legacy-erp-01",    risk: "Medium", reason: "Vendor EOL — migration planned Q3 2026",           requestor: "CloudOps" },
  { id: "RA-044", cve: "CVE-2025-1974",  asset: "nginx-ingress",    risk: "Medium", reason: "WAF rule active, patch in next maintenance window", requestor: "NetSec" },
  { id: "RA-045", cve: "CVE-2024-47076", asset: "print-server-01",  risk: "Medium", reason: "Air-gapped VLAN, no remote access",                 requestor: "InfraSec" },
  { id: "RA-046", cve: "CVE-2025-24085", asset: "ios-mdm-server",   risk: "Low",    reason: "Not exploitable in current config",                 requestor: "IAM Team" },
  { id: "RA-047", cve: "CVE-2024-38063", asset: "ipv6-stack",       risk: "Low",    reason: "IPv6 disabled on all affected hosts",               requestor: "NetSec" },
  { id: "RA-048", cve: "CVE-2025-0411",  asset: "7-zip-workstations",risk: "Low",   reason: "EDR detects and blocks exploitation attempt",      requestor: "DevSec" },
];

// ── Helpers ────────────────────────────────────────────────────

function SeverityBadge({ sev }: { sev: string }) {
  const cls =
    sev === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    sev === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    sev === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                         "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{sev}</Badge>;
}

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === "open"        ? "border-red-500/30 text-red-400 bg-red-500/10" :
    status === "in-progress" ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
    status === "accepted"    ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
                               "border-green-500/30 text-green-400 bg-green-500/10";
  return <Badge className={cn("text-[10px] border", cls)}>{status}</Badge>;
}

function CvssScore({ score }: { score: number }) {
  const color = score >= 9 ? "text-red-400" : score >= 7 ? "text-amber-400" : "text-yellow-400";
  return <span className={cn("font-bold tabular-nums text-xs", color)}>{score.toFixed(1)}</span>;
}

// ── Component ──────────────────────────────────────────────────

export default function VulnRiskQueue() {
  const [refreshing, setRefreshing] = useState(false);
  const [accepted, setAccepted] = useState<Set<string>>(new Set());
  const [rejected, setRejected] = useState<Set<string>>(new Set());
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/vuln-prioritization/scored?org_id=${ORG_ID}&limit=50`),
      apiFetch(`/api/v1/vuln-prioritization/stats?org_id=${ORG_ID}`),
    ]).then(([scoredResult, statsResult]) => {
      const scored = scoredResult.status === "fulfilled" ? scoredResult.value : null;
      const stats  = statsResult.status  === "fulfilled" ? statsResult.value  : null;
      if (scored || stats) {
        setLiveData({ scored, stats });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  const distMax = Math.max(...DISTRIBUTION.map((d) => d.count));

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Vulnerability Risk Queue"
        description="Prioritized remediation backlog"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Critical Queue"  value={liveData?.stats?.by_tier?.critical ?? liveData?.stats?.critical_count ?? 47}                                                                                              icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="High Queue"      value={liveData?.stats?.by_tier?.high ?? liveData?.stats?.high_count ?? 124}                                                                                                     icon={TrendingUp}    trend="up"   className="border-amber-500/20" />
        <KpiCard title="Avg Risk Score"  value={liveData?.stats?.avg_priority_score != null ? `${Number(liveData.stats.avg_priority_score).toFixed(1)}/10` : liveData?.stats?.avg_score != null ? `${Number(liveData.stats.avg_score).toFixed(1)}/10` : "7.8/10"} icon={Shield}        trend="down" className="border-purple-500/20" />
        <KpiCard title="SLA at Risk"     value={liveData?.stats?.sla_breached ?? liveData?.stats?.sla_at_risk ?? 23}                                                                                                      icon={Clock}         trend="up"   className="border-yellow-500/20" />
      </div>

      {/* Priority queue table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-red-400" />
              Priority Queue
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">{(liveData?.scored ?? QUEUE).length} items</Badge>
          </div>
          <CardDescription className="text-xs">Sorted by composite risk score — CVSS × EPSS × KEV weighting</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">CVE</TableHead>
                  <TableHead className="text-[11px] h-8">Asset</TableHead>
                  <TableHead className="text-[11px] h-8">CVSS</TableHead>
                  <TableHead className="text-[11px] h-8">EPSS</TableHead>
                  <TableHead className="text-[11px] h-8">KEV</TableHead>
                  <TableHead className="text-[11px] h-8">Composite</TableHead>
                  <TableHead className="text-[11px] h-8">Team</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">SLA</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.scored ?? QUEUE).map((row: any) => {
                  const cve       = row.cve ?? row.cve_id;
                  const asset     = row.asset ?? row.asset_id;
                  const cvss      = row.cvss ?? row.cvss_score ?? 0;
                  const epss      = row.epss ?? row.epss_score ?? 0;
                  const kev       = row.kev ?? row.kev_listed ?? false;
                  const composite = row.composite ?? row.priority_score ?? 0;
                  const team      = row.team ?? row.assigned_team ?? "—";
                  const status    = row.status ?? "open";
                  const sla       = row.sla ?? row.sla_due ?? row.due_date ?? "—";
                  return (
                  <TableRow key={cve ?? row.id} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2 text-blue-400">{cve}</TableCell>
                    <TableCell className="text-xs py-2 font-medium">{asset}</TableCell>
                    <TableCell className="py-2"><CvssScore score={cvss} /></TableCell>
                    <TableCell className="text-xs tabular-nums py-2 text-muted-foreground">{(epss * 100).toFixed(0)}%</TableCell>
                    <TableCell className="py-2">
                      {kev
                        ? <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">KEV</Badge>
                        : <span className="text-[10px] text-muted-foreground">—</span>
                      }
                    </TableCell>
                    <TableCell className="py-2">
                      <span className={cn("font-bold tabular-nums text-xs", composite >= 9 ? "text-red-400" : composite >= 8 ? "text-amber-400" : "text-yellow-400")}>
                        {Number(composite).toFixed(1)}
                      </span>
                    </TableCell>
                    <TableCell className="text-xs py-2 text-muted-foreground">{team}</TableCell>
                    <TableCell className="py-2"><StatusBadge status={status} /></TableCell>
                    <TableCell className="text-xs tabular-nums py-2 text-muted-foreground">{sla}</TableCell>
                  </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Risk distribution + Team workload */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Risk distribution */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-blue-400" />
              Risk Distribution
            </CardTitle>
            <CardDescription className="text-xs">Vulnerability count by severity tier</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {DISTRIBUTION.map((d) => (
              <div key={d.label} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className={cn("font-semibold", d.text)}>{d.label}</span>
                  <span className="tabular-nums font-bold">{d.count}</span>
                </div>
                <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${(d.count / distMax) * 100}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={cn("h-full rounded-full", d.color)}
                  />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Team workload */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Users className="h-4 w-4 text-indigo-400" />
              Team Workload
            </CardTitle>
            <CardDescription className="text-xs">Assigned vulnerabilities and resolution performance per team</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Team</TableHead>
                  <TableHead className="text-[11px] h-8">Assigned</TableHead>
                  <TableHead className="text-[11px] h-8">Overdue</TableHead>
                  <TableHead className="text-[11px] h-8">Avg Resolution</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {TEAMS.map((t) => (
                  <TableRow key={t.name} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5">{t.name}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 font-bold">{t.assigned}</TableCell>
                    <TableCell className={cn("text-xs tabular-nums py-2.5 font-semibold", t.overdue > 5 ? "text-red-400" : "text-amber-400")}>
                      {t.overdue}
                    </TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{t.avgResolution}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      {/* Risk acceptance panel */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Shield className="h-4 w-4 text-amber-400" />
              Risk Acceptance Queue
            </CardTitle>
            <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">
              {RISK_ACCEPTANCE.length} pending review
            </Badge>
          </div>
          <CardDescription className="text-xs">Formal risk acceptance requests awaiting CISO approval</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {RISK_ACCEPTANCE.map((r) => (
            <div
              key={r.id}
              className={cn(
                "flex items-center gap-3 rounded-lg border p-3",
                accepted.has(r.id) ? "border-green-500/30 bg-green-500/5 opacity-60" :
                rejected.has(r.id) ? "border-red-500/30 bg-red-500/5 opacity-60" :
                "border-border bg-muted/10"
              )}
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[10px] font-mono text-muted-foreground">{r.id}</span>
                  <span className="text-xs font-semibold font-mono text-blue-400">{r.cve}</span>
                  <SeverityBadge sev={r.risk} />
                  <span className="text-[10px] text-muted-foreground">— {r.asset}</span>
                </div>
                <p className="text-[10px] text-muted-foreground mt-1 truncate">{r.reason}</p>
                <p className="text-[10px] text-muted-foreground">Requested by: <span className="font-medium text-foreground">{r.requestor}</span></p>
              </div>
              <div className="flex items-center gap-1.5 flex-shrink-0">
                {accepted.has(r.id) ? (
                  <span className="text-[10px] text-green-400 font-semibold">Approved</span>
                ) : rejected.has(r.id) ? (
                  <span className="text-[10px] text-red-400 font-semibold">Rejected</span>
                ) : (
                  <>
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-6 px-2 text-[10px] border-green-500/30 text-green-400 hover:bg-green-500/10"
                      onClick={() => setAccepted((prev) => new Set([...prev, r.id]))}
                    >
                      <CheckCircle2 className="h-3 w-3 mr-1" />Approve
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-6 px-2 text-[10px] border-red-500/30 text-red-400 hover:bg-red-500/10"
                      onClick={() => setRejected((prev) => new Set([...prev, r.id]))}
                    >
                      <XCircle className="h-3 w-3 mr-1" />Reject
                    </Button>
                  </>
                )}
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </motion.div>
  );
}
