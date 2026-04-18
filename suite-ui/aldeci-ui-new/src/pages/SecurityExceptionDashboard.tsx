/**
 * SecurityExceptionDashboard
 *
 * Risk-accepted exceptions with approval workflows and expiry tracking.
 *   1. KPIs: Total Exceptions, Pending Approval, Expiring Soon, Critical Accepted
 *   2. Exception table — 12 rows
 *   3. Approval queue — 5 pending exceptions
 *   4. Expiring exceptions — 8 rows with countdown bar
 *   5. Stats panel — by_type bars + by_risk horizontal bars
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ShieldAlert, Clock, AlertTriangle, CheckCircle, XCircle, HelpCircle, RefreshCw, BarChart3 } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const ORG_ID = "default";

async function apiFetch(path: string) {
  const key =
    (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) ||
    import.meta.env.VITE_API_KEY ||
    "dev-key";
  const res = await fetch(`${API_BASE}/api/v1${path}`, { headers: { "X-API-Key": key } });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ───────────────────────────────────────────────────

const EXCEPTIONS = [
  { id: "EXC-001", title: "CVE-2025-1234 unpatched on air-gapped host", type: "vulnerability", risk: "critical", status: "approved",  requestor: "J. Smith",   expires: "2026-06-15", daysLeft: 60 },
  { id: "EXC-002", title: "Outbound SMTP without MTA-STS enforcement",  type: "policy",        risk: "high",     status: "approved",  requestor: "M. Patel",   expires: "2026-05-01", daysLeft: 15 },
  { id: "EXC-003", title: "Admin access without MFA on legacy system",   type: "access",        risk: "critical", status: "pending",   requestor: "R. Chen",    expires: "2026-07-01", daysLeft: 76 },
  { id: "EXC-004", title: "TLS 1.1 required for partner integration",    type: "config",        risk: "medium",   status: "approved",  requestor: "A. Torres",  expires: "2026-04-28", daysLeft: 12 },
  { id: "EXC-005", title: "PCI DSS 6.3.3 carve-out for legacy POS",     type: "compliance",    risk: "high",     status: "pending",   requestor: "K. Johnson", expires: "2026-08-01", daysLeft: 107 },
  { id: "EXC-006", title: "Shared service account credentials",          type: "access",        risk: "high",     status: "rejected",  requestor: "T. Wilson",  expires: "N/A",        daysLeft: -1 },
  { id: "EXC-007", title: "Self-signed cert on internal API gateway",    type: "config",        risk: "medium",   status: "approved",  requestor: "S. Davis",   expires: "2026-05-10", daysLeft: 24 },
  { id: "EXC-008", title: "SOC2 CC6.1 gap — physical access log gaps",  type: "compliance",    risk: "medium",   status: "pending",   requestor: "L. Brown",   expires: "2026-09-01", daysLeft: 138 },
  { id: "EXC-009", title: "Log4j 2.14 in isolated research sandbox",     type: "vulnerability", risk: "critical", status: "approved",  requestor: "N. Garcia",  expires: "2026-04-30", daysLeft: 14 },
  { id: "EXC-010", title: "Unencrypted backup to on-prem NAS",           type: "policy",        risk: "high",     status: "expired",   requestor: "P. Lee",     expires: "2026-04-10", daysLeft: -6 },
  { id: "EXC-011", title: "SSH password auth on jump server",            type: "config",        risk: "high",     status: "pending",   requestor: "C. Martinez",expires: "2026-06-01", daysLeft: 46 },
  { id: "EXC-012", title: "HIPAA audit control PHI access logging gap",  type: "compliance",    risk: "critical", status: "approved",  requestor: "E. Taylor",  expires: "2026-05-20", daysLeft: 34 },
];

const PENDING_QUEUE = [
  {
    id: "EXC-003",
    title: "Admin access without MFA on legacy system",
    risk: "critical",
    justification: "Legacy payroll system (EOL 2027) cannot support modern MFA protocols. Migration project approved and scheduled.",
    controls: "IP allowlisting, enhanced monitoring, quarterly access review",
    requestor: "R. Chen",
    team: "IT Operations",
  },
  {
    id: "EXC-005",
    title: "PCI DSS 6.3.3 carve-out for legacy POS",
    risk: "high",
    justification: "POS hardware refresh Q3 2026. Current devices cannot receive firmware updates. Isolated VLAN in place.",
    controls: "Network isolation, IDS rules, compensating SIEM alerts",
    requestor: "K. Johnson",
    team: "Retail Ops",
  },
  {
    id: "EXC-008",
    title: "SOC2 CC6.1 gap — physical access log gaps",
    risk: "medium",
    justification: "Badge system vendor EOL before replacement deployment. Manual log process documented.",
    controls: "Manual check-in log, security guard escort policy, CCTV coverage",
    requestor: "L. Brown",
    team: "Facilities",
  },
  {
    id: "EXC-011",
    title: "SSH password auth on jump server",
    risk: "high",
    justification: "Automated CI/CD pipeline requires password auth; key distribution causes build failures in current toolchain.",
    controls: "Vault-issued short-lived passwords, session recording, failed-login alerting",
    requestor: "C. Martinez",
    team: "Platform Eng",
  },
  {
    id: "EXC-015",
    title: "Container image with known medium CVEs in prod",
    risk: "medium",
    justification: "Upstream base image vendor has not released patch. Runtime WAF rules deployed as compensating control.",
    controls: "Runtime WAF, network policy egress block, weekly rescan schedule",
    requestor: "D. Robinson",
    team: "AppSec",
  },
];

const EXPIRING = [
  { id: "EXC-009", title: "Log4j 2.14 in isolated research sandbox",  risk: "critical", expires: "2026-04-30", daysLeft: 14 },
  { id: "EXC-004", title: "TLS 1.1 required for partner integration", risk: "medium",   expires: "2026-04-28", daysLeft: 12 },
  { id: "EXC-010", title: "Unencrypted backup to on-prem NAS",        risk: "high",     expires: "2026-04-10", daysLeft: -6 },
  { id: "EXC-002", title: "Outbound SMTP without MTA-STS",            risk: "high",     expires: "2026-05-01", daysLeft: 15 },
  { id: "EXC-007", title: "Self-signed cert on internal API gateway",  risk: "medium",   expires: "2026-05-10", daysLeft: 24 },
  { id: "EXC-012", title: "HIPAA audit control PHI access logging gap",risk: "critical", expires: "2026-05-20", daysLeft: 34 },
  { id: "EXC-011", title: "SSH password auth on jump server",          risk: "high",     expires: "2026-06-01", daysLeft: 46 },
  { id: "EXC-001", title: "CVE-2025-1234 unpatched on air-gapped host",risk: "critical", expires: "2026-06-15", daysLeft: 60 },
];

const TYPE_DIST = [
  { label: "Vulnerability", count: 3, color: "bg-red-500" },
  { label: "Policy",        count: 2, color: "bg-amber-500" },
  { label: "Compliance",    count: 3, color: "bg-purple-500" },
  { label: "Config",        count: 3, color: "bg-blue-500" },
  { label: "Access",        count: 2, color: "bg-orange-500" },
];
const TYPE_TOTAL = TYPE_DIST.reduce((s, t) => s + t.count, 0);

const RISK_DIST = [
  { label: "Critical", count: 4, color: "bg-red-500" },
  { label: "High",     count: 5, color: "bg-amber-500" },
  { label: "Medium",   count: 4, color: "bg-yellow-500" },
  { label: "Low",      count: 0, color: "bg-muted" },
];
const RISK_MAX = Math.max(...RISK_DIST.map((r) => r.count));

// ── Helpers ─────────────────────────────────────────────────────

function TypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    vulnerability: "border-red-500/30 text-red-400 bg-red-500/10",
    policy:        "border-amber-500/30 text-amber-400 bg-amber-500/10",
    compliance:    "border-purple-500/30 text-purple-400 bg-purple-500/10",
    config:        "border-blue-500/30 text-blue-400 bg-blue-500/10",
    access:        "border-orange-500/30 text-orange-400 bg-orange-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border text-muted-foreground")}>{type}</Badge>;
}

function RiskBadge({ risk }: { risk: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-border text-muted-foreground",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[risk] ?? "border-border text-muted-foreground")}>{risk}</Badge>;
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    pending:  "border-blue-500/30 text-blue-400 bg-blue-500/10",
    approved: "border-green-500/30 text-green-400 bg-green-500/10",
    rejected: "border-red-500/30 text-red-400 bg-red-500/10",
    expired:  "border-border text-muted-foreground",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>{status}</Badge>;
}

function DaysLeftCell({ days }: { days: number }) {
  if (days < 0) return <span className="text-xs font-bold text-red-500">Expired {Math.abs(days)}d ago</span>;
  const cls = days < 14 ? "text-red-400" : days < 30 ? "text-amber-400" : "text-muted-foreground";
  return <span className={cn("text-xs tabular-nums font-medium", cls)}>{days}d</span>;
}

function CountdownBar({ days }: { days: number }) {
  const capped = Math.max(0, Math.min(days, 30));
  const pct = (capped / 30) * 100;
  const color = days < 7 ? "bg-red-500" : days < 14 ? "bg-amber-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full bg-muted/30 overflow-hidden">
        <div className={cn("h-full rounded-full transition-all", color)} style={{ width: `${pct}%` }} />
      </div>
      <DaysLeftCell days={days} />
    </div>
  );
}

// ── Component ───────────────────────────────────────────────────

export default function SecurityExceptionDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  const loadData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/security-exceptions/list?org_id=${ORG_ID}&limit=50`),
      apiFetch(`/security-exceptions/stats?org_id=${ORG_ID}`),
    ]).then(([listResult, statsResult]) => {
      const list  = listResult.status  === "fulfilled" ? listResult.value  : null;
      const stats = statsResult.status === "fulfilled" ? statsResult.value : null;
      if (list || stats) {
        setLiveData({ list, stats });
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { loadData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    loadData();
    setTimeout(() => setRefreshing(false), 800);
  };

  // KPI values — live with mock fallback
  const totalExceptions  = liveData?.stats?.total_exceptions  ?? liveData?.list?.length ?? 47;
  const pendingApproval  = liveData?.stats?.pending_count     ?? liveData?.stats?.pending ?? 8;
  const expiringSoon     = liveData?.stats?.expiring_soon     ?? 5;
  const criticalAccepted = liveData?.stats?.critical_accepted ?? liveData?.stats?.critical_count ?? 3;

  // Exception rows — live list mapped to table shape, fall back to mock
  const exceptions: typeof EXCEPTIONS = liveData?.list?.length
    ? liveData.list.slice(0, 50).map((e: any) => ({
        id:        e.id ?? e.exception_id ?? "—",
        title:     e.title ?? e.description ?? "—",
        type:      e.type ?? e.exception_type ?? "policy",
        risk:      e.risk ?? e.risk_level ?? "medium",
        status:    e.status ?? "pending",
        requestor: e.requestor ?? e.requested_by ?? "—",
        expires:   e.expires ?? e.expiry_date ?? e.expires_at ?? "—",
        daysLeft:  e.days_left ?? e.days_remaining ?? 0,
      }))
    : EXCEPTIONS;

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
        title="Security Exceptions"
        description="Risk-accepted exceptions with approval workflows and expiry tracking"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Exceptions"   value={totalExceptions}  icon={ShieldAlert}    className="border-blue-500/20" />
        <KpiCard title="Pending Approval"   value={pendingApproval}  icon={Clock}          trend="up" className="border-amber-500/20" />
        <KpiCard title="Expiring Soon"      value={expiringSoon}     icon={AlertTriangle}  trend="up" className="border-yellow-500/20" />
        <KpiCard title="Critical Accepted"  value={criticalAccepted} icon={CheckCircle}    className="border-red-500/20" />
      </div>

      {/* Exception table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-amber-400" />
              Exception Registry
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">{exceptions.length} exceptions</Badge>
          </div>
          <CardDescription className="text-xs">All active, pending, and recently expired security exceptions</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Risk</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Requestor</TableHead>
                  <TableHead className="text-[11px] h-8">Expires</TableHead>
                  <TableHead className="text-[11px] h-8">Days Left</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {exceptions.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  exceptions.map((row) => (
                  <TableRow key={row.id} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5">{row.id}</TableCell>
                    <TableCell className="text-xs py-2.5 max-w-[200px] truncate">{row.title}</TableCell>
                    <TableCell className="py-2.5"><TypeBadge type={row.type} /></TableCell>
                    <TableCell className="py-2.5"><RiskBadge risk={row.risk} /></TableCell>
                    <TableCell className="py-2.5"><StatusBadge status={row.status} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{row.requestor}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{row.expires}</TableCell>
                    <TableCell className="py-2.5"><DaysLeftCell days={row.daysLeft} /></TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">Review</Button>
                    </TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Approval queue */}
      <Card className="border-blue-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-blue-400">
              <Clock className="h-4 w-4" />
              Approval Queue
            </CardTitle>
            <Badge className="text-[10px] border border-blue-500/30 text-blue-400 bg-blue-500/10">{PENDING_QUEUE.length} pending</Badge>
          </div>
          <CardDescription className="text-xs">Exceptions awaiting security team review and approval decision</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {PENDING_QUEUE.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            PENDING_QUEUE.map((item) => (
            <div key={item.id} className="rounded-lg border border-border bg-muted/20 p-4 space-y-3">
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-mono text-muted-foreground">{item.id}</span>
                    <RiskBadge risk={item.risk} />
                  </div>
                  <p className="text-sm font-medium mt-1">{item.title}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">Requested by {item.requestor} · {item.team}</p>
                </div>
                <div className="flex gap-2 shrink-0">
                  <Button variant="outline" size="sm" className="h-7 px-3 text-xs border-green-500/30 text-green-400 hover:bg-green-500/10">
                    <CheckCircle className="h-3 w-3 mr-1" /> Approve
                  </Button>
                  <Button variant="outline" size="sm" className="h-7 px-3 text-xs border-red-500/30 text-red-400 hover:bg-red-500/10">
                    <XCircle className="h-3 w-3 mr-1" /> Reject
                  </Button>
                  <Button variant="outline" size="sm" className="h-7 px-3 text-xs">
                    <HelpCircle className="h-3 w-3 mr-1" /> Info
                  </Button>
                </div>
              </div>
              <div className="grid grid-cols-1 gap-2 text-xs lg:grid-cols-2">
                <div>
                  <span className="text-muted-foreground font-medium">Business justification: </span>
                  <span className="text-foreground">{item.justification}</span>
                </div>
                <div>
                  <span className="text-muted-foreground font-medium">Compensating controls: </span>
                  <span className="text-foreground">{item.controls}</span>
                </div>
              </div>
            </div>
          )))}
        </CardContent>
      </Card>

      {/* Expiring exceptions + Stats */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Expiring */}
        <Card className="border-yellow-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-yellow-400">
              <AlertTriangle className="h-4 w-4" />
              Expiring Exceptions (Next 30 Days)
            </CardTitle>
            <CardDescription className="text-xs">Exceptions requiring renewal or remediation decisions soon</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {EXPIRING.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              EXPIRING.map((item) => (
              <div key={item.id} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2 min-w-0 flex-1">
                    <span className="font-mono text-muted-foreground shrink-0">{item.id}</span>
                    <span className="truncate">{item.title}</span>
                  </div>
                  <RiskBadge risk={item.risk} />
                </div>
                <CountdownBar days={item.daysLeft} />
              </div>
            )))}
          </CardContent>
        </Card>

        {/* Stats */}
        <div className="flex flex-col gap-4">
          {/* By type */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <BarChart3 className="h-4 w-4 text-purple-400" />
                Exceptions by Type
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2.5">
              {TYPE_DIST.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                TYPE_DIST.map((t) => (
                <div key={t.label} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground">{t.label}</span>
                    <span className="font-bold tabular-nums">{t.count}</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-muted/30 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${(t.count / TYPE_TOTAL) * 100}%` }}
                      transition={{ duration: 0.8, ease: "easeOut" }}
                      className={cn("h-full rounded-full", t.color)}
                    />
                  </div>
                </div>
              )))}
            </CardContent>
          </Card>

          {/* By risk */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-red-400" />
                Exceptions by Risk Level
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2.5">
              {RISK_DIST.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                RISK_DIST.map((r) => (
                <div key={r.label} className="flex items-center gap-3">
                  <span className="text-xs text-muted-foreground w-16 shrink-0">{r.label}</span>
                  <div className="flex-1 h-4 bg-muted/30 rounded overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${(r.count / RISK_MAX) * 100}%` }}
                      transition={{ duration: 0.8, ease: "easeOut" }}
                      className={cn("h-full", r.color)}
                    />
                  </div>
                  <span className="text-xs font-bold tabular-nums w-4 text-right">{r.count}</span>
                </div>
              )))}
            </CardContent>
          </Card>
        </div>
      </div>
    </motion.div>
  );
}
