/**
 * PAM Dashboard
 *
 * Privileged Access Management — vault, session control, and just-in-time access.
 *   1. KPIs: Privileged Accounts, Active Sessions, Pending Approvals, Overdue Rotation
 *   2. Privileged accounts table (12 rows)
 *   3. Session requests table (10 rows)
 *   4. Active sessions panel (5 cards)
 *   5. Policies table (4 rows)
 *
 * API stubs: GET /api/v1/pam/accounts, /api/v1/pam/sessions, /api/v1/pam/requests
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Shield, Key, Clock, AlertTriangle, RefreshCw, Video, CheckCircle, XCircle, Lock } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
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

const ACCOUNTS = [
  { username: "ro**@prod-db-01",    type: "root",      system: "prod-db-01",    owner: "DBAdmin",   risk: 92, rotated: "45 days ago", status: "overdue" },
  { username: "ad**@corp-dc-01",    type: "admin",     system: "corp-dc-01",    owner: "NetOps",    risk: 78, rotated: "12 days ago", status: "active" },
  { username: "svc-**@k8s-cluster", type: "service",   system: "k8s-cluster",   owner: "Platform",  risk: 65, rotated: "3 days ago",  status: "active" },
  { username: "ro**@prod-db-02",    type: "root",      system: "prod-db-02",    owner: "DBAdmin",   risk: 88, rotated: "38 days ago", status: "overdue" },
  { username: "em**@break-glass",   type: "emergency", system: "break-glass",   owner: "CISO",      risk: 95, rotated: "90 days ago", status: "overdue" },
  { username: "ad**@jump-host-01",  type: "admin",     system: "jump-host-01",  owner: "InfraSec",  risk: 70, rotated: "8 days ago",  status: "active" },
  { username: "sh**@citrix-farm",   type: "shared",    system: "citrix-farm",   owner: "IT Ops",    risk: 85, rotated: "52 days ago", status: "overdue" },
  { username: "svc-**@ci-runner",   type: "service",   system: "ci-runner",     owner: "DevOps",    risk: 45, rotated: "1 day ago",   status: "active" },
  { username: "ad**@aws-mgmt",      type: "admin",     system: "aws-mgmt",      owner: "CloudOps",  risk: 72, rotated: "5 days ago",  status: "active" },
  { username: "ro**@analytics-db",  type: "root",      system: "analytics-db",  owner: "DataEng",   risk: 80, rotated: "29 days ago", status: "warning" },
  { username: "sh**@legacy-erp",    type: "shared",    system: "legacy-erp",    owner: "Finance IT", risk: 90, rotated: "60 days ago", status: "overdue" },
  { username: "svc-**@vault-agent", type: "service",   system: "vault-agent",   owner: "SecOps",    risk: 30, rotated: "today",       status: "active" },
];

const SESSION_REQUESTS = [
  { requester: "j.smith",    target: "prod-db-01",    type: "interactive", justification: "Emergency DB recovery for incident INC-4421",       duration: "2h",  status: "pending" },
  { requester: "a.patel",    target: "aws-mgmt",      type: "api",        justification: "Automated infra provisioning pipeline run",           duration: "1h",  status: "approved" },
  { requester: "m.chen",     target: "corp-dc-01",    type: "interactive", justification: "AD group policy update for finance OU",               duration: "30m", status: "pending" },
  { requester: "r.jones",    target: "k8s-cluster",   type: "scheduled",  justification: "Nightly cert rotation job",                           duration: "15m", status: "approved" },
  { requester: "l.garcia",   target: "jump-host-01",  type: "interactive", justification: "Patch deployment for CVE-2025-4821",                  duration: "4h",  status: "pending" },
  { requester: "t.wu",       target: "analytics-db",  type: "api",        justification: "BI pipeline credential refresh",                       duration: "1h",  status: "denied" },
  { requester: "k.brown",    target: "citrix-farm",   type: "interactive", justification: "Legacy app troubleshooting for JIRA PLAT-9922",       duration: "2h",  status: "approved" },
  { requester: "s.davis",    target: "prod-db-02",    type: "interactive", justification: "Schema migration for Q2 release",                     duration: "3h",  status: "pending" },
  { requester: "e.martinez", target: "ci-runner",     type: "scheduled",  justification: "Dependency audit cron",                               duration: "20m", status: "approved" },
  { requester: "n.taylor",   target: "legacy-erp",    type: "interactive", justification: "Month-end reconciliation support for Finance",        duration: "6h",  status: "pending" },
];

const ACTIVE_SESSIONS = [
  { id: "SES-8821", requester: "a.patel",  target: "aws-mgmt",     started: "14m ago",  elapsed: "14:32", recording: true },
  { id: "SES-8819", requester: "r.jones",  target: "k8s-cluster",  started: "22m ago",  elapsed: "22:11", recording: true },
  { id: "SES-8815", requester: "k.brown",  target: "citrix-farm",  started: "1h ago",   elapsed: "01:04:47", recording: true },
  { id: "SES-8810", requester: "e.martinez",target: "ci-runner",   started: "38m ago",  elapsed: "38:05", recording: false },
  { id: "SES-8803", requester: "d.nguyen", target: "vault-agent",  started: "2h ago",   elapsed: "02:12:09", recording: true },
];

const POLICIES = [
  { name: "Production Database Access", mfa: true,  approval: true,  maxDuration: "2h",  recording: true  },
  { name: "Cloud Management Console",   mfa: true,  approval: true,  maxDuration: "4h",  recording: true  },
  { name: "CI/CD Service Accounts",     mfa: false, approval: false, maxDuration: "1h",  recording: false },
  { name: "Break-Glass Emergency",      mfa: true,  approval: true,  maxDuration: "8h",  recording: true  },
];

// ── Helpers ────────────────────────────────────────────────────

function TypeBadge({ type }: { type: string }) {
  const cls =
    type === "root"      ? "border-red-500/30 text-red-400 bg-red-500/10" :
    type === "admin"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    type === "emergency" ? "border-purple-500/30 text-purple-400 bg-purple-500/10" :
    type === "shared"    ? "border-orange-500/30 text-orange-400 bg-orange-500/10" :
                           "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{type}</Badge>;
}

function SessionTypeBadge({ type }: { type: string }) {
  const cls =
    type === "interactive" ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
    type === "api"         ? "border-cyan-500/30 text-cyan-400 bg-cyan-500/10" :
                             "border-slate-500/30 text-slate-400 bg-slate-500/10";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{type}</Badge>;
}

function ApprovalBadge({ status }: { status: string }) {
  const cls =
    status === "pending"  ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
    status === "approved" ? "border-green-500/30 text-green-400 bg-green-500/10" :
                            "border-red-500/30 text-red-400 bg-red-500/10";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{status}</Badge>;
}

function RiskBar({ score }: { score: number }) {
  const color = score >= 70 ? "bg-red-500" : score >= 50 ? "bg-amber-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-1.5">
      <div className="relative h-1.5 w-16 rounded-full bg-muted/30 overflow-hidden">
        <div className={cn("h-full rounded-full", color)} style={{ width: `${score}%` }} />
      </div>
      <span className={cn("text-[10px] font-bold tabular-nums", score >= 70 ? "text-red-400" : score >= 50 ? "text-amber-400" : "text-green-400")}>{score}</span>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === "active"  ? "border-green-500/30 text-green-400 bg-green-500/10" :
    status === "overdue" ? "border-red-500/30 text-red-400 bg-red-500/10" :
                           "border-yellow-500/30 text-yellow-400 bg-yellow-500/10";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{status}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function PAMDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/pam/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/pam/accounts?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/pam/sessions?org_id=${ORG_ID}`),
    ]).then(([statsRes, accountsRes, sessionsRes]) => {
      const stats    = statsRes.status    === "fulfilled" ? statsRes.value    : null;
      const accounts = accountsRes.status === "fulfilled" ? accountsRes.value : null;
      const sessions = sessionsRes.status === "fulfilled" ? sessionsRes.value : null;
      if (stats || accounts || sessions) {
        setLiveData({ stats, accounts, sessions });
      }
    })
      .finally(() => setLoading(false)).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

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
        title="Privileged Access Management"
        description="Vault, session control, and just-in-time access"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Privileged Accounts" value={liveData?.stats?.total_accounts ?? (liveData?.accounts?.length ?? 347)} icon={Key} />
        <KpiCard title="Active Sessions"     value={liveData?.stats?.active_sessions ?? (liveData?.sessions?.filter((s: PAMSession) => s.approval_status === "approved").length ?? 12)} icon={Shield} trend="up" className="border-blue-500/20" />
        <KpiCard title="Pending Approvals"   value={liveData?.stats?.pending_approvals ?? (liveData?.sessions?.filter((s: PAMSession) => s.approval_status === "pending").length ?? 8)} icon={Clock} trend="up" className="border-yellow-500/20" />
        <KpiCard title="Overdue Rotation"    value={liveData?.stats?.overdue_rotation ?? (liveData?.accounts?.filter((a: PAMAccount) => a.status === "overdue").length ?? 23)} icon={AlertTriangle} trend="up" className="border-red-500/20" />
      </div>

      {/* Privileged Accounts Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Key className="h-4 w-4 text-amber-400" />
              Privileged Accounts
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {(liveData?.accounts ?? ACCOUNTS).filter((a: PAMAccount) => a.status === "overdue").length} overdue
            </Badge>
          </div>
          <CardDescription className="text-xs">Managed credentials across all systems</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Username</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">System</TableHead>
                  <TableHead className="text-[11px] h-8">Owner</TableHead>
                  <TableHead className="text-[11px] h-8">Risk</TableHead>
                  <TableHead className="text-[11px] h-8">Last Rotated</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.accounts ?? ACCOUNTS).map((row: PAMAccount, i: number) => (
                  <TableRow key={row.id ?? i} className={cn("hover:bg-muted/30", row.status === "overdue" && "bg-red-500/5")}>
                    <TableCell className="text-xs font-mono py-2.5">{row.username}</TableCell>
                    <TableCell className="py-2.5"><TypeBadge type={row.account_type ?? row.type} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{row.system}</TableCell>
                    <TableCell className="text-xs py-2.5">{row.owner}</TableCell>
                    <TableCell className="py-2.5"><RiskBar score={row.risk_score ?? row.risk ?? 0} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{row.last_rotated ?? row.rotated}</TableCell>
                    <TableCell className="py-2.5"><StatusBadge status={row.status} /></TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">Rotate</Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Session Requests Table */}
      <Card className="border-yellow-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-yellow-400">
              <Clock className="h-4 w-4" />
              Session Requests
            </CardTitle>
            <Badge className="text-[10px] border border-yellow-500/30 text-yellow-400 bg-yellow-500/10">
              {(liveData?.sessions ?? SESSION_REQUESTS).filter((r: PAMSession) => (r.approval_status ?? r.status) === "pending").length} pending
            </Badge>
          </div>
          <CardDescription className="text-xs">Just-in-time access requests awaiting review</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Requester</TableHead>
                  <TableHead className="text-[11px] h-8">Target</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Justification</TableHead>
                  <TableHead className="text-[11px] h-8">Duration</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.sessions ?? SESSION_REQUESTS).map((row: any, i: number) => {
                  const rowStatus = row.approval_status ?? row.status;
                  return (
                  <TableRow key={row.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5">{row.requester}</TableCell>
                    <TableCell className="text-xs py-2.5 font-mono text-muted-foreground">{row.target_system ?? row.target}</TableCell>
                    <TableCell className="py-2.5"><SessionTypeBadge type={row.session_type ?? row.type} /></TableCell>
                    <TableCell className="text-xs py-2.5 max-w-[220px] truncate text-muted-foreground">{row.justification}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums">{row.requested_duration_minutes ? `${row.requested_duration_minutes}m` : row.duration}</TableCell>
                    <TableCell className="py-2.5"><ApprovalBadge status={rowStatus} /></TableCell>
                    <TableCell className="py-2.5 text-right">
                      {rowStatus === "pending" ? (
                        <div className="flex items-center gap-1 justify-end">
                          <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] border-green-500/30 text-green-400 hover:bg-green-500/10">
                            <CheckCircle className="h-3 w-3 mr-0.5" /> Approve
                          </Button>
                          <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] border-red-500/30 text-red-400 hover:bg-red-500/10">
                            <XCircle className="h-3 w-3 mr-0.5" /> Deny
                          </Button>
                        </div>
                      ) : (
                        <span className="text-[10px] text-muted-foreground">—</span>
                      )}
                    </TableCell>
                  </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Active Sessions + Policies */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Active Sessions */}
        <Card className="border-blue-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-blue-400">
              <Shield className="h-4 w-4" />
              Active Sessions
            </CardTitle>
            <CardDescription className="text-xs">Live privileged sessions with recording status</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {(liveData?.sessions?.filter((s: any) => (s.approval_status ?? s.status) === "approved") ?? ACTIVE_SESSIONS).map((s: any, i: number) => (
              <div key={s.id ?? s.session_id ?? i} className="flex items-center justify-between rounded-lg border border-border/50 bg-muted/10 px-3 py-2.5">
                <div className="flex flex-col gap-0.5 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-muted-foreground">{s.id ?? s.session_id ?? `SES-${i}`}</span>
                    {(s.recording ?? s.recording_enabled) && (
                      <Badge className="text-[9px] border border-red-500/30 text-red-400 bg-red-500/10 flex items-center gap-0.5">
                        <Video className="h-2.5 w-2.5" /> REC
                      </Badge>
                    )}
                  </div>
                  <span className="text-xs font-medium truncate">{s.requester} → {s.target_system ?? s.target}</span>
                  <span className="text-[10px] text-muted-foreground">
                    {s.started_at ? new Date(s.started_at).toLocaleTimeString() : s.started ? `Started ${s.started}` : ""}
                    {s.elapsed ? ` · Elapsed ${s.elapsed}` : ""}
                  </span>
                </div>
                <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] border-red-500/30 text-red-400 hover:bg-red-500/10 shrink-0 ml-2">
                  End
                </Button>
              </div>
            ))
            )}
          </CardContent>
        </Card>

        {/* Policies */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Lock className="h-4 w-4 text-muted-foreground" />
                  Access Policies
                </CardTitle>
                <CardDescription className="text-xs">JIT policy rules per access tier</CardDescription>
              </div>
              <Button variant="outline" size="sm" className="h-7 text-xs">Edit</Button>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Policy</TableHead>
                  <TableHead className="text-[11px] h-8">MFA</TableHead>
                  <TableHead className="text-[11px] h-8">Approval</TableHead>
                  <TableHead className="text-[11px] h-8">Max Dur.</TableHead>
                  <TableHead className="text-[11px] h-8">Rec.</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {POLICIES.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  POLICIES.map((p, i) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="text-xs py-2.5 font-medium max-w-[150px] truncate">{p.name}</TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", p.mfa ? "border-green-500/30 text-green-400 bg-green-500/10" : "border-border text-muted-foreground")}>
                        {p.mfa ? "Required" : "None"}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", p.approval ? "border-amber-500/30 text-amber-400 bg-amber-500/10" : "border-border text-muted-foreground")}>
                        {p.approval ? "Required" : "Auto"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 font-medium">{p.maxDuration}</TableCell>
                    <TableCell className="py-2.5">
                      {p.recording ? (
                        <Video className="h-3.5 w-3.5 text-red-400" />
                      ) : (
                        <span className="text-[10px] text-muted-foreground">—</span>
                      )}
                    </TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
