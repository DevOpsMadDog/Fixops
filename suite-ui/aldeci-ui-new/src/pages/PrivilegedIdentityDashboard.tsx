/**
 * Privileged Identity Dashboard
 *
 * Privileged account management with session monitoring and certification tracking.
 * Route: /privileged-identity
 */

import { useState } from "react";
import { motion } from "framer-motion";
import {
  Shield, Lock, AlertTriangle, CheckCircle2, XCircle, Clock,
  RefreshCw, UserCheck, Activity, Key, Eye, Users,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock Data ──────────────────────────────────────────────────

const MOCK_ACCOUNTS = [
  { id: "pa-001", username: "svc-db-prod", account_type: "service", system_name: "prod-db-01", department: "Engineering", risk_level: "critical", mfa_enabled: false, last_used: "2026-04-16T09:10:00Z", password_last_rotated: "2025-10-01T00:00:00Z", status: "active", certified: true },
  { id: "pa-002", username: "admin-aws-root", account_type: "cloud_root", system_name: "AWS", department: "Infrastructure", risk_level: "critical", mfa_enabled: true, last_used: "2026-04-15T14:22:00Z", password_last_rotated: "2026-01-15T00:00:00Z", status: "active", certified: false },
  { id: "pa-003", username: "j.smith-admin", account_type: "human_admin", system_name: "AD", department: "IT Ops", risk_level: "high", mfa_enabled: true, last_used: "2026-04-16T08:45:00Z", password_last_rotated: "2026-03-01T00:00:00Z", status: "active", certified: true },
  { id: "pa-004", username: "svc-ci-deploy", account_type: "service", system_name: "Jenkins", department: "DevOps", risk_level: "high", mfa_enabled: false, last_used: "2026-04-16T10:05:00Z", password_last_rotated: "2025-12-10T00:00:00Z", status: "active", certified: false },
  { id: "pa-005", username: "dba-oracle", account_type: "service", system_name: "Oracle DB", department: "Data", risk_level: "high", mfa_enabled: false, last_used: "2026-04-14T16:30:00Z", password_last_rotated: "2025-08-20T00:00:00Z", status: "suspended", certified: false },
  { id: "pa-006", username: "netadmin", account_type: "human_admin", system_name: "Cisco", department: "Network", risk_level: "medium", mfa_enabled: true, last_used: "2026-04-13T11:00:00Z", password_last_rotated: "2026-02-14T00:00:00Z", status: "active", certified: true },
  { id: "pa-007", username: "svc-monitoring", account_type: "service", system_name: "Datadog", department: "Ops", risk_level: "low", mfa_enabled: false, last_used: "2026-04-16T10:45:00Z", password_last_rotated: "2026-04-01T00:00:00Z", status: "active", certified: true },
  { id: "pa-008", username: "former-cto-admin", account_type: "human_admin", system_name: "AD", department: "Executive", risk_level: "critical", mfa_enabled: false, last_used: "2025-12-01T09:00:00Z", password_last_rotated: "2025-06-01T00:00:00Z", status: "revoked", certified: false },
];

const MOCK_SESSIONS = [
  { id: "sess-001", username: "j.smith-admin", session_type: "rdp", target_system: "prod-dc-01", started_at: "2026-04-16T09:30:00Z", commands_executed: 42, anomaly_score: 28 },
  { id: "sess-002", username: "svc-ci-deploy", session_type: "ssh", target_system: "build-server-03", started_at: "2026-04-16T10:00:00Z", commands_executed: 187, anomaly_score: 64 },
  { id: "sess-003", username: "netadmin", session_type: "cli", target_system: "core-sw-02", started_at: "2026-04-16T08:15:00Z", commands_executed: 23, anomaly_score: 12 },
  { id: "sess-004", username: "admin-aws-root", session_type: "web_console", target_system: "AWS Console", started_at: "2026-04-16T07:50:00Z", commands_executed: 8, anomaly_score: 71 },
  { id: "sess-005", username: "dba-oracle", session_type: "database", target_system: "Oracle DB", started_at: "2026-04-16T06:40:00Z", commands_executed: 312, anomaly_score: 88 },
];

// ── Helpers ────────────────────────────────────────────────────

const RISK_COLORS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high:     "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low:      "bg-green-500/15 text-green-400 border-green-500/30",
};

const STATUS_COLORS: Record<string, string> = {
  active:    "bg-green-500/15 text-green-400 border-green-500/30",
  revoked:   "bg-red-500/15 text-red-400 border-red-500/30",
  suspended: "bg-orange-500/15 text-orange-400 border-orange-500/30",
};

const ACCT_TYPE_COLORS: Record<string, string> = {
  service:     "bg-blue-500/15 text-blue-400 border-blue-500/30",
  human_admin: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  cloud_root:  "bg-red-500/15 text-red-400 border-red-500/30",
};

const SESSION_TYPE_COLORS: Record<string, string> = {
  rdp:         "bg-blue-500/15 text-blue-400 border-blue-500/30",
  ssh:         "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  cli:         "bg-green-500/15 text-green-400 border-green-500/30",
  web_console: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  database:    "bg-orange-500/15 text-orange-400 border-orange-500/30",
};

function timeAgo(iso: string) {
  const mins = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (mins < 60) return `${mins}m ago`;
  const days = Math.round(mins / 1440);
  if (days > 30) return `${days}d ago`;
  return `${Math.round(mins / 60)}h ago`;
}

function rotationAge(iso: string) {
  const days = Math.round((Date.now() - new Date(iso).getTime()) / 86400000);
  return { days, needsRotation: days > 90 };
}

function AnomalyBar({ score }: { score: number }) {
  const color = score >= 70 ? "bg-red-500" : score >= 40 ? "bg-yellow-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 bg-zinc-700 rounded-full overflow-hidden">
        <div className={cn("h-full rounded-full", color)} style={{ width: `${score}%` }} />
      </div>
      <span className="text-[10px] text-zinc-400">{score}</span>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────

export default function PrivilegedIdentityDashboard() {
  const [certifyTarget, setCertifyTarget] = useState("");
  const [certifiedSet, setCertifiedSet] = useState<Set<string>>(
    new Set(MOCK_ACCOUNTS.filter(a => a.certified).map(a => a.id))
  );
  const [rotatedSet, setRotatedSet] = useState<Set<string>>(new Set());

  const highRisk = MOCK_ACCOUNTS.filter(a => ["critical","high"].includes(a.risk_level)).length;
  const activeSessions = MOCK_SESSIONS.length;
  const needsRotation = MOCK_ACCOUNTS.filter(a => {
    const { needsRotation } = rotationAge(a.password_last_rotated);
    return needsRotation && !rotatedSet.has(a.id);
  }).length;
  const uncertified = MOCK_ACCOUNTS.filter(a => !certifiedSet.has(a.id)).length;

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      <PageHeader
        title="Privileged Identity Management"
        description="Privileged account lifecycle, session monitoring, and access certification"
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <KpiCard title="Total Accounts" value={MOCK_ACCOUNTS.length} icon={<Users className="h-5 w-5" />} />
        <KpiCard title="High Risk" value={highRisk} icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <KpiCard title="Active Sessions" value={activeSessions} icon={<Activity className="h-5 w-5 text-blue-400" />} />
        <KpiCard title="Needs Rotation" value={needsRotation} icon={<RefreshCw className="h-5 w-5 text-orange-400" />} />
        <KpiCard title="Uncertified" value={uncertified} icon={<UserCheck className="h-5 w-5 text-yellow-400" />} />
      </div>

      {/* Accounts Table */}
      <Card className="bg-gray-800 border-zinc-700">
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm text-zinc-200">Privileged Accounts</CardTitle>
            <div className="flex gap-2">
              <input className="bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-xs text-white placeholder-zinc-600 w-40" placeholder="Account to certify..." value={certifyTarget} onChange={e => setCertifyTarget(e.target.value)} />
              <Button size="sm" className="bg-purple-600 hover:bg-purple-700 text-xs" onClick={() => {
                const acct = MOCK_ACCOUNTS.find(a => a.username === certifyTarget || a.id === certifyTarget);
                if (acct) setCertifiedSet(s => new Set([...s, acct.id]));
                setCertifyTarget("");
              }}>
                <UserCheck className="h-3 w-3 mr-1" /> Certify
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-zinc-700">
                  {["Username", "Type", "System", "Department", "Risk", "MFA", "Last Used", "Pwd Rotated", "Certified", "Status", ""].map(h => (
                    <th key={h} className="text-left py-2 px-2 text-zinc-500 font-medium whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {MOCK_ACCOUNTS.map(a => {
                  const { days, needsRotation: needs } = rotationAge(a.password_last_rotated);
                  const isRotated = rotatedSet.has(a.id);
                  const isCertified = certifiedSet.has(a.id);
                  return (
                    <tr key={a.id} className="border-b border-zinc-700/50 hover:bg-zinc-700/20">
                      <td className="py-2 px-2 font-mono text-zinc-200">{a.username}</td>
                      <td className="py-2 px-2"><Badge className={cn("text-[9px] border", ACCT_TYPE_COLORS[a.account_type])}>{a.account_type.replace("_"," ")}</Badge></td>
                      <td className="py-2 px-2 text-zinc-400">{a.system_name}</td>
                      <td className="py-2 px-2 text-zinc-400">{a.department}</td>
                      <td className="py-2 px-2"><Badge className={cn("text-[9px] border capitalize", RISK_COLORS[a.risk_level])}>{a.risk_level}</Badge></td>
                      <td className="py-2 px-2 text-center">
                        {a.mfa_enabled ? <Lock className="h-3 w-3 text-green-400 inline" /> : <XCircle className="h-3 w-3 text-red-400 inline" />}
                      </td>
                      <td className="py-2 px-2 text-zinc-500 whitespace-nowrap">{timeAgo(a.last_used)}</td>
                      <td className="py-2 px-2 whitespace-nowrap">
                        <span className={cn("text-[10px]", (needs && !isRotated) ? "text-orange-400 font-semibold" : "text-zinc-500")}>
                          {isRotated ? "Just now" : `${days}d ago`}
                          {needs && !isRotated && " ⚠"}
                        </span>
                      </td>
                      <td className="py-2 px-2 text-center">
                        {isCertified ? <CheckCircle2 className="h-3 w-3 text-green-400 inline" /> : <XCircle className="h-3 w-3 text-red-400 inline" />}
                      </td>
                      <td className="py-2 px-2"><Badge className={cn("text-[9px] border capitalize", STATUS_COLORS[a.status] ?? "border-zinc-600 text-zinc-400")}>{a.status}</Badge></td>
                      <td className="py-2 px-2">
                        {a.status === "active" && !isRotated && (
                          <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px] text-blue-400 hover:text-blue-300"
                            onClick={() => setRotatedSet(s => new Set([...s, a.id]))}>
                            <Key className="h-3 w-3 mr-1" /> Rotate
                          </Button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Active Sessions */}
      <Card className="bg-gray-800 border-zinc-700">
        <CardHeader className="pb-2"><CardTitle className="text-sm text-zinc-200">Active Sessions</CardTitle></CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-3">
            {MOCK_SESSIONS.map(s => (
              <motion.div key={s.id} initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }}
                className="bg-zinc-900 rounded-lg p-3 border border-zinc-700 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-white">{s.username}</span>
                  <Badge className={cn("text-[9px] border capitalize", SESSION_TYPE_COLORS[s.session_type])}>{s.session_type.replace("_"," ")}</Badge>
                </div>
                <p className="text-[10px] text-zinc-400">{s.target_system}</p>
                <div className="flex items-center justify-between text-[10px] text-zinc-500">
                  <span>{timeAgo(s.started_at)}</span>
                  <span>{s.commands_executed} cmds</span>
                </div>
                <div>
                  <p className="text-[10px] text-zinc-500 mb-1">Anomaly Score</p>
                  <AnomalyBar score={s.anomaly_score} />
                </div>
              </motion.div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
