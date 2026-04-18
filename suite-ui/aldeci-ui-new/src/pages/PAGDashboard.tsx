/**
 * PAG (Privileged Access Governance) Dashboard
 *
 * Privileged account monitoring, session tracking, and anomaly detection.
 *   1. KPIs: Total PA Accounts, Active Sessions Today, Open Anomalies, High Risk Accounts
 *   2. Privileged accounts table (username, account_type, system, owner, risk_score, last_used)
 *
 * Route: /pag
 * API: GET /api/v1/pag/accounts
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { KeyRound, RefreshCw, AlertTriangle, UserCheck, Activity } from "lucide-react";

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

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_ACCOUNTS = [
  { username: "svc-deploy-prod",   account_type: "service",        system: "k8s-prod-cluster",     owner: "DevOps",       risk_score: 91, last_used: "2 min ago" },
  { username: "admin-db-primary",  account_type: "admin",          system: "postgres-primary",      owner: "DBA Team",     risk_score: 87, last_used: "15 min ago" },
  { username: "root-bastion-01",   account_type: "root",           system: "bastion-host-01",       owner: "SecOps",       risk_score: 78, last_used: "1 hr ago" },
  { username: "svc-ci-runner",     account_type: "service",        system: "jenkins-master",        owner: "DevOps",       risk_score: 55, last_used: "30 min ago" },
  { username: "domain-admin-01",   account_type: "domain_admin",   system: "ad-dc-primary",         owner: "IT Ops",       risk_score: 95, last_used: "5 min ago" },
  { username: "vault-accessor",    account_type: "service",        system: "hashicorp-vault",       owner: "Security",     risk_score: 42, last_used: "3 hr ago" },
  { username: "break-glass-01",    account_type: "break_glass",    system: "aws-root",              owner: "CISO",         risk_score: 99, last_used: "7 days ago" },
  { username: "svc-monitoring",    account_type: "service",        system: "prometheus-stack",      owner: "SRE",          risk_score: 28, last_used: "1 min ago" },
];

const MOCK_STATS = { total_pa_accounts: 312, active_sessions_today: 47, open_anomalies: 8, high_risk_accounts: 19 };

// ── Badge helpers ──────────────────────────────────────────────

function AccountTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    admin:        "border-red-500/30 text-red-400 bg-red-500/10",
    root:         "border-red-600/30 text-red-300 bg-red-600/10",
    domain_admin: "border-fuchsia-500/30 text-fuchsia-400 bg-fuchsia-500/10",
    service:      "border-purple-500/30 text-purple-400 bg-purple-500/10",
    break_glass:  "border-orange-500/30 text-orange-400 bg-orange-500/10",
    shared:       "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", map[type] ?? "border-border")}>
      {type.replace(/_/g, " ")}
    </Badge>
  );
}

function RiskScore({ score }: { score: number }) {
  const color = score >= 80 ? "text-red-400" : score >= 60 ? "text-orange-400" : score >= 40 ? "text-yellow-400" : "text-green-400";
  return <span className={cn("font-mono font-bold text-[12px]", color)}>{score}</span>;
}

// ── Component ──────────────────────────────────────────────────

export default function PAGDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveAccounts, setLiveAccounts] = useState<any[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [liveStats, setLiveStats]       = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/pag/accounts?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/pag/stats?org_id=${ORG_ID}`),
    ]).then(([accountsRes, statsRes]) => {
      if (accountsRes.status === "fulfilled") setLiveAccounts(accountsRes.value?.accounts ?? accountsRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const accounts = liveAccounts ?? MOCK_ACCOUNTS;
  const stats    = liveStats    ?? MOCK_STATS;

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
        title="Privileged Access Governance"
        description="Privileged account lifecycle, session monitoring, and anomaly detection across all critical systems"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total PA Accounts"      value={stats.total_pa_accounts}      icon={KeyRound}      trend="flat" />
        <KpiCard title="Active Sessions Today"  value={stats.active_sessions_today}  icon={Activity}      trend="up"   className="border-purple-500/20" />
        <KpiCard title="Open Anomalies"         value={stats.open_anomalies}         icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="High Risk Accounts"     value={stats.high_risk_accounts}     icon={UserCheck}     trend="flat" className="border-fuchsia-500/20" />
      </div>

      {/* Accounts Table */}
      <Card className="border-purple-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-purple-400">
              <KeyRound className="h-4 w-4" />
              Privileged Account Registry
            </CardTitle>
            <Badge className="text-[10px] border border-fuchsia-500/30 text-fuchsia-400 bg-fuchsia-500/10">
              {accounts.filter((a: any) => a.risk_score >= 80).length} high risk
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Service accounts, admin accounts, break-glass credentials — risk-scored and usage-tracked
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Username</TableHead>
                  <TableHead className="text-[11px] h-8">Account Type</TableHead>
                  <TableHead className="text-[11px] h-8">System</TableHead>
                  <TableHead className="text-[11px] h-8">Owner</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Score</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Last Used</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {accounts.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  accounts.map((acc: any, i: number) => (
                  <TableRow key={acc.username ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] font-semibold text-purple-300">
                      {acc.username ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <AccountTypeBadge type={acc.account_type ?? "service"} />
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground max-w-[160px] truncate">
                      {acc.system ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">
                      {acc.owner ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <RiskScore score={acc.risk_score ?? 0} />
                    </TableCell>
                    <TableCell className="py-2 text-right text-[11px] text-muted-foreground">
                      {acc.last_used ?? "—"}
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
