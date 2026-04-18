/**
 * Identity Risk Dashboard
 *
 * Identity risk monitoring = high-risk users, MFA gaps, risky login events.
 *   1. KPIs: Identities Monitored, High Risk Users, MFA Gaps, Risky Logins Today
 *   2. Identity risk events table (user, risk_score, risk_factors, last_seen, status)
 *
 * Route: /identity-risk
 * API: GET /api/v1/identity-risk/identities
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Users, RefreshCw, AlertTriangle, ShieldOff, LogIn } from "lucide-react";

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

// == Mock data ==================================================

const MOCK_IDENTITIES = [
  { id: "IDR-001", user: "j.morrison@acme.com",    risk_score: 94, risk_factors: ["impossible_travel", "admin_escalation"], last_seen: "3 min ago",  status: "critical" },
  { id: "IDR-002", user: "svc-deploy@acme.com",    risk_score: 88, risk_factors: ["no_mfa", "overprivileged"],              last_seen: "1 hr ago",   status: "high" },
  { id: "IDR-003", user: "k.patel@acme.com",       risk_score: 72, risk_factors: ["off_hours_login", "new_device"],        last_seen: "22 min ago", status: "high" },
  { id: "IDR-004", user: "d.chen@acme.com",        risk_score: 61, risk_factors: ["multiple_failures", "vpn_anomaly"],     last_seen: "45 min ago", status: "medium" },
  { id: "IDR-005", user: "svc-monitor@acme.com",   risk_score: 55, risk_factors: ["no_mfa", "stale_password"],             last_seen: "2 hr ago",   status: "medium" },
  { id: "IDR-006", user: "a.nguyen@acme.com",      risk_score: 43, risk_factors: ["new_country_login"],                    last_seen: "4 hr ago",   status: "medium" },
  { id: "IDR-007", user: "r.santos@acme.com",      risk_score: 21, risk_factors: [],                                       last_seen: "6 hr ago",   status: "low" },
  { id: "IDR-008", user: "m.taylor@acme.com",      risk_score: 18, risk_factors: [],                                       last_seen: "1 day ago",  status: "low" },
];

const MOCK_STATS = { identities_monitored: 1284, high_risk_users: 12, mfa_gaps: 34, risky_logins_today: 7 };

// == Badge helpers ==============================================

function RiskLevelBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-rose-500/30 text-rose-400 bg-rose-500/10",
    medium:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    low:      "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>{status}</Badge>;
}

function RiskScoreBar({ score }: { score: number }) {
  const color = score >= 80 ? "bg-red-500" : score >= 60 ? "bg-rose-500" : score >= 40 ? "bg-amber-500" : "bg-green-500";
  const textColor = score >= 80 ? "text-red-400" : score >= 60 ? "text-rose-400" : score >= 40 ? "text-amber-400" : "text-green-400";
  return (
    <div className="flex items-center gap-2">
      <div className="relative h-1.5 flex-1 rounded-full bg-muted/30 overflow-hidden min-w-[60px]">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ duration: 0.6 }}
          className={cn("h-full rounded-full", color)}
        />
      </div>
      <span className={cn("text-[10px] font-bold tabular-nums w-6 text-right", textColor)}>{score}</span>
    </div>
  );
}

// == Component ==================================================

export default function IdentityRiskDashboard() {
  const [refreshing, setRefreshing]       = useState(false);
  const [liveIdentities, setLiveIdentities] = useState<any[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [liveStats, setLiveStats]           = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/identity-risk/identities?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/identity-risk/stats?org_id=${ORG_ID}`),
    ]).then(([idRes, statsRes]) => {
      if (idRes.status === "fulfilled") setLiveIdentities(idRes.value?.identities ?? idRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const identities = liveIdentities ?? MOCK_IDENTITIES;
  const stats      = liveStats      ?? MOCK_STATS;

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
        title="Identity Risk"
        description="User risk scoring, MFA gap analysis, and anomalous login detection"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Identities Monitored" value={stats.identities_monitored.toLocaleString()} icon={Users}         trend="up" />
        <KpiCard title="High Risk Users"      value={stats.high_risk_users}                       icon={AlertTriangle}  trend="up" className="border-red-500/20" />
        <KpiCard title="MFA Gaps"             value={stats.mfa_gaps}                              icon={ShieldOff}      trend="up" className="border-rose-500/20" />
        <KpiCard title="Risky Logins Today"   value={stats.risky_logins_today}                   icon={LogIn}          trend="up" className="border-rose-500/20" />
      </div>

      {/* Identity Risk Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <Users className="h-4 w-4" />
              Identity Risk Events
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {identities.filter((i: any) => ["critical", "high"].includes(i.status)).length} high+critical
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Users ranked by risk score with contributing risk factors
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">User</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[120px]">Risk Score</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Factors</TableHead>
                  <TableHead className="text-[11px] h-8">Last Seen</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Level</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {identities.map((id: any, i: number) => {
                  const factors: string[] = id.risk_factors ?? [];
                  return (
                    <TableRow key={id.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 font-mono text-[10px] text-muted-foreground">{id.id}</TableCell>
                      <TableCell className="py-2 font-mono text-[11px]">{id.user ?? id.username ?? id.email ?? "="}</TableCell>
                      <TableCell className="py-2 min-w-[120px]">
                        <RiskScoreBar score={id.risk_score ?? id.score ?? 0} />
                      </TableCell>
                      <TableCell className="py-2">
                        <div className="flex flex-wrap gap-1">
                          {factors.length === 0
                            ? <span className="text-[10px] text-muted-foreground">none</span>
                            : factors.slice(0, 2).map((f) => (
                                <Badge key={f} className="text-[9px] border border-rose-500/30 text-rose-400 bg-rose-500/10 font-mono">
                                  {f.replace(/_/g, " ")}
                                </Badge>
                              ))
                          }
                          {factors.length > 2 && (
                            <span className="text-[10px] text-muted-foreground">+{factors.length - 2}</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{id.last_seen ?? "="}</TableCell>
                      <TableCell className="py-2 text-right">
                        <RiskLevelBadge status={id.status ?? id.risk_level ?? "low"} />
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
