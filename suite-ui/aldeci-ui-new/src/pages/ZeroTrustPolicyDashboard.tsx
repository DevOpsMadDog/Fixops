/**
 * Zero Trust Policy Dashboard
 *
 * Never trust, always verify — continuous access evaluation.
 *   1. KPIs: Active Policies, Access Requests Today, Allow Rate, Violations
 *   2. Policy table (10 rows)
 *   3. Access request log (15 recent requests)
 *   4. Trust score board (8 entities)
 *   5. Violation feed (8 violations)
 *
 * Route: /zero-trust-policies (avoids conflict with /zero-trust)
 * API stubs: GET /api/v1/zero-trust/policies, /api/v1/zero-trust/requests, /api/v1/zero-trust/trust-scores
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Lock, Shield, Users, Activity, RefreshCw,
  AlertTriangle, CheckCircle, XCircle, Eye,
} from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "default";

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
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const POLICIES = [
  { name: "Unmanaged Device Block",         type: "device_trust",    action: "deny",        conditions: ["device_managed=false"],            priority: 1,  enabled: true  },
  { name: "Admin MFA Enforcement",           type: "user_identity",   action: "mfa_required", conditions: ["role=admin", "mfa_verified=false"], priority: 2,  enabled: true  },
  { name: "Sensitive Data — Trusted Nets",   type: "network_access",  action: "allow",        conditions: ["network=corp", "data_class=secret"], priority: 3,  enabled: true  },
  { name: "External IP — Finance Apps",      type: "application",     action: "deny",         conditions: ["src_external=true", "app=finance"],  priority: 4,  enabled: true  },
  { name: "Contractor Access Restriction",   type: "user_identity",   action: "monitor",      conditions: ["user_type=contractor"],             priority: 5,  enabled: true  },
  { name: "Cloud Storage DLP Gate",          type: "data",            action: "mfa_required", conditions: ["resource=s3", "pii_detected=true"],  priority: 6,  enabled: true  },
  { name: "High-Risk Score Auto-Block",      type: "user_identity",   action: "deny",         conditions: ["risk_score>80"],                    priority: 7,  enabled: true  },
  { name: "SaaS App — Corp Network Only",    type: "application",     action: "allow",        conditions: ["src=corp_vpn", "app_type=saas"],     priority: 8,  enabled: false },
  { name: "Legacy System Monitoring",        type: "network_access",  action: "monitor",      conditions: ["dst_legacy=true"],                  priority: 9,  enabled: true  },
  { name: "PCI Scope Micro-segmentation",    type: "network_access",  action: "deny",         conditions: ["zone=pci", "src_zone!=pci"],         priority: 10, enabled: true  },
];

const REQUESTS = [
  { user: "alice.chen",    device: "MAC-CORP-041", resource: "/api/finance/reports", risk: 12, mfa: true,  decision: "allow",  ts: "09:44:01" },
  { user: "bob.smith",     device: "WIN-CORP-088", resource: "/api/hr/salaries",     risk: 28, mfa: true,  decision: "allow",  ts: "09:44:15" },
  { user: "carol.white",   device: "BYOD-092",     resource: "/api/admin/users",     risk: 76, mfa: false, decision: "deny",   ts: "09:44:22" },
  { user: "dave.jones",    device: "MAC-CORP-017", resource: "/storage/pii-bucket",  risk: 44, mfa: true,  decision: "mfa",    ts: "09:44:38" },
  { user: "eve.martinez",  device: "WIN-CORP-055", resource: "/api/cloud/billing",   risk: 18, mfa: true,  decision: "allow",  ts: "09:44:50" },
  { user: "frank.lee",     device: "BYOD-134",     resource: "/api/finance/tx",      risk: 88, mfa: false, decision: "deny",   ts: "09:45:02" },
  { user: "grace.kim",     device: "MAC-CORP-022", resource: "/api/vuln/reports",    risk: 9,  mfa: true,  decision: "allow",  ts: "09:45:11" },
  { user: "henry.patel",   device: "WIN-CORP-067", resource: "/admin/scim",          risk: 35, mfa: true,  decision: "mfa",    ts: "09:45:19" },
  { user: "iris.wang",     device: "MAC-CORP-038", resource: "/api/soc/alerts",      risk: 6,  mfa: true,  decision: "allow",  ts: "09:45:27" },
  { user: "jack.o'brien",  device: "CONTRACTOR-01",resource: "/api/code/deploys",    risk: 62, mfa: false, decision: "deny",   ts: "09:45:33" },
  { user: "kate.nguyen",   device: "WIN-CORP-091", resource: "/api/ai/brain",        risk: 21, mfa: true,  decision: "allow",  ts: "09:45:44" },
  { user: "liam.brown",    device: "BYOD-077",     resource: "/storage/secret-keys", risk: 91, mfa: false, decision: "deny",   ts: "09:45:55" },
  { user: "mia.davis",     device: "MAC-CORP-009", resource: "/api/grc/risks",       risk: 14, mfa: true,  decision: "allow",  ts: "09:46:08" },
  { user: "noah.taylor",   device: "WIN-CORP-043", resource: "/api/network/flows",   risk: 33, mfa: true,  decision: "allow",  ts: "09:46:20" },
  { user: "olivia.moore",  device: "BYOD-055",     resource: "/api/exec/briefing",   risk: 72, mfa: true,  decision: "mfa",    ts: "09:46:31" },
];

const TRUST_SCORES = [
  { entity: "alice.chen",      type: "user",        score: 91, factors: 6, updated: "2 min ago" },
  { entity: "MAC-CORP-041",    type: "device",      score: 95, factors: 5, updated: "2 min ago" },
  { entity: "Jira Cloud",      type: "application", score: 88, factors: 4, updated: "5 min ago" },
  { entity: "carol.white",     type: "user",        score: 31, factors: 4, updated: "1 min ago" },
  { entity: "BYOD-092",        type: "device",      score: 22, factors: 5, updated: "1 min ago" },
  { entity: "frank.lee",       type: "user",        score: 18, factors: 3, updated: "30 sec ago" },
  { entity: "GitHub Actions",  type: "application", score: 82, factors: 4, updated: "10 min ago" },
  { entity: "Finance API",     type: "application", score: 97, factors: 7, updated: "8 min ago" },
];

const VIOLATIONS = [
  { type: "policy_bypass",    severity: "critical", ctx: "carol.white bypassed device policy on BYOD-092",          ts: "09:44:22" },
  { type: "risk_threshold",   severity: "critical", ctx: "frank.lee — risk score 88 exceeded auto-block threshold", ts: "09:45:02" },
  { type: "mfa_skip",         severity: "high",     ctx: "liam.brown attempted access without MFA from BYOD-077",   ts: "09:45:55" },
  { type: "policy_bypass",    severity: "high",     ctx: "jack.o'brien contractor accessing restricted deploy API",  ts: "09:45:33" },
  { type: "risk_threshold",   severity: "high",     ctx: "olivia.moore — borderline risk score 72 on BYOD",         ts: "09:46:31" },
  { type: "geo_anomaly",      severity: "medium",   ctx: "Unusual login location detected for henry.patel",          ts: "09:45:19" },
  { type: "trust_decay",      severity: "medium",   ctx: "BYOD-092 trust score dropped 40pts in last 24 hrs",       ts: "09:30:00" },
  { type: "session_anomaly",  severity: "low",      ctx: "dave.jones — concurrent sessions from 2 different IPs",   ts: "09:44:38" },
];

// ── Helpers ────────────────────────────────────────────────────

const POLICY_TYPE_COLORS: Record<string, string> = {
  device_trust:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
  user_identity:  "border-purple-500/30 text-purple-400 bg-purple-500/10",
  network_access: "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  application:    "border-amber-500/30 text-amber-400 bg-amber-500/10",
  data:           "border-rose-500/30 text-rose-400 bg-rose-500/10",
};

const ACTION_COLORS: Record<string, string> = {
  allow:        "border-green-500/30 text-green-400 bg-green-500/10",
  deny:         "border-red-500/30 text-red-400 bg-red-500/10",
  mfa_required: "border-orange-500/30 text-orange-400 bg-orange-500/10",
  monitor:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
};

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-500",
  high:     "bg-amber-500",
  medium:   "bg-yellow-500",
  low:      "bg-blue-500",
};

const ENTITY_TYPE_COLORS: Record<string, string> = {
  user:        "border-purple-500/30 text-purple-400 bg-purple-500/10",
  device:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
  application: "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
};

function TrustBar({ score }: { score: number }) {
  const color = score >= 80 ? "bg-green-500" : score >= 50 ? "bg-amber-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="relative h-1.5 w-24 rounded-full bg-muted/30 overflow-hidden">
        <div className={cn("h-full rounded-full transition-all", color)} style={{ width: `${score}%` }} />
      </div>
      <span className={cn(
        "text-xs font-bold tabular-nums",
        score >= 80 ? "text-green-400" : score >= 50 ? "text-amber-400" : "text-red-400"
      )}>{score}</span>
    </div>
  );
}

function DecisionBadge({ decision }: { decision: string }) {
  const map: Record<string, string> = {
    allow:   "border-green-500/30 text-green-400 bg-green-500/10",
    deny:    "border-red-500/30 text-red-400 bg-red-500/10",
    mfa:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    monitor: "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  const label: Record<string, string> = { allow: "ALLOW", deny: "DENY", mfa: "MFA REQ" };
  return <Badge className={cn("text-[10px] border", map[decision] ?? "")}>{label[decision] ?? decision}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function ZeroTrustPolicyDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/zero-trust/policies?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/zero-trust/access-log?org_id=${ORG_ID}&limit=15`),
      apiFetch(`/api/v1/zero-trust/trust-scores?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/zero-trust/stats?org_id=${ORG_ID
    setLoading(false);}`),
    ]).then(([policiesResult, requestsResult, scoresResult, statsResult]) => {
      const policies = policiesResult.status === "fulfilled" ? policiesResult.value : null;
      const requests = requestsResult.status === "fulfilled" ? requestsResult.value : null;
      const scores   = scoresResult.status   === "fulfilled" ? scoresResult.value   : null;
      const stats    = statsResult.status    === "fulfilled" ? statsResult.value    : null;
      if (policies || requests || scores || stats) {
        setLiveData({ policies, requests, scores, stats });
      }
    }).finally(() => setDataLoading(false));
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
        title="Zero Trust Policies"
        description="Never trust, always verify — continuous access evaluation"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Policies"        value={liveData?.stats?.total_policies ?? liveData?.policies?.length ?? 24}                                                               icon={Lock}          trend="up"   />
        <KpiCard title="Access Requests Today"  value={liveData?.stats?.total_requests ?? liveData?.stats?.requests_today ?? "847"}                                                      icon={Activity}      trend="up"   />
        <KpiCard title="Allow Rate"             value={liveData?.stats?.allow_rate != null ? `${(liveData.stats.allow_rate * 100).toFixed(1)}%` : liveData?.stats?.allow_rate ?? "73.4%"} icon={CheckCircle}   trend="down" className="border-amber-500/20" />
        <KpiCard title="Violations"             value={liveData?.stats?.violations ?? liveData?.stats?.total_violations ?? 12}                                                           icon={AlertTriangle} trend="up"   className="border-red-500/20" />
      </div>

      {/* Policy table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Shield className="h-4 w-4 text-blue-400" />
            Policy Configuration
          </CardTitle>
          <CardDescription className="text-xs">Active Zero Trust policies ordered by evaluation priority</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8 w-8">#</TableHead>
                  <TableHead className="text-[11px] h-8">Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Action</TableHead>
                  <TableHead className="text-[11px] h-8">Conditions</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Enabled</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.policies ?? POLICIES).map((p: any) => (
                  <TableRow key={p.name ?? p.policy_name ?? p.id} className="hover:bg-muted/30">
                    <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{p.priority ?? "—"}</TableCell>
                    <TableCell className="text-xs py-2.5 font-medium">{p.name ?? p.policy_name}</TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", POLICY_TYPE_COLORS[p.type ?? p.resource_type] ?? "border-border text-muted-foreground")}>
                        {(p.type ?? p.resource_type ?? "policy").replace("_", " ")}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", ACTION_COLORS[p.action] ?? "border-border text-muted-foreground")}>
                        {(p.action ?? "—").replace("_", " ")}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {(Array.isArray(p.conditions) ? p.conditions : Object.entries(p.conditions ?? {}).map(([k, v]) => `${k}=${v}`)).map((c: string) => (
                          <span key={c} className="text-[10px] bg-muted/40 rounded px-1.5 py-0.5 text-muted-foreground font-mono">{c}</span>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="py-2.5 text-right">
                      {(p.enabled ?? p.is_active ?? true)
                        ? <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">ON</Badge>
                        : <Badge className="text-[10px] border border-border text-muted-foreground">OFF</Badge>
                      }
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Access request log + Trust scores */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Access requests */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan-400" />
              Access Request Log
            </CardTitle>
            <CardDescription className="text-xs">15 most recent access evaluations</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="max-h-80 overflow-y-auto divide-y divide-border/40">
              {(liveData?.requests ?? REQUESTS).map((r: any, i: number) => (
                <div key={i} className="flex items-center gap-2 px-4 py-2 hover:bg-muted/20 transition-colors">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] font-medium truncate">{r.user ?? r.principal_id}</span>
                      <span className="text-[10px] text-muted-foreground truncate hidden sm:inline">{r.device ?? r.device_id ?? ""}</span>
                    </div>
                    <div className="text-[10px] text-muted-foreground truncate font-mono">{r.resource ?? r.resource_id}</div>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    {/* Risk score */}
                    <div className="relative h-1 w-12 rounded-full bg-muted/30 overflow-hidden">
                      <div
                        className={cn("h-full rounded-full", (r.risk ?? r.risk_score ?? 0) > 70 ? "bg-red-500" : (r.risk ?? r.risk_score ?? 0) > 40 ? "bg-amber-500" : "bg-green-500")}
                        style={{ width: `${r.risk ?? r.risk_score ?? 0}%` }}
                      />
                    </div>
                    {/* MFA badge */}
                    {(r.mfa ?? r.mfa_verified)
                      ? <CheckCircle className="h-3 w-3 text-green-500" title="MFA verified" />
                      : <XCircle    className="h-3 w-3 text-red-500"   title="No MFA" />
                    }
                    <DecisionBadge decision={r.decision ?? r.decision_result ?? "allow"} />
                    <span className="text-[10px] text-muted-foreground tabular-nums">{r.ts ?? r.evaluated_at ?? ""}</span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Trust scores + Violations */}
        <div className="flex flex-col gap-4">
          {/* Trust scores */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Users className="h-4 w-4 text-purple-400" />
                Trust Score Board
              </CardTitle>
              <CardDescription className="text-xs">Entity trust scores and contributing factors</CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Entity</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8">Trust Score</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Factors</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(liveData?.scores ?? TRUST_SCORES).map((e: any) => (
                    <TableRow key={e.entity ?? e.entity_id} className="hover:bg-muted/30">
                      <TableCell className="text-xs font-mono py-2">{e.entity ?? e.entity_id}</TableCell>
                      <TableCell className="py-2">
                        <Badge className={cn("text-[10px] border capitalize", ENTITY_TYPE_COLORS[e.type ?? e.entity_type] ?? "border-border text-muted-foreground")}>{e.type ?? e.entity_type}</Badge>
                      </TableCell>
                      <TableCell className="py-2"><TrustBar score={e.score ?? e.trust_score ?? 0} /></TableCell>
                      <TableCell className="text-xs tabular-nums py-2 text-right text-muted-foreground">{e.factors ?? (e.score_factors ? Object.keys(e.score_factors).length : "—")}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          {/* Violations */}
          <Card className="border-red-500/20">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
                <Eye className="h-4 w-4" />
                Violation Feed
              </CardTitle>
              <CardDescription className="text-xs">Recent policy violations and anomalies</CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <div className="divide-y divide-border/40">
                {VIOLATIONS.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  VIOLATIONS.map((v, i) => (
                  <div key={i} className="flex items-start gap-2 px-4 py-2.5">
                    <span className={cn("w-2 h-2 rounded-full mt-1 shrink-0", SEV_COLORS[v.severity])} />
                    <div className="flex-1 min-w-0">
                      <Badge className="text-[10px] border border-border mb-0.5 capitalize">{v.type.replace("_", " ")}</Badge>
                      <p className="text-[11px] text-muted-foreground leading-snug">{v.ctx}</p>
                    </div>
                    <span className="text-[10px] text-muted-foreground/60 tabular-nums shrink-0">{v.ts}</span>
                  </div>
                ))}
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </motion.div>
  );
}
