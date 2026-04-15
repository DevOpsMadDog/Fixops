/**
 * Identity Analytics Dashboard
 *
 * User risk scoring, anomaly detection, and access certification.
 *   1. KPIs: Identities Tracked, Critical Risk, MFA Disabled + Privileged, Pending Certifications
 *   2. Risk tier distribution — colored animated bars
 *   3. Identity risk table (15 rows)
 *   4. Login event feed (12 events)
 *   5. Active risks panel (8 open risks)
 *   6. Certification queue (5 pending)
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Users, AlertTriangle, ShieldAlert, RefreshCw, UserCheck, Clock, Activity, Lock } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const RISK_TIERS = [
  { label: "Critical", count: 12,  color: "bg-red-500",    text: "text-red-400",    width: 10 },
  { label: "High",     count: 58,  color: "bg-amber-500",  text: "text-amber-400",  width: 32 },
  { label: "Medium",   count: 214, color: "bg-yellow-500", text: "text-yellow-400", width: 62 },
  { label: "Low",      count: 963, color: "bg-green-500",  text: "text-green-400",  width: 100 },
];

const IDENTITIES = [
  { user: "alice.chen",    dept: "Engineering",  type: "human",           privileged: true,  mfa: true,  score: 82, tier: "High",     last: "2026-04-16 09:14" },
  { user: "svc-deploy",    dept: "DevOps",        type: "service_account", privileged: true,  mfa: false, score: 91, tier: "Critical",  last: "2026-04-16 08:52" },
  { user: "bob.martin",    dept: "Finance",       type: "human",           privileged: false, mfa: false, score: 74, tier: "High",     last: "2026-04-15 23:44" },
  { user: "bot-scanner",   dept: "Security",      type: "bot",             privileged: false, mfa: false, score: 35, tier: "Low",      last: "2026-04-16 09:00" },
  { user: "shared-qa",     dept: "QA",            type: "shared",          privileged: false, mfa: false, score: 68, tier: "Medium",   last: "2026-04-15 17:30" },
  { user: "carlos.ruiz",   dept: "IT",            type: "human",           privileged: true,  mfa: true,  score: 55, tier: "Medium",   last: "2026-04-16 07:55" },
  { user: "svc-backup",    dept: "Infra",         type: "service_account", privileged: true,  mfa: false, score: 88, tier: "Critical",  last: "2026-04-16 03:00" },
  { user: "dana.kim",      dept: "HR",            type: "human",           privileged: false, mfa: true,  score: 22, tier: "Low",      last: "2026-04-16 09:18" },
  { user: "erin.walsh",    dept: "Legal",         type: "human",           privileged: false, mfa: true,  score: 41, tier: "Low",      last: "2026-04-15 14:10" },
  { user: "bot-monitor",   dept: "DevOps",        type: "bot",             privileged: false, mfa: false, score: 28, tier: "Low",      last: "2026-04-16 09:01" },
  { user: "frank.bell",    dept: "Sales",         type: "human",           privileged: false, mfa: false, score: 61, tier: "Medium",   last: "2026-04-15 19:47" },
  { user: "svc-analytics", dept: "Analytics",     type: "service_account", privileged: false, mfa: false, score: 45, tier: "Medium",   last: "2026-04-16 06:30" },
  { user: "grace.lee",     dept: "Engineering",   type: "human",           privileged: true,  mfa: true,  score: 79, tier: "High",     last: "2026-04-16 09:05" },
  { user: "shared-mgmt",   dept: "Management",    type: "shared",          privileged: true,  mfa: false, score: 95, tier: "Critical",  last: "2026-04-14 11:20" },
  { user: "henry.park",    dept: "Engineering",   type: "human",           privileged: false, mfa: true,  score: 18, tier: "Low",      last: "2026-04-16 08:44" },
];

const LOGIN_EVENTS = [
  { type: "privilege_escalation", user: "svc-deploy",  ip: "10.0.1.45",   country: "US", device: "srv-k8s-01", success: true,  at: "09:14:22" },
  { type: "mfa_bypass",           user: "shared-mgmt", ip: "185.220.101.5",country: "RU", device: "unknown",    success: true,  at: "09:12:07" },
  { type: "failed",               user: "bob.martin",  ip: "203.0.113.42", country: "CN", device: "win-laptop",  success: false, at: "09:10:51" },
  { type: "login",                user: "alice.chen",  ip: "10.0.2.11",   country: "US", device: "mac-pro-4",   success: true,  at: "09:08:33" },
  { type: "failed",               user: "bob.martin",  ip: "203.0.113.42", country: "CN", device: "win-laptop",  success: false, at: "09:08:29" },
  { type: "failed",               user: "bob.martin",  ip: "203.0.113.43", country: "CN", device: "win-laptop",  success: false, at: "09:08:25" },
  { type: "login",                user: "carlos.ruiz", ip: "10.0.3.7",    country: "US", device: "win-desk-12", success: true,  at: "09:05:14" },
  { type: "mfa_bypass",           user: "frank.bell",  ip: "172.16.5.22", country: "UK", device: "iphone-13",   success: true,  at: "09:03:01" },
  { type: "login",                user: "grace.lee",   ip: "10.0.2.44",   country: "US", device: "mac-air-7",   success: true,  at: "08:58:47" },
  { type: "privilege_escalation", user: "svc-backup",  ip: "10.0.1.90",   country: "US", device: "srv-bkp-02",  success: true,  at: "03:00:05" },
  { type: "failed",               user: "dana.kim",    ip: "10.0.4.33",   country: "US", device: "mac-mini-3",  success: false, at: "02:44:18" },
  { type: "login",                user: "erin.walsh",  ip: "10.0.5.19",   country: "IE", device: "win-laptop",  success: true,  at: "14:10:30" },
];

const ACTIVE_RISKS = [
  { type: "impossible_travel",     sev: "Critical", identity: "shared-mgmt",   detected: "09:12" },
  { type: "mfa_bypass",            sev: "Critical", identity: "shared-mgmt",   detected: "09:12" },
  { type: "credential_spray",      sev: "High",     identity: "bob.martin",    detected: "09:09" },
  { type: "privilege_escalation",  sev: "Critical", identity: "svc-deploy",    detected: "09:14" },
  { type: "unusual_hours",         sev: "Medium",   identity: "svc-backup",    detected: "03:00" },
  { type: "excessive_privilege",   sev: "High",     identity: "svc-deploy",    detected: "2026-04-15" },
  { type: "dormant_account",       sev: "Low",      identity: "shared-qa",     detected: "2026-04-14" },
  { type: "new_device",            sev: "Medium",   identity: "frank.bell",    detected: "09:03" },
];

const CERT_QUEUE = [
  { user: "alice.chen",    access: "Admin — Kubernetes",   reviewer: "ops-manager",  next: "2026-04-20" },
  { user: "carlos.ruiz",   access: "Privileged — AWS Root",reviewer: "ciso",          next: "2026-04-18" },
  { user: "shared-mgmt",   access: "Shared — ERP Admin",  reviewer: "ciso",          next: "2026-04-17" },
  { user: "grace.lee",     access: "Admin — GitHub Org",   reviewer: "dev-lead",      next: "2026-04-22" },
  { user: "svc-deploy",    access: "CI/CD — Production",   reviewer: "devsec-lead",   next: "2026-04-19" },
];

// ── Helpers ────────────────────────────────────────────────────

function TierBadge({ tier }: { tier: string }) {
  const cls =
    tier === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    tier === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    tier === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                          "border-border text-muted-foreground bg-muted/20";
  return <Badge className={cn("text-[10px] border", cls)}>{tier}</Badge>;
}

function TypeBadge({ t }: { t: string }) {
  const map: Record<string, string> = {
    human:           "border-blue-500/30 text-blue-400 bg-blue-500/10",
    service_account: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    bot:             "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    shared:          "border-orange-500/30 text-orange-400 bg-orange-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[t] ?? "")}>{t.replace("_", " ")}</Badge>;
}

function EventBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    login:               "border-blue-500/30 text-blue-400 bg-blue-500/10",
    failed:              "border-red-500/30 text-red-400 bg-red-500/10",
    mfa_bypass:          "border-red-600/40 text-red-300 bg-red-600/15",
    privilege_escalation:"border-orange-500/30 text-orange-400 bg-orange-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[type] ?? "")}>{type.replace(/_/g, " ")}</Badge>;
}

function RiskTypeBadge({ t }: { t: string }) {
  const map: Record<string, string> = {
    impossible_travel:    "border-red-500/30 text-red-400 bg-red-500/10",
    credential_spray:     "border-red-500/30 text-red-400 bg-red-500/10",
    mfa_bypass:           "border-red-600/40 text-red-300 bg-red-600/15",
    unusual_hours:        "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    new_device:           "border-blue-500/30 text-blue-400 bg-blue-500/10",
    excessive_privilege:  "border-amber-500/30 text-amber-400 bg-amber-500/10",
    dormant_account:      "border-border text-muted-foreground bg-muted/20",
    privilege_escalation: "border-orange-500/30 text-orange-400 bg-orange-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[t] ?? "")}>{t.replace(/_/g, " ")}</Badge>;
}

function SevDot({ sev }: { sev: string }) {
  const cls =
    sev === "Critical" ? "bg-red-500" :
    sev === "High"     ? "bg-amber-500" :
    sev === "Medium"   ? "bg-yellow-500" : "bg-green-500";
  return <span className={cn("inline-block w-2 h-2 rounded-full shrink-0", cls)} />;
}

// ── Component ──────────────────────────────────────────────────

export default function IdentityAnalyticsDashboard() {
  const [refreshing, setRefreshing] = useState(false);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Identity Analytics"
        description="User risk scoring, anomaly detection, and access certification"
        actions={
          <Button variant="outline" size="sm" onClick={() => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); }} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Identities Tracked"       value="1,247" icon={Users}      trend="up" />
        <KpiCard title="Critical Risk"             value={12}    icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="MFA Off + Privileged"      value={8}     icon={Lock}       trend="up"   className="border-amber-500/20" />
        <KpiCard title="Pending Certifications"    value={23}    icon={UserCheck}  trend="neutral" className="border-yellow-500/20" />
      </div>

      {/* Risk Tier Distribution */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Activity className="h-4 w-4 text-blue-400" />
            Risk Tier Distribution
          </CardTitle>
          <CardDescription className="text-xs">Identity count by risk tier across all 1,247 tracked identities</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {RISK_TIERS.map((tier) => (
            <div key={tier.label} className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className={cn("font-semibold", tier.text)}>{tier.label}</span>
                <span className="font-bold tabular-nums text-foreground">{tier.count.toLocaleString()} identities</span>
              </div>
              <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${tier.width}%` }}
                  transition={{ duration: 0.8, ease: "easeOut" }}
                  className={cn("h-full rounded-full", tier.color)}
                />
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Identity Risk Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Users className="h-4 w-4 text-indigo-400" />
              Identity Risk Table
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">15 identities</Badge>
          </div>
          <CardDescription className="text-xs">All tracked identities sorted by risk score</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Username</TableHead>
                  <TableHead className="text-[11px] h-8">Dept</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Privileged</TableHead>
                  <TableHead className="text-[11px] h-8">MFA</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Score</TableHead>
                  <TableHead className="text-[11px] h-8">Tier</TableHead>
                  <TableHead className="text-[11px] h-8">Last Login</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {IDENTITIES.map((row) => (
                  <TableRow key={row.user} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5">{row.user}</TableCell>
                    <TableCell className="py-2.5">
                      <Badge className="text-[10px] border border-border text-muted-foreground">{row.dept}</Badge>
                    </TableCell>
                    <TableCell className="py-2.5"><TypeBadge t={row.type} /></TableCell>
                    <TableCell className="py-2.5">
                      {row.privileged
                        ? <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">Privileged</Badge>
                        : <span className="text-[10px] text-muted-foreground">—</span>}
                    </TableCell>
                    <TableCell className="py-2.5">
                      <span className={cn("text-xs font-bold", row.mfa ? "text-green-400" : "text-red-400")}>
                        {row.mfa ? "✓" : "✗"}
                      </span>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <div className="flex items-center gap-2">
                        <div className="relative h-1.5 w-20 rounded-full bg-muted/30 overflow-hidden">
                          <div
                            className={cn("h-full rounded-full", row.score >= 80 ? "bg-red-500" : row.score >= 60 ? "bg-amber-500" : row.score >= 40 ? "bg-yellow-500" : "bg-green-500")}
                            style={{ width: `${row.score}%` }}
                          />
                        </div>
                        <span className="text-xs tabular-nums font-medium">{row.score}</span>
                      </div>
                    </TableCell>
                    <TableCell className="py-2.5"><TierBadge tier={row.tier} /></TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{row.last}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Login Event Feed + Active Risks side by side */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Login Event Feed */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan-400" />
              Login Event Feed
            </CardTitle>
            <CardDescription className="text-xs">Recent authentication events (last 12)</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Event</TableHead>
                    <TableHead className="text-[11px] h-8">User</TableHead>
                    <TableHead className="text-[11px] h-8">Src IP</TableHead>
                    <TableHead className="text-[11px] h-8">Geo</TableHead>
                    <TableHead className="text-[11px] h-8">OK</TableHead>
                    <TableHead className="text-[11px] h-8">Time</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {LOGIN_EVENTS.map((ev, i) => (
                    <TableRow key={i} className="hover:bg-muted/30">
                      <TableCell className="py-2"><EventBadge type={ev.type} /></TableCell>
                      <TableCell className="text-xs font-mono py-2 max-w-[80px] truncate">{ev.user}</TableCell>
                      <TableCell className="text-xs font-mono py-2 text-muted-foreground">{ev.ip}</TableCell>
                      <TableCell className="text-xs py-2">{ev.country}</TableCell>
                      <TableCell className="py-2">
                        <span className={cn("text-xs font-bold", ev.success ? "text-green-400" : "text-red-400")}>
                          {ev.success ? "✓" : "✗"}
                        </span>
                      </TableCell>
                      <TableCell className="text-xs tabular-nums py-2 text-muted-foreground">{ev.at}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Active Risks Panel */}
        <Card className="border-red-500/20">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
                <ShieldAlert className="h-4 w-4" />
                Active Risks
              </CardTitle>
              <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">8 open</Badge>
            </div>
            <CardDescription className="text-xs">Open identity risks requiring attention</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {ACTIVE_RISKS.map((r, i) => (
              <div key={i} className="flex items-center gap-3 rounded-lg border border-border bg-muted/10 px-3 py-2.5">
                <SevDot sev={r.sev} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <RiskTypeBadge t={r.type} />
                  </div>
                  <div className="text-xs text-muted-foreground truncate">
                    <span className="font-mono text-foreground">{r.identity}</span>
                    {" · "}detected {r.detected}
                  </div>
                </div>
                <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] shrink-0">
                  Resolve
                </Button>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Certification Queue */}
      <Card className="border-yellow-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-yellow-400">
              <Clock className="h-4 w-4" />
              Certification Queue
            </CardTitle>
            <Badge className="text-[10px] border border-yellow-500/30 text-yellow-400 bg-yellow-500/10">5 pending</Badge>
          </div>
          <CardDescription className="text-xs">Access certifications requiring reviewer approval</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="text-[11px] h-8">Identity</TableHead>
                <TableHead className="text-[11px] h-8">Access Level</TableHead>
                <TableHead className="text-[11px] h-8">Reviewer</TableHead>
                <TableHead className="text-[11px] h-8">Next Review</TableHead>
                <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {CERT_QUEUE.map((c, i) => (
                <TableRow key={i} className="hover:bg-muted/30">
                  <TableCell className="text-xs font-mono py-2.5">{c.user}</TableCell>
                  <TableCell className="text-xs py-2.5 max-w-[180px] truncate">{c.access}</TableCell>
                  <TableCell className="text-xs py-2.5 text-muted-foreground">{c.reviewer}</TableCell>
                  <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{c.next}</TableCell>
                  <TableCell className="py-2.5 text-right">
                    <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] border-green-500/30 text-green-400 hover:bg-green-500/10">
                      Certify
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </motion.div>
  );
}
