/**
 * Bug Bounty Program Tracker
 *
 * Manage researcher submissions, triage findings, and track rewards:
 *   1. KPIs: Total Submissions, Valid Reports, Paid Bounties, Avg Response Time
 *   2. Recent Submissions table (10 rows)
 *   3. Severity Distribution with avg bounty per tier
 *   4. Top Researchers leaderboard
 *   5. Program Stats: MTTD, MTTF, valid_rate, duplicate_rate
 *   6. Scope widget: In Scope / Out of Scope
 *
 * Route: /bug-bounty
 * API: GET /api/v1/bug-bounty/submissions (mock fallback)
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Bug,
  Trophy,
  DollarSign,
  Clock,
  CheckCircle,
  AlertTriangle,
  Users,
  Target,
  ShieldCheck,
  XCircle,
  BarChart3,
  ListChecks,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helpers ─────────────────────────────────────────────
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

// ══════════════════════════════════════════════════════════════
// Types
// ══════════════════════════════════════════════════════════════

type Severity = "P1" | "P2" | "P3" | "P4";
type SubmissionStatus = "New" | "Triaging" | "Valid" | "Duplicate" | "Invalid" | "Rewarded" | "Closed";
type ReputationBadge = "Gold" | "Silver" | "Bronze";

interface Submission {
  id: string;
  researcher_handle: string;
  title: string;
  severity: Severity;
  status: SubmissionStatus;
  bounty_paid: number | null;
  submitted_at: string;
}

interface Researcher {
  handle: string;
  total_submissions: number;
  valid_count: number;
  total_earned: number;
  badge: ReputationBadge;
}

// ══════════════════════════════════════════════════════════════
// Mock Data
// ══════════════════════════════════════════════════════════════

const MOCK_SUBMISSIONS: Submission[] = [
  { id: "BB-1041", researcher_handle: "h4cker99", title: "SQL injection in /api/v1/login", severity: "P1", status: "Rewarded", bounty_paid: 5000, submitted_at: "2026-04-14 09:12" },
  { id: "BB-1042", researcher_handle: "whitehat_alex", title: "IDOR on user profile endpoint", severity: "P2", status: "Valid", bounty_paid: null, submitted_at: "2026-04-14 11:34" },
  { id: "BB-1043", researcher_handle: "sec_researcher_42", title: "XSS in search results", severity: "P3", status: "Triaging", bounty_paid: null, submitted_at: "2026-04-14 13:05" },
  { id: "BB-1044", researcher_handle: "bounty_hunter_pro", title: "Rate limiting bypass on auth endpoint", severity: "P2", status: "Valid", bounty_paid: 1500, submitted_at: "2026-04-14 14:22" },
  { id: "BB-1045", researcher_handle: "null_pointer", title: "Server-side request forgery via webhook URL", severity: "P1", status: "Rewarded", bounty_paid: 7500, submitted_at: "2026-04-13 08:47" },
  { id: "BB-1046", researcher_handle: "0xdeadbeef", title: "Insecure direct object reference on /api/v1/reports", severity: "P2", status: "Rewarded", bounty_paid: 2500, submitted_at: "2026-04-13 16:18" },
  { id: "BB-1047", researcher_handle: "pwnmaster_z", title: "Reflected XSS in error message", severity: "P3", status: "Duplicate", bounty_paid: null, submitted_at: "2026-04-13 10:55" },
  { id: "BB-1048", researcher_handle: "sec_researcher_42", title: "Missing rate limit on password reset", severity: "P3", status: "Valid", bounty_paid: 750, submitted_at: "2026-04-12 14:30" },
  { id: "BB-1049", researcher_handle: "h4cker99", title: "Sensitive data in error stack traces", severity: "P4", status: "Closed", bounty_paid: 200, submitted_at: "2026-04-12 09:10" },
  { id: "BB-1050", researcher_handle: "vuln_watcher", title: "Open redirect in OAuth callback", severity: "P3", status: "New", bounty_paid: null, submitted_at: "2026-04-15 07:44" },
];

const MOCK_RESEARCHERS: Researcher[] = [
  { handle: "null_pointer", total_submissions: 31, valid_count: 18, total_earned: 42500, badge: "Gold" },
  { handle: "h4cker99", total_submissions: 28, valid_count: 14, total_earned: 31200, badge: "Gold" },
  { handle: "bounty_hunter_pro", total_submissions: 22, valid_count: 11, total_earned: 18750, badge: "Silver" },
  { handle: "whitehat_alex", total_submissions: 19, valid_count: 9, total_earned: 12400, badge: "Silver" },
  { handle: "0xdeadbeef", total_submissions: 15, valid_count: 7, total_earned: 8900, badge: "Bronze" },
];

const IN_SCOPE = [
  "*.aldeci.io — all subdomains",
  "suite-api (FastAPI gateway) — all /api/v1/* endpoints",
  "suite-ui (React SPA) — authenticated surfaces",
  "Authentication & session management",
  "Access control / privilege escalation",
  "Data injection (SQLi, XXE, SSTI)",
];

const OUT_OF_SCOPE = [
  "Physical attacks, social engineering",
  "Denial of service (DoS/DDoS)",
  "Third-party services (Slack, Okta, etc.)",
  "scanner outputs / false positives without PoC",
  "suite-ui/aldeci (legacy UI — FROZEN)",
  "Issues already publicly disclosed",
];

// ══════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════

function severityColor(s: Severity) {
  return cn({
    "bg-red-500/15 text-red-400 border-red-500/30": s === "P1",
    "bg-orange-500/15 text-orange-400 border-orange-500/30": s === "P2",
    "bg-yellow-500/15 text-yellow-400 border-yellow-500/30": s === "P3",
    "bg-slate-500/15 text-slate-400 border-slate-500/30": s === "P4",
  });
}

function statusColor(st: SubmissionStatus) {
  return cn({
    "bg-blue-500/15 text-blue-400 border-blue-500/30": st === "New",
    "bg-purple-500/15 text-purple-400 border-purple-500/30": st === "Triaging",
    "bg-emerald-500/15 text-emerald-400 border-emerald-500/30": st === "Valid" || st === "Rewarded",
    "bg-slate-500/15 text-slate-400 border-slate-500/30": st === "Duplicate" || st === "Closed",
    "bg-red-500/15 text-red-400 border-red-500/30": st === "Invalid",
  });
}

function badgeColor(b: ReputationBadge) {
  return cn({
    "bg-yellow-500/15 text-yellow-400 border-yellow-500/30": b === "Gold",
    "bg-slate-400/15 text-slate-300 border-slate-400/30": b === "Silver",
    "bg-amber-700/15 text-amber-600 border-amber-700/30": b === "Bronze",
  });
}

// ══════════════════════════════════════════════════════════════
// Component
// ══════════════════════════════════════════════════════════════

export default function BugBounty() {
  const [_tab, setTab] = useState<"submissions" | "researchers">("submissions");
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/bounty/programs?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/bounty/submissions?org_id=${ORG_ID}`),
    ]).then(([programsResult, submissionsResult]) => {
      const programs    = programsResult.status    === "fulfilled" ? programsResult.value    : null;
      const submissions = submissionsResult.status === "fulfilled" ? submissionsResult.value : null;
      if (programs || submissions) {
        setLiveData({ programs, submissions });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  const displaySubmissions: Submission[] = (() => {
    const raw = liveData?.submissions;
    if (!raw) return MOCK_SUBMISSIONS;
    const arr = Array.isArray(raw) ? raw : raw.items ?? raw.submissions ?? null;
    if (!arr || arr.length === 0) return MOCK_SUBMISSIONS;
    // Normalise API fields to UI shape
    return arr.map((s: any) => ({
      id: s.id ?? s.submission_id ?? "",
      researcher_handle: s.reporter_name ?? s.reporter_email ?? s.researcher_handle ?? "unknown",
      title: s.title ?? "",
      severity: s.severity ?? "P4",
      status: s.status ?? "New",
      bounty_paid: s.reward_amount ?? s.bounty_paid ?? null,
      submitted_at: s.submitted_at ?? s.created_at ?? "",
    }));
  })();

  // KPI overrides from live programs
  const firstProgram = liveData?.programs?.[0] ?? liveData?.programs;
  const liveStats = firstProgram?.metrics ?? null;

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="Bug Bounty Program"
        description="Manage researcher submissions, triage findings, and track rewards"
        icon={<Bug className="h-6 w-6 text-emerald-400" />}
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}>
          <KpiCard title="Total Submissions" value={liveStats?.total_submissions ?? "847"} icon={<Bug className="h-4 w-4" />} trend={{ value: 12, label: "vs last month", direction: "up" }} />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
          <KpiCard title="Valid Reports" value={liveStats?.accepted_count ?? "234"} icon={<CheckCircle className="h-4 w-4" />} trend={{ value: 8, label: "vs last month", direction: "up" }} />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
          <KpiCard title="Paid Bounties" value={liveStats?.total_rewards_paid != null ? `$${Number(liveStats.total_rewards_paid).toLocaleString()}` : "$124,500"} icon={<DollarSign className="h-4 w-4" />} trend={{ value: 5, label: "vs last month", direction: "up" }} />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
          <KpiCard title="Avg Response Time" value={liveStats?.avg_triage_time_hours != null ? `${liveStats.avg_triage_time_hours}h` : "4.2h"} icon={<Clock className="h-4 w-4" />} trend={{ value: 18, label: "faster vs last month", direction: "down" }} />
        </motion.div>
      </div>

      {/* Submissions Table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-sm font-medium">
            <ListChecks className="h-4 w-4 text-muted-foreground" />
            Recent Submissions {dataLoading && <span className="text-xs text-muted-foreground">(loading...)</span>}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Researcher</TableHead>
                <TableHead>Title</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Bounty</TableHead>
                <TableHead>Submitted</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {displaySubmissions.map((row) => (
                <TableRow key={row.id}>
                  <TableCell className="font-mono text-xs text-muted-foreground">{row.id}</TableCell>
                  <TableCell className="font-medium text-sm">{row.researcher_handle}</TableCell>
                  <TableCell className="max-w-[220px] truncate text-sm">{row.title}</TableCell>
                  <TableCell>
                    <Badge variant="outline" className={cn("text-xs", severityColor(row.severity))}>
                      {row.severity}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className={cn("text-xs", statusColor(row.status))}>
                      {row.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-sm">
                    {row.bounty_paid != null ? `$${row.bounty_paid.toLocaleString()}` : <span className="text-muted-foreground">—</span>}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{row.submitted_at}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Severity Distribution */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm font-medium">
              <BarChart3 className="h-4 w-4 text-muted-foreground" />
              Severity Distribution
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            {(
              [
                { sev: "P1" as Severity, count: 12, avg: 6250, label: "Critical" },
                { sev: "P2" as Severity, count: 45, avg: 1800, label: "High" },
                { sev: "P3" as Severity, count: 89, avg: 650, label: "Medium" },
                { sev: "P4" as Severity, count: 128, avg: 200, label: "Low" },
              ] as { sev: Severity; count: number; avg: number; label: string }[]
            ).map(({ sev, count, avg, label }) => (
              <div key={sev} className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2 w-24">
                  <Badge variant="outline" className={cn("text-xs w-10 justify-center", severityColor(sev))}>
                    {sev}
                  </Badge>
                  <span className="text-xs text-muted-foreground">{label}</span>
                </div>
                <div className="flex-1 bg-muted rounded-full h-2">
                  <div
                    className={cn("h-2 rounded-full", {
                      "bg-red-500": sev === "P1",
                      "bg-orange-500": sev === "P2",
                      "bg-yellow-500": sev === "P3",
                      "bg-slate-500": sev === "P4",
                    })}
                    style={{ width: `${Math.round((count / 128) * 100)}%` }}
                  />
                </div>
                <span className="text-sm font-semibold w-8 text-right">{count}</span>
                <span className="text-xs text-muted-foreground w-16 text-right">avg ${avg.toLocaleString()}</span>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Top Researchers */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm font-medium">
              <Trophy className="h-4 w-4 text-muted-foreground" />
              Top Researchers
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            {MOCK_RESEARCHERS.map((r, idx) => (
              <div key={r.handle} className="flex items-center gap-3">
                <span className="text-xs text-muted-foreground w-4">#{idx + 1}</span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium truncate">{r.handle}</span>
                    <Badge variant="outline" className={cn("text-xs", badgeColor(r.badge))}>
                      {r.badge}
                    </Badge>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {r.valid_count}/{r.total_submissions} valid
                  </div>
                </div>
                <span className="text-sm font-semibold text-emerald-400">${r.total_earned.toLocaleString()}</span>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Program Stats */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm font-medium">
              <ShieldCheck className="h-4 w-4 text-muted-foreground" />
              Program Stats
            </CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-4">
            {[
              { label: "MTTD", value: "4.2h", sub: "mean time to triage", icon: <Clock className="h-4 w-4 text-blue-400" /> },
              { label: "MTTF", value: "6.8d", sub: "mean time to fix", icon: <AlertTriangle className="h-4 w-4 text-orange-400" /> },
              { label: "Valid Rate", value: "27.6%", sub: "of total submissions", icon: <CheckCircle className="h-4 w-4 text-emerald-400" /> },
              { label: "Dupe Rate", value: "18.3%", sub: "of total submissions", icon: <XCircle className="h-4 w-4 text-slate-400" /> },
            ].map(({ label, value, sub, icon }) => (
              <div key={label} className="flex flex-col gap-1">
                <div className="flex items-center gap-1.5">{icon}<span className="text-xs text-muted-foreground">{label}</span></div>
                <span className="text-xl font-bold">{value}</span>
                <span className="text-xs text-muted-foreground">{sub}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Scope Widget */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-emerald-400">
              <Target className="h-4 w-4" />
              In Scope
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="flex flex-col gap-2">
              {IN_SCOPE.map((item) => (
                <li key={item} className="flex items-start gap-2 text-sm">
                  <CheckCircle className="h-3.5 w-3.5 mt-0.5 text-emerald-400 shrink-0" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-red-400">
              <XCircle className="h-4 w-4" />
              Out of Scope
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="flex flex-col gap-2">
              {OUT_OF_SCOPE.map((item) => (
                <li key={item} className="flex items-start gap-2 text-sm">
                  <XCircle className="h-3.5 w-3.5 mt-0.5 text-red-400 shrink-0" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
