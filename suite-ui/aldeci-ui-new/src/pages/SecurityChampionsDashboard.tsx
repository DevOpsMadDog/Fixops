// FOLDED into Admin hero 2026-04-27 — preserve for git history
// Tab path: /admin?tab=champions
/**
 * Security Champions Dashboard
 *
 * Track champion activities, certifications, awareness campaigns, and program health.
 *   1. KPIs: Active Champions, Certifications Valid, Active Campaigns, Avg Points Score
 *   2. Champions leaderboard — 15 rows sorted by points desc
 *   3. Activity feed — 20 activity rows
 *   4. Certifications panel — 12 cert rows
 *   5. Active campaigns — 5 campaign cards
 *   6. Level distribution
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Award, Users, Shield, Star, RefreshCw, BookOpen, Trophy, CheckCircle, Clock } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

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
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const CHAMPIONS = [
  { rank: 1,  name: "Alex Chen",       department: "Engineering", team: "Platform",   level: "platinum", points: 2847, recent_activity: "Led secure code review for auth module", certs: 4 },
  { rank: 2,  name: "Sarah Kim",        department: "Security",    team: "AppSec",     level: "gold",     points: 1923, recent_activity: "Delivered phishing awareness training",    certs: 5 },
  { rank: 3,  name: "Marcus Webb",      department: "DevOps",      team: "Platform",   level: "gold",     points: 1654, recent_activity: "Fixed critical misconfig in CI pipeline",   certs: 3 },
  { rank: 4,  name: "Priya Patel",      department: "Engineering", team: "Backend",    level: "gold",     points: 1432, recent_activity: "Reported SSRF vulnerability in API",        certs: 3 },
  { rank: 5,  name: "James O'Brien",    department: "IT Ops",      team: "Infra",      level: "silver",   points: 987,  recent_activity: "Completed CISSP certification",             certs: 2 },
  { rank: 6,  name: "Diana Flores",     department: "Engineering", team: "Frontend",   level: "silver",   points: 874,  recent_activity: "Mentored 3 junior devs on OWASP Top 10",   certs: 2 },
  { rank: 7,  name: "Raj Gupta",        department: "Data",        team: "Analytics",  level: "silver",   points: 812,  recent_activity: "Identified exposed PII in data pipeline",   certs: 1 },
  { rank: 8,  name: "Emily Thornton",   department: "Engineering", team: "Mobile",     level: "silver",   points: 763,  recent_activity: "Added SAST scan to mobile build",           certs: 2 },
  { rank: 9,  name: "Carlos Mendez",    department: "DevOps",      team: "SRE",        level: "silver",   points: 698,  recent_activity: "Hardened Kubernetes cluster config",         certs: 1 },
  { rank: 10, name: "Nadia Hassan",     department: "Product",     team: "Core",       level: "bronze",   points: 521,  recent_activity: "Participated in threat modeling workshop",  certs: 1 },
  { rank: 11, name: "Luke Patterson",   department: "Engineering", team: "Backend",    level: "bronze",   points: 487,  recent_activity: "Completed Security+ certification",         certs: 1 },
  { rank: 12, name: "Yuki Tanaka",      department: "Security",    team: "GRC",        level: "bronze",   points: 443,  recent_activity: "Contributed to ISO 27001 audit evidence",  certs: 2 },
  { rank: 13, name: "Omar Shaikh",      department: "IT Ops",      team: "Helpdesk",   level: "bronze",   points: 398,  recent_activity: "Reported social engineering attempt",       certs: 0 },
  { rank: 14, name: "Grace Liu",        department: "Engineering", team: "Platform",   level: "bronze",   points: 356,  recent_activity: "Fixed secrets leak in git history",         certs: 1 },
  { rank: 15, name: "Tom Bradley",      department: "Data",        team: "BI",         level: "bronze",   points: 312,  recent_activity: "Completed GDPR data handling training",     certs: 0 },
];

const ACTIVITIES = [
  { champion: "Alex Chen",      type: "code_review",         points: 120, completed_at: "2026-04-16 09:15", department: "Engineering", desc: "Security review of OAuth token refresh logic" },
  { champion: "Sarah Kim",      type: "awareness_campaign",  points: 200, completed_at: "2026-04-16 08:30", department: "Security",    desc: "Q2 phishing awareness campaign kickoff" },
  { champion: "Marcus Webb",    type: "vulnerability_report", points: 300, completed_at: "2026-04-15 17:45", department: "DevOps",      desc: "CI pipeline secrets exposure — medium severity" },
  { champion: "Priya Patel",    type: "vulnerability_report", points: 400, completed_at: "2026-04-15 16:20", department: "Engineering", desc: "SSRF vulnerability in internal API gateway" },
  { champion: "James O'Brien",  type: "training",            points:  50, completed_at: "2026-04-15 14:00", department: "IT Ops",      desc: "Completed CISSP exam — passed" },
  { champion: "Diana Flores",   type: "mentoring",           points:  75, completed_at: "2026-04-15 13:30", department: "Engineering", desc: "OWASP Top 10 session with frontend team" },
  { champion: "Alex Chen",      type: "tool_contribution",   points: 150, completed_at: "2026-04-15 11:00", department: "Engineering", desc: "Custom Semgrep rule for SQL injection patterns" },
  { champion: "Raj Gupta",      type: "vulnerability_report", points: 250, completed_at: "2026-04-15 10:15", department: "Data",        desc: "PII exposure in analytics export endpoint" },
  { champion: "Emily Thornton", type: "tool_contribution",   points:  90, completed_at: "2026-04-14 17:30", department: "Engineering", desc: "Integrated SAST into iOS build pipeline" },
  { champion: "Carlos Mendez",  type: "code_review",         points:  80, completed_at: "2026-04-14 16:00", department: "DevOps",      desc: "K8s RBAC config review for production cluster" },
  { champion: "Sarah Kim",      type: "training",            points:  60, completed_at: "2026-04-14 14:00", department: "Security",    desc: "Cloud security fundamentals — internal workshop" },
  { champion: "Nadia Hassan",   type: "training",            points:  40, completed_at: "2026-04-14 13:00", department: "Product",     desc: "Threat modeling workshop — 3h session" },
  { champion: "Luke Patterson", type: "training",            points:  50, completed_at: "2026-04-14 11:30", department: "Engineering", desc: "CompTIA Security+ — passed exam" },
  { champion: "Marcus Webb",    type: "incident_response",   points: 180, completed_at: "2026-04-14 09:00", department: "DevOps",      desc: "Assisted in P2 incident — log4j scanner false positive" },
  { champion: "Yuki Tanaka",    type: "awareness_campaign",  points: 100, completed_at: "2026-04-13 16:45", department: "Security",    desc: "ISO 27001 evidence collection campaign" },
  { champion: "Omar Shaikh",    type: "vulnerability_report", points: 150, completed_at: "2026-04-13 15:20", department: "IT Ops",      desc: "Social engineering attempt reported to SecOps" },
  { champion: "Grace Liu",      type: "vulnerability_report", points: 200, completed_at: "2026-04-13 14:00", department: "Engineering", desc: "Git history secrets leak — credentials rotated" },
  { champion: "Alex Chen",      type: "mentoring",           points:  75, completed_at: "2026-04-13 12:30", department: "Engineering", desc: "Secure coding practices — onboarding session" },
  { champion: "Diana Flores",   type: "code_review",         points:  90, completed_at: "2026-04-13 11:00", department: "Engineering", desc: "Frontend XSS review for new form components" },
  { champion: "Tom Bradley",    type: "training",            points:  35, completed_at: "2026-04-13 10:00", department: "Data",        desc: "GDPR data handling and retention training module" },
];

const CERTIFICATIONS = [
  { champion: "Sarah Kim",      cert: "CISSP",              provider: "ISC2",      expires: "2028-03-15", status: "valid",         days: 699 },
  { champion: "Alex Chen",      cert: "OSCP",               provider: "OffSec",    expires: "2027-06-01", status: "valid",         days: 411 },
  { champion: "Alex Chen",      cert: "AWS Security",       provider: "AWS",       expires: "2026-11-30", status: "valid",         days: 228 },
  { champion: "Marcus Webb",    cert: "GCP Security",       provider: "Google",    expires: "2027-01-15", status: "valid",         days: 274 },
  { champion: "James O'Brien",  cert: "CISSP",              provider: "ISC2",      expires: "2029-04-10", status: "valid",         days: 1089 },
  { champion: "Sarah Kim",      cert: "CISM",               provider: "ISACA",     expires: "2026-07-01", status: "valid",         days: 76 },
  { champion: "Emily Thornton", cert: "CompTIA Security+",  provider: "CompTIA",   expires: "2026-05-30", status: "expiring_soon", days: 44 },
  { champion: "Diana Flores",   cert: "CompTIA Security+",  provider: "CompTIA",   expires: "2026-05-15", status: "expiring_soon", days: 29 },
  { champion: "Priya Patel",    cert: "AWS Security",       provider: "AWS",       expires: "2026-04-30", status: "expiring_soon", days: 14 },
  { champion: "Carlos Mendez",  cert: "GCP Security",       provider: "Google",    expires: "2026-04-20", status: "expiring_soon", days: 4 },
  { champion: "Luke Patterson", cert: "CompTIA Security+",  provider: "CompTIA",   expires: "2026-02-28", status: "expired",       days: -47 },
  { champion: "Yuki Tanaka",    cert: "CEH",                provider: "EC-Council", expires: "2026-01-15", status: "expired",      days: -91 },
];

const CAMPAIGNS = [
  {
    title: "Q2 Phishing Simulation",
    type: "phishing_simulation",
    department: "All Departments",
    participants: 412,
    total: 480,
    status: "active",
    start: "2026-04-01",
    end: "2026-04-30",
  },
  {
    title: "Secure Coding Bootcamp",
    type: "training",
    department: "Engineering",
    participants: 67,
    total: 80,
    status: "active",
    start: "2026-04-08",
    end: "2026-04-22",
  },
  {
    title: "Data Privacy Awareness",
    type: "awareness",
    department: "Data & Product",
    participants: 54,
    total: 60,
    status: "active",
    start: "2026-04-10",
    end: "2026-04-24",
  },
  {
    title: "Cloud Security Basics",
    type: "training",
    department: "DevOps",
    participants: 28,
    total: 35,
    status: "active",
    start: "2026-04-14",
    end: "2026-04-28",
  },
  {
    title: "OWASP Top 10 Workshop",
    type: "training",
    department: "Engineering",
    participants: 72,
    total: 80,
    status: "active",
    start: "2026-04-15",
    end: "2026-05-06",
  },
];

const LEVEL_DISTRIBUTION = [
  { level: "Platinum", count: 1,  threshold: 2500, color: "bg-purple-500",  text: "text-purple-400", next: "—" },
  { level: "Gold",     count: 4,  threshold: 1000, color: "bg-yellow-500",  text: "text-yellow-400", next: "2500 pts" },
  { level: "Silver",   count: 5,  threshold: 500,  color: "bg-gray-400",    text: "text-gray-300",   next: "1000 pts" },
  { level: "Bronze",   count: 6,  threshold: 0,    color: "bg-orange-600",  text: "text-orange-400", next: "500 pts" },
];

// ── Helpers ──────────────────────────────────────────────────────

function LevelBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    platinum: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    gold:     "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    silver:   "border-gray-400/30 text-gray-300 bg-gray-500/10",
    bronze:   "border-orange-600/30 text-orange-400 bg-orange-600/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[level] ?? "")}>{level}</Badge>;
}

function ActivityTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    training:             "border-blue-500/30 text-blue-400 bg-blue-500/10",
    mentoring:            "border-green-500/30 text-green-400 bg-green-500/10",
    code_review:          "border-purple-500/30 text-purple-400 bg-purple-500/10",
    incident_response:    "border-red-500/30 text-red-400 bg-red-500/10",
    awareness_campaign:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    vulnerability_report: "border-orange-500/30 text-orange-400 bg-orange-500/10",
    tool_contribution:    "border-indigo-500/30 text-indigo-400 bg-indigo-500/10",
  };
  const labels: Record<string, string> = {
    training:             "Training",
    mentoring:            "Mentoring",
    code_review:          "Code Review",
    incident_response:    "Incident Response",
    awareness_campaign:   "Awareness",
    vulnerability_report: "Vuln Report",
    tool_contribution:    "Tool Contrib",
  };
  return <Badge className={cn("text-[10px] border", map[type] ?? "")}>{labels[type] ?? type}</Badge>;
}

function CertStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    valid:         "border-green-500/30 text-green-400 bg-green-500/10",
    expiring_soon: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    expired:       "border-red-500/30 text-red-400 bg-red-500/10",
  };
  const labels: Record<string, string> = {
    valid:         "Valid",
    expiring_soon: "Expiring Soon",
    expired:       "Expired",
  };
  return <Badge className={cn("text-[10px] border", map[status] ?? "")}>{labels[status] ?? status}</Badge>;
}

function CampaignTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    phishing_simulation: "border-red-500/30 text-red-400 bg-red-500/10",
    awareness:           "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    training:            "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  const labels: Record<string, string> = {
    phishing_simulation: "Phishing Sim",
    awareness:           "Awareness",
    training:            "Training",
  };
  return <Badge className={cn("text-[10px] border", map[type] ?? "")}>{labels[type] ?? type}</Badge>;
}

function RankBadge({ rank }: { rank: number }) {
  const cls =
    rank === 1 ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" :
    rank === 2 ? "bg-gray-400/20 text-gray-300 border-gray-400/30" :
    rank === 3 ? "bg-orange-600/20 text-orange-400 border-orange-600/30" :
                 "bg-muted/20 text-muted-foreground border-border/50";
  return (
    <span className={cn("inline-flex items-center justify-center w-6 h-6 rounded-full text-[10px] font-bold border", cls)}>
      {rank}
    </span>
  );
}

const MAX_POINTS = 2847;

// ── Component ──────────────────────────────────────────────────

export default function SecurityChampionsDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/security-champions/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/security-champions/champions?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/security-champions/campaigns?org_id=${ORG_ID}`),
    ]).then(([statsResult, championsResult, campaignsResult]) => {
      const stats     = statsResult.status     === "fulfilled" ? statsResult.value     : null;
      const champions = championsResult.status === "fulfilled" ? championsResult.value : null;
      const campaigns = campaignsResult.status === "fulfilled" ? campaignsResult.value : null;
      if (stats || champions || campaigns) {
        setLiveData({ stats, champions, campaigns });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Security Champions Program"
        description="Track champion activities, certifications, awareness campaigns, and program health"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Champions"      value={liveData?.stats?.active_champions ?? 34}                    icon={Users}  trend="up"   className="border-purple-500/20" />
        <KpiCard title="Certifications Valid"  value={liveData?.stats?.valid_certifications ?? 89}                icon={Award}  trend="up"   className="border-green-500/20" />
        <KpiCard title="Active Campaigns"      value={liveData?.stats?.active_campaigns ?? 5}                     icon={Shield} trend="flat" className="border-blue-500/20" />
        <KpiCard title="Avg Points Score"      value={liveData?.stats?.avg_points_score ?? "847"}                 icon={Star}   trend="up"   className="border-yellow-500/20" />
      </div>

      {/* Champions Leaderboard */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Trophy className="h-4 w-4 text-yellow-400" />
            Champions Leaderboard
          </CardTitle>
          <CardDescription className="text-xs">Ranked by total points — {CHAMPIONS.length} active champions shown</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8 w-10">Rank</TableHead>
                  <TableHead className="text-[11px] h-8">Champion</TableHead>
                  <TableHead className="text-[11px] h-8">Department</TableHead>
                  <TableHead className="text-[11px] h-8">Team</TableHead>
                  <TableHead className="text-[11px] h-8">Level</TableHead>
                  <TableHead className="text-[11px] h-8">Points</TableHead>
                  <TableHead className="text-[11px] h-8">Recent Activity</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Certs</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.champions?.items ?? liveData?.champions ?? CHAMPIONS).map((c: any) => (
                  <TableRow key={c.rank} className="hover:bg-muted/30">
                    <TableCell className="py-2.5"><RankBadge rank={c.rank} /></TableCell>
                    <TableCell className="text-xs font-semibold py-2.5">{c.name}</TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{c.department}</TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{c.team}</TableCell>
                    <TableCell className="py-2.5"><LevelBadge level={c.level} /></TableCell>
                    <TableCell className="py-2.5">
                      <div className="flex items-center gap-2">
                        <div className="relative h-1.5 w-16 rounded-full bg-muted/30 overflow-hidden">
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${(c.points / MAX_POINTS) * 100}%` }}
                            transition={{ duration: 0.7, ease: "easeOut" }}
                            className={cn(
                              "h-full rounded-full",
                              c.level === "platinum" ? "bg-purple-500" :
                              c.level === "gold"     ? "bg-yellow-500" :
                              c.level === "silver"   ? "bg-gray-400"   : "bg-orange-600"
                            )}
                          />
                        </div>
                        <span className="text-xs font-bold tabular-nums">{c.points.toLocaleString()}</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-[10px] py-2.5 text-muted-foreground max-w-[200px] truncate">{c.recent_activity}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-right font-medium">{c.certs}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Activity Feed + Certifications */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Activity Feed */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BookOpen className="h-4 w-4 text-indigo-400" />
              Recent Activity Feed
            </CardTitle>
            <CardDescription className="text-xs">Latest champion activities and point awards</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Champion</TableHead>
                    <TableHead className="text-[11px] h-8">Activity</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Pts</TableHead>
                    <TableHead className="text-[11px] h-8">Date</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {ACTIVITIES.map((a, i) => (
                    <TableRow key={i} className="hover:bg-muted/30">
                      <TableCell className="text-xs font-medium py-2">{a.champion}</TableCell>
                      <TableCell className="py-2"><ActivityTypeBadge type={a.type} /></TableCell>
                      <TableCell className="text-xs py-2 tabular-nums font-bold text-green-400 text-right">+{a.points}</TableCell>
                      <TableCell className="text-[10px] py-2 tabular-nums text-muted-foreground">{a.completed_at.slice(0, 10)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Certifications */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-green-400" />
              Certifications
            </CardTitle>
            <CardDescription className="text-xs">Champion certification status and expiry tracking</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Champion</TableHead>
                    <TableHead className="text-[11px] h-8">Certification</TableHead>
                    <TableHead className="text-[11px] h-8">Provider</TableHead>
                    <TableHead className="text-[11px] h-8">Expires</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {CERTIFICATIONS.map((cert, i) => (
                    <TableRow key={i} className="hover:bg-muted/30">
                      <TableCell className="text-xs font-medium py-2">{cert.champion}</TableCell>
                      <TableCell className="text-xs py-2 font-semibold">{cert.cert}</TableCell>
                      <TableCell className="text-[10px] py-2 text-muted-foreground">{cert.provider}</TableCell>
                      <TableCell className="text-[10px] py-2 tabular-nums text-muted-foreground">{cert.expires}</TableCell>
                      <TableCell className="py-2"><CertStatusBadge status={cert.status} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Active Campaigns */}
      <div>
        <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <Shield className="h-4 w-4 text-blue-400" />
          Active Campaigns
        </h3>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
          {(liveData?.campaigns?.items ?? liveData?.campaigns ?? CAMPAIGNS).map((c: any) => {
            const pct = Math.round((c.participants / c.total) * 100);
            return (
              <Card key={c.title} className="border-blue-500/20">
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between gap-2">
                    <CardTitle className="text-xs font-semibold leading-tight">{c.title}</CardTitle>
                    <Badge className="text-[9px] border border-green-500/30 text-green-400 bg-green-500/10 shrink-0">Active</Badge>
                  </div>
                  <CampaignTypeBadge type={c.type} />
                </CardHeader>
                <CardContent className="pt-0 space-y-2">
                  <p className="text-[10px] text-muted-foreground">{c.department}</p>
                  <div className="space-y-1">
                    <div className="flex items-center justify-between text-[10px]">
                      <span className="text-muted-foreground">Completion</span>
                      <span className="font-bold tabular-nums">{c.participants}/{c.total} ({pct}%)</span>
                    </div>
                    <Progress value={pct} className="h-1.5" />
                  </div>
                  <div className="flex items-center gap-1 text-[9px] text-muted-foreground">
                    <Clock className="h-2.5 w-2.5" />
                    <span>{c.start} → {c.end}</span>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>

      {/* Level Distribution */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Star className="h-4 w-4 text-yellow-400" />
            Level Distribution
          </CardTitle>
          <CardDescription className="text-xs">Champion tier breakdown and promotion thresholds</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            {LEVEL_DISTRIBUTION.map((l) => (
              <div key={l.level} className="flex flex-col items-center gap-2 p-4 rounded-lg bg-muted/20 border border-border/40">
                <div className={cn("w-10 h-10 rounded-full flex items-center justify-center", l.color + "/20", "border-2", l.color.replace("bg-", "border-"))}>
                  <Trophy className={cn("h-5 w-5", l.text)} />
                </div>
                <span className={cn("text-xs font-bold", l.text)}>{l.level}</span>
                <span className="text-2xl font-black tabular-nums">{l.count}</span>
                {l.next !== "—" && (
                  <span className="text-[9px] text-muted-foreground text-center">Next: {l.next}</span>
                )}
                {l.next === "—" && (
                  <span className="text-[9px] text-muted-foreground text-center">Top tier</span>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
