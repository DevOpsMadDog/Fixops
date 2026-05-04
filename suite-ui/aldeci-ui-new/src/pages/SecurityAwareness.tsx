// FOLDED into Admin hero 2026-04-27 — preserve for git history
// Tab path: /admin?tab=awareness
/**
 * Security Awareness Training Tracker
 *
 * Phishing simulations, training completion, and human risk scores dashboard.
 * Route: /security-awareness
 *
 * Features:
 *   1. KPI row: completion rate, phishing click rate, high risk users, avg risk score
 *   2. Phishing Campaign Results table with click-rate color coding
 *   3. Training Completion by Department (horizontal progress bars)
 *   4. High Risk Users panel with Assign Training action
 *   5. Upcoming Training calendar cards
 *   6. 6-month human risk score trend chart
 *
 * API: GET /api/v1/security-awareness/campaigns
 *      GET /api/v1/security-awareness/completion
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Users,
  AlertTriangle,
  CheckCircle2,
  TrendingDown,
  Mail,
  BookOpen,
  Calendar,
  ShieldAlert,
  UserX,
  Award,
  BarChart3,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const ORG_ID = "default";

function getApiKey() {
  return (
    (typeof window !== "undefined" && localStorage.getItem("aldeci_api_key")) ||
    import.meta.env.VITE_API_KEY ||
    "dev-key"
  );
}

async function apiFetch(path: string) {
  const res = await fetch(`/api/v1${path}`, {
    headers: { "X-API-Key": getApiKey() },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

interface PhishingCampaign {
  id: string;
  campaign_name: string;
  sent_count: number;
  clicked_count: number;
  reported_count: number;
  open_rate: number;
  click_rate: number;
  credential_submitted_rate: number;
  date: string;
}

interface DepartmentCompletion {
  department: string;
  completion_rate: number;
}

interface HighRiskUser {
  id: string;
  user_masked: string;
  department: string;
  phishing_clicks: number;
  training_skips: number;
  risk_score: number;
}

interface UpcomingTraining {
  id: string;
  title: string;
  mandatory: boolean;
  due_date: string;
  completion_rate: number;
}

// ═══════════════════════════════════════════════════════════
// No mock data — all state initialised empty
// ═══════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

function riskScoreColor(score: number): string {
  if (score >= 80) return "text-red-400 bg-red-500/10 border-red-500/20";
  if (score >= 60) return "text-orange-400 bg-orange-500/10 border-orange-500/20";
  if (score >= 40) return "text-yellow-400 bg-yellow-500/10 border-yellow-500/20";
  return "text-green-400 bg-green-500/10 border-green-500/20";
}

function completionBarColor(rate: number): string {
  if (rate >= 90) return "bg-green-500";
  if (rate >= 75) return "bg-blue-500";
  if (rate >= 60) return "bg-yellow-500";
  return "bg-red-500";
}

// ═══════════════════════════════════════════════════════════
// Phishing Campaigns Table
// ═══════════════════════════════════════════════════════════

function CampaignsTable({ campaigns }: { campaigns: PhishingCampaign[] }) {
  return (
    <Card className="border border-border">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2">
          <Mail className="w-4 h-4 text-orange-400" />
          Phishing Campaign Results
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-xs text-muted-foreground">
                <th className="py-2.5 px-4 text-left font-medium">Campaign</th>
                <th className="py-2.5 px-4 text-right font-medium">Sent</th>
                <th className="py-2.5 px-4 text-right font-medium">Clicked</th>
                <th className="py-2.5 px-4 text-right font-medium">Reported</th>
                <th className="py-2.5 px-4 text-right font-medium">Open Rate</th>
                <th className="py-2.5 px-4 text-right font-medium">Click Rate</th>
                <th className="py-2.5 px-4 text-right font-medium">Creds Submitted</th>
                <th className="py-2.5 px-4 text-left font-medium">Date</th>
              </tr>
            </thead>
            <tbody>
              {campaigns.map((c, i) => (
                <motion.tr
                  key={c.id}
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.04, duration: 0.22 }}
                  className="border-b border-border/50 hover:bg-accent/30 transition-colors"
                >
                  <td className="py-3 px-4">
                    <span className="text-sm font-medium">{c.campaign_name}</span>
                  </td>
                  <td className="py-3 px-4 text-right text-xs text-muted-foreground">
                    {c.sent_count.toLocaleString()}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <span
                      className={cn(
                        "text-xs font-semibold",
                        c.click_rate > 15 ? "text-red-400" : "text-muted-foreground"
                      )}
                    >
                      {c.clicked_count}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    <span className="text-xs font-semibold text-green-400">
                      {c.reported_count}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right text-xs text-muted-foreground">
                    {c.open_rate.toFixed(1)}%
                  </td>
                  <td className="py-3 px-4 text-right">
                    <span
                      className={cn(
                        "text-xs font-semibold",
                        c.click_rate > 15 ? "text-red-400" : "text-green-400"
                      )}
                    >
                      {c.click_rate.toFixed(1)}%
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    <span
                      className={cn(
                        "text-xs font-semibold",
                        c.credential_submitted_rate > 10
                          ? "text-red-400"
                          : "text-muted-foreground"
                      )}
                    >
                      {c.credential_submitted_rate.toFixed(1)}%
                    </span>
                  </td>
                  <td className="py-3 px-4 text-xs text-muted-foreground">
                    {c.date}
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Department Completion Bars
// ═══════════════════════════════════════════════════════════

function DepartmentCompletion({ departments }: { departments: DepartmentCompletion[] }) {
  return (
    <Card className="border border-border">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2">
          <BookOpen className="w-4 h-4 text-blue-400" />
          Training Completion by Department
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {departments.map((dept, i) => (
            <motion.div
              key={dept.department}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.05, duration: 0.22 }}
              className="space-y-1"
            >
              <div className="flex items-center justify-between text-xs">
                <span className="text-foreground font-medium">{dept.department}</span>
                <span
                  className={cn(
                    "font-semibold",
                    dept.completion_rate >= 90
                      ? "text-green-400"
                      : dept.completion_rate >= 75
                      ? "text-blue-400"
                      : dept.completion_rate >= 60
                      ? "text-yellow-400"
                      : "text-red-400"
                  )}
                >
                  {dept.completion_rate}%
                </span>
              </div>
              <div className="h-2 w-full rounded-full bg-accent overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${dept.completion_rate}%` }}
                  transition={{ delay: i * 0.05 + 0.1, duration: 0.5, ease: "easeOut" }}
                  className={cn("h-full rounded-full", completionBarColor(dept.completion_rate))}
                />
              </div>
            </motion.div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// High Risk Users Panel
// ═══════════════════════════════════════════════════════════

function HighRiskUsersPanel({ users }: { users: HighRiskUser[] }) {
  return (
    <Card className="border border-border">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2">
          <UserX className="w-4 h-4 text-red-400" />
          High Risk Users
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-xs text-muted-foreground">
                <th className="py-2.5 px-4 text-left font-medium">User</th>
                <th className="py-2.5 px-4 text-left font-medium">Department</th>
                <th className="py-2.5 px-4 text-right font-medium">Phishing Clicks</th>
                <th className="py-2.5 px-4 text-right font-medium">Training Skips</th>
                <th className="py-2.5 px-4 text-center font-medium">Risk Score</th>
                <th className="py-2.5 px-4 text-center font-medium">Action</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user, i) => (
                <motion.tr
                  key={user.id}
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.03, duration: 0.2 }}
                  className="border-b border-border/50 hover:bg-accent/30 transition-colors"
                >
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      <div className="w-7 h-7 rounded-full bg-accent flex items-center justify-center text-xs font-semibold text-foreground">
                        {user.user_masked}
                      </div>
                    </div>
                  </td>
                  <td className="py-3 px-4 text-xs text-muted-foreground">
                    {user.department}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <span
                      className={cn(
                        "text-xs font-semibold",
                        user.phishing_clicks >= 5 ? "text-red-400" : "text-orange-400"
                      )}
                    >
                      {user.phishing_clicks}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    <span
                      className={cn(
                        "text-xs font-semibold",
                        user.training_skips >= 3 ? "text-red-400" : "text-yellow-400"
                      )}
                    >
                      {user.training_skips}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-center">
                    <Badge
                      className={cn(
                        "text-xs border font-semibold",
                        riskScoreColor(user.risk_score)
                      )}
                    >
                      {user.risk_score}
                    </Badge>
                  </td>
                  <td className="py-3 px-4 text-center">
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-7 px-2.5 text-xs"
                    >
                      Assign Training
                    </Button>
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Upcoming Training Cards
// ═══════════════════════════════════════════════════════════

function UpcomingTrainings({ trainings }: { trainings: UpcomingTraining[] }) {
  return (
    <Card className="border border-border">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2">
          <Calendar className="w-4 h-4 text-purple-400" />
          Upcoming Training
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {trainings.map((t, i) => (
            <motion.div
              key={t.id}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.06, duration: 0.22 }}
              className="flex flex-col gap-2 p-3 rounded-lg border border-border/60 bg-accent/20"
            >
              <div className="flex items-start justify-between gap-2">
                <span className="text-sm font-medium text-foreground leading-snug">
                  {t.title}
                </span>
                <Badge
                  className={cn(
                    "text-[10px] border shrink-0",
                    t.mandatory
                      ? "text-red-400 bg-red-500/10 border-red-500/20"
                      : "text-blue-400 bg-blue-500/10 border-blue-500/20"
                  )}
                >
                  {t.mandatory ? "Mandatory" : "Optional"}
                </Badge>
              </div>
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span>Due: {t.due_date}</span>
                <span
                  className={cn(
                    "font-semibold",
                    t.completion_rate >= 50 ? "text-green-400" : "text-yellow-400"
                  )}
                >
                  {t.completion_rate}% complete
                </span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-accent overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${t.completion_rate}%` }}
                  transition={{ delay: i * 0.06 + 0.15, duration: 0.45, ease: "easeOut" }}
                  className={cn(
                    "h-full rounded-full",
                    t.completion_rate >= 50 ? "bg-green-500" : "bg-yellow-500"
                  )}
                />
              </div>
            </motion.div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Risk Trend Chart (div-based bar chart)
// ═══════════════════════════════════════════════════════════

interface RiskTrendPoint { month: string; score: number; }

function RiskTrendChart({ data }: { data: RiskTrendPoint[] }) {
  if (!data.length) return (
    <Card className="border border-border">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2">
          <BarChart3 className="w-4 h-4 text-cyan-400" />
          6-Month Human Risk Score Trend
        </CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-xs text-muted-foreground">No trend data available.</p>
      </CardContent>
    </Card>
  );

  const maxScore = Math.max(...data.map((d) => d.score), 1);

  return (
    <Card className="border border-border">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2">
          <BarChart3 className="w-4 h-4 text-cyan-400" />
          6-Month Human Risk Score Trend
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-end gap-3 h-32">
          {data.map((d, i) => {
            const heightPct = (d.score / maxScore) * 100;
            return (
              <div key={d.month} className="flex flex-col items-center gap-1.5 flex-1">
                <span className="text-[10px] font-semibold text-cyan-400">{d.score}</span>
                <motion.div
                  initial={{ height: 0 }}
                  animate={{ height: `${heightPct}%` }}
                  transition={{ delay: i * 0.08, duration: 0.45, ease: "easeOut" }}
                  className={cn(
                    "w-full rounded-t",
                    d.score >= 55 ? "bg-red-500/60" : d.score >= 45 ? "bg-orange-500/60" : "bg-cyan-500/60"
                  )}
                  style={{ minHeight: "4px" }}
                />
                <span className="text-[10px] text-muted-foreground">{d.month}</span>
              </div>
            );
          })}
        </div>
        <p className="text-[11px] text-muted-foreground mt-3 flex items-center gap-1.5">
          <TrendingDown className="w-3.5 h-3.5 text-green-400" />
          Org-wide risk trend over the last 6 months
        </p>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════

interface AwarenessStats {
  avg_completion_pct: number | null;
  avg_phishing_click_rate: number | null;
  high_risk_count: number | null;
  avg_risk_score: number | null;
}

export default function SecurityAwareness() {
  const [loading, setLoading]                   = useState(true);
  const [stats, setStats]                       = useState<AwarenessStats>({ avg_completion_pct: null, avg_phishing_click_rate: null, high_risk_count: null, avg_risk_score: null });
  const [campaigns, setCampaigns]               = useState<PhishingCampaign[]>([]);
  const [departments, setDepartments]           = useState<DepartmentCompletion[]>([]);
  const [highRiskUsers, setHighRiskUsers]       = useState<HighRiskUser[]>([]);
  const [upcomingTrainings, setUpcomingTrainings] = useState<UpcomingTraining[]>([]);
  const [riskTrend, setRiskTrend]               = useState<RiskTrendPoint[]>([]);

  useEffect(() => {
    setLoading(true);
    Promise.allSettled([
      apiFetch(`/awareness-score/orgs/${ORG_ID}/stats`),
      apiFetch(`/awareness-score/orgs/${ORG_ID}/employees`),
      apiFetch(`/awareness-score/orgs/${ORG_ID}/department-summary`),
      apiFetch(`/security-awareness/campaigns?org_id=${ORG_ID}`),
      apiFetch(`/security-awareness/trainings?org_id=${ORG_ID}`),
      apiFetch(`/awareness-score/orgs/${ORG_ID}/risk-trend`),
    ]).then(([statsRes, employeesRes, deptRes, campaignsRes, trainingsRes, trendRes]) => {
      if (statsRes.status === "fulfilled") {
        const s = statsRes.value;
        setStats({
          avg_completion_pct: s.avg_completion_pct ?? null,
          avg_phishing_click_rate: s.avg_phishing_click_rate ?? null,
          high_risk_count: s.high_risk_count ?? s.high_risk_users ?? null,
          avg_risk_score: s.avg_risk_score ?? null,
        });
      }
      if (employeesRes.status === "fulfilled") {
        const arr = Array.isArray(employeesRes.value) ? employeesRes.value : employeesRes.value?.items ?? [];
        setHighRiskUsers(
          arr
            .filter((e: any) => (e.risk_score ?? 0) >= 50)
            .slice(0, 10)
            .map((e: any, i: number) => ({
              id: e.employee_id ?? `u${i}`,
              user_masked: e.name ? `${e.name[0]}.${e.name.split(" ")[1]?.[0] ?? ""}.` : `U${i}`,
              department: e.department ?? "",
              phishing_clicks: e.phishing_click_count ?? e.phishing_clicks ?? 0,
              training_skips: e.training_skips ?? 0,
              risk_score: e.risk_score ?? 0,
            }))
        );
      }
      if (deptRes.status === "fulfilled") {
        const arr = Array.isArray(deptRes.value) ? deptRes.value : deptRes.value?.departments ?? [];
        setDepartments(arr.map((d: any) => ({
          department: d.department ?? d.name ?? "",
          completion_rate: d.avg_completion_pct ?? d.completion_rate ?? d.avg_score ?? 0,
        })));
      }
      if (campaignsRes.status === "fulfilled") {
        const arr = Array.isArray(campaignsRes.value) ? campaignsRes.value : campaignsRes.value?.campaigns ?? [];
        setCampaigns(arr);
      }
      if (trainingsRes.status === "fulfilled") {
        const arr = Array.isArray(trainingsRes.value) ? trainingsRes.value : trainingsRes.value?.trainings ?? [];
        setUpcomingTrainings(arr);
      }
      if (trendRes.status === "fulfilled") {
        const arr = Array.isArray(trendRes.value) ? trendRes.value : trendRes.value?.trend ?? [];
        setRiskTrend(arr);
      }
    }).finally(() => setLoading(false));
  }, []);

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
    </div>
  );

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="Security Awareness Training"
        description="Track phishing simulations, training completion, and human risk scores"
        badge="AWARENESS"
      />

      {/* KPI row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard
          title="Training Completion Rate"
          value={stats.avg_completion_pct != null ? `${Math.round(stats.avg_completion_pct)}%` : "—"}
          icon={CheckCircle2} trend="up"
          trendLabel="Completion rate"
        />
        <KpiCard
          title="Phishing Click Rate"
          value={stats.avg_phishing_click_rate != null ? `${stats.avg_phishing_click_rate.toFixed(1)}%` : "—"}
          icon={Mail} trend="down"
          trendLabel="Click rate"
        />
        <KpiCard
          title="High Risk Users"
          value={stats.high_risk_count ?? "—"}
          icon={ShieldAlert} trend="down"
          trendLabel="Users above risk threshold"
        />
        <KpiCard
          title="Avg Human Risk Score"
          value={stats.avg_risk_score != null ? `${Math.round(stats.avg_risk_score)}/100` : "—"}
          icon={Users} trend="down"
          trendLabel="Lower is better"
        />
      </div>

      {campaigns.length > 0 && <CampaignsTable campaigns={campaigns} />}
      {campaigns.length === 0 && (
        <Card className="border border-border">
          <CardContent className="py-8 text-center text-xs text-muted-foreground">No phishing campaigns found.</CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <DepartmentCompletion departments={departments} />
        {upcomingTrainings.length > 0
          ? <UpcomingTrainings trainings={upcomingTrainings} />
          : <Card className="border border-border"><CardContent className="py-8 text-center text-xs text-muted-foreground">No upcoming trainings scheduled.</CardContent></Card>
        }
      </div>

      {highRiskUsers.length > 0 && <HighRiskUsersPanel users={highRiskUsers} />}

      <RiskTrendChart data={riskTrend} />
    </div>
  );
}
