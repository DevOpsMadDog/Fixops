/**
 * Security Awareness Dashboard
 *
 * Employee training scores, phishing resistance, and risk tier tracking.
 *   1. KPIs: Employees Tracked, Champions, At Risk, Avg Score
 *   2. Risk tier distribution bands
 *   3. Employee scorecard table (15 rows)
 *   4. Phishing test results (10 recent)
 *   5. Department summary (8 departments)
 *   6. Training completions timeline (8 recent)
 *
 * API stubs: GET /api/v1/awareness/scores, /api/v1/awareness/phishing, /api/v1/awareness/training
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { GraduationCap, Users, AlertTriangle, Award, RefreshCw, Shield, CheckCircle } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
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

const TIER_BANDS = [
  { tier: "Champion",   color: "bg-green-500",  textColor: "text-green-400",  count: 47,  pct: 14 },
  { tier: "Proficient", color: "bg-blue-500",   textColor: "text-blue-400",   count: 188, pct: 55 },
  { tier: "Developing", color: "bg-amber-500",  textColor: "text-amber-400",  count: 84,  pct: 25 },
  { tier: "At Risk",    color: "bg-red-500",    textColor: "text-red-400",    count: 23,  pct: 7  },
];

const EMPLOYEES = [
  { name: "Sarah Chen",      department: "Engineering",    role: "Sr. Engineer",       training_score: 94, phishing_score: 98, overall: 96, tier: "Champion" },
  { name: "Marcus Williams", department: "Security",       role: "SOC Analyst",        training_score: 97, phishing_score: 100,overall: 99, tier: "Champion" },
  { name: "Priya Patel",     department: "Finance",        role: "CFO",                training_score: 88, phishing_score: 91, overall: 90, tier: "Proficient" },
  { name: "Tom Anderson",    department: "HR",             role: "HR Manager",         training_score: 72, phishing_score: 78, overall: 75, tier: "Proficient" },
  { name: "Lisa Zhang",      department: "Engineering",    role: "DevOps",             training_score: 85, phishing_score: 89, overall: 87, tier: "Proficient" },
  { name: "David Kim",       department: "Sales",          role: "Account Executive",  training_score: 61, phishing_score: 55, overall: 58, tier: "Developing" },
  { name: "Emma Johnson",    department: "Marketing",      role: "Marketing Lead",     training_score: 68, phishing_score: 72, overall: 70, tier: "Developing" },
  { name: "James Brown",     department: "Legal",          role: "Counsel",            training_score: 79, phishing_score: 83, overall: 81, tier: "Proficient" },
  { name: "Ana Rodriguez",   department: "Finance",        role: "Accountant",         training_score: 41, phishing_score: 38, overall: 40, tier: "At Risk" },
  { name: "Chris Taylor",    department: "IT",             role: "SysAdmin",           training_score: 91, phishing_score: 95, overall: 93, tier: "Champion" },
  { name: "Sophie Martin",   department: "HR",             role: "Recruiter",          training_score: 55, phishing_score: 49, overall: 52, tier: "Developing" },
  { name: "Kevin Lee",       department: "Engineering",    role: "Backend Dev",        training_score: 82, phishing_score: 87, overall: 85, tier: "Proficient" },
  { name: "Rachel Green",    department: "Sales",          role: "Sales Manager",      training_score: 44, phishing_score: 41, overall: 43, tier: "At Risk" },
  { name: "Mike Davis",      department: "Marketing",      role: "Content Writer",     training_score: 63, phishing_score: 67, overall: 65, tier: "Developing" },
  { name: "Nina Sharma",     department: "Security",       role: "GRC Analyst",        training_score: 95, phishing_score: 97, overall: 96, tier: "Champion" },
];

const PHISHING_TESTS = [
  { employee: "Ana Rodriguez",   campaign: "Q2 Phishing Wave 1",       sent_at: "2026-04-14 09:00", clicked: true,  reported: false },
  { employee: "Rachel Green",    campaign: "Q2 Phishing Wave 1",       sent_at: "2026-04-14 09:00", clicked: true,  reported: false },
  { employee: "David Kim",       campaign: "Executive Lure Test",      sent_at: "2026-04-13 10:30", clicked: true,  reported: false },
  { employee: "Sophie Martin",   campaign: "Invoice Spear Phish",      sent_at: "2026-04-12 14:00", clicked: true,  reported: false },
  { employee: "Mike Davis",      campaign: "Q2 Phishing Wave 1",       sent_at: "2026-04-14 09:00", clicked: false, reported: true  },
  { employee: "Emma Johnson",    campaign: "HR Benefits Lure",         sent_at: "2026-04-11 11:00", clicked: false, reported: true  },
  { employee: "Sarah Chen",      campaign: "Executive Lure Test",      sent_at: "2026-04-13 10:30", clicked: false, reported: true  },
  { employee: "Marcus Williams", campaign: "Invoice Spear Phish",      sent_at: "2026-04-12 14:00", clicked: false, reported: true  },
  { employee: "Tom Anderson",    campaign: "HR Benefits Lure",         sent_at: "2026-04-11 11:00", clicked: false, reported: false },
  { employee: "James Brown",     campaign: "Q2 Phishing Wave 1",       sent_at: "2026-04-14 09:00", clicked: false, reported: false },
];

const DEPARTMENTS = [
  { dept: "Security",    avg_score: 97, at_risk: 0, champions: 4 },
  { dept: "Engineering", avg_score: 88, at_risk: 0, champions: 3 },
  { dept: "IT",          avg_score: 85, at_risk: 0, champions: 2 },
  { dept: "Legal",       avg_score: 79, at_risk: 0, champions: 1 },
  { dept: "Finance",     avg_score: 65, at_risk: 2, champions: 1 },
  { dept: "HR",          avg_score: 63, at_risk: 1, champions: 0 },
  { dept: "Marketing",   avg_score: 67, at_risk: 1, champions: 0 },
  { dept: "Sales",       avg_score: 51, at_risk: 3, champions: 0 },
];

const TRAINING_COMPLETIONS = [
  { employee: "Sarah Chen",      training_type: "Phishing Awareness",  score: 95, passed: true,  completed_at: "2026-04-15 16:30" },
  { employee: "Marcus Williams", training_type: "OPSEC Fundamentals",  score: 98, passed: true,  completed_at: "2026-04-15 14:00" },
  { employee: "Ana Rodriguez",   training_type: "Phishing Awareness",  score: 48, passed: false, completed_at: "2026-04-15 11:30" },
  { employee: "Chris Taylor",    training_type: "Incident Response",   score: 91, passed: true,  completed_at: "2026-04-15 10:15" },
  { employee: "David Kim",       training_type: "Social Engineering",  score: 55, passed: false, completed_at: "2026-04-14 17:00" },
  { employee: "Nina Sharma",     training_type: "GRC Compliance",      score: 97, passed: true,  completed_at: "2026-04-14 15:45" },
  { employee: "Rachel Green",    training_type: "Phishing Awareness",  score: 44, passed: false, completed_at: "2026-04-14 13:30" },
  { employee: "Lisa Zhang",      training_type: "DevSecOps Basics",    score: 86, passed: true,  completed_at: "2026-04-14 11:00" },
];

// ── Helpers ────────────────────────────────────────────────────

function TierBadge({ tier }: { tier: string }) {
  const map: Record<string, string> = {
    Champion:   "border-green-500/30 text-green-400 bg-green-500/10",
    Proficient: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    Developing: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    "At Risk":  "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[tier] ?? "border-border")}>{tier}</Badge>;
}

function DeptBadge({ dept }: { dept: string }) {
  const colors = ["border-blue-500/30 text-blue-400 bg-blue-500/10","border-purple-500/30 text-purple-400 bg-purple-500/10","border-teal-500/30 text-teal-400 bg-teal-500/10","border-indigo-500/30 text-indigo-400 bg-indigo-500/10","border-cyan-500/30 text-cyan-400 bg-cyan-500/10"];
  const idx = dept.charCodeAt(0) % colors.length;
  return <Badge className={cn("text-[10px] border", colors[idx])}>{dept}</Badge>;
}

function TrainingTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    "Phishing Awareness": "border-red-500/30 text-red-400 bg-red-500/10",
    "OPSEC Fundamentals": "border-blue-500/30 text-blue-400 bg-blue-500/10",
    "Incident Response":  "border-amber-500/30 text-amber-400 bg-amber-500/10",
    "Social Engineering": "border-purple-500/30 text-purple-400 bg-purple-500/10",
    "GRC Compliance":     "border-teal-500/30 text-teal-400 bg-teal-500/10",
    "DevSecOps Basics":   "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>{type}</Badge>;
}

function ScoreBar({ score, small }: { score: number; small?: boolean }) {
  const color = score >= 85 ? "bg-green-500" : score >= 65 ? "bg-blue-500" : score >= 50 ? "bg-amber-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className={cn("relative rounded-full bg-muted/30 overflow-hidden", small ? "h-1 w-16" : "h-1.5 w-20")}>
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ duration: 0.6 }}
          className={cn("h-full rounded-full", color)}
        />
      </div>
      <span className={cn("tabular-nums font-medium", small ? "text-[10px]" : "text-xs",
        score >= 85 ? "text-green-400" : score >= 65 ? "text-blue-400" : score >= 50 ? "text-amber-400" : "text-red-400"
      )}>{score}</span>
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function AwarenessScoreDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/awareness-score/orgs/${ORG_ID}/stats`),
      apiFetch(`/api/v1/awareness-score/orgs/${ORG_ID}/employees`),
      apiFetch(`/api/v1/awareness-score/orgs/${ORG_ID}/scores`),
    ]).then(([statsResult, employeesResult, scoresResult]) => {
      const stats     = statsResult.status     === "fulfilled" ? statsResult.value     : null;
      const employees = employeesResult.status === "fulfilled" ? employeesResult.value : null;
      const scores    = scoresResult.status    === "fulfilled" ? scoresResult.value    : null;
      if (stats || employees || scores) {
        setLiveData({ stats, employees, scores });
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
        title="Security Awareness"
        description="Employee training scores, phishing resistance, and risk tier tracking"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Employees Tracked" value={liveData?.stats?.total_employees ?? liveData?.stats?.trained_employees ?? 342}    icon={Users}          trend="up"   />
        <KpiCard title="Champions"         value={liveData?.stats?.champions ?? liveData?.stats?.certifications_expiring ?? 47}     icon={Award}          trend="up"   className="border-green-500/20" />
        <KpiCard title="At Risk"           value={liveData?.stats?.at_risk ?? liveData?.stats?.phishing_click_rate ?? 23}     icon={AlertTriangle}  trend="up"   className="border-red-500/20" />
        <KpiCard title="Avg Score"         value={liveData?.stats?.avg_score ?? "71.4"}   icon={GraduationCap}  trend="up"   className="border-blue-500/20" />
      </div>

      {/* Risk Tier Distribution */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Shield className="h-4 w-4 text-blue-400" />
            Risk Tier Distribution
          </CardTitle>
          <CardDescription className="text-xs">Employee population by security awareness tier</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {TIER_BANDS.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            TIER_BANDS.map((band) => (
            <div key={band.tier} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span className={cn("font-semibold", band.textColor)}>{band.tier}</span>
                  <span className="text-muted-foreground">{band.pct}%</span>
                </div>
                <span className="tabular-nums font-bold">{band.count} employees</span>
              </div>
              <div className="relative h-6 rounded-lg bg-muted/20 overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${band.pct}%` }}
                  transition={{ duration: 0.9, ease: "easeOut" }}
                  className={cn("h-full rounded-lg flex items-center px-2", band.color, "opacity-80")}
                >
                  {band.pct > 10 && <span className="text-[10px] font-semibold text-white">{band.tier}</span>}
                </motion.div>
              </div>
            </div>
          )))}
        </CardContent>
      </Card>

      {/* Employee Scorecard */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Users className="h-4 w-4 text-indigo-400" />
            Employee Scorecard
          </CardTitle>
          <CardDescription className="text-xs">Training score, phishing resistance, and overall security awareness rating</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Employee</TableHead>
                  <TableHead className="text-[11px] h-8">Department</TableHead>
                  <TableHead className="text-[11px] h-8">Role</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[120px]">Training Score</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[120px]">Phishing Resistance</TableHead>
                  <TableHead className="text-[11px] h-8">Overall</TableHead>
                  <TableHead className="text-[11px] h-8">Tier</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.employees?.items ?? liveData?.employees ?? liveData?.scores ?? EMPLOYEES).map((emp: any) => (
                  <TableRow key={emp.name} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-xs font-medium">{emp.name}</TableCell>
                    <TableCell className="py-2"><DeptBadge dept={emp.department} /></TableCell>
                    <TableCell className="py-2 text-xs text-muted-foreground">{emp.role}</TableCell>
                    <TableCell className="py-2"><ScoreBar score={emp.training_score} /></TableCell>
                    <TableCell className="py-2"><ScoreBar score={emp.phishing_score} /></TableCell>
                    <TableCell className="py-2">
                      <span className={cn("text-sm font-bold tabular-nums",
                        emp.overall >= 85 ? "text-green-400" : emp.overall >= 65 ? "text-blue-400" : emp.overall >= 50 ? "text-amber-400" : "text-red-400"
                      )}>{emp.overall}</span>
                    </TableCell>
                    <TableCell className="py-2"><TierBadge tier={emp.tier} /></TableCell>
                  </TableRow>
                ))
              )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Phishing + Department side by side */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Phishing Test Results */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-red-400" />
              Recent Phishing Tests
            </CardTitle>
            <CardDescription className="text-xs">Click and report rates from recent phishing simulations</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Employee</TableHead>
                  <TableHead className="text-[11px] h-8">Campaign</TableHead>
                  <TableHead className="text-[11px] h-8">Sent</TableHead>
                  <TableHead className="text-[11px] h-8">Clicked</TableHead>
                  <TableHead className="text-[11px] h-8">Reported</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.campaigns?.items ?? liveData?.campaigns ?? PHISHING_TESTS).map((t: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-xs font-medium">{t.employee}</TableCell>
                    <TableCell className="py-2 text-xs text-muted-foreground truncate max-w-[140px]">{t.campaign}</TableCell>
                    <TableCell className="py-2 text-[11px] tabular-nums text-muted-foreground">{t.sent_at}</TableCell>
                    <TableCell className="py-2">
                      {t.clicked
                        ? <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">Clicked</Badge>
                        : <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Safe</Badge>
                      }
                    </TableCell>
                    <TableCell className="py-2">
                      {t.reported
                        ? <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Reported</Badge>
                        : <span className="text-[10px] text-muted-foreground">—</span>
                      }
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Department Summary */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <GraduationCap className="h-4 w-4 text-teal-400" />
              Department Summary
            </CardTitle>
            <CardDescription className="text-xs">Average awareness score and risk counts by department</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {DEPARTMENTS.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              DEPARTMENTS.map((d) => (
              <div key={d.dept} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium">{d.dept}</span>
                  <div className="flex items-center gap-1.5">
                    {d.at_risk > 0 && (
                      <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">{d.at_risk} at risk</Badge>
                    )}
                    {d.champions > 0 && (
                      <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">{d.champions} champion{d.champions > 1 ? "s" : ""}</Badge>
                    )}
                  </div>
                </div>
                <ScoreBar score={d.avg_score} />
              </div>
            )))}
          </CardContent>
        </Card>
      </div>

      {/* Training Completions */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <CheckCircle className="h-4 w-4 text-green-400" />
            Training Completions This Month
          </CardTitle>
          <CardDescription className="text-xs">Recent module completions with pass/fail status</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Employee</TableHead>
                  <TableHead className="text-[11px] h-8">Training Module</TableHead>
                  <TableHead className="text-[11px] h-8">Completed</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[120px]">Score</TableHead>
                  <TableHead className="text-[11px] h-8">Result</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.training?.items ?? liveData?.training ?? TRAINING_COMPLETIONS).map((t: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-xs font-medium">{t.employee}</TableCell>
                    <TableCell className="py-2"><TrainingTypeBadge type={t.training_type} /></TableCell>
                    <TableCell className="py-2 text-[11px] tabular-nums text-muted-foreground">{t.completed_at}</TableCell>
                    <TableCell className="py-2"><ScoreBar score={t.score} small /></TableCell>
                    <TableCell className="py-2">
                      {t.passed
                        ? <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Passed</Badge>
                        : <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">Failed</Badge>
                      }
                    </TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
