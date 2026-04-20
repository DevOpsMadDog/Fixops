/**
 * Security Gamification Dashboard
 *
 * Security awareness gamification — challenges, leaderboard, and completion tracking.
 *   1. KPIs: Total Challenges, Active Users, Total Completions, Top Points
 *   2. Leaderboard table (rank, user_id, total_points)
 *   3. Challenges table (title, type, points, difficulty)
 *
 * Route: /security-gamification
 * API: GET /api/v1/awareness-gamification
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Trophy, RefreshCw, Star, Users, Zap } from "lucide-react";

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
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_LEADERBOARD = [
  { rank: 1,  user_id: "user-alice-k",    total_points: 4820 },
  { rank: 2,  user_id: "user-bob-m",      total_points: 4410 },
  { rank: 3,  user_id: "user-carol-j",    total_points: 3990 },
  { rank: 4,  user_id: "user-dan-t",      total_points: 3750 },
  { rank: 5,  user_id: "user-eve-r",      total_points: 3340 },
  { rank: 6,  user_id: "user-frank-s",    total_points: 2980 },
  { rank: 7,  user_id: "user-grace-l",    total_points: 2710 },
  { rank: 8,  user_id: "user-henry-p",    total_points: 2450 },
];

const MOCK_CHALLENGES = [
  { title: "Phishing Identification Sprint",  type: "quiz",        points: 200, difficulty: "medium" },
  { title: "Password Hygiene Challenge",      type: "interactive", points: 150, difficulty: "easy" },
  { title: "Social Engineering Simulation",   type: "simulation",  points: 500, difficulty: "hard" },
  { title: "Secure Coding Fundamentals",      type: "course",      points: 350, difficulty: "medium" },
  { title: "MFA Setup Race",                  type: "task",        points: 100, difficulty: "easy" },
  { title: "Incident Response Tabletop",      type: "simulation",  points: 750, difficulty: "hard" },
];

const MOCK_STATS = { total_challenges: 42, active_users: 318, total_completions: 2847, top_points: 4820 };

// ── Badge helpers ──────────────────────────────────────────────

function DifficultyBadge({ difficulty }: { difficulty: string }) {
  const map: Record<string, string> = {
    easy:   "border-green-500/30 text-green-400 bg-green-500/10",
    medium: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    hard:   "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[difficulty] ?? "border-border")}>
      {difficulty}
    </Badge>
  );
}

function ChallengTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    quiz:        "border-amber-500/30 text-amber-400 bg-amber-500/10",
    interactive: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    simulation:  "border-orange-500/30 text-orange-400 bg-orange-500/10",
    course:      "border-lime-500/30 text-lime-400 bg-lime-500/10",
    task:        "border-teal-500/30 text-teal-400 bg-teal-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border")}>
      {type}
    </Badge>
  );
}

function RankBadge({ rank }: { rank: number }) {
  if (rank === 1) return <span className="text-yellow-400 font-bold text-[13px]">🥇</span>;
  if (rank === 2) return <span className="text-slate-300 font-bold text-[13px]">🥈</span>;
  if (rank === 3) return <span className="text-amber-600 font-bold text-[13px]">🥉</span>;
  return <span className="font-mono text-[11px] text-muted-foreground">#{rank}</span>;
}

// ── Component ──────────────────────────────────────────────────

export default function SecurityGamificationDashboard() {
  const [refreshing, setRefreshing]       = useState(false);
  const [liveLeaderboard, setLiveLB]      = useState<any[] | null>(null);
  const [liveChallenges, setLiveChallenges] = useState<any[] | null>(null);
  const [liveStats, setLiveStats]         = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/awareness-gamification/leaderboard?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/awareness-gamification/challenges?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/awareness-gamification/stats?org_id=${ORG_ID}`),
    ]).then(([lbRes, challengesRes, statsRes]) => {
      if (lbRes.status === "fulfilled") setLiveLB(lbRes.value?.leaderboard ?? lbRes.value ?? null);
      if (challengesRes.status === "fulfilled") setLiveChallenges(challengesRes.value?.challenges ?? challengesRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    });
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const leaderboard = liveLeaderboard ?? MOCK_LEADERBOARD;
  const challenges  = liveChallenges  ?? MOCK_CHALLENGES;
  const stats       = liveStats       ?? MOCK_STATS;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Security Gamification"
        description="Security awareness challenges, leaderboards, and completion tracking to drive engagement"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Challenges"   value={stats.total_challenges}   icon={Zap}    trend="flat" />
        <KpiCard title="Active Users"       value={stats.active_users}       icon={Users}  trend="up"   className="border-yellow-500/20" />
        <KpiCard title="Total Completions"  value={stats.total_completions}  icon={Star}   trend="up"   className="border-amber-500/20" />
        <KpiCard title="Top Points"         value={stats.top_points}         icon={Trophy} trend="flat" className="border-orange-500/20" />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Leaderboard */}
        <Card className="border-yellow-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-yellow-400">
              <Trophy className="h-4 w-4" />
              Leaderboard
            </CardTitle>
            <CardDescription className="text-xs">Top performers this quarter</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Rank</TableHead>
                    <TableHead className="text-[11px] h-8">User</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Points</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {leaderboard.map((entry: any, i: number) => (
                    <TableRow key={entry.user_id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2">
                        <RankBadge rank={entry.rank ?? i + 1} />
                      </TableCell>
                      <TableCell className="py-2 font-mono text-[11px] text-amber-300">
                        {entry.user_id ?? "—"}
                      </TableCell>
                      <TableCell className="py-2 text-right font-mono font-bold text-[12px] text-yellow-400">
                        {(entry.total_points ?? 0).toLocaleString()}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Challenges */}
        <Card className="border-amber-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
              <Zap className="h-4 w-4" />
              Active Challenges
            </CardTitle>
            <CardDescription className="text-xs">Current challenge catalog with point values</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Title</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8">Difficulty</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Points</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {challenges.map((ch: any, i: number) => (
                    <TableRow key={ch.title ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-medium max-w-[160px] truncate">
                        {ch.title ?? "—"}
                      </TableCell>
                      <TableCell className="py-2">
                        <ChallengTypeBadge type={ch.type ?? "quiz"} />
                      </TableCell>
                      <TableCell className="py-2">
                        <DifficultyBadge difficulty={ch.difficulty ?? "medium"} />
                      </TableCell>
                      <TableCell className="py-2 text-right font-mono font-bold text-[12px] text-yellow-400">
                        {ch.points ?? 0}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
