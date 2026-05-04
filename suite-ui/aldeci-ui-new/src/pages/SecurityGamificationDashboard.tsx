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

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "";
const ORG_ID = "default";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

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

interface LeaderboardEntry { rank: number; user_id: string; total_points: number; }
interface Challenge { title: string; type: string; points: number; difficulty: string; }
interface GamificationStats { total_challenges: number; active_users: number; total_completions: number; top_points: number; }

export default function SecurityGamificationDashboard() {
  const [refreshing, setRefreshing]         = useState(false);
  const [loading, setLoading]               = useState(true);
  const [leaderboard, setLeaderboard]       = useState<LeaderboardEntry[]>([]);
  const [challenges, setChallenges]         = useState<Challenge[]>([]);
  const [stats, setStats]                   = useState<GamificationStats>({ total_challenges: 0, active_users: 0, total_completions: 0, top_points: 0 });

  const load = () => {
    setLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/awareness-gamification/leaderboard?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/awareness-gamification/challenges?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/awareness-gamification/stats?org_id=${ORG_ID}`),
    ]).then(([lbRes, challengesRes, statsRes]) => {
      if (lbRes.status === "fulfilled") setLeaderboard(lbRes.value?.leaderboard ?? lbRes.value ?? []);
      if (challengesRes.status === "fulfilled") setChallenges(challengesRes.value?.challenges ?? challengesRes.value ?? []);
      if (statsRes.status === "fulfilled") setStats(statsRes.value ?? { total_challenges: 0, active_users: 0, total_completions: 0, top_points: 0 });
    }).finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handleRefresh = () => { setRefreshing(true); load(); setTimeout(() => setRefreshing(false), 800); };

  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;


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
