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
import { getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { motion } from "framer-motion";
import { Award, Users, Shield, Star, RefreshCw, BookOpen, Trophy, CheckCircle, Clock } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY;
const ORG_ID = (getStoredOrgId() ?? "default");

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
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────






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

// MAX_POINTS is derived from live data in the component, not hardcoded

// ── Component ──────────────────────────────────────────────────

const arr = (v: any): any[] => (Array.isArray(v) ? v : []);
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
        <KpiCard title="Active Champions"      value={liveData?.stats?.active_champions ?? "—"}                    icon={Users}  trend="up"   className="border-purple-500/20" />
        <KpiCard title="Certifications Valid"  value={liveData?.stats?.valid_certifications ?? "—"}                icon={Award}  trend="up"   className="border-green-500/20" />
        <KpiCard title="Active Campaigns"      value={liveData?.stats?.active_campaigns ?? "—"}                     icon={Shield} trend="flat" className="border-blue-500/20" />
        <KpiCard title="Avg Points Score"      value={liveData?.stats?.avg_points_score ?? "—"}                 icon={Star}   trend="up"   className="border-yellow-500/20" />
      </div>

      {/* Champions Leaderboard */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Trophy className="h-4 w-4 text-yellow-400" />
            Champions Leaderboard
          </CardTitle>
          <CardDescription className="text-xs">Ranked by total points — {(liveData?.champions?.items ?? liveData?.champions ?? []).length} active champions shown</CardDescription>
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
                {(() => {
                  const rows = liveData?.champions?.items ?? liveData?.champions ?? [];
                  if (rows.length === 0) return (
                    <TableRow><TableCell colSpan={8}><EmptyState icon={Trophy} title="No champions yet" description="Champions will appear here once enrolled in the program." /></TableCell></TableRow>
                  );
                  const maxPts = Math.max(...rows.map((c: any) => c.points ?? 0), 1);
                  return rows.map((c: any) => (
                    <TableRow key={c.rank ?? c.id ?? c.name} className="hover:bg-muted/30">
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
                              animate={{ width: `${((c.points ?? 0) / maxPts) * 100}%` }}
                              transition={{ duration: 0.7, ease: "easeOut" }}
                              className={cn(
                                "h-full rounded-full",
                                c.level === "platinum" ? "bg-purple-500" :
                                c.level === "gold"     ? "bg-yellow-500" :
                                c.level === "silver"   ? "bg-gray-400"   : "bg-orange-600"
                              )}
                            />
                          </div>
                          <span className="text-xs font-bold tabular-nums">{(c.points ?? 0).toLocaleString()}</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-[10px] py-2.5 text-muted-foreground max-w-[200px] truncate">{c.recent_activity}</TableCell>
                      <TableCell className="text-xs py-2.5 tabular-nums text-right font-medium">{c.certs}</TableCell>
                    </TableRow>
                  ));
                })()}
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
                  {(liveData?.activities?.items ?? liveData?.activities ?? []).length === 0 ? (
                    <TableRow><TableCell colSpan={4}><EmptyState icon={BookOpen} title="No activity yet" description="Champion activities will appear here once logged." /></TableCell></TableRow>
                  ) : (arr(liveData?.activities?.items ?? liveData?.activities ?? [])).map((a: any, i: number) => (
                    <TableRow key={i} className="hover:bg-muted/30">
                      <TableCell className="text-xs font-medium py-2">{a.champion}</TableCell>
                      <TableCell className="py-2"><ActivityTypeBadge type={a.type} /></TableCell>
                      <TableCell className="text-xs py-2 tabular-nums font-bold text-green-400 text-right">+{a.points}</TableCell>
                      <TableCell className="text-[10px] py-2 tabular-nums text-muted-foreground">{(a.completed_at ?? "").slice(0, 10)}</TableCell>
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
                  {(liveData?.certifications?.items ?? liveData?.certifications ?? []).length === 0 ? (
                    <TableRow><TableCell colSpan={5}><EmptyState icon={CheckCircle} title="No certifications yet" description="Champion certifications will appear here once recorded." /></TableCell></TableRow>
                  ) : (arr(liveData?.certifications?.items ?? liveData?.certifications ?? [])).map((cert: any, i: number) => (
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
          {(liveData?.campaigns?.items ?? liveData?.campaigns ?? []).length === 0 ? (
            <div className="col-span-full"><EmptyState icon={Shield} title="No active campaigns" description="Security awareness campaigns will appear here once launched." /></div>
          ) : (arr(liveData?.campaigns?.items ?? liveData?.campaigns ?? [])).map((c: any) => {
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
          {(liveData?.stats?.level_distribution ?? liveData?.level_distribution ?? []).length === 0 ? (
            <EmptyState icon={Star} title="No level data yet" description="Champion level distribution will appear here once champions are enrolled." />
          ) : (
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              {(arr(liveData?.stats?.level_distribution ?? liveData?.level_distribution ?? [])).map((l: any) => (
                <div key={l.level} className="flex flex-col items-center gap-2 p-4 rounded-lg bg-muted/20 border border-border/40">
                  <div className="w-10 h-10 rounded-full flex items-center justify-center bg-muted/30 border-2 border-border">
                    <Trophy className="h-5 w-5 text-muted-foreground" />
                  </div>
                  <span className="text-xs font-bold capitalize">{l.level}</span>
                  <span className="text-2xl font-black tabular-nums">{l.count}</span>
                  {l.next && l.next !== "—" && (
                    <span className="text-[9px] text-muted-foreground text-center">Next: {l.next}</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
