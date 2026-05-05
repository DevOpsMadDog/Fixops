/**
 * DeveloperSecurityHub — P20 Developer + P11 Security Champion unified workspace
 *
 * 4 tabs:
 *   pr-findings  — findings linked to current user's open PRs
 *   champion     — training progress, badges, leaderboard rank
 *   my-code      — repos owned/contributed-to with security score
 *   helpers      — one-line fix suggestions from SAST findings
 *
 * Route: /developer
 * LOC target: ~280
 */

import { useState, useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  GitPullRequest, Trophy, Code2, Lightbulb,
  RefreshCw, AlertTriangle, GitBranch, Star,
  ShieldCheck, Flame, Bug, KeyRound, Package,
  CheckCircle2, ExternalLink, Award, Users,
  BookOpen, Terminal,
} from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";
import { getStoredAuthToken } from "@/lib/api";

// ── API ──────────────────────────────────────────────────────────────────────

const API_BASE = import.meta.env.VITE_API_URL || "";

async function apiFetch<T = unknown>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": getStoredAuthToken() },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

// ── Types ────────────────────────────────────────────────────────────────────

type Severity = "critical" | "high" | "medium" | "low";

interface PRFinding {
  id: string;
  pr_number: number;
  repo: string;
  file: string;
  severity: Severity;
  title: string;
  fix_suggestion?: string;
}

interface RepoScore {
  id: string;
  name: string;
  language: string;
  security_score: number;
  findings: number;
  last_scan: string;
}

interface FixHelper {
  id: string;
  title: string;
  file: string;
  repo: string;
  fix_snippet: string;
  rule_id?: string;
}

interface ChampionStats {
  rank: number;
  points: number;
  level: string;
  courses_completed: number;
  courses_total: number;
  badges: string[];
}

// ── Severity helpers ─────────────────────────────────────────────────────────

const SEV: Record<Severity, { dot: string; text: string; bg: string; label: string; icon: typeof Flame }> = {
  critical: { dot: "bg-red-500",    text: "text-red-400",    bg: "bg-red-950/40",    label: "Critical", icon: Flame },
  high:     { dot: "bg-orange-500", text: "text-orange-400", bg: "bg-orange-950/40", label: "High",     icon: AlertTriangle },
  medium:   { dot: "bg-amber-500",  text: "text-amber-400",  bg: "bg-amber-950/40",  label: "Medium",   icon: Bug },
  low:      { dot: "bg-blue-500",   text: "text-blue-400",   bg: "bg-blue-950/40",   label: "Low",      icon: KeyRound },
};

function SevBadge({ severity }: { severity: Severity }) {
  const s = SEV[severity] ?? SEV.medium;
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-xs font-medium", s.text, s.bg)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", s.dot)} />
      {s.label}
    </span>
  );
}

// ── EmptyState ───────────────────────────────────────────────────────────────

function EmptyState({ icon: Icon, message }: { icon: typeof GitPullRequest; message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 gap-3 text-muted-foreground">
      <Icon className="h-8 w-8 opacity-40" />
      <p className="text-sm">{message}</p>
    </div>
  );
}

// ── Skeleton ─────────────────────────────────────────────────────────────────

function Skeleton() {
  return (
    <div className="animate-pulse space-y-3 p-4">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-12 rounded-md bg-muted/30" />
      ))}
    </div>
  );
}

// ── Tab: PR Findings ─────────────────────────────────────────────────────────

function PRFindingsTab() {
  const [items, setItems] = useState<PRFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    Promise.allSettled([
      apiFetch<{ findings?: PRFinding[]; items?: PRFinding[] }>("/api/v1/sast/findings?author=$user&org_id=default"),
      apiFetch<{ findings?: PRFinding[]; items?: PRFinding[] }>("/api/v1/dast/findings?author=$user&org_id=default"),
    ]).then(([sastR, dastR]) => {
      const merged: PRFinding[] = [];
      for (const r of [sastR, dastR]) {
        if (r.status === "fulfilled") {
          const raw = r.value;
          const arr: PRFinding[] = Array.isArray(raw) ? (raw as PRFinding[]) : ((raw?.findings ?? raw?.items ?? []) as PRFinding[]);
          merged.push(...arr);
        }
      }
      if (merged.length === 0 && sastR.status === "rejected" && dastR.status === "rejected") {
        setError("Could not reach scanner API.");
      }
      setItems(merged);
    }).finally(() => setLoading(false));
  }, []);

  if (loading) return <Skeleton />;

  return (
    <div className="space-y-4">
      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-950/20 px-4 py-2.5 text-xs text-amber-400">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
          {error}
        </div>
      )}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <GitPullRequest className="h-4 w-4 text-primary" />
            PR-Linked Findings
            <span className="font-mono text-xs font-normal text-muted-foreground">({items.length})</span>
          </CardTitle>
          <CardDescription className="text-xs">SAST + DAST findings tied to your open pull requests</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {items.length === 0
            ? <EmptyState icon={GitPullRequest} message="No PR-linked findings. Your code is clean." />
            : (
              <div className="divide-y divide-border/30">
                {items.map((f) => (
                  <motion.div
                    key={f.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="flex items-start gap-3 px-4 py-3"
                  >
                    <SevBadge severity={f.severity} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium text-foreground truncate">{f.title}</p>
                      <div className="mt-0.5 flex flex-wrap items-center gap-2 text-[10px] text-muted-foreground">
                        <span className="font-mono">PR #{f.pr_number ?? "—"}</span>
                        <span className="opacity-40">·</span>
                        <span className="font-mono">{f.repo}</span>
                        <span className="opacity-40">·</span>
                        <span className="truncate max-w-[180px]">{f.file}</span>
                      </div>
                    </div>
                    {f.fix_suggestion && (
                      <span className="shrink-0 inline-flex items-center gap-1 rounded border border-emerald-700/40 bg-emerald-950/30 px-2 py-0.5 text-[10px] text-emerald-400">
                        <CheckCircle2 className="h-2.5 w-2.5" /> Fix Available
                      </span>
                    )}
                  </motion.div>
                ))}
              </div>
            )}
        </CardContent>
      </Card>
    </div>
  );
}

// ── Tab: Champion ────────────────────────────────────────────────────────────

function ChampionTab() {
  const [stats, setStats] = useState<ChampionStats | null>(null);
  const [campaigns, setCampaigns] = useState<{ title: string; participants: number; total: number; type: string }[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    Promise.allSettled([
      apiFetch<ChampionStats>("/api/v1/security-training/courses?org_id=default"),
      apiFetch<{ items?: typeof campaigns; campaigns?: typeof campaigns }>("/api/v1/security-training/campaigns?org_id=default"),
      apiFetch<{ programs?: typeof campaigns }>("/api/v1/training-effectiveness/programs?org_id=default"),
    ]).then(([statsR, campsR, programsR]) => {
      if (statsR.status === "fulfilled") setStats(statsR.value as ChampionStats);
      const campsVal = campsR.status === "fulfilled" ? campsR.value : null;
      const progsVal = programsR.status === "fulfilled" ? programsR.value : null;
      const arr =
        (campsVal && (Array.isArray(campsVal) ? campsVal : (campsVal?.items ?? campsVal?.campaigns))) ||
        (progsVal && (Array.isArray(progsVal) ? progsVal : progsVal?.programs)) ||
        [];
      setCampaigns(arr as typeof campaigns);
    }).finally(() => setLoading(false));
  }, []);

  if (loading) return <Skeleton />;

  const pct = stats ? Math.round((stats.courses_completed / Math.max(stats.courses_total, 1)) * 100) : 0;

  return (
    <div className="space-y-4">
      {/* KPI row */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiCard title="Leaderboard Rank" value={stats?.rank != null ? `#${stats.rank}` : "—"} icon={Trophy} />
        <KpiCard title="Points" value={stats?.points ?? "—"} icon={Star} trend="up" />
        <KpiCard title="Level" value={stats?.level ?? "—"} icon={Award} />
        <KpiCard title="Courses Done" value={stats ? `${stats.courses_completed}/${stats.courses_total}` : "—"} icon={BookOpen} />
      </div>

      {/* Training progress */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
            Training Progress
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {stats ? (
            <>
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">Overall completion</span>
                <span className="font-bold tabular-nums">{pct}%</span>
              </div>
              <Progress value={pct} className="h-2" />
              {stats.badges && stats.badges.length > 0 && (
                <div className="flex flex-wrap gap-2 pt-1">
                  {stats.badges.map((b) => (
                    <Badge key={b} className="border border-yellow-500/30 bg-yellow-500/10 text-yellow-400 text-[10px]">
                      <Award className="h-2.5 w-2.5 mr-1" />{b}
                    </Badge>
                  ))}
                </div>
              )}
            </>
          ) : (
            <p className="text-xs text-muted-foreground">No training data available. Enroll in a campaign to get started.</p>
          )}
        </CardContent>
      </Card>

      {/* Active campaigns */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Users className="h-4 w-4 text-blue-400" />
            Active Campaigns
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {campaigns.length === 0
            ? <EmptyState icon={Users} message="No active campaigns." />
            : (
              <div className="divide-y divide-border/30">
                {campaigns.map((c, i) => {
                  const cp = Math.round(((c.participants ?? 0) / Math.max(c.total ?? 1, 1)) * 100);
                  return (
                    <div key={i} className="px-4 py-3 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium">{c.title}</span>
                        <span className="text-[10px] text-muted-foreground tabular-nums">{cp}%</span>
                      </div>
                      <Progress value={cp} className="h-1.5" />
                    </div>
                  );
                })}
              </div>
            )}
        </CardContent>
      </Card>
    </div>
  );
}

// ── Tab: My Code ─────────────────────────────────────────────────────────────

function MyCodeTab() {
  const [repos, setRepos] = useState<RepoScore[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    Promise.allSettled([
      apiFetch<{ repos?: RepoScore[]; items?: RepoScore[] }>("/api/v1/repos/list?owner=$user&org_id=default"),
      apiFetch<{ groups?: RepoScore[]; items?: RepoScore[] }>("/api/v1/asset-inventory/groups?org_id=default"),
    ]).then(([reposR, groupsR]) => {
      const reposVal = reposR.status === "fulfilled" ? reposR.value : null;
      const groupsVal = groupsR.status === "fulfilled" ? groupsR.value : null;
      const arr: RepoScore[] =
        (reposVal && (Array.isArray(reposVal) ? (reposVal as RepoScore[]) : (reposVal?.repos ?? reposVal?.items ?? []))) ||
        (groupsVal && (Array.isArray(groupsVal) ? (groupsVal as RepoScore[]) : (groupsVal?.groups ?? groupsVal?.items ?? []))) ||
        [];
      if (arr.length === 0 && reposR.status === "rejected") setError("Repos API unavailable.");
      setRepos(arr);
    }).finally(() => setLoading(false));
  }, []);

  if (loading) return <Skeleton />;

  function scoreColor(s: number) {
    if (s >= 80) return "text-emerald-400";
    if (s >= 60) return "text-amber-400";
    if (s >= 40) return "text-orange-400";
    return "text-red-400";
  }

  return (
    <div className="space-y-4">
      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-950/20 px-4 py-2.5 text-xs text-amber-400">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" />{error}
        </div>
      )}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <GitBranch className="h-4 w-4 text-primary" />
            My Repositories
            <span className="font-mono text-xs font-normal text-muted-foreground">({repos.length})</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {repos.length === 0
            ? <EmptyState icon={GitBranch} message="No repositories found. Connect a code source to get started." />
            : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border/40 text-muted-foreground">
                      <th className="px-4 py-2.5 text-left font-medium">Repository</th>
                      <th className="px-4 py-2.5 text-left font-medium">Language</th>
                      <th className="px-4 py-2.5 text-center font-medium">Score</th>
                      <th className="px-4 py-2.5 text-center font-medium">Findings</th>
                      <th className="px-4 py-2.5 text-left font-medium">Last Scan</th>
                    </tr>
                  </thead>
                  <tbody>
                    {repos.map((r) => (
                      <tr key={r.id} className="border-b border-border/20 hover:bg-muted/20 transition-colors">
                        <td className="px-4 py-2.5 font-mono font-medium">{r.name}</td>
                        <td className="px-4 py-2.5 text-muted-foreground">{r.language ?? "—"}</td>
                        <td className="px-4 py-2.5 text-center">
                          <span className={cn("font-bold tabular-nums", scoreColor(r.security_score ?? 0))}>
                            {r.security_score ?? "—"}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 text-center tabular-nums">
                          <span className={cn(r.findings > 5 ? "text-orange-400" : r.findings > 0 ? "text-amber-400" : "text-emerald-400")}>
                            {r.findings ?? 0}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 text-muted-foreground tabular-nums">
                          {r.last_scan ? new Date(r.last_scan).toLocaleDateString() : "Never"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
        </CardContent>
      </Card>
    </div>
  );
}

// ── Tab: Helpers (AutoFix snippets) ──────────────────────────────────────────

function HelpersTab() {
  const [helpers, setHelpers] = useState<FixHelper[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    Promise.allSettled([
      apiFetch<{ fixes?: FixHelper[]; items?: FixHelper[] }>("/api/v1/sast/auto-fix?org_id=default"),
      apiFetch<{ findings?: (FixHelper & { suggested_fix?: string })[]; items?: (FixHelper & { suggested_fix?: string })[] }>("/api/v1/sast/findings?org_id=default"),
    ]).then(([autoFixR, findingsR]) => {
      if (autoFixR.status === "fulfilled") {
        const raw = autoFixR.value;
        const arr: FixHelper[] = Array.isArray(raw) ? (raw as FixHelper[]) : ((raw?.fixes ?? raw?.items ?? []) as FixHelper[]);
        if (arr.length > 0) { setHelpers(arr); return; }
      }
      // Fallback: extract suggested_fix from findings
      if (findingsR.status === "fulfilled") {
        const raw = findingsR.value;
        type RawFinding = FixHelper & { suggested_fix?: string };
        const arr: RawFinding[] = Array.isArray(raw) ? (raw as RawFinding[]) : ((raw?.findings ?? raw?.items ?? []) as RawFinding[]);
        setHelpers(
          arr
            .filter((f) => f.suggested_fix ?? f.fix_snippet)
            .map((f) => ({
              id: f.id,
              title: f.title,
              file: f.file,
              repo: f.repo,
              fix_snippet: f.fix_snippet ?? f.suggested_fix ?? "",
              rule_id: f.rule_id,
            }))
        );
      }
    }).finally(() => setLoading(false));
  }, []);

  if (loading) return <Skeleton />;

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Lightbulb className="h-4 w-4 text-amber-400" />
            One-Line Fix Helpers
            <span className="font-mono text-xs font-normal text-muted-foreground">({helpers.length})</span>
          </CardTitle>
          <CardDescription className="text-xs">AI-generated SAST fix snippets — click to expand</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {helpers.length === 0
            ? <EmptyState icon={Package} message="No fix suggestions available. Run a SAST scan first." />
            : (
              <div className="divide-y divide-border/30">
                {helpers.map((h) => (
                  <div key={h.id} className="px-4 py-3">
                    <button
                      onClick={() => setExpanded(expanded === h.id ? null : h.id)}
                      className="w-full flex items-start gap-3 text-left group"
                    >
                      <Terminal className="h-3.5 w-3.5 mt-0.5 text-primary shrink-0" />
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium text-foreground group-hover:text-primary transition-colors truncate">
                          {h.title}
                        </p>
                        <p className="text-[10px] text-muted-foreground font-mono truncate">
                          {h.repo} · {h.file}
                          {h.rule_id && <span className="ml-2 opacity-60">[{h.rule_id}]</span>}
                        </p>
                      </div>
                      <span className="shrink-0 inline-flex items-center gap-1 rounded border border-emerald-700/40 bg-emerald-950/30 px-2 py-0.5 text-[10px] text-emerald-400">
                        <CheckCircle2 className="h-2.5 w-2.5" /> Fix
                      </span>
                    </button>
                    {expanded === h.id && h.fix_snippet && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: "auto" }}
                        exit={{ opacity: 0, height: 0 }}
                        className="mt-3 overflow-hidden"
                      >
                        <pre className="rounded-md border border-emerald-900/40 bg-emerald-950/20 p-3 text-[11px] font-mono text-emerald-300/80 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                          {h.fix_snippet}
                        </pre>
                      </motion.div>
                    )}
                  </div>
                ))}
              </div>
            )}
        </CardContent>
      </Card>
    </div>
  );
}

// ── Main Hub ─────────────────────────────────────────────────────────────────

const TABS = [
  { key: "pr-findings", label: "PR Findings",    icon: GitPullRequest },
  { key: "champion",    label: "Champion",        icon: Trophy },
  { key: "my-code",     label: "My Code",         icon: Code2 },
  { key: "helpers",     label: "Fix Helpers",     icon: Lightbulb },
] as const;

type TabKey = typeof TABS[number]["key"];

export default function DeveloperSecurityHub() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [refreshKey, setRefreshKey] = useState(0);

  const rawTab = searchParams.get("tab") as TabKey | null;
  const activeTab: TabKey = TABS.some((t) => t.key === rawTab) ? (rawTab as TabKey) : "pr-findings";

  function setTab(t: TabKey) {
    setSearchParams({ tab: t }, { replace: true });
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Developer Security Hub"
        description="Your unified workspace — PR findings, champion progress, repo scores, and AI fix helpers."
        badge="P20 + P11"
        actions={
          <Button variant="outline" size="sm" onClick={() => setRefreshKey((k) => k + 1)}>
            <RefreshCw className="h-3.5 w-3.5 mr-2" />
            Refresh
          </Button>
        }
      />

      <Tabs value={activeTab} onValueChange={(v) => setTab(v as TabKey)}>
        <TabsList className="h-9 gap-1">
          {TABS.map(({ key, label, icon: Icon }) => (
            <TabsTrigger key={key} value={key} className="gap-1.5 text-xs h-7 px-3">
              <Icon className="h-3.5 w-3.5" />
              {label}
            </TabsTrigger>
          ))}
        </TabsList>

        <div className="mt-4" key={refreshKey}>
          <TabsContent value="pr-findings" forceMount={activeTab === "pr-findings" || undefined}>
            {activeTab === "pr-findings" && <PRFindingsTab />}
          </TabsContent>
          <TabsContent value="champion" forceMount={activeTab === "champion" || undefined}>
            {activeTab === "champion" && <ChampionTab />}
          </TabsContent>
          <TabsContent value="my-code" forceMount={activeTab === "my-code" || undefined}>
            {activeTab === "my-code" && <MyCodeTab />}
          </TabsContent>
          <TabsContent value="helpers" forceMount={activeTab === "helpers" || undefined}>
            {activeTab === "helpers" && <HelpersTab />}
          </TabsContent>
        </div>
      </Tabs>
    </div>
  );
}
