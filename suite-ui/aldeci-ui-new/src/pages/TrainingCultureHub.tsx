/**
 * TrainingCultureHub — Security Training & Culture unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone training/culture dashboards into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md (S29 Admin Console — Training &
 * Culture sub-cluster). All three sources hit real backend routers — zero mocks.
 *
 *   tab            | endpoint(s)
 *   ---------------|---------------------------------------
 *   training       | /api/v1/security-training/{stats,courses,campaigns}
 *   effectiveness  | /api/v1/training-effectiveness/{summary,programs,department-compliance}
 *   culture        | /api/v1/security-culture/{summary,departments}
 *
 * Route: /admin/training-culture
 * Persona target: Security Awareness Lead (#21), CISO (#1), GRC Analyst (#12)
 */

import { useEffect, useMemo, useState, useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  GraduationCap,
  TrendingUp,
  Heart,
  BookOpen,
  Users,
  CheckCircle2,
  Clock,
  BarChart3,
  Building2,
  Target,
  Award,
  AlertTriangle,
  RefreshCw,
} from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { API_BASE_URL, API_KEY, DEFAULT_ORG_ID } from "@/lib/api-config";

// ---------------------------------------------------------------------------
// Fetch helper
// ---------------------------------------------------------------------------

async function apiFetch<T>(path: string): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Org-ID": DEFAULT_ORG_ID,
  };
  if (API_KEY) headers["X-API-Key"] = API_KEY;

  const res = await fetch(`${API_BASE_URL}${path}`, { headers });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface TrainingStats {
  total_courses?: number;
  total_enrollments?: number;
  completed_enrollments?: number;
  completion_rate?: number;
  overdue_count?: number;
  active_campaigns?: number;
  avg_score?: number;
  [key: string]: unknown;
}

interface Course {
  id?: string;
  course_id?: string;
  title?: string;
  category?: string;
  duration_minutes?: number;
  difficulty?: string;
  format?: string;
  [key: string]: unknown;
}

interface Campaign {
  id?: string;
  campaign_id?: string;
  name?: string;
  status?: string;
  completion_rate?: number;
  target_group?: string;
  [key: string]: unknown;
}

interface EffectivenessSummary {
  total_programs?: number;
  avg_completion_rate?: number;
  avg_knowledge_gain?: number;
  avg_retention_score?: number;
  total_participants?: number;
  [key: string]: unknown;
}

interface Program {
  program_id?: string;
  program_name?: string;
  training_type?: string;
  delivery_method?: string;
  completion_rate?: number;
  knowledge_gain?: number;
  [key: string]: unknown;
}

interface DeptCompliance {
  department?: string;
  completion_rate?: number;
  avg_score?: number;
  [key: string]: unknown;
}

interface CultureSummary {
  overall_score?: number;
  metric_count?: number;
  initiative_count?: number;
  assessment_count?: number;
  trend?: string;
  [key: string]: unknown;
}

interface DeptCultureScore {
  department?: string;
  culture_score?: number;
  metric_count?: number;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Tab: Training
// ---------------------------------------------------------------------------

function TrainingPanel() {
  const [stats, setStats] = useState<TrainingStats | null>(null);
  const [courses, setCourses] = useState<Course[]>([]);
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, c, camp] = await Promise.all([
        apiFetch<TrainingStats>("/api/v1/security-training/stats"),
        apiFetch<Course[]>("/api/v1/security-training/courses"),
        apiFetch<Campaign[]>("/api/v1/security-training/campaigns"),
      ]);
      setStats(s);
      setCourses(Array.isArray(c) ? c : []);
      setCampaigns(Array.isArray(camp) ? camp : []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load training data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const completionRate = stats?.completion_rate ?? 0;
  const overdueCount = stats?.overdue_count ?? 0;

  return (
    <div className="space-y-6">
      {/* KPI row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <KpiCard
          title="Total Courses"
          value={stats?.total_courses ?? 0}
          icon={BookOpen}
          description="Courses in catalog"
        />
        <KpiCard
          title="Enrollments"
          value={stats?.total_enrollments ?? 0}
          icon={Users}
          description="Active enrollments"
        />
        <KpiCard
          title="Completion Rate"
          value={`${Number(completionRate).toFixed(1)}%`}
          icon={CheckCircle2}
          trend={completionRate >= 70 ? "up" : "down"}
          trendLabel={completionRate >= 70 ? "On target" : "Below 70% target"}
        />
        <KpiCard
          title="Overdue"
          value={overdueCount}
          icon={Clock}
          trend={overdueCount > 0 ? "down" : "flat"}
          trendLabel={overdueCount > 0 ? "Needs attention" : "None overdue"}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Courses table */}
        <Card className="p-5">
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <BookOpen className="h-4 w-4 text-primary" />
            Course Catalog
          </h3>
          {courses.length === 0 ? (
            <EmptyState
              icon={BookOpen}
              title="No courses yet"
              description="Create courses via the API to populate this list."
            />
          ) : (
            <div className="divide-y divide-border">
              {courses.slice(0, 8).map((c, i) => (
                <div key={c.id ?? c.course_id ?? i} className="py-2.5 flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <p className="text-sm font-medium truncate">{c.title ?? "Untitled"}</p>
                    <p className="text-xs text-muted-foreground capitalize">
                      {c.category ?? "—"} · {c.duration_minutes ?? "?"} min · {c.difficulty ?? "—"}
                    </p>
                  </div>
                  <Badge variant="outline" className="shrink-0 text-xs capitalize">
                    {c.format ?? "—"}
                  </Badge>
                </div>
              ))}
              {courses.length > 8 && (
                <p className="pt-2 text-xs text-muted-foreground">
                  +{courses.length - 8} more
                </p>
              )}
            </div>
          )}
        </Card>

        {/* Campaigns */}
        <Card className="p-5">
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <Target className="h-4 w-4 text-primary" />
            Active Campaigns
          </h3>
          {campaigns.length === 0 ? (
            <EmptyState
              icon={Target}
              title="No campaigns"
              description="Training campaigns will appear here once created."
            />
          ) : (
            <div className="divide-y divide-border">
              {campaigns.slice(0, 8).map((camp, i) => {
                const rate = Number(camp.completion_rate ?? 0);
                return (
                  <div key={camp.id ?? camp.campaign_id ?? i} className="py-2.5 flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <p className="text-sm font-medium truncate">{camp.name ?? "Unnamed"}</p>
                      <p className="text-xs text-muted-foreground">
                        {camp.target_group ?? "All users"}
                      </p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <div className="w-20 h-1.5 rounded-full bg-muted overflow-hidden">
                        <div
                          className="h-full rounded-full bg-primary transition-all"
                          style={{ width: `${Math.min(rate, 100)}%` }}
                        />
                      </div>
                      <span className="text-xs font-medium w-10 text-right">
                        {rate.toFixed(0)}%
                      </span>
                      <Badge
                        variant={camp.status === "active" ? "default" : "secondary"}
                        className="text-xs capitalize"
                      >
                        {camp.status ?? "draft"}
                      </Badge>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tab: Effectiveness
// ---------------------------------------------------------------------------

function EffectivenessPanel() {
  const [summary, setSummary] = useState<EffectivenessSummary | null>(null);
  const [programs, setPrograms] = useState<Program[]>([]);
  const [deptCompliance, setDeptCompliance] = useState<DeptCompliance[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, p, d] = await Promise.all([
        apiFetch<EffectivenessSummary>("/api/v1/training-effectiveness/summary"),
        apiFetch<Program[]>("/api/v1/training-effectiveness/programs"),
        apiFetch<DeptCompliance[]>("/api/v1/training-effectiveness/department-compliance"),
      ]);
      setSummary(s);
      setPrograms(Array.isArray(p) ? p : []);
      setDeptCompliance(Array.isArray(d) ? d : []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load effectiveness data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  return (
    <div className="space-y-6">
      {/* KPI row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <KpiCard
          title="Programs"
          value={summary?.total_programs ?? 0}
          icon={BarChart3}
          description="Training programs"
        />
        <KpiCard
          title="Participants"
          value={summary?.total_participants ?? 0}
          icon={Users}
          description="Total enrolled"
        />
        <KpiCard
          title="Avg Completion"
          value={`${Number(summary?.avg_completion_rate ?? 0).toFixed(1)}%`}
          icon={CheckCircle2}
          trend={(summary?.avg_completion_rate ?? 0) >= 70 ? "up" : "down"}
        />
        <KpiCard
          title="Knowledge Gain"
          value={`${Number(summary?.avg_knowledge_gain ?? 0).toFixed(1)}%`}
          icon={TrendingUp}
          trend={(summary?.avg_knowledge_gain ?? 0) > 0 ? "up" : "flat"}
          description="Avg pre→post score delta"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Programs list */}
        <Card className="p-5">
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <Award className="h-4 w-4 text-primary" />
            Training Programs
          </h3>
          {programs.length === 0 ? (
            <EmptyState
              icon={Award}
              title="No programs yet"
              description="Programs appear once created via the API."
            />
          ) : (
            <div className="divide-y divide-border">
              {programs.slice(0, 8).map((p, i) => {
                const rate = Number(p.completion_rate ?? 0);
                return (
                  <div key={p.program_id ?? i} className="py-2.5 flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <p className="text-sm font-medium truncate">{p.program_name ?? "Unnamed"}</p>
                      <p className="text-xs text-muted-foreground capitalize">
                        {p.training_type ?? "—"} · {p.delivery_method ?? "—"}
                      </p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <div className="w-20 h-1.5 rounded-full bg-muted overflow-hidden">
                        <div
                          className="h-full rounded-full bg-green-500 transition-all"
                          style={{ width: `${Math.min(rate, 100)}%` }}
                        />
                      </div>
                      <span className="text-xs font-medium w-10 text-right">
                        {rate.toFixed(0)}%
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>

        {/* Department compliance */}
        <Card className="p-5">
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <Building2 className="h-4 w-4 text-primary" />
            Department Compliance
          </h3>
          {deptCompliance.length === 0 ? (
            <EmptyState
              icon={Building2}
              title="No department data"
              description="Department compliance metrics appear once programs are enrolled."
            />
          ) : (
            <div className="divide-y divide-border">
              {deptCompliance.slice(0, 8).map((d, i) => {
                const rate = Number(d.completion_rate ?? 0);
                const score = Number(d.avg_score ?? 0);
                return (
                  <div key={d.department ?? i} className="py-2.5 flex items-center justify-between gap-3">
                    <p className="text-sm font-medium truncate min-w-0">{d.department ?? "Unknown"}</p>
                    <div className="flex items-center gap-3 shrink-0 text-xs text-muted-foreground">
                      <span>{rate.toFixed(0)}% complete</span>
                      <span>avg {score.toFixed(0)}</span>
                      {rate < 50 && (
                        <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tab: Culture
// ---------------------------------------------------------------------------

function CulturePanel() {
  const [summary, setSummary] = useState<CultureSummary | null>(null);
  const [departments, setDepartments] = useState<DeptCultureScore[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, d] = await Promise.all([
        apiFetch<CultureSummary>("/api/v1/security-culture/summary"),
        apiFetch<DeptCultureScore[]>("/api/v1/security-culture/departments"),
      ]);
      setSummary(s);
      setDepartments(Array.isArray(d) ? d : []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load culture data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const overallScore = Number(summary?.overall_score ?? 0);

  return (
    <div className="space-y-6">
      {/* KPI row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <KpiCard
          title="Culture Score"
          value={`${overallScore.toFixed(1)}`}
          icon={Heart}
          trend={overallScore >= 70 ? "up" : overallScore >= 40 ? "flat" : "down"}
          trendLabel={
            overallScore >= 70
              ? "Healthy culture"
              : overallScore >= 40
              ? "Developing"
              : "Needs improvement"
          }
        />
        <KpiCard
          title="Initiatives"
          value={summary?.initiative_count ?? 0}
          icon={Target}
          description="Active culture initiatives"
        />
        <KpiCard
          title="Metrics Tracked"
          value={summary?.metric_count ?? 0}
          icon={BarChart3}
          description="Culture metrics"
        />
        <KpiCard
          title="Assessments"
          value={summary?.assessment_count ?? 0}
          icon={CheckCircle2}
          description="Completed assessments"
        />
      </div>

      {/* Department culture scores */}
      <Card className="p-5">
        <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
          <Building2 className="h-4 w-4 text-primary" />
          Department Culture Scores
        </h3>
        {departments.length === 0 ? (
          <EmptyState
            icon={Building2}
            title="No department data"
            description="Record culture metrics for departments to see scores here."
          />
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {departments.map((d, i) => {
              const score = Number(d.culture_score ?? 0);
              const color =
                score >= 70
                  ? "bg-green-500"
                  : score >= 40
                  ? "bg-amber-500"
                  : "bg-red-500";
              return (
                <div
                  key={d.department ?? i}
                  className="rounded-lg border border-border p-3 flex items-center justify-between gap-3"
                >
                  <div className="min-w-0">
                    <p className="text-sm font-medium truncate">{d.department ?? "Unknown"}</p>
                    <p className="text-xs text-muted-foreground">
                      {d.metric_count ?? 0} metrics
                    </p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <div className="w-16 h-1.5 rounded-full bg-muted overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all ${color}`}
                        style={{ width: `${Math.min(score, 100)}%` }}
                      />
                    </div>
                    <span className="text-sm font-bold tabular-nums w-10 text-right">
                      {score.toFixed(0)}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Card>

      {/* Trend badge */}
      {summary?.trend && (
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <RefreshCw className="h-3 w-3" />
          Trend: <span className="font-medium capitalize text-foreground">{summary.trend}</span>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tab definitions
// ---------------------------------------------------------------------------

type TabKey = "training" | "effectiveness" | "culture";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "training",
    label: "Training",
    icon: GraduationCap,
    description:
      "Course catalog, enrollment, and active training campaigns — /api/v1/security-training/*",
  },
  {
    key: "effectiveness",
    label: "Effectiveness",
    icon: TrendingUp,
    description:
      "Program effectiveness metrics — completion rates, knowledge retention, department compliance — /api/v1/training-effectiveness/*",
  },
  {
    key: "culture",
    label: "Culture",
    icon: Heart,
    description:
      "Org-wide security culture posture, sentiment scores, and maturity — /api/v1/security-culture/*",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

// ---------------------------------------------------------------------------
// Hub
// ---------------------------------------------------------------------------

export default function TrainingCultureHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "training";
  const [tab, setTab] = useState<TabKey>(initial);

  // Single effect: sync tab state <-> URL param without object-identity churn.
  // deps use params.toString() (primitive) — avoids infinite replaceState loop.
  useEffect(() => {
    const urlTab = params.get("tab");
    if (urlTab !== tab) {
      if (isTabKey(urlTab)) {
        setTab(urlTab);
      } else {
        const next = new URLSearchParams(params.toString());
        next.set("tab", tab);
        setParams(next, { replace: true });
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, params.toString()]);

  const activeMeta = useMemo(() => TABS.find(t => t.key === tab) ?? TABS[0], [tab]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Training & Culture"
        description="Unified workspace — security training delivery, program effectiveness, and org-wide culture posture."
        badge={activeMeta.label}
      />

      <Tabs value={tab} onValueChange={v => setTab(v as TabKey)} className="w-full">
        <TabsList className="h-auto flex-wrap gap-1 bg-muted/40 p-1">
          {TABS.map(t => {
            const Icon = t.icon;
            return (
              <TabsTrigger key={t.key} value={t.key} className="text-xs gap-1.5">
                <Icon className="h-3.5 w-3.5" />
                {t.label}
              </TabsTrigger>
            );
          })}
        </TabsList>

        <p className="text-xs text-muted-foreground mt-2 mb-1">{activeMeta.description}</p>

        <TabsContent value="training">
          <TrainingPanel />
        </TabsContent>
        <TabsContent value="effectiveness">
          <EffectivenessPanel />
        </TabsContent>
        <TabsContent value="culture">
          <CulturePanel />
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
