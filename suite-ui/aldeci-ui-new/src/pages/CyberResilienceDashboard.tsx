/**
 * Cyber Resilience Dashboard
 *
 * Data sources (real API):
 *   GET /api/v1/cyber-resilience/score?org_id=default
 *     → { overall_score, by_domain: { [domain]: { avg_score } }, maturity_distribution }
 *   GET /api/v1/cyber-resilience/exercises?org_id=default
 *     → [] | Exercise[]
 *   GET /api/v1/cyber-resilience/assessments?org_id=default
 *     → Assessment[] (id, resilience_domain, maturity_level, score, assessor, assessment_date)
 *
 * NO mock LESSONS, HISTORY, EXERCISES, METRICS arrays.
 * Honest EmptyState when API returns [].
 * Route: /cyber-resilience
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ShieldAlert, Star, TrendingUp, BookOpen, BarChart2, RefreshCw } from "lucide-react";
import { EmptyState } from "@/components/shared/EmptyState";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import api, { buildApiUrl, getStoredAuthToken, getStoredAuthStrategy, getStoredOrgId } from "@/lib/api";

// ── Types ──────────────────────────────────────────────────────

interface ScoreResponse {
  overall_score: number;
  by_domain: Record<string, { avg_score: number }>;
  maturity_distribution: Record<string, number>;
}

interface Exercise {
  id: string;
  exercise_name: string;
  type: "tabletop" | "red_team" | "purple_team" | "drill" | "simulation";
  status: "scheduled" | "completed" | "cancelled";
  participants: number;
  findings_count: number;
  scheduled_date: string;
}

interface Assessment {
  id: string;
  org_id: string;
  assessment_name: string;
  resilience_domain: string;
  maturity_level: number;
  max_level: number;
  score: number;
  evidence: string;
  assessor: string;
  assessment_date: string;
  next_review: string;
  created_at: string;
}

// ── Auth headers ────────────────────────────────────────────────

function apiHeaders(): Record<string, string> {
  const token = getStoredAuthToken();
  const strategy = getStoredAuthStrategy();
  const orgId = getStoredOrgId();
  const h: Record<string, string> = { "Content-Type": "application/json", "X-Org-ID": orgId };
  if (token) {
    if (strategy === "jwt") h.Authorization = token.toLowerCase().startsWith("bearer ") ? token : `Bearer ${token}`;
    else h["X-API-Key"] = token;
  }
  return h;
}

// ── Domain colors ───────────────────────────────────────────────

const DOMAIN_COLORS: Record<string, string> = {
  identify: "#38bdf8",
  protect:  "#a78bfa",
  detect:   "#f59e0b",
  respond:  "#f97316",
  recover:  "#ef4444",
  adapt:    "#ec4899",
};

function domainColor(key: string): string {
  return DOMAIN_COLORS[key.toLowerCase()] ?? "#6366f1";
}

// ── Helpers ────────────────────────────────────────────────────

function Stars({ count, max = 5 }: { count: number; max?: number }) {
  return (
    <div className="flex gap-0.5">
      {Array.from({ length: max }, (_, i) => (
        <Star key={i} size={12} className={i < count ? "text-yellow-400 fill-yellow-400" : "text-gray-600"} />
      ))}
    </div>
  );
}

function typeBadge(type: Exercise["type"]) {
  const map: Record<string, string> = {
    tabletop: "bg-blue-500/20 text-blue-300",
    red_team: "bg-red-500/20 text-red-300",
    purple_team: "bg-purple-500/20 text-purple-300",
    drill: "bg-teal-500/20 text-teal-300",
    simulation: "bg-orange-500/20 text-orange-300",
  };
  return <span className={`px-2 py-0.5 rounded text-xs ${map[type] ?? "bg-gray-600 text-gray-300"}`}>{type.replace("_", " ")}</span>;
}

function statusBadge(status: Exercise["status"]) {
  const map: Record<string, string> = {
    scheduled: "bg-blue-500/20 text-blue-300",
    completed: "bg-green-500/20 text-green-300",
    cancelled: "bg-gray-600/40 text-gray-400",
  };
  return <span className={`px-2 py-0.5 rounded text-xs ${map[status]}`}>{status}</span>;
}

// ── SVG Arc Gauge ──────────────────────────────────────────────

function ArcGauge({ score }: { score: number }) {
  const r = 60, cx = 80, cy = 80, startAngle = 210, arcRange = 300;
  const pct = Math.min(100, Math.max(0, score)) / 100;
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const arcX = (deg: number) => cx + r * Math.cos(toRad(deg));
  const arcY = (deg: number) => cy + r * Math.sin(toRad(deg));
  const describeArc = (from: number, to: number, large: boolean) =>
    `M ${arcX(from)} ${arcY(from)} A ${r} ${r} 0 ${large ? 1 : 0} 1 ${arcX(to)} ${arcY(to)}`;
  const fillEnd = startAngle + pct * arcRange;
  const fillLarge = pct * arcRange > 180;
  const color = score >= 70 ? "#22c55e" : score >= 50 ? "#f59e0b" : "#ef4444";

  return (
    <svg viewBox="0 0 160 140" className="w-48 h-40 mx-auto">
      <path d={describeArc(startAngle, startAngle + arcRange, true)} fill="none" stroke="#334155" strokeWidth="12" strokeLinecap="round" />
      <path d={describeArc(startAngle, fillEnd, fillLarge)} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round" />
      <text x={cx} y={cy + 6} textAnchor="middle" fontSize="28" fontWeight="bold" fill="white">{Math.round(score)}</text>
      <text x={cx} y={cy + 22} textAnchor="middle" fontSize="9" fill="#94a3b8">/ 100</text>
      <text x={cx} y={cy + 36} textAnchor="middle" fontSize="9" fill={color}>
        {score >= 70 ? "RESILIENT" : score >= 50 ? "DEVELOPING" : "AT RISK"}
      </text>
    </svg>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function CyberResilienceDashboard() {
  const orgId = getStoredOrgId();
  const [metricFilter, setMetricFilter] = useState<string>("all");

  // Score + domains
  const scoreQuery = useQuery<ScoreResponse>({
    queryKey: ["cyber-resilience-score", orgId],
    queryFn: async () => {
      const url = buildApiUrl("/api/v1/cyber-resilience/score", { org_id: orgId });
      const res = await api.get<ScoreResponse>(url);
      return res.data;
    },
    staleTime: 60_000,
    refetchInterval: 120_000,
  });

  // Exercises
  const exercisesQuery = useQuery<Exercise[]>({
    queryKey: ["cyber-resilience-exercises", orgId],
    queryFn: async () => {
      const url = buildApiUrl("/api/v1/cyber-resilience/exercises", { org_id: orgId });
      const res = await api.get<Exercise[]>(url);
      return Array.isArray(res.data) ? res.data : [];
    },
    staleTime: 60_000,
  });

  // Assessments (domain detail with evidence, assessor, etc.)
  const assessmentsQuery = useQuery<Assessment[]>({
    queryKey: ["cyber-resilience-assessments", orgId],
    queryFn: async () => {
      const url = buildApiUrl("/api/v1/cyber-resilience/assessments", { org_id: orgId });
      const res = await api.get<Assessment[]>(url);
      return Array.isArray(res.data) ? res.data : [];
    },
    staleTime: 60_000,
  });

  const refetchAll = () => {
    scoreQuery.refetch();
    exercisesQuery.refetch();
    assessmentsQuery.refetch();
  };

  if (scoreQuery.isLoading) return <PageSkeleton />;
  if (scoreQuery.isError) return <ErrorState message="Failed to load resilience data" onRetry={refetchAll} />;

  const scoreData = scoreQuery.data!;
  const exercises = exercisesQuery.data ?? [];
  const assessments = assessmentsQuery.data ?? [];
  const overallScore = scoreData.overall_score ?? 0;

  // Build domain list from score.by_domain
  const domains = Object.entries(scoreData.by_domain ?? {}).map(([key, val]) => ({
    key,
    name: key.charAt(0).toUpperCase() + key.slice(1),
    score: val.avg_score ?? 0,
    color: domainColor(key),
    // maturity from distribution if present, or derive from score
    maturity: (() => {
      const dist = scoreData.maturity_distribution ?? {};
      // find maturity level for this domain from assessments
      const match = assessments.find((a) => a.resilience_domain === key);
      if (match) return match.maturity_level;
      // fallback: estimate from score
      if (val.avg_score >= 80) return 4;
      if (val.avg_score >= 60) return 3;
      if (val.avg_score >= 40) return 2;
      return 1;
    })(),
  }));

  const filteredExercises = exercises.filter((ex) => {
    if (metricFilter === "all") return true;
    if (metricFilter === "time") return ex.type === "tabletop" || ex.type === "drill";
    if (metricFilter === "rate") return ex.type === "red_team" || ex.type === "purple_team" || ex.type === "simulation";
    return true;
  });

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <ShieldAlert className="text-green-400" size={28} />
          <div>
            <h1 className="text-2xl font-bold">Cyber Resilience Dashboard</h1>
            <p className="text-gray-400 text-sm">NIST CSF maturity, exercise tracking, and resilience assessments</p>
          </div>
        </div>
        <button
          onClick={refetchAll}
          className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-gray-700 hover:bg-gray-600 text-sm text-gray-300 transition-colors"
          aria-label="Refresh resilience data"
        >
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Gauge */}
        <div className="bg-gray-800 rounded-lg p-6 flex flex-col items-center lg:col-span-1">
          <h2 className="text-sm font-semibold mb-2 text-gray-300">Resilience Score</h2>
          <ArcGauge score={overallScore} />
          {/* Maturity distribution summary */}
          {Object.keys(scoreData.maturity_distribution ?? {}).length > 0 && (
            <div className="mt-4 w-full space-y-1">
              <p className="text-xs text-gray-400 mb-1 flex items-center gap-1"><TrendingUp size={12} /> Maturity Distribution</p>
              {Object.entries(scoreData.maturity_distribution ?? {}).sort(([a], [b]) => Number(b) - Number(a)).map(([level, count]) => (
                <div key={level} className="flex items-center justify-between text-xs">
                  <span className="text-gray-400">Level {level}</span>
                  <span className="font-mono text-gray-200">{count} domain{Number(count) !== 1 ? "s" : ""}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* NIST CSF domains */}
        <div className="bg-gray-800 rounded-lg p-6 lg:col-span-3">
          <h2 className="text-lg font-semibold mb-4">NIST CSF Domain Maturity</h2>
          {domains.length === 0 ? (
            <EmptyState icon={ShieldAlert} title="No domain data" description="Domain assessment data will appear here once assessments are recorded." />
          ) : (
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              {domains.map((d) => (
                <div key={d.key} className="bg-gray-700/50 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-semibold text-sm" style={{ color: d.color }}>{d.name}</span>
                    <Stars count={d.maturity} />
                  </div>
                  <div className="text-xs text-gray-400 mb-1">Level {d.maturity}/5 · Score {Math.round(d.score)}</div>
                  <div className="bg-gray-700 rounded-full h-2">
                    <div className="h-2 rounded-full transition-all duration-700" style={{ width: `${d.score}%`, backgroundColor: d.color }} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Exercise tracker */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <BarChart2 size={18} className="text-green-400" /> Exercise Tracker
        </h2>
        {exercises.length === 0 ? (
          <EmptyState icon={BarChart2} title="No exercises recorded" description="Tabletop exercises, red team engagements, and drills will appear here once scheduled or completed." />
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-400 border-b border-gray-700">
                <th className="text-left py-2">Exercise</th>
                <th className="text-left py-2">Type</th>
                <th className="text-left py-2">Status</th>
                <th className="text-right py-2">Participants</th>
                <th className="text-right py-2">Findings</th>
                <th className="text-left py-2 pl-4">Date</th>
              </tr>
            </thead>
            <tbody>
              {exercises.map((ex) => (
                <tr key={ex.id} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                  <td className="py-2 text-gray-200 font-medium">{ex.exercise_name}</td>
                  <td className="py-2">{typeBadge(ex.type)}</td>
                  <td className="py-2">{statusBadge(ex.status)}</td>
                  <td className="py-2 text-right text-gray-300">{ex.participants}</td>
                  <td className="py-2 text-right">
                    {ex.findings_count > 0
                      ? <span className="text-orange-400 font-medium">{ex.findings_count}</span>
                      : <span className="text-gray-500">—</span>}
                  </td>
                  <td className="py-2 pl-4 text-gray-400">{ex.scheduled_date}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Assessments / Lessons learned */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <BookOpen size={18} className="text-green-400" /> Domain Assessments
          </h2>
          {assessments.length === 0 ? (
            <EmptyState icon={BookOpen} title="No assessments recorded" description="Domain assessments and lessons learned will appear here once recorded." />
          ) : (
            <div className="space-y-3">
              {assessments.map((a) => (
                <div key={a.id} className="bg-gray-700/40 rounded-lg p-3">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="text-sm text-gray-200 font-medium">{a.assessment_name}</p>
                      <p className="text-xs text-gray-400 mt-0.5 capitalize">Domain: {a.resilience_domain}</p>
                      {a.evidence && <p className="text-xs text-gray-500 mt-1 line-clamp-2">{a.evidence}</p>}
                    </div>
                    <div className="text-right shrink-0">
                      <div className="flex items-center gap-1 justify-end mb-1">
                        <Stars count={a.maturity_level} max={a.max_level} />
                      </div>
                      <span className={`text-xs font-medium ${a.score >= 70 ? "text-green-400" : a.score >= 50 ? "text-yellow-400" : "text-red-400"}`}>
                        {a.score.toFixed(0)}%
                      </span>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 mt-2 text-xs text-gray-500">
                    <span>Assessor: {a.assessor || "—"}</span>
                    <span>{a.assessment_date.slice(0, 10)}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Metrics from score.by_domain */}
        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <TrendingUp size={18} className="text-green-400" /> Domain Scores
            </h2>
            <select
              className="bg-gray-700 rounded px-2 py-1 text-xs text-gray-300"
              value={metricFilter}
              onChange={(e) => setMetricFilter(e.target.value)}
            >
              <option value="all">All Domains</option>
              <option value="identify">Identify / Protect</option>
              <option value="detect">Detect / Respond</option>
            </select>
          </div>
          {domains.length === 0 ? (
            <EmptyState icon={TrendingUp} title="No domain metrics" description="Domain score metrics will appear once assessments are completed." />
          ) : (
            <div className="space-y-4">
              {domains
                .filter((d) => {
                  if (metricFilter === "all") return true;
                  if (metricFilter === "identify") return ["identify", "protect"].includes(d.key);
                  if (metricFilter === "detect") return ["detect", "respond", "recover"].includes(d.key);
                  return true;
                })
                .map((d) => {
                  const target = 80;
                  const pct = Math.min(100, Math.round((d.score / target) * 100));
                  const onTarget = d.score >= target;
                  return (
                    <div key={d.key}>
                      <div className="flex justify-between text-sm mb-1">
                        <span className="text-gray-300">{d.name}</span>
                        <span className={onTarget ? "text-green-400" : "text-orange-400"}>
                          {Math.round(d.score)}% / {target}% target
                        </span>
                      </div>
                      <div className="flex gap-1 items-center">
                        <div className="flex-1 bg-gray-700 rounded-full h-2">
                          <div
                            className={`h-2 rounded-full transition-all duration-700 ${onTarget ? "bg-green-500" : "bg-orange-500"}`}
                            style={{ width: `${Math.min(d.score, 100)}%`, backgroundColor: d.color }}
                          />
                        </div>
                        <span className="text-xs text-gray-500 w-8 text-right">{pct}%</span>
                      </div>
                    </div>
                  );
                })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
