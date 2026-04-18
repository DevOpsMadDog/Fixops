/**
 * Security Health Scorecard Dashboard
 *
 * Overall security health grade with domain-level breakdown, snapshot
 * history sparkline, improvement areas, and target tracking.
 *
 * Route: /health-scorecard
 */

import { useState, useEffect } from "react";
import {
  ShieldCheck,
  TrendingUp,
  Target,
  Camera,
  AlertTriangle,
  CheckCircle2,
  Clock,
} from "lucide-react";

// ── Types ──────────────────────────────────────────────────────

interface Domain {
  domain_name: string;
  category: "technical" | "process" | "people" | "governance";
  score: number;
  max_score: number;
  status: "green" | "amber" | "red";
  weight: number;
}

interface Snapshot {
  date: string;
  score: number;
  grade: string;
}

interface GradeTrend {
  period: string;
  grade: string;
  score: number;
  change: number;
}

interface TargetItem {
  domain: string;
  target_score: number;
  current_score: number;
  deadline: string;
  owner: string;
}

// ── Mock data ──────────────────────────────────────────────────

const DOMAINS: Domain[] = [
  { domain_name: "Vulnerability Management", category: "technical", score: 82, max_score: 100, status: "green", weight: 15 },
  { domain_name: "Identity & Access", category: "technical", score: 74, max_score: 100, status: "amber", weight: 14 },
  { domain_name: "Endpoint Security", category: "technical", score: 91, max_score: 100, status: "green", weight: 12 },
  { domain_name: "Incident Response", category: "process", score: 68, max_score: 100, status: "amber", weight: 12 },
  { domain_name: "Security Awareness", category: "people", score: 55, max_score: 100, status: "red", weight: 10 },
  { domain_name: "Data Protection", category: "governance", score: 79, max_score: 100, status: "green", weight: 10 },
  { domain_name: "Cloud Security", category: "technical", score: 61, max_score: 100, status: "red", weight: 10 },
  { domain_name: "Network Security", category: "technical", score: 87, max_score: 100, status: "green", weight: 9 },
  { domain_name: "Compliance", category: "governance", score: 93, max_score: 100, status: "green", weight: 8 },
];

const SNAPSHOTS: Snapshot[] = [
  { date: "Feb 5", score: 68, grade: "C" },
  { date: "Feb 20", score: 70, grade: "C" },
  { date: "Mar 5", score: 71, grade: "C" },
  { date: "Mar 20", score: 73, grade: "C" },
  { date: "Apr 1", score: 75, grade: "B" },
  { date: "Apr 4", score: 74, grade: "B" },
  { date: "Apr 7", score: 76, grade: "B" },
  { date: "Apr 10", score: 77, grade: "B" },
  { date: "Apr 13", score: 78, grade: "B" },
  { date: "Apr 16", score: 79, grade: "B" },
];

const GRADE_TREND: GradeTrend[] = [
  { period: "Q3 2025", grade: "D", score: 58, change: 0 },
  { period: "Q4 2025", grade: "C", score: 67, change: +9 },
  { period: "Q1 2026", grade: "C", score: 72, change: +5 },
  { period: "Q2 2026 (current)", grade: "B", score: 79, change: +7 },
];

const TARGETS: TargetItem[] = [
  { domain: "Security Awareness", target_score: 75, current_score: 55, deadline: "2026-06-30", owner: "CISO" },
  { domain: "Cloud Security", target_score: 80, current_score: 61, deadline: "2026-07-15", owner: "Cloud Team" },
  { domain: "Incident Response", target_score: 85, current_score: 68, deadline: "2026-05-31", owner: "SOC Lead" },
  { domain: "Identity & Access", target_score: 90, current_score: 74, deadline: "2026-06-15", owner: "IAM Team" },
];

// ── Helpers ────────────────────────────────────────────────────

function computeOverallScore(domains: Domain[]): number {
  const totalWeight = domains.reduce((s, d) => s + d.weight, 0);
  const weighted = domains.reduce((s, d) => s + (d.score / d.max_score) * d.weight, 0);
  return Math.round((weighted / totalWeight) * 100);
}

function scoreToGrade(score: number): { grade: string; color: string; bg: string } {
  if (score >= 90) return { grade: "A", color: "text-green-400", bg: "bg-green-500/20 border border-green-500/40" };
  if (score >= 80) return { grade: "B", color: "text-teal-400", bg: "bg-teal-500/20 border border-teal-500/40" };
  if (score >= 70) return { grade: "C", color: "text-yellow-400", bg: "bg-yellow-500/20 border border-yellow-500/40" };
  if (score >= 60) return { grade: "D", color: "text-orange-400", bg: "bg-orange-500/20 border border-orange-500/40" };
  return { grade: "F", color: "text-red-400", bg: "bg-red-500/20 border border-red-500/40" };
}

function statusDot(status: Domain["status"]) {
  const cls = status === "green" ? "bg-green-400" : status === "amber" ? "bg-yellow-400" : "bg-red-400";
  return <span className={`inline-block w-2.5 h-2.5 rounded-full ${cls}`} />;
}

function categoryColor(cat: Domain["category"]) {
  const map: Record<string, string> = {
    technical: "bg-blue-500/20 text-blue-300",
    process: "bg-purple-500/20 text-purple-300",
    people: "bg-pink-500/20 text-pink-300",
    governance: "bg-teal-500/20 text-teal-300",
  };
  return map[cat] ?? "bg-gray-600 text-gray-300";
}

const SPARK_W = 320;
const SPARK_H = 60;
const SPARK_PAD = 8;

function Sparkline({ data }: { data: Snapshot[] }) {
  if (data.length < 2) return null;
  const scores = data.map((d) => d.score);
  const min = Math.min(...scores) - 2;
  const max = Math.max(...scores) + 2;
  const toX = (i: number) =>
    SPARK_PAD + (i / (data.length - 1)) * (SPARK_W - SPARK_PAD * 2);
  const toY = (v: number) =>
    SPARK_PAD + ((max - v) / (max - min)) * (SPARK_H - SPARK_PAD * 2);
  const pts = data.map((d, i) => `${toX(i)},${toY(d.score)}`).join(" ");
  return (
    <svg viewBox={`0 0 ${SPARK_W} ${SPARK_H}`} className="w-full h-16">
      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4 flex items-center justify-between">
          <p className="text-red-400 text-sm">{error}</p>
          <button
            onClick={() => { setError(null); window.location.reload(); }}
            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
          >
            Retry
          </button>
        </div>
      )}
      <polyline
        points={pts}
        fill="none"
        stroke="#38bdf8"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      {data.map((d, i) => (
        <circle key={i} cx={toX(i)} cy={toY(d.score)} r="3" fill="#38bdf8" />
      ))}
      {data.map((d, i) => (
        <text
          key={`lbl-${i}`}
          x={toX(i)}
          y={SPARK_H - 1}
          fontSize="7"
          fill="#94a3b8"
          textAnchor="middle"
        >
          {d.date}
        </text>
      ))}
    </svg>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function SecurityHealthScorecardDashboard() {
  const [snapshotMsg, setSnapshotMsg] = useState<string | null>(null);
  useEffect(() => {
    fetch("/api/v1/health-scorecard", { headers: { "X-API-Key": localStorage.getItem("apiKey") || "" } })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(() => { /* live data available */ })
      .catch(() => { setError('Failed to load data'); });
  }, []);
  const overallScore = computeOverallScore(DOMAINS);
  const { grade, color, bg } = scoreToGrade(overallScore);
  const redDomains = DOMAINS.filter((d) => d.status === "red");

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldCheck className="text-sky-400" size={28} />
          <div>
            <h1 className="text-2xl font-bold">Security Health Scorecard</h1>
            <p className="text-gray-400 text-sm">Weighted domain scoring across all security pillars</p>
          </div>
        </div>
        <button
          onClick={() => {
            const ts = new Date().toLocaleTimeString();
            setSnapshotMsg(`Snapshot captured at ${ts}`);
            setTimeout(() => setSnapshotMsg(null), 3000);
          }}
          className="flex items-center gap-2 px-4 py-2 bg-sky-600 hover:bg-sky-500 rounded-lg text-sm font-medium transition-colors"
        >
          <Camera size={16} /> Take Snapshot
        </button>
      </div>

      {snapshotMsg && (
        <div className="bg-green-900/30 border border-green-500/40 rounded-lg px-4 py-2 text-green-300 text-sm flex items-center gap-2">
          <CheckCircle2 size={16} /> {snapshotMsg}
        </div>
      )}

      {/* Overall grade + stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className={`bg-gray-800 rounded-lg p-6 flex flex-col items-center justify-center md:col-span-1 ${bg}`}>
          <div className={`text-7xl font-black ${color}`}>{grade}</div>
          <div className="text-gray-300 text-sm mt-1">Overall Grade</div>
          <div className="text-3xl font-bold text-white mt-1">{overallScore}</div>
          <div className="text-gray-400 text-xs">/ 100</div>
        </div>
        <div className="bg-gray-800 rounded-lg p-6 flex flex-col justify-center">
          <div className="text-gray-400 text-sm mb-1">Domains Healthy</div>
          <div className="text-3xl font-bold text-green-400">
            {DOMAINS.filter((d) => d.status === "green").length}
            <span className="text-gray-500 text-lg">/{DOMAINS.length}</span>
          </div>
          <div className="text-gray-400 text-xs mt-1">Above threshold</div>
        </div>
        <div className="bg-gray-800 rounded-lg p-6 flex flex-col justify-center">
          <div className="text-gray-400 text-sm mb-1">Needs Attention</div>
          <div className="text-3xl font-bold text-yellow-400">
            {DOMAINS.filter((d) => d.status === "amber").length}
          </div>
          <div className="text-gray-400 text-xs mt-1">Amber domains</div>
        </div>
        <div className="bg-gray-800 rounded-lg p-6 flex flex-col justify-center">
          <div className="text-gray-400 text-sm mb-1">Critical Gaps</div>
          <div className="text-3xl font-bold text-red-400">
            {redDomains.length}
          </div>
          <div className="text-gray-400 text-xs mt-1">Red domains</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Domain grid */}
        <div className="lg:col-span-2 bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <ShieldCheck size={18} className="text-sky-400" /> Domain Breakdown
          </h2>
          <div className="space-y-3">
            {DOMAINS.map((d) => {
              const pct = Math.round((d.score / d.max_score) * 100);
              const barColor = d.status === "green" ? "bg-green-500" : d.status === "amber" ? "bg-yellow-500" : "bg-red-500";
              return (
                <div key={d.domain_name} className="grid grid-cols-12 items-center gap-2 text-sm">
                  <div className="col-span-4 font-medium text-gray-200 truncate">{d.domain_name}</div>
                  <div className="col-span-2">
                    <span className={`px-2 py-0.5 rounded text-xs ${categoryColor(d.category)}`}>
                      {d.category}
                    </span>
                  </div>
                  <div className="col-span-4">
                    <div className="bg-gray-700 rounded-full h-2">
                      <div className={`${barColor} rounded-full h-2`} style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                  <div className="col-span-1 text-right text-gray-300">{d.score}</div>
                  <div className="col-span-1 flex justify-center">{statusDot(d.status)}</div>
                </div>
              );
            })}
          </div>
          <div className="mt-3 pt-3 border-t border-gray-700 text-xs text-gray-500">
            Weights: {DOMAINS.map((d) => `${d.domain_name.split(" ")[0]} ${d.weight}%`).join(" · ")}
          </div>
        </div>

        {/* Right panel: sparkline + improvement areas */}
        <div className="space-y-4">
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-sm font-semibold mb-3 flex items-center gap-2">
              <TrendingUp size={16} className="text-sky-400" /> Score History (last 10 snapshots)
            </h2>
            <Sparkline data={SNAPSHOTS} />
          </div>

          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-sm font-semibold mb-3 flex items-center gap-2">
              <AlertTriangle size={16} className="text-red-400" /> Improvement Areas
            </h2>
            {redDomains.length === 0 ? (
              <p className="text-gray-400 text-xs">No critical gaps — all domains passing.</p>
            ) : (
              <div className="space-y-2">
                {redDomains.map((d) => {
                  const gap = d.max_score - d.score;
                  return (
                    <div key={d.domain_name} className="flex items-center justify-between text-sm">
                      <span className="text-red-300">{d.domain_name}</span>
                      <span className="text-red-400 font-bold">−{gap}%</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Grade trend table */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <TrendingUp size={18} className="text-sky-400" /> Grade Trend
        </h2>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-gray-400 border-b border-gray-700">
              <th className="text-left py-2">Period</th>
              <th className="text-center py-2">Grade</th>
              <th className="text-right py-2">Score</th>
              <th className="text-right py-2">Change</th>
            </tr>
          </thead>
          <tbody>
            {GRADE_TREND.map((row) => {
              const g = scoreToGrade(row.score);
              return (
                <tr key={row.period} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                  <td className="py-2 text-gray-200">{row.period}</td>
                  <td className="py-2 text-center">
                    <span className={`font-bold text-lg ${g.color}`}>{row.grade}</span>
                  </td>
                  <td className="py-2 text-right text-gray-200">{row.score}</td>
                  <td className="py-2 text-right">
                    {row.change === 0 ? (
                      <span className="text-gray-500">—</span>
                    ) : (
                      <span className={row.change > 0 ? "text-green-400" : "text-red-400"}>
                        {row.change > 0 ? "+" : ""}{row.change}
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Target tracking table */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Target size={18} className="text-sky-400" /> Target Tracking
        </h2>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-gray-400 border-b border-gray-700">
              <th className="text-left py-2">Domain</th>
              <th className="text-right py-2">Current</th>
              <th className="text-right py-2">Target</th>
              <th className="text-right py-2">Gap</th>
              <th className="text-left py-2 pl-4">Deadline</th>
              <th className="text-left py-2">Owner</th>
            </tr>
          </thead>
          <tbody>
            {TARGETS.map((t) => {
              const gap = t.target_score - t.current_score;
              const pct = Math.round((t.current_score / t.target_score) * 100);
              return (
                <tr key={t.domain} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                  <td className="py-2 text-gray-200">{t.domain}</td>
                  <td className="py-2 text-right text-gray-300">{t.current_score}</td>
                  <td className="py-2 text-right text-sky-300">{t.target_score}</td>
                  <td className="py-2 text-right text-red-400 font-medium">−{gap}</td>
                  <td className="py-2 pl-4">
                    <div className="flex items-center gap-1 text-gray-400">
                      <Clock size={12} /> {t.deadline}
                    </div>
                  </td>
                  <td className="py-2">
                    <span className="px-2 py-0.5 bg-gray-700 rounded text-gray-300">{t.owner}</span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
