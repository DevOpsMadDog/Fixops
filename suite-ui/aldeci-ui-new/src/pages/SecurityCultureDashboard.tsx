/**
 * Security Culture Dashboard
 *
 * Culture metrics grid (7 categories), initiative tracker, assessment
 * history cards, department culture scores table.
 *
 * Route: /security-culture
 */

import { useState, useEffect } from "react";
import { Heart, TrendingUp, TrendingDown, Minus, RefreshCw, Users, ClipboardList, BarChart2 } from "lucide-react";

// == Types =====================================================================

type CultureCategory = "phishing-resilience" | "training-completion" | "policy-compliance" | "incident-reporting" | "security-advocacy" | "tool-adoption" | "vulnerability-disclosure";
type MaturityLevel = "optimized" | "managed" | "defined" | "developing" | "initial";
type InitiativeStatus = "active" | "planned" | "completed" | "paused";
type Trend = "up" | "down" | "flat";

interface CultureMetric {
  category: CultureCategory;
  label: string;
  value: number;
  target: number;
  trend: Trend;
  trend_delta: number; // pp change vs last quarter
}

interface Initiative {
  id: string;
  name: string;
  type: string;
  completion_rate: number;
  participants: number;
  status: InitiativeStatus;
  quarter: string;
}

interface Assessment {
  id: string;
  title: string;
  date: string;
  score: number; // 0-100
  maturity_level: MaturityLevel;
  strengths: string[];
  weaknesses: string[];
  assessor: string;
}

interface DeptScore {
  department: string;
  headcount: number;
  culture_score: number;
  training_rate: number;
  phishing_pass: number;
  reporting_rate: number;
}

// == Mock data =================================================================

const MOCK_METRICS: CultureMetric[] = [
  { category: "phishing-resilience",     label: "Phishing Resilience",     value: 87, target: 90, trend: "up",   trend_delta: 5  },
  { category: "training-completion",     label: "Training Completion",     value: 91, target: 95, trend: "up",   trend_delta: 3  },
  { category: "policy-compliance",       label: "Policy Compliance",       value: 78, target: 85, trend: "flat", trend_delta: 0  },
  { category: "incident-reporting",      label: "Incident Reporting",      value: 64, target: 80, trend: "up",   trend_delta: 8  },
  { category: "security-advocacy",       label: "Security Advocacy",       value: 71, target: 75, trend: "up",   trend_delta: 4  },
  { category: "tool-adoption",           label: "Security Tool Adoption",  value: 83, target: 90, trend: "down", trend_delta: -2 },
  { category: "vulnerability-disclosure", label: "Vuln Disclosure Rate",   value: 55, target: 70, trend: "up",   trend_delta: 12 },
];

const MOCK_INITIATIVES: Initiative[] = [
  { id: "ini-001", name: "Security Champions Program",           type: "Advocacy",   completion_rate: 78, participants: 142, status: "active",    quarter: "Q2 2026" },
  { id: "ini-002", name: "Phishing Simulation Campaign",         type: "Awareness",  completion_rate: 100, participants: 1840, status: "completed", quarter: "Q1 2026" },
  { id: "ini-003", name: "Secure Development Training",          type: "Training",   completion_rate: 62, participants: 312, status: "active",    quarter: "Q2 2026" },
  { id: "ini-004", name: "Incident Reporting Gamification",      type: "Engagement", completion_rate: 35, participants: 88,  status: "active",    quarter: "Q2 2026" },
  { id: "ini-005", name: "Security Culture Assessment Q1 2026",  type: "Assessment", completion_rate: 100, participants: 65,  status: "completed", quarter: "Q1 2026" },
  { id: "ini-006", name: "Zero Trust Awareness Webinar Series",  type: "Training",   completion_rate: 0,  participants: 0,   status: "planned",   quarter: "Q3 2026" },
];

const MOCK_ASSESSMENTS: Assessment[] = [
  {
    id: "asm-001", title: "Security Culture Assessment Q1 2026", date: "2026-03-28", score: 74, maturity_level: "managed",
    strengths: ["Strong phishing awareness", "High training participation", "Security champions network active"],
    weaknesses: ["Low incident self-reporting", "Security tool adoption gaps in Ops team"],
    assessor: "SANS Security Awareness",
  },
  {
    id: "asm-002", title: "Security Culture Assessment Q4 2025", date: "2025-12-15", score: 68, maturity_level: "defined",
    strengths: ["Policy compliance improving", "Leadership buy-in increasing"],
    weaknesses: ["Phishing click rate still above target", "Limited vuln disclosure culture"],
    assessor: "Internal GRC Team",
  },
  {
    id: "asm-003", title: "Security Culture Assessment Q3 2025", date: "2025-09-20", score: 59, maturity_level: "developing",
    strengths: ["Mandatory training completion met", "Security newsletter engagement up"],
    weaknesses: ["No formal security champions program", "Incident reporting culturally stigmatized"],
    assessor: "External Consultant",
  },
];

const MOCK_DEPT_SCORES: DeptScore[] = [
  { department: "Engineering",    headcount: 320, culture_score: 88, training_rate: 96, phishing_pass: 91, reporting_rate: 72 },
  { department: "Finance",        headcount: 85,  culture_score: 81, training_rate: 94, phishing_pass: 88, reporting_rate: 65 },
  { department: "Sales",          headcount: 210, culture_score: 71, training_rate: 88, phishing_pass: 79, reporting_rate: 52 },
  { department: "Customer Svc",   headcount: 145, culture_score: 68, training_rate: 91, phishing_pass: 74, reporting_rate: 44 },
  { department: "HR",             headcount: 55,  culture_score: 77, training_rate: 93, phishing_pass: 85, reporting_rate: 60 },
  { department: "Operations",     headcount: 190, culture_score: 65, training_rate: 82, phishing_pass: 71, reporting_rate: 38 },
  { department: "Legal",          headcount: 28,  culture_score: 84, training_rate: 97, phishing_pass: 90, reporting_rate: 70 },
  { department: "Product",        headcount: 95,  culture_score: 82, training_rate: 95, phishing_pass: 87, reporting_rate: 63 },
];

// == Helpers ===================================================================

function maturityColor(m: MaturityLevel): string {
  return m === "optimized"  ? "bg-purple-500/20 text-purple-300"
       : m === "managed"    ? "bg-blue-500/20 text-blue-300"
       : m === "defined"    ? "bg-green-500/20 text-green-300"
       : m === "developing" ? "bg-amber-500/20 text-amber-300"
       :                      "bg-red-500/20 text-red-300";
}

function statusBadge(s: InitiativeStatus): string {
  return s === "active"    ? "bg-green-500/20 text-green-300"
       : s === "completed" ? "bg-gray-500/20 text-gray-400"
       : s === "planned"   ? "bg-blue-500/20 text-blue-300"
       :                     "bg-amber-500/20 text-amber-300";
}

function scoreColor(s: number): string {
  return s >= 80 ? "text-green-400" : s >= 65 ? "text-blue-400" : s >= 50 ? "text-amber-400" : "text-red-400";
}

function scoreBarColor(s: number): string {
  return s >= 80 ? "bg-green-500" : s >= 65 ? "bg-blue-400" : s >= 50 ? "bg-amber-400" : "bg-red-500";
}

function TrendIcon({ trend, delta }: { trend: Trend; delta: number }) {
  if (trend === "up")   return <span className="text-green-400 text-xs flex items-center gap-0.5"><TrendingUp className="w-3 h-3" />+{delta}pp</span>;
  if (trend === "down") return <span className="text-red-400 text-xs flex items-center gap-0.5"><TrendingDown className="w-3 h-3" />{delta}pp</span>;
  return <span className="text-gray-400 text-xs flex items-center gap-0.5"><Minus className="w-3 h-3" />0pp</span>;
}

function CircleProgress({ pct }: { pct: number }) {
  const r = 20;
  const circ = 2 * Math.PI * r;
  const filled = (pct / 100) * circ;
  const color = pct >= 80 ? "#22c55e" : pct >= 50 ? "#6366f1" : "#f97316";
  return (
    <svg width="52" height="52" className="flex-shrink-0">
      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4 flex items-center justify-between" role="status" aria-live="polite">
          <p className="text-red-400 text-sm">{error}</p>
          <button
            onClick={() => { setError(null); window.location.reload(); }}
            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
           aria-label="Refresh data">
            Retry
          </button>
        </div>
      )}
      <circle cx="26" cy="26" r={r} fill="none" stroke="#374151" strokeWidth="4" />
      <circle
        cx="26" cy="26" r={r} fill="none" stroke={color} strokeWidth="4"
        strokeDasharray={`${filled} ${circ - filled}`}
        strokeDashoffset={circ / 4}
        strokeLinecap="round"
      />
      <text x="26" y="30" textAnchor="middle" fontSize="10" fill="white" fontWeight="bold">{pct}%</text>
    </svg>
  );
}

// == Component =================================================================

export default function SecurityCultureDashboard() {
  const [selectedAssessment, setSelectedAssessment] = useState<string>("asm-001");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    fetch("/api/v1/security-culture", { headers: { "X-API-Key": localStorage.getItem("apiKey") || "" } })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(() => { /* live data available */ })
      .catch(() => { setError('Failed to load data'); })
      .finally(() => setLoading(false));
  }, []);

  const selAsmn = MOCK_ASSESSMENTS.find(a => a.id === selectedAssessment)!;

  const avgCulture = Math.round(MOCK_DEPT_SCORES.reduce((s, d) => s + d.culture_score, 0) / MOCK_DEPT_SCORES.length);
  const avgMetric  = Math.round(MOCK_METRICS.reduce((s, m) => s + m.value, 0) / MOCK_METRICS.length);

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Heart className="w-6 h-6 text-pink-400" />
            Security Culture
          </h1>
          <p className="text-gray-400 text-sm mt-1">Organizational security culture metrics, initiatives, and maturity assessments</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm transition-colors">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      {/* Summary KPIs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: "Avg Culture Score",     value: `${avgCulture}%`,                                  color: "text-pink-400" },
          { label: "Avg Metric vs Target",  value: `${avgMetric}%`,                                   color: "text-white" },
          { label: "Active Initiatives",    value: MOCK_INITIATIVES.filter(i => i.status === "active").length, color: "text-green-400" },
          { label: "Current Maturity",      value: MOCK_ASSESSMENTS[0].maturity_level,                color: "text-blue-400" },
        ].map(k => (
          <div key={k.label} className="bg-gray-800 rounded-lg p-4 text-center">
            <div className={`text-2xl font-bold capitalize ${k.color}`}>{k.value}</div>
            <div className="text-gray-400 text-xs mt-1">{k.label}</div>
          </div>
        ))}
      </div>

      {/* Culture metrics grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {MOCK_METRICS.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
            <p className="text-lg font-medium">No data available</p>
            <p className="text-sm">Data will appear here once available</p>
          </div>
        ) : (
          MOCK_METRICS.map(metric => {
          const pct = Math.round((metric.value / metric.target) * 100);
          const gap = metric.target - metric.value;
          return (
            <div key={metric.category} className="bg-gray-800 rounded-lg p-4">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <div className="font-medium text-white text-sm">{metric.label}</div>
                  <TrendIcon trend={metric.trend} delta={metric.trend_delta} />
                </div>
                <div className="text-right">
                  <div className={`text-xl font-bold ${scoreColor(metric.value)}`}>{metric.value}%</div>
                  <div className="text-gray-500 text-xs">tgt: {metric.target}%</div>
                </div>
              </div>
              {/* Value vs target bar */}
              <div className="relative w-full bg-gray-700 rounded-full h-2 mb-1">
                <div className={`h-2 rounded-full ${scoreBarColor(metric.value)}`} style={{ width: `${metric.value}%` }} />
                <div className="absolute top-0 h-2 w-0.5 bg-white/60" style={{ left: `${metric.target}%` }} />
              </div>
              <div className="flex justify-between text-xs text-gray-500">
                <span>{pct}% of target</span>
                {gap > 0 && <span className="text-amber-400">{gap}pp gap</span>}
              </div>
            </div>
          );
        })
        )}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Initiative tracker */}
        <div className="xl:col-span-1 bg-gray-800 rounded-lg overflow-hidden">
          <div className="p-4 border-b border-gray-700">
            <h2 className="font-semibold text-white flex items-center gap-2">
              <ClipboardList className="w-4 h-4 text-indigo-400" /> Initiatives
            </h2>
          </div>
          <div className="divide-y divide-gray-700/50">
            {MOCK_INITIATIVES.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              MOCK_INITIATIVES.map(ini => (
              <div key={ini.id} className="p-4 flex items-center gap-3">
                <CircleProgress pct={ini.completion_rate} />
                <div className="flex-1 min-w-0">
                  <div className="text-gray-200 text-sm font-medium truncate">{ini.name}</div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="bg-gray-700 text-gray-400 text-xs px-1.5 py-0.5 rounded">{ini.type}</span>
                    <span className={`text-xs px-1.5 py-0.5 rounded-full capitalize ${statusBadge(ini.status)}`}>{ini.status}</span>
                  </div>
                  <div className="text-gray-500 text-xs mt-1">
                    {ini.participants > 0 ? `${ini.participants.toLocaleString()} participants` : "Not started"} = {ini.quarter}
                  </div>
                </div>
              </div>
            ))
          )}
          </div>
        </div>

        {/* Assessment history */}
        <div className="xl:col-span-2 space-y-4">
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="p-4 border-b border-gray-700">
              <h2 className="font-semibold text-white flex items-center gap-2">
                <BarChart2 className="w-4 h-4 text-purple-400" /> Assessment History
              </h2>
            </div>
            <div className="divide-y divide-gray-700/50">
              {MOCK_ASSESSMENTS.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                MOCK_ASSESSMENTS.map(asm => (
                <div
                  key={asm.id}
                  onClick={() => setSelectedAssessment(asm.id)}
                  className={`p-4 cursor-pointer hover:bg-gray-700/40 transition-colors ${selectedAssessment === asm.id ? "bg-gray-700/60" : ""}`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-white text-sm">{asm.title}</div>
                      <div className="text-gray-400 text-xs mt-0.5">{asm.date} = {asm.assessor}</div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <span className={`text-2xl font-bold ${scoreColor(asm.score)}`}>{asm.score}</span>
                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium capitalize ${maturityColor(asm.maturity_level)}`}>
                        {asm.maturity_level}
                      </span>
                    </div>
                  </div>

                  {selectedAssessment === asm.id && (
                    <div className="mt-3 grid grid-cols-2 gap-3">
                      <div>
                        <div className="text-xs text-green-400 font-medium mb-1">Strengths</div>
                        <ul className="space-y-1">
                          {asm.strengths.map(s => (
                            <li key={s} className="text-gray-300 text-xs flex items-start gap-1">
                              <span className="text-green-400 mt-0.5">=</span> {s}
                            </li>
                          )))}
                        </ul>
                      </div>
                      <div>
                        <div className="text-xs text-red-400 font-medium mb-1" role="status" aria-live="polite">Weaknesses</div>
                        <ul className="space-y-1">
                          {asm.weaknesses.map(w => (
                            <li key={w} className="text-gray-300 text-xs flex items-start gap-1">
                              <span className="text-red-400 mt-0.5">=</span> {w}
                            </li>
                          )))}
                        </ul>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Score trend */}
          <div className="bg-gray-800 rounded-lg p-4">
            <div className="text-xs text-gray-400 mb-2">Score Trend (Q3 2025 = Q1 2026)</div>
            <div className="flex items-end gap-3 h-16">
              {MOCK_ASSESSMENTS.slice().reverse().map((a, i) => {
                const h = Math.round((a.score / 100) * 64);
                return (
                  <div key={a.id} className="flex flex-col items-center gap-1 flex-1">
                    <div className="w-full rounded-t" style={{ height: `${h}px`, backgroundColor: i === MOCK_ASSESSMENTS.length - 1 ? "#6366f1" : "#374151" }} />
                    <span className="text-xs text-gray-500">{a.score}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Department culture scores table */}
      <div className="bg-gray-800 rounded-lg overflow-hidden">
        <div className="p-4 border-b border-gray-700">
          <h2 className="font-semibold text-white flex items-center gap-2">
            <Users className="w-4 h-4 text-cyan-400" /> Department Culture Scores
          </h2>
        </div>
        <div className="overflow-x-auto">
          <table role="table" className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700 text-gray-400 text-xs uppercase">
                <th className="text-left p-3">Department</th>
                <th className="text-left p-3">Headcount</th>
                <th className="text-left p-3">Culture Score</th>
                <th className="text-left p-3 hidden sm:table-cell">Training Rate</th>
                <th className="text-left p-3 hidden md:table-cell">Phishing Pass</th>
                <th className="text-left p-3 hidden lg:table-cell">Reporting Rate</th>
              </tr>
            </thead>
            <tbody>
              {MOCK_DEPT_SCORES.sort((a, b) => b.culture_score - a.culture_score).map(dept => (
                <tr key={dept.department} className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors">
                  <td className="p-3 text-gray-200 font-medium">{dept.department}</td>
                  <td className="p-3 text-gray-400 text-xs">{dept.headcount}</td>
                  <td className="p-3">
                    <div className="flex items-center gap-2">
                      <span className={`font-bold ${scoreColor(dept.culture_score)}`}>{dept.culture_score}%</span>
                      <div className="w-20 bg-gray-700 rounded-full h-1.5">
                        <div className={`h-1.5 rounded-full ${scoreBarColor(dept.culture_score)}`} style={{ width: `${dept.culture_score}%` }} />
                      </div>
                    </div>
                  </td>
                  <td className="p-3 hidden sm:table-cell">
                    <span className={`text-xs font-medium ${scoreColor(dept.training_rate)}`}>{dept.training_rate}%</span>
                  </td>
                  <td className="p-3 hidden md:table-cell">
                    <span className={`text-xs font-medium ${scoreColor(dept.phishing_pass)}`}>{dept.phishing_pass}%</span>
                  </td>
                  <td className="p-3 hidden lg:table-cell">
                    <span className={`text-xs font-medium ${scoreColor(dept.reporting_rate)}`}>{dept.reporting_rate}%</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
