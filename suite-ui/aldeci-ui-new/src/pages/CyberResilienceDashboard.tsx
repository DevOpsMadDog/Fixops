/**
 * Cyber Resilience Dashboard
 *
 * Overall resilience score gauge, NIST CSF domain grid with maturity stars,
 * exercise tracker, lessons learned panel, metrics trend bars, and history sparkline.
 *
 * Route: /cyber-resilience
 */

import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/cyber-resilience";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

import {
  ShieldAlert,
  Star,
  TrendingUp,
  BookOpen,
  BarChart2,
} from "lucide-react";

// ── Types ──────────────────────────────────────────────────────

interface CSFDomain {
  name: string;
  key: "identify" | "protect" | "detect" | "respond" | "recover" | "adapt";
  maturity: 1 | 2 | 3 | 4 | 5;
  score: number;
  color: string;
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

interface MetricItem {
  category: string;
  value: number;
  target: number;
  unit: string;
}

interface Snapshot {
  date: string;
  score: number;
}

// ── Mock data ──────────────────────────────────────────────────

const CSF_DOMAINS: CSFDomain[] = [
  { name: "Identify", key: "identify", maturity: 4, score: 82, color: "#38bdf8" },
  { name: "Protect", key: "protect", maturity: 4, score: 79, color: "#a78bfa" },
  { name: "Detect", key: "detect", maturity: 3, score: 71, color: "#f59e0b" },
  { name: "Respond", key: "respond", maturity: 3, score: 68, color: "#f97316" },
  { name: "Recover", key: "recover", maturity: 2, score: 55, color: "#ef4444" },
  { name: "Adapt", key: "adapt", maturity: 2, score: 50, color: "#ec4899" },
];

const OVERALL_SCORE = Math.round(CSF_DOMAINS.reduce((s, d) => s + d.score, 0) / CSF_DOMAINS.length);

const EXERCISES: Exercise[] = [
  { id: "ex01", exercise_name: "Q1 Ransomware Tabletop", type: "tabletop", status: "completed", participants: 18, findings_count: 7, scheduled_date: "2026-03-15" },
  { id: "ex02", exercise_name: "Supply Chain Attack Simulation", type: "simulation", status: "completed", participants: 12, findings_count: 4, scheduled_date: "2026-04-02" },
  { id: "ex03", exercise_name: "Red Team: Cloud Infrastructure", type: "red_team", status: "scheduled", participants: 6, findings_count: 0, scheduled_date: "2026-04-28" },
  { id: "ex04", exercise_name: "Purple Team: EDR Evasion", type: "purple_team", status: "scheduled", participants: 10, findings_count: 0, scheduled_date: "2026-05-10" },
  { id: "ex05", exercise_name: "IR Drill: Data Breach", type: "drill", status: "completed", participants: 22, findings_count: 11, scheduled_date: "2026-02-20" },
];

const METRICS: MetricItem[] = [
  { category: "Mean Time to Detect (h)", value: 4.2, target: 2.0, unit: "h" },
  { category: "Mean Time to Respond (h)", value: 8.5, target: 6.0, unit: "h" },
  { category: "Recovery Time Objective (%)", value: 72, target: 90, unit: "%" },
  { category: "Backup Success Rate (%)", value: 96, target: 99, unit: "%" },
  { category: "Incident Containment Rate (%)", value: 85, target: 95, unit: "%" },
];

const LESSONS = [
  { id: "l01", finding: "IR runbook lacked cloud-specific containment steps", exercise: "Q1 Ransomware Tabletop", status: "resolved" },
  { id: "l02", finding: "Communication plan had outdated vendor contacts", exercise: "IR Drill: Data Breach", status: "in_progress" },
  { id: "l03", finding: "Recovery playbook not tested for multi-region failure", exercise: "Supply Chain Simulation", status: "open" },
  { id: "l04", finding: "Log retention insufficient for forensics (< 90 days)", exercise: "IR Drill: Data Breach", status: "resolved" },
];

const HISTORY: Snapshot[] = [
  { date: "Oct", score: 48 },
  { date: "Nov", score: 52 },
  { date: "Dec", score: 55 },
  { date: "Jan", score: 58 },
  { date: "Feb", score: 61 },
  { date: "Mar", score: 63 },
  { date: "Apr", score: 67 },
];

// ── Helpers ────────────────────────────────────────────────────

function Stars({ count, max = 5 }: { count: number; max?: number }) {
  return (
    <div className="flex gap-0.5">
      {Array.from({ length: max }, (_, i) => (
        <Star
          key={i}
          size={12}
          className={i < count ? "text-yellow-400 fill-yellow-400" : "text-gray-600"}
        />
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

function lessonStatus(s: string) {
  const map: Record<string, string> = {
    resolved: "text-green-400",
    in_progress: "text-yellow-400",
    open: "text-red-400",
  };
  return <span className={`text-xs font-medium ${map[s] ?? "text-gray-400"}`}>{s.replace("_", " ")}</span>;
}

// ── SVG Arc Gauge ──────────────────────────────────────────────

function ArcGauge({ score }: { score: number }) {
  const r = 60;
  const cx = 80;
  const cy = 80;
  const startAngle = 210;
  const endAngle = 330;
  const arcRange = 300; // degrees
  const pct = Math.min(100, Math.max(0, score)) / 100;
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const arcX = (deg: number) => cx + r * Math.cos(toRad(deg));
  const arcY = (deg: number) => cy + r * Math.sin(toRad(deg));

  const describeArc = (from: number, to: number, large: boolean) => {
    const x1 = arcX(from);
    const y1 = arcY(from);
    const x2 = arcX(to);
    const y2 = arcY(to);
    return `M ${x1} ${y1} A ${r} ${r} 0 ${large ? 1 : 0} 1 ${x2} ${y2}`;
  };

  const fillEnd = startAngle + pct * arcRange;
  const fillLarge = pct * arcRange > 180;
  const color = score >= 70 ? "#22c55e" : score >= 50 ? "#f59e0b" : "#ef4444";

  return (
    <svg viewBox="0 0 160 140" className="w-48 h-40 mx-auto">
      <path d={describeArc(startAngle, startAngle + arcRange, true)} fill="none" stroke="#334155" strokeWidth="12" strokeLinecap="round" />
      <path d={describeArc(startAngle, fillEnd, fillLarge)} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round" />
      <text x={cx} y={cy + 6} textAnchor="middle" fontSize="28" fontWeight="bold" fill="white">{score}</text>
      <text x={cx} y={cy + 22} textAnchor="middle" fontSize="9" fill="#94a3b8">/ 100</text>
      <text x={cx} y={cy + 36} textAnchor="middle" fontSize="9" fill={color}>
        {score >= 70 ? "RESILIENT" : score >= 50 ? "DEVELOPING" : "AT RISK"}
      </text>
    </svg>
  );
}

// ── Sparkline ──────────────────────────────────────────────────

function Sparkline({ data }: { data: Snapshot[] }) {
  if (data.length < 2) return null;
  const W = 280, H = 50, PAD = 8;
  const scores = data.map((d) => d.score);
  const min = Math.min(...scores) - 3;
  const max = Math.max(...scores) + 3;
  const toX = (i: number) => PAD + (i / (data.length - 1)) * (W - PAD * 2);
  const toY = (v: number) => PAD + ((max - v) / (max - min)) * (H - PAD * 2);
  const pts = data.map((d, i) => `${toX(i)},${toY(d.score)}`).join(" ");
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-12">
      <polyline points={pts} fill="none" stroke="#22c55e" strokeWidth="2" strokeLinejoin="round" />
      {data.map((d, i) => (
        <circle key={i} cx={toX(i)} cy={toY(d.score)} r="3" fill="#22c55e" />
      ))}
      {data.map((d, i) => (
        <text key={`l${i}`} x={toX(i)} y={H} fontSize="7" fill="#94a3b8" textAnchor="middle">{d.date}</text>
      ))}
    </svg>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function CyberResilienceDashboard() {
  const [metricFilter, setMetricFilter] = useState<string>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    fetch(`${_API_BASE}/score?org_id=default`, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(() => { /* live data available */ })
      .catch((e) => setError(e?.message || 'Failed to load data'))
      .finally(() => setLoading(false));
  }, []);

  const filteredMetrics = metricFilter === "all" ? METRICS : METRICS.filter((m) =>
    m.category.toLowerCase().includes(metricFilter.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <ShieldAlert className="text-green-400" size={28} />
        <div>
          <h1 className="text-2xl font-bold">Cyber Resilience Dashboard</h1>
          <p className="text-gray-400 text-sm">NIST CSF maturity, exercise tracking, and resilience metrics</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Gauge + sparkline */}
        <div className="bg-gray-800 rounded-lg p-6 flex flex-col items-center lg:col-span-1">
          <h2 className="text-sm font-semibold mb-2 text-gray-300">Resilience Score</h2>
          <ArcGauge score={OVERALL_SCORE} />
          <div className="mt-4 w-full">
            <div className="text-xs text-gray-400 mb-1 flex items-center gap-1">
              <TrendingUp size={12} /> 6-month trend
            </div>
            <Sparkline data={HISTORY} />
          </div>
        </div>

        {/* NIST CSF domains */}
        <div className="bg-gray-800 rounded-lg p-6 lg:col-span-3">
          <h2 className="text-lg font-semibold mb-4">NIST CSF Domain Maturity</h2>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
            {CSF_DOMAINS.map((d) => (
              <div key={d.key} className="bg-gray-700/50 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-semibold text-sm" style={{ color: d.color }}>{d.name}</span>
                  <Stars count={d.maturity} />
                </div>
                <div className="text-xs text-gray-400 mb-1">Level {d.maturity}/5 · Score {d.score}</div>
                <div className="bg-gray-700 rounded-full h-2">
                  <div
                    className="h-2 rounded-full"
                    style={{ width: `${d.score}%`, backgroundColor: d.color }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Exercise tracker */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <BarChart2 size={18} className="text-green-400" /> Exercise Tracker
        </h2>
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
            {EXERCISES.map((ex) => (
              <tr key={ex.id} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                <td className="py-2 text-gray-200 font-medium">{ex.exercise_name}</td>
                <td className="py-2">{typeBadge(ex.type)}</td>
                <td className="py-2">{statusBadge(ex.status)}</td>
                <td className="py-2 text-right text-gray-300">{ex.participants}</td>
                <td className="py-2 text-right">
                  {ex.findings_count > 0 ? (
                    <span className="text-orange-400 font-medium">{ex.findings_count}</span>
                  ) : (
                    <span className="text-gray-500">—</span>
                  )}
                </td>
                <td className="py-2 pl-4 text-gray-400">{ex.scheduled_date}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Lessons learned */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <BookOpen size={18} className="text-green-400" /> Lessons Learned
          </h2>
          <div className="space-y-3">
            {LESSONS.map((l) => (
              <div key={l.id} className="bg-gray-700/40 rounded-lg p-3">
                <div className="flex items-start justify-between gap-2">
                  <p className="text-sm text-gray-200">{l.finding}</p>
                  {lessonStatus(l.status)}
                </div>
                <p className="text-xs text-gray-500 mt-1">Source: {l.exercise}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Metrics trend */}
        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <TrendingUp size={18} className="text-green-400" /> Resilience Metrics
            </h2>
            <select
              className="bg-gray-700 rounded px-2 py-1 text-xs text-gray-300"
              value={metricFilter}
              onChange={(e) => setMetricFilter(e.target.value)}
            >
              <option value="all">All Metrics</option>
              <option value="time">Time-based</option>
              <option value="rate">Rate-based</option>
            </select>
          </div>
          <div className="space-y-4">
            {filteredMetrics.map((m) => {
              const pct = Math.min(100, Math.round((m.value / m.target) * 100));
              const onTarget = m.value >= m.target;

              if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;

              return (
                <div key={m.category}>
                  <div className="flex justify-between text-sm mb-1">
                    <span className="text-gray-300">{m.category}</span>
                    <span className={onTarget ? "text-green-400" : "text-orange-400"}>
                      {m.value}{m.unit} / {m.target}{m.unit}
                    </span>
                  </div>
                  <div className="flex gap-1 items-center">
                    <div className="flex-1 bg-gray-700 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full ${onTarget ? "bg-green-500" : "bg-orange-500"}`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                    <span className="text-xs text-gray-500 w-8 text-right">{pct}%</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
