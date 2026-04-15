/**
 * Posture Trends Dashboard
 *
 * Shows metric trend cards with velocity indicators, CSS sparklines,
 * stagnating metrics alerts, targets progress table, and velocity summary.
 *
 * Route: /posture-trends
 * API: GET /api/v1/posture-trends
 */

import { useState } from "react";

// ── Types ──────────────────────────────────────────────────────

type Velocity = "improving" | "declining" | "stable";
type Category =
  | "vulnerability_management"
  | "identity_access"
  | "cloud_security"
  | "endpoint_protection"
  | "network_security"
  | "data_security"
  | "incident_response"
  | "compliance";

interface MetricTrend {
  id: string;
  category: Category;
  metric_name: string;
  current_value: number;
  previous_value: number;
  change_pct: number;
  velocity: Velocity;
  confidence: number;
  unit: string;
  higher_is_better: boolean;
  datapoints: number[];
  stagnating: boolean;
}

interface TargetProgress {
  id: string;
  metric_name: string;
  current: number;
  target: number;
  unit: string;
  gap: number;
  eta_days: number;
  on_track: boolean;
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_TRENDS: MetricTrend[] = [
  {
    id: "mt-001", category: "vulnerability_management", metric_name: "Critical Vuln MTTR",
    current_value: 28, previous_value: 36, change_pct: -22.2, velocity: "improving",
    confidence: 91, unit: "hrs", higher_is_better: false,
    datapoints: [52, 48, 44, 40, 36, 34, 31, 28], stagnating: false,
  },
  {
    id: "mt-002", category: "identity_access", metric_name: "MFA Adoption Rate",
    current_value: 94, previous_value: 89, change_pct: 5.6, velocity: "improving",
    confidence: 97, unit: "%", higher_is_better: true,
    datapoints: [72, 78, 82, 85, 88, 89, 91, 94], stagnating: false,
  },
  {
    id: "mt-003", category: "cloud_security", metric_name: "Cloud Posture Score",
    current_value: 71, previous_value: 74, change_pct: -4.1, velocity: "declining",
    confidence: 84, unit: "pts", higher_is_better: true,
    datapoints: [68, 72, 75, 76, 74, 73, 74, 71], stagnating: false,
  },
  {
    id: "mt-004", category: "endpoint_protection", metric_name: "Endpoint Coverage",
    current_value: 98, previous_value: 98, change_pct: 0.0, velocity: "stable",
    confidence: 99, unit: "%", higher_is_better: true,
    datapoints: [97, 97, 98, 98, 98, 98, 98, 98], stagnating: true,
  },
  {
    id: "mt-005", category: "network_security", metric_name: "Firewall Rule Violations",
    current_value: 43, previous_value: 31, change_pct: 38.7, velocity: "declining",
    confidence: 76, unit: "events/day", higher_is_better: false,
    datapoints: [18, 22, 25, 28, 31, 36, 40, 43], stagnating: false,
  },
  {
    id: "mt-006", category: "data_security", metric_name: "DLP Policy Coverage",
    current_value: 81, previous_value: 79, change_pct: 2.5, velocity: "improving",
    confidence: 88, unit: "%", higher_is_better: true,
    datapoints: [70, 72, 74, 76, 78, 79, 80, 81], stagnating: false,
  },
  {
    id: "mt-007", category: "incident_response", metric_name: "Mean Time to Detect",
    current_value: 4.2, previous_value: 4.3, change_pct: -2.3, velocity: "stable",
    confidence: 82, unit: "hrs", higher_is_better: false,
    datapoints: [6.1, 5.8, 5.4, 5.0, 4.7, 4.5, 4.3, 4.2], stagnating: true,
  },
  {
    id: "mt-008", category: "compliance", metric_name: "Overall Compliance Score",
    current_value: 76, previous_value: 69, change_pct: 10.1, velocity: "improving",
    confidence: 93, unit: "%", higher_is_better: true,
    datapoints: [55, 60, 63, 67, 69, 71, 73, 76], stagnating: false,
  },
];

const MOCK_TARGETS: TargetProgress[] = [
  { id: "tp-001", metric_name: "Critical Vuln MTTR",    current: 28,  target: 24,   unit: "hrs", gap: 4,    eta_days: 21,  on_track: true  },
  { id: "tp-002", metric_name: "MFA Adoption Rate",     current: 94,  target: 100,  unit: "%",   gap: 6,    eta_days: 45,  on_track: true  },
  { id: "tp-003", metric_name: "Cloud Posture Score",   current: 71,  target: 85,   unit: "pts", gap: 14,   eta_days: 120, on_track: false },
  { id: "tp-004", metric_name: "Firewall Violations",   current: 43,  target: 10,   unit: "/day",gap: 33,   eta_days: 90,  on_track: false },
  { id: "tp-005", metric_name: "DLP Policy Coverage",   current: 81,  target: 95,   unit: "%",   gap: 14,   eta_days: 60,  on_track: true  },
  { id: "tp-006", metric_name: "Compliance Score",      current: 76,  target: 90,   unit: "%",   gap: 14,   eta_days: 40,  on_track: true  },
];

// ── Helpers ────────────────────────────────────────────────────

const categoryLabels: Record<Category, string> = {
  vulnerability_management: "Vuln Mgmt",
  identity_access:          "Identity",
  cloud_security:           "Cloud",
  endpoint_protection:      "Endpoint",
  network_security:         "Network",
  data_security:            "Data",
  incident_response:        "IR",
  compliance:               "Compliance",
};

function velocityIndicator(v: Velocity, higherIsBetter: boolean): { symbol: string; color: string } {
  if (v === "stable") return { symbol: "→", color: "text-gray-400" };
  const improving = (v === "improving" && higherIsBetter) || (v === "declining" && !higherIsBetter);
  if (improving) return { symbol: "↑", color: "text-green-400" };
  return { symbol: "↓", color: "text-red-400" };
}

function sparklinePath(points: number[]): string {
  if (points.length < 2) return "";
  const min = Math.min(...points);
  const max = Math.max(...points);
  const range = max - min || 1;
  const W = 80;
  const H = 28;
  const step = W / (points.length - 1);
  return points.map((v, i) => {
    const x = i * step;
    const y = H - ((v - min) / range) * H;
    return `${i === 0 ? "M" : "L"} ${x.toFixed(1)} ${y.toFixed(1)}`;
  }).join(" ");
}

function sparklineColor(velocity: Velocity, higherIsBetter: boolean): string {
  const good = (velocity === "improving" && higherIsBetter) || (velocity === "declining" && !higherIsBetter);
  const bad  = (velocity === "declining" && higherIsBetter) || (velocity === "improving" && !higherIsBetter);
  if (good) return "#22c55e";
  if (bad)  return "#ef4444";
  return "#6b7280";
}

// ── Component ──────────────────────────────────────────────────

export default function PostureTrendsDashboard() {
  const [filterCategory, setFilterCategory] = useState<Category | "all">("all");

  const filteredTrends = filterCategory === "all"
    ? MOCK_TRENDS
    : MOCK_TRENDS.filter(t => t.category === filterCategory);

  const stagnating = MOCK_TRENDS.filter(t => t.stagnating);

  const improving = MOCK_TRENDS.filter(t => {
    const ind = velocityIndicator(t.velocity, t.higher_is_better);
    return ind.symbol === "↑";
  });
  const declining = MOCK_TRENDS.filter(t => {
    const ind = velocityIndicator(t.velocity, t.higher_is_better);
    return ind.symbol === "↓";
  });

  const fastestImproving = improving.reduce<MetricTrend | null>((best, t) =>
    !best || Math.abs(t.change_pct) > Math.abs(best.change_pct) ? t : best, null);
  const fastestDeclining = declining.reduce<MetricTrend | null>((best, t) =>
    !best || Math.abs(t.change_pct) > Math.abs(best.change_pct) ? t : best, null);

  const categories = [...new Set(MOCK_TRENDS.map(t => t.category))];

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Posture Trends</h1>
          <p className="text-gray-400 mt-1">Security posture velocity, metric trajectories, and target progress</p>
        </div>
      </div>

      {/* Velocity Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Improving",  value: improving.length,                      color: "text-green-400" },
          { label: "Declining",  value: declining.length,                      color: "text-red-400" },
          { label: "Stable",     value: MOCK_TRENDS.filter(t => t.velocity === "stable").length, color: "text-gray-400" },
          { label: "Stagnating", value: stagnating.length,                     color: "text-amber-400" },
        ].map(s => (
          <div key={s.label} className="bg-gray-800 rounded-lg p-5">
            <p className="text-gray-400 text-sm">{s.label}</p>
            <p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p>
            <p className="text-gray-500 text-xs mt-1">metrics</p>
          </div>
        ))}
      </div>

      {/* Velocity summary callouts */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {fastestImproving && (
          <div className="bg-green-900/20 border border-green-700 rounded-lg p-4">
            <p className="text-green-400 text-xs font-semibold uppercase tracking-wide mb-1">Fastest Improving</p>
            <p className="text-white font-medium">{fastestImproving.metric_name}</p>
            <p className="text-green-400 text-sm">+{Math.abs(fastestImproving.change_pct).toFixed(1)}% change</p>
          </div>
        )}
        {fastestDeclining && (
          <div className="bg-red-900/20 border border-red-700 rounded-lg p-4">
            <p className="text-red-400 text-xs font-semibold uppercase tracking-wide mb-1">Fastest Declining</p>
            <p className="text-white font-medium">{fastestDeclining.metric_name}</p>
            <p className="text-red-400 text-sm">{fastestDeclining.change_pct.toFixed(1)}% change</p>
          </div>
        )}
      </div>

      {/* Stagnating alert */}
      {stagnating.length > 0 && (
        <div className="bg-amber-900/20 border border-amber-700 rounded-lg p-4">
          <p className="text-amber-400 font-semibold text-sm mb-2">Stagnating Metrics — No meaningful change detected</p>
          <div className="flex flex-wrap gap-2">
            {stagnating.map(m => (
              <span key={m.id} className="bg-amber-800/40 text-amber-200 px-2 py-1 rounded text-xs">
                {m.metric_name} ({m.current_value} {m.unit})
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Category Filter */}
      <div className="flex gap-2 flex-wrap">
        <button
          onClick={() => setFilterCategory("all")}
          className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${filterCategory === "all" ? "bg-blue-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"}`}
        >
          All
        </button>
        {categories.map(cat => (
          <button
            key={cat}
            onClick={() => setFilterCategory(cat)}
            className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${filterCategory === cat ? "bg-blue-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"}`}
          >
            {categoryLabels[cat]}
          </button>
        ))}
      </div>

      {/* Metric Trend Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {filteredTrends.map(metric => {
          const ind = velocityIndicator(metric.velocity, metric.higher_is_better);
          const sColor = sparklineColor(metric.velocity, metric.higher_is_better);
          const path = sparklinePath(metric.datapoints);
          return (
            <div key={metric.id} className="bg-gray-800 rounded-lg p-5 space-y-3">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <p className="text-gray-500 text-xs">{categoryLabels[metric.category]}</p>
                  <p className="text-white text-sm font-semibold mt-0.5">{metric.metric_name}</p>
                </div>
                <span className={`text-2xl font-bold ${ind.color}`}>{ind.symbol}</span>
              </div>

              {/* Current value */}
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold text-white">{metric.current_value}</span>
                <span className="text-gray-400 text-sm">{metric.unit}</span>
                <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${
                  ind.symbol === "↑" ? "bg-green-900 text-green-300" :
                  ind.symbol === "↓" ? "bg-red-900 text-red-300" :
                  "bg-gray-700 text-gray-300"
                }`}>
                  {metric.change_pct > 0 ? "+" : ""}{metric.change_pct.toFixed(1)}%
                </span>
              </div>

              {/* Sparkline */}
              <svg width="80" height="28" className="overflow-visible">
                <path d={path} fill="none" stroke={sColor} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                {/* Last point dot */}
                {metric.datapoints.length > 0 && (() => {
                  const pts = metric.datapoints;
                  const min = Math.min(...pts);
                  const max = Math.max(...pts);
                  const range = max - min || 1;
                  const x = (pts.length - 1) * (80 / (pts.length - 1));
                  const y = 28 - ((pts[pts.length - 1] - min) / range) * 28;
                  return <circle cx={x} cy={y} r="3" fill={sColor} />;
                })()}
              </svg>

              {/* Confidence + previous */}
              <div className="flex items-center justify-between text-xs text-gray-500">
                <span>Confidence: <span className="text-gray-300 font-medium">{metric.confidence}%</span></span>
                <span>Prev: {metric.previous_value} {metric.unit}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Targets Progress Table */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Targets Progress</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-500 text-xs uppercase border-b border-gray-700">
                <th className="text-left pb-2 pr-4">Metric</th>
                <th className="text-left pb-2 pr-4">Current</th>
                <th className="text-left pb-2 pr-4">Target</th>
                <th className="text-left pb-2 pr-4">Gap</th>
                <th className="text-left pb-2 pr-4">ETA</th>
                <th className="text-left pb-2">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700/50">
              {MOCK_TARGETS.map(tp => (
                <tr key={tp.id} className="hover:bg-gray-700/30 transition-colors">
                  <td className="py-2.5 pr-4 text-gray-200 font-medium">{tp.metric_name}</td>
                  <td className="py-2.5 pr-4 text-white font-semibold">{tp.current} <span className="text-gray-500 text-xs font-normal">{tp.unit}</span></td>
                  <td className="py-2.5 pr-4 text-gray-400">{tp.target} <span className="text-gray-600 text-xs">{tp.unit}</span></td>
                  <td className="py-2.5 pr-4 text-amber-400">{tp.gap} {tp.unit}</td>
                  <td className="py-2.5 pr-4 text-gray-400">{tp.eta_days}d</td>
                  <td className="py-2.5">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${tp.on_track ? "bg-green-700 text-green-100" : "bg-red-700 text-red-100"}`}>
                      {tp.on_track ? "On Track" : "At Risk"}
                    </span>
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
